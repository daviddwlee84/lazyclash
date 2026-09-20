package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type capturedConnection struct {
	evidence  ConnectionEvidence
	baseline  bool
	firstSeen time.Time
}
type urlCapture struct {
	mu          sync.Mutex
	wg          sync.WaitGroup
	host        string
	connections map[string]capturedConnection
	logs        []LogEvidence
	failed      bool
}

func beginURLCapture(ctx context.Context, client *core.Client, host string, observeOnly bool) *urlCapture {
	c := &urlCapture{host: host, connections: map[string]capturedConnection{}, logs: []LogEvidence{}}
	c.read(ctx, client, true)
	if observeOnly {
		return c
	}
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				c.mu.Lock()
				c.failed = true
				c.mu.Unlock()
				return
			case <-ticker.C:
				c.read(ctx, client, false)
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		count := 0
		pattern := regexp.MustCompile(`(?i)(^|[^a-z0-9._-])` + regexp.QuoteMeta(strings.TrimSuffix(host, ".")) + `([^a-z0-9._-]|$)`)
		err := client.StreamWithOptions(ctx, "logs", url.Values{"level": {"debug"}}, core.StreamOptions{Duration: time.Minute, Limit: 128}, func(record core.Object) (bool, error) {
			count++
			payload, _ := record["payload"].(string)
			if pattern.MatchString(payload) {
				c.mu.Lock()
				if len(c.logs) < 16 {
					c.logs = append(c.logs, LogEvidence{Level: evidenceText(record["type"]), Host: host, Confidence: "unknown", Note: "Host mentioned during the bounded observation window; raw log text is omitted and does not identify which request caused it."})
				}
				c.mu.Unlock()
			}
			return true, nil
		})
		if count >= 128 || ctx.Err() == nil && err != nil {
			c.mu.Lock()
			c.failed = true
			c.mu.Unlock()
		}
	}()
	return c
}

func (c *urlCapture) wait() { c.wg.Wait() }
func (c *urlCapture) read(ctx context.Context, client *core.Client, baseline bool) {
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	object, err := client.Connections(readCtx)
	if err != nil {
		if ctx.Err() == nil {
			c.mu.Lock()
			c.failed = true
			c.mu.Unlock()
		}
		return
	}
	rows, _ := object["connections"].([]any)
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, row := range rows {
		if i >= 5000 {
			c.failed = true
			break
		}
		item, _ := row.(map[string]any)
		metadata, _ := item["metadata"].(map[string]any)
		host := evidenceText(metadata["host"])
		if !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(c.host, ".")) && !(net.ParseIP(c.host) != nil && evidenceText(metadata["destinationIP"]) == c.host) {
			continue
		}
		id := evidenceText(item["id"])
		if id == "" {
			continue
		}
		if _, exists := c.connections[id]; exists {
			continue
		}
		if len(c.connections) >= 64 {
			c.failed = true
			break
		}
		chains := []string{}
		if raw, ok := item["chains"].([]any); ok {
			for _, chain := range raw {
				if s := evidenceText(chain); s != "" {
					chains = append(chains, s)
				}
				if len(chains) >= 16 {
					break
				}
			}
		}
		c.connections[id] = capturedConnection{evidence: ConnectionEvidence{ID: id, Host: host, SourceAddress: metadataAddress(metadata, "source"), DestinationAddress: metadataAddress(metadata, "destination"), InboundType: evidenceText(metadata["type"]), Network: evidenceText(metadata["network"]), Rule: evidenceText(item["rule"]), RulePayload: evidenceText(item["rulePayload"]), Chains: chains}, baseline: baseline, firstSeen: time.Now()}
	}
}

func metadataAddress(metadata map[string]any, prefix string) string {
	ip := evidenceText(metadata[prefix+"IP"])
	if ip == "" {
		return ""
	}
	port := ""
	switch v := metadata[prefix+"Port"].(type) {
	case string:
		port = v
	case float64:
		port = strconv.Itoa(int(v))
	case int:
		port = strconv.Itoa(v)
	}
	if port == "" {
		return ip
	}
	return net.JoinHostPort(ip, port)
}

func correlateURL(c *urlCapture, result URLResult, ssh bool) ([]ConnectionEvidence, []LogEvidence) {
	requests := append([]RequestEvidence{}, result.Local.Requests...)
	requests = append(requests, result.ExplicitProxy)
	if result.Remote != nil {
		requests = append(requests, result.Remote.Requests...)
	}
	for _, outbound := range result.Core.Outbounds {
		requests = append(requests, RequestEvidence{Source: "core URLTest/" + outbound.Policy, StartedAt: outbound.StartedAt, FinishedAt: outbound.FinishedAt})
	}
	connections := []ConnectionEvidence{}
	probableCounts := map[string]int{}
	for _, entry := range c.connections {
		evidence := entry.evidence
		evidence.Confidence = "unknown"
		evidence.Reason = "Host match alone does not identify a request."
		if entry.baseline {
			evidence.Reason = "Connection existed before the diagnostic request window."
			connections = append(connections, evidence)
			continue
		}
		matches := []RequestEvidence{}
		for _, request := range requests {
			if request.StartedAt.IsZero() || request.FinishedAt.IsZero() {
				continue
			}
			if entry.firstSeen.Before(request.StartedAt) || entry.firstSeen.After(request.FinishedAt) {
				continue
			}
			matches = append(matches, request)
			if !ssh && request.LocalAddress != "" && request.LocalAddress == evidence.SourceAddress && !strings.HasPrefix(request.Source, "SSH") {
				evidence.Confidence = "observed"
				evidence.RequestSource = request.Source
				evidence.Reason = "Destination host and local source address/port matched during the request window."
				break
			}
		}
		if evidence.Confidence != "observed" && len(matches) == 1 {
			evidence.Confidence = "probable"
			evidence.RequestSource = matches[0].Source
			evidence.Reason = "Unique host/time candidate without a verified source tuple."
			if ssh {
				evidence.Reason = "Unique host/time candidate; SSH forwarding source tuples cannot be mapped exactly."
			}
			probableCounts[evidence.RequestSource]++
		}
		connections = append(connections, evidence)
	}
	for i := range connections {
		if connections[i].Confidence == "probable" && probableCounts[connections[i].RequestSource] > 1 {
			connections[i].Confidence = "unknown"
			connections[i].Reason = "Multiple new connections fit the same request window; correlation is ambiguous."
			connections[i].RequestSource = ""
		}
	}
	sort.Slice(connections, func(i, j int) bool { return connections[i].ID < connections[j].ID })
	return connections, append([]LogEvidence{}, c.logs...)
}

func urlTopology(target config.Target, result URLResult) []TopologyNode {
	nodes := []TopologyNode{{Kind: "client", Label: "local diagnostic process", Confidence: "observed"}, {Kind: "environment", Label: "local environment and OS proxy configuration (application use varies)", Confidence: "observed"}}
	if target.ProbeProxy != "" {
		nodes = append(nodes, TopologyNode{Kind: "proxy", Label: safeEndpoint(target.ProbeProxy), Confidence: "observed"})
	}
	if target.SSHHost != "" {
		nodes = append(nodes, TopologyNode{Kind: "ssh", Label: "SSH " + target.SSHHost, Confidence: "observed"})
	}
	tun := "unknown"
	if result.Core.TUNKnown {
		tun = strconv.FormatBool(result.Core.TUNEnabled)
	}
	nodes = append(nodes, TopologyNode{Kind: "core", Label: fmt.Sprintf("core mode=%s TUN=%s", result.Core.Mode, tun), Confidence: map[bool]string{true: "observed", false: "unknown"}[result.Core.Available]})
	var strongest *ConnectionEvidence
	for i := range result.Connections {
		candidate := &result.Connections[i]
		if candidate.Confidence == "unknown" {
			continue
		}
		if strongest == nil || candidate.Confidence == "observed" && strongest.Confidence != "observed" || candidate.Confidence == strongest.Confidence && candidate.ID < strongest.ID {
			strongest = candidate
		}
	}
	if strongest != nil {
		nodes = append(nodes, TopologyNode{Kind: "inbound", Label: strongest.InboundType + " " + strongest.Network, Confidence: strongest.Confidence}, TopologyNode{Kind: "rule", Label: strongest.Rule + " " + strongest.RulePayload, Confidence: strongest.Confidence})
		for i := len(strongest.Chains) - 1; i >= 0; i-- {
			nodes = append(nodes, TopologyNode{Kind: "outbound", Label: strongest.Chains[i], Confidence: strongest.Confidence})
		}
	} else {
		nodes = append(nodes, TopologyNode{Kind: "route", Label: "Rule and outbound route unknown; no uniquely correlated core connection", Confidence: "unknown"})
	}
	nodes = append(nodes, TopologyNode{Kind: "destination", Label: result.Host, Confidence: "observed"})
	return nodes
}
