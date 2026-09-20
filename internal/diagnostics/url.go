package diagnostics

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// RunURL compares deliberately separate request/resolver contexts. Missing
// capabilities are evidence, never a reason to silently change the route.
func RunURL(ctx context.Context, target config.Target, rawURL string, opts URLOptions) (URLResult, error) {
	u, err := diagnosticURL(rawURL)
	if err != nil {
		return URLResult{}, err
	}
	if opts.ReadOnly && !opts.ObserveOnly {
		return URLResult{}, ErrReadOnly
	}
	if opts.ObserveOnly && opts.ReferenceDoH != "" {
		return URLResult{}, errors.New("reference DoH is active and cannot be combined with observe-only")
	}
	if opts.ReferenceDoH != "" {
		doh, err := diagnosticURL(opts.ReferenceDoH)
		if err != nil || doh.Scheme != "https" || doh.RawQuery != "" {
			return URLResult{}, errors.New("reference DoH must be an HTTPS endpoint without credentials, query or fragment")
		}
		if target.ProbeProxy == "" {
			return URLResult{}, ErrNoProxy
		}
	}
	if strings.IndexFunc(opts.Via, unicode.IsControl) >= 0 || len(opts.Via) > 256 {
		return URLResult{}, errors.New("invalid outbound policy name")
	}
	limit := opts.Timeout
	if limit <= 0 || limit > time.Minute {
		limit = time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	result := URLResult{TargetID: target.ID, URL: publicURL(u), Host: u.Hostname(), SampledAt: opts.now(), ObserveOnly: opts.ObserveOnly, Connections: []ConnectionEvidence{}, Logs: []LogEvidence{}, Topology: []TopologyNode{}, Warnings: []string{}, ExplicitProxy: RequestEvidence{Source: "explicit data proxy", Status: "not-run"}}
	result.Warnings = append(result.Warnings, "Host processes, core resolver/outbounds and explicit proxy requests are different contexts; no-application-proxy can still traverse TUN or transparent routing.", "A missing active connection is not evidence that a request bypassed the core. DNS differences do not establish DNS pollution.")
	if target.SSHHost != "" {
		result.Warnings = append(result.Warnings, "SSH environment is a noninteractive process, not every application or the core service environment. SSH forwarding prevents exact local source-tuple correlation.")
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	client, closer, openErr := open(ctx, target, opts.ObserveOnly)
	if closer != nil {
		defer closer.Close()
	}
	var proxies map[string]core.Proxy
	if openErr == nil && client != nil {
		defer client.Close()
		result.Core.Available = true
		readCtx, stop := context.WithTimeout(ctx, 4*time.Second)
		version, _ := client.Version(readCtx)
		result.Core.Version = evidenceText(version["version"])
		settings, configErr := client.Config(readCtx)
		if configErr != nil {
			result.Core.Error = "runtime settings unavailable"
		}
		result.Core.Mode = evidenceText(settings["mode"])
		if tun, ok := settings["tun"].(map[string]any); ok {
			result.Core.TUNEnabled, result.Core.TUNKnown = tun["enable"].(bool)
		}
		proxies, _ = client.Proxies(readCtx)
		stop()
	} else {
		result.Core.Error = "controller unavailable; other contexts are still tested independently"
		if connection.IsAuthRequired(openErr) {
			return result, openErr
		}
	}
	if opts.Via != "" {
		if _, ok := proxies[opts.Via]; !ok {
			if result.Core.Available {
				return result, errors.New("requested outbound policy does not exist in this target")
			}
			result.Warnings = append(result.Warnings, "Requested policy could not be verified while the controller is unavailable.")
		}
	}
	captureCtx, stopCapture := context.WithCancel(ctx)
	var capture *urlCapture
	if client != nil && openErr == nil {
		capture = beginURLCapture(captureCtx, client, u.Hostname(), opts.ObserveOnly)
	}
	collector := opts.HostCollector
	if collector == nil {
		collector = CollectHost
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	hostRequest := HostRequest{URL: u.String(), Host: u.Hostname(), Port: port, ObserveOnly: opts.ObserveOnly, InventoryOnly: true}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); result.Local = collectURLHost(ctx, collector, "", hostRequest) }()
	if target.SSHHost != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			remote := collectURLHost(ctx, collector, target.SSHHost, hostRequest)
			result.Remote = &remote
		}()
	}
	if !opts.ObserveOnly {
		if client != nil && openErr == nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, kind := range []string{"A", "AAAA"} {
					result.Core.DNS = append(result.Core.DNS, coreDNS(ctx, client, u.Hostname(), kind))
				}
			}()
		}
	}
	wg.Wait()
	// Keep request windows distinct so the diagnostic does not manufacture its
	// own correlation ambiguity. Inventory/resolver reads can run concurrently.
	if !opts.ObserveOnly {
		hostRequest.InventoryOnly, hostRequest.RequestOnly = false, true
		for _, host := range []struct {
			alias    string
			evidence *HostEvidence
		}{{"", &result.Local}, {target.SSHHost, result.Remote}} {
			if host.evidence == nil {
				continue
			}
			for _, kind := range []string{"environment", "no-application-proxy"} {
				if ctx.Err() != nil {
					break
				}
				hostRequest.RequestKind = kind
				sample := collectURLHost(ctx, collector, host.alias, hostRequest)
				host.evidence.Requests = append(host.evidence.Requests, sample.Requests...)
			}
		}
		if ctx.Err() == nil {
			result.ExplicitProxy = explicitURLRequest(ctx, target, u.String(), opts.Options)
		}
		if client != nil && openErr == nil {
			names := []string{"DIRECT"}
			if opts.Via != "" && opts.Via != "DIRECT" {
				names = append(names, opts.Via)
			}
			for _, name := range names {
				if ctx.Err() != nil {
					break
				}
				result.Core.Outbounds = append(result.Core.Outbounds, outboundURLTest(ctx, client, proxies, name, u.String()))
			}
		}
		if opts.ReferenceDoH != "" && ctx.Err() == nil {
			result.ReferenceDNS = referenceDNS(ctx, target, u.Hostname(), opts)
		}
	}
	stopCapture()
	if capture != nil {
		capture.wait()
		result.Connections, result.Logs = correlateURL(capture, result, target.SSHHost != "")
		if capture.failed {
			result.Warnings = append(result.Warnings, "Core event collection was unavailable, disconnected or reached its collection bound; retained evidence may be incomplete.")
		}
	}
	result.Topology = urlTopology(target, result)
	result.Recommendation = recommendDomain(result, opts.Via, proxies)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return result, nil
}

func diagnosticURL(raw string) (*url.URL, error) {
	if len(raw) > 8192 || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, errors.New("URL must be a bounded HTTP(S) URL without credentials or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.ContainsAny(u.Hostname(), " ,\t\n\\") {
		return nil, errors.New("URL must be HTTP(S), with a host and without credentials or a fragment")
	}
	for _, c := range u.Hostname() {
		if c > unicode.MaxASCII {
			return nil, errors.New("URL host must use ASCII or Punycode; convert internationalized domain names before diagnosis")
		}
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("URL port must be between 1 and 65535")
		}
	}
	return u, nil
}

func collectURLHost(ctx context.Context, collector func(context.Context, string, HostRequest) (HostEvidence, error), host string, request HostRequest) HostEvidence {
	result, err := collector(ctx, host, request)
	if result.Scope == "" {
		if host == "" {
			result.Scope = "local process"
		} else {
			result.Scope = "SSH noninteractive process"
		}
	}
	if err != nil {
		if result.Error == "" {
			result.Error = "host evidence unavailable"
		}
		if request.RequestOnly && len(result.Requests) == 0 {
			result.Requests = []RequestEvidence{{Source: result.Scope + "/" + request.RequestKind, Status: "unavailable", Error: result.Error}}
		}
	}
	return result
}

func publicURL(u *url.URL) string {
	copy := *u
	copy.RawQuery, copy.Fragment, copy.ForceQuery = "", "", false
	return copy.String()
}

func evidenceText(v any) string {
	s, _ := v.(string)
	s = strings.Join(strings.Fields(core.Sanitize(s)), " ")
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

func explicitURLRequest(ctx context.Context, target config.Target, endpoint string, opts Options) RequestEvidence {
	r := RequestEvidence{Source: "explicit data proxy", Status: "unavailable", Route: route(target, safeEndpoint(target.ProbeProxy)), Note: "Fresh HEAD request, no redirects; controller availability is independent. HTTP status is not a core URLTest result. DNS/connect/TLS/first-byte times are cumulative local transport milestones and can describe the proxy, not destination DNS."}
	p, err := newProbe(ctx, target, opts)
	if err != nil {
		if errors.Is(err, ErrNoProxy) {
			r.Error = ErrNoProxy.Error()
		} else {
			r.Error = "explicit proxy setup unavailable"
		}
		return r
	}
	defer p.Close()
	r.StartedAt = time.Now()
	var mu sync.Mutex
	trace := &httptrace.ClientTrace{DNSDone: func(httptrace.DNSDoneInfo) {
		mu.Lock()
		defer mu.Unlock()
		r.DNSMilliseconds = float64(time.Since(r.StartedAt)) / float64(time.Millisecond)
	}, ConnectDone: func(_, _ string, err error) {
		if err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		r.ConnectMilliseconds = float64(time.Since(r.StartedAt)) / float64(time.Millisecond)
	}, TLSHandshakeDone: func(tls.ConnectionState, error) {
		mu.Lock()
		defer mu.Unlock()
		r.TLSMilliseconds = float64(time.Since(r.StartedAt)) / float64(time.Millisecond)
	}, GotConn: func(info httptrace.GotConnInfo) {
		mu.Lock()
		defer mu.Unlock()
		r.LocalAddress, r.RemoteAddress = info.Conn.LocalAddr().String(), info.Conn.RemoteAddr().String()
	}, GotFirstResponseByte: func() {
		mu.Lock()
		defer mu.Unlock()
		r.FirstByteMilliseconds = float64(time.Since(r.StartedAt)) / float64(time.Millisecond)
	}}
	request, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, endpoint, nil)
	request.Header.Set("User-Agent", "lazyclash")
	response, err := probeClient(p, 5*time.Second).Do(request)
	mu.Lock()
	defer mu.Unlock()
	r.FinishedAt = time.Now()
	r.Milliseconds = float64(r.FinishedAt.Sub(r.StartedAt)) / float64(time.Millisecond)
	if err != nil {
		r.Status, r.Error = "failed", safeRequestError(ctx, err).Error()
		return r
	}
	response.Body.Close()
	r.Status, r.HTTPStatus = "http-response", response.StatusCode
	return r
}

func safeEndpoint(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "configured proxy (invalid endpoint)"
	}
	u.User = nil
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.ForceQuery = false
	return u.String()
}

func coreDNS(ctx context.Context, client *core.Client, host, kind string) DNSResult {
	r := DNSResult{Source: "core resolver", Type: kind, Addresses: []string{}}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	object, err := client.DNSQuery(ctx, host, kind)
	if err != nil {
		r.Error = "core DNS query unavailable"
		return r
	}
	answers, _ := object["Answer"].([]any)
	for _, answer := range answers {
		row, _ := answer.(map[string]any)
		ip := evidenceText(row["data"])
		if net.ParseIP(ip) != nil {
			r.Addresses = append(r.Addresses, ip)
		}
	}
	return r
}

func outboundURLTest(ctx context.Context, client *core.Client, proxies map[string]core.Proxy, name, endpoint string) OutboundEvidence {
	r := OutboundEvidence{Policy: name, Status: "unavailable", Note: "Core URLTest proves a response-time sample only, not HTTP status or page usability; may update health/history. No selector or mode is changed."}
	current := name
	seen := map[string]bool{}
	for len(r.Chain) < 16 {
		if seen[current] {
			r.Error = "outbound selection contains a cycle"
			return r
		}
		seen[current] = true
		r.Chain = append(r.Chain, current)
		proxy, ok := proxies[current]
		if !ok {
			if current == "DIRECT" {
				r.Leaf = current
				break
			}
			r.Error = "outbound selection is unavailable"
			return r
		}
		if len(proxy.All) == 0 {
			r.Leaf = current
			break
		}
		if proxy.Now == "" {
			r.Error = "outbound group has no observed selected leaf"
			return r
		}
		current = proxy.Now
	}
	if r.Leaf == "" {
		r.Error = "outbound chain exceeds limit"
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	r.StartedAt = time.Now()
	object, err := client.URLDelay(ctx, r.Leaf, endpoint, 5*time.Second)
	r.FinishedAt = time.Now()
	if err != nil {
		r.Status, r.Error = "failed", "core outbound URLTest failed"
		return r
	}
	switch delay := object["delay"].(type) {
	case float64:
		r.Milliseconds = delay
	case int:
		r.Milliseconds = float64(delay)
	default:
		r.Error = "core URLTest returned no timing sample"
		return r
	}
	if r.Milliseconds < 0 {
		r.Error = "core URLTest returned an invalid timing sample"
		return r
	}
	r.Status = "response-sample"
	return r
}

func recommendDomain(result URLResult, via string, proxies map[string]core.Proxy) *RuleRecommendation {
	if result.ObserveOnly || result.Core.Mode != "rule" || via == "" || via == "DIRECT" || strings.Contains(via, ",") || net.ParseIP(result.Host) != nil {
		return nil
	}
	if _, ok := proxies[via]; !ok {
		return nil
	}
	for _, c := range result.Host {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return nil
		}
	}
	for _, connection := range result.Connections {
		if connection.Confidence == "observed" && len(connection.Chains) > 0 && !strings.EqualFold(connection.Chains[0], "DIRECT") {
			return nil
		}
	}
	failed, responded := false, false
	for _, p := range result.Core.Outbounds {
		if p.Policy == "DIRECT" && p.Status == "failed" {
			failed = true
		}
		if p.Policy == via && p.Status == "response-sample" && p.Leaf != "" && !strings.EqualFold(p.Leaf, "DIRECT") {
			responded = true
		}
	}
	if !failed || !responded {
		return nil
	}
	host := strings.ToLower(strings.TrimSuffix(result.Host, "."))
	reason := "Core DIRECT URLTest failed while the chosen alternative returned a timing sample. This compares core paths only; URLTest does not expose HTTP status or prove application success. The rule affects requests reaching this core in rule mode; review before adding it."
	if result.Local.Environment.NoProxyMatches || result.Remote != nil && result.Remote.Environment.NoProxyMatches {
		reason += " An observed NO_PROXY match may bypass an application proxy; adding a core rule does not change NO_PROXY or application settings."
	}
	return &RuleRecommendation{Type: "DOMAIN", Domain: host, Policy: via, Rule: "DOMAIN," + host + "," + via, Confidence: "tentative", Reason: reason}
}

func FormatURL(r URLResult) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("URL diagnosis: %s\nTarget: %s · %s", r.URL, r.TargetID, r.SampledAt.Format(time.RFC3339)))
	for _, host := range []*HostEvidence{&r.Local, r.Remote} {
		if host == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %s · DNS %s", host.Scope, host.System, strings.Join(host.DNS.Addresses, ", ")))
		if host.Error != "" {
			lines = append(lines, "  "+host.Error)
		}
		for _, request := range host.Requests {
			lines = append(lines, formatRequest(request))
		}
	}
	tun := "unknown"
	if r.Core.TUNKnown {
		tun = strconv.FormatBool(r.Core.TUNEnabled)
	}
	lines = append(lines, fmt.Sprintf("Core: available=%t mode=%s TUN=%s", r.Core.Available, r.Core.Mode, tun), formatRequest(r.ExplicitProxy))
	for _, outbound := range r.Core.Outbounds {
		lines = append(lines, fmt.Sprintf("  Core URLTest %s → %s: %s %.1f ms %s", outbound.Policy, outbound.Leaf, outbound.Status, outbound.Milliseconds, outbound.Error))
	}
	for _, connection := range r.Connections {
		lines = append(lines, fmt.Sprintf("  %s: %s → %s · %s (%s)", connection.Confidence, connection.Rule, strings.Join(connection.Chains, " ← "), connection.RequestSource, connection.Reason))
	}
	if len(r.Connections) == 0 {
		lines = append(lines, "  No correlated active connection captured; routing remains unknown.")
	}
	if r.Recommendation != nil {
		lines = append(lines, "Tentative rule: "+r.Recommendation.Rule, r.Recommendation.Reason)
	}
	lines = append(lines, r.Warnings...)
	return core.Sanitize(strings.Join(lines, "\n"))
}

func formatRequest(r RequestEvidence) string {
	return fmt.Sprintf("  %s: %s · HTTP %d · %.1f ms %s", r.Source, r.Status, r.HTTPStatus, r.Milliseconds, r.Error)
}
