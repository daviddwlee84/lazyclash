package ruleobserve

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

// Accumulator has no I/O and is safe for stream and UI callers concurrently.
// Once full it keeps existing groups and reports dropped new observations.
type Accumulator struct {
	mu       sync.Mutex
	snapshot Snapshot
	groups   map[string]*Group
}

func New(targetID string, started time.Time) *Accumulator {
	var id [16]byte
	_, _ = rand.Read(id[:])
	if started.IsZero() {
		started = time.Now()
	}
	return &Accumulator{snapshot: Snapshot{Version: 1, ID: hex.EncodeToString(id[:]), TargetID: metadataText(targetID), Mode: "normal", Status: "observing", StartedAt: started, UpdatedAt: started, Groups: []Group{}, GapDetails: []Gap{}}, groups: map[string]*Group{}}
}

func (a *Accumulator) Observe(record core.Object, at time.Time) {
	if e, ok := Parse(record, at); ok {
		a.Add(e)
	}
}

func (a *Accumulator) Add(e Event) {
	e = safeEvent(e)
	// Healthy explicit matches are outside this workbench's evidence scope.
	// Preserve successful fallback observations for the optional MATCH view.
	if e.Kind == KindDialSuccess && !strings.EqualFold(e.Rule, "Match") {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.At.IsZero() {
		e.At = a.snapshot.UpdatedAt
	}
	if e.At.After(a.snapshot.UpdatedAt) {
		a.snapshot.UpdatedAt = e.At
	}
	a.snapshot.Observed++
	if e.Kind == KindOtherWarning {
		a.snapshot.Unparsed++
	}
	key := groupKey(e.Host, e.IsIP)
	g := a.groups[key]
	if g == nil {
		if len(a.groups) >= MaxGroups {
			// A full list of healthy fallback hosts must not hide a newly
			// observed anomaly. Evict the oldest success-only group first.
			victim := ""
			if e.Kind != KindDialSuccess {
				for k, candidate := range a.groups {
					if candidate.ErrorCount+candidate.OtherCount != 0 {
						continue
					}
					if victim == "" || candidate.LastSeen.Before(a.groups[victim].LastSeen) || candidate.LastSeen.Equal(a.groups[victim].LastSeen) && k < victim {
						victim = k
					}
				}
			}
			if victim == "" {
				a.snapshot.Dropped++
				return
			}
			a.snapshot.Dropped += a.groups[victim].Count
			delete(a.groups, victim)
		}
		g = &Group{Key: key, Host: e.Host, IsIP: e.IsIP, FirstSeen: e.At, LastSeen: e.At, Variants: []Variant{}}
		a.groups[key] = g
	}
	g.Count++
	switch e.Kind {
	case KindDialError:
		g.ErrorCount++
	case KindDialSuccess:
		g.SuccessCount++
	default:
		g.OtherCount++
	}
	updateTimes(&g.FirstSeen, &g.LastSeen, e.At)
	v := Variant{Kind: e.Kind, Network: e.Network, Port: e.Port, Process: e.Process, Rule: e.Rule, RulePayload: e.RulePayload, Policy: e.Policy, ErrorKind: e.ErrorKind}
	wanted := variantKey(v)
	for i := range g.Variants {
		if variantKey(g.Variants[i]) == wanted {
			current := &g.Variants[i]
			current.Count++
			updateTimes(&current.FirstSeen, &current.LastSeen, e.At)
			current.Samples = addSample(current.Samples, e.Summary)
			return
		}
	}
	if len(g.Variants) >= MaxVariants {
		g.DroppedVariants++
		a.snapshot.Dropped++
		return
	}
	v.Count, v.FirstSeen, v.LastSeen, v.Samples = 1, e.At, e.At, []string{e.Summary}
	g.Variants = append(g.Variants, v)
}

// Gap records an observation boundary. The caller's free-form message is
// converted to a fixed reason before it can reach a durable snapshot.
func (a *Accumulator) Gap(at time.Time, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot.Gaps++
	if at.After(a.snapshot.UpdatedAt) {
		a.snapshot.UpdatedAt = at
	}
	if len(a.snapshot.GapDetails) < MaxGapDetails {
		a.snapshot.GapDetails = append(a.snapshot.GapDetails, Gap{At: at, Reason: safeGapReason(reason)})
	}
}

// Snapshot returns detached, deterministically sorted state. at marks the
// observation window end, including intervals with no qualifying logs.
func (a *Accumulator) Snapshot(at time.Time) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.snapshot
	if at.After(s.UpdatedAt) {
		s.UpdatedAt = at
	}
	s.GapDetails = append([]Gap{}, s.GapDetails...)
	s.Groups = make([]Group, 0, len(a.groups))
	for _, g := range a.groups {
		copy := *g
		copy.Variants = append([]Variant{}, g.Variants...)
		for i := range copy.Variants {
			copy.Variants[i].Samples = append([]string{}, copy.Variants[i].Samples...)
		}
		sort.Slice(copy.Variants, func(i, j int) bool { return variantKey(copy.Variants[i]) < variantKey(copy.Variants[j]) })
		s.Groups = append(s.Groups, copy)
	}
	sort.Slice(s.Groups, func(i, j int) bool {
		if s.Groups[i].ErrorCount != s.Groups[j].ErrorCount {
			return s.Groups[i].ErrorCount > s.Groups[j].ErrorCount
		}
		if s.Groups[i].OtherCount != s.Groups[j].OtherCount {
			return s.Groups[i].OtherCount > s.Groups[j].OtherCount
		}
		return s.Groups[i].Key < s.Groups[j].Key
	})
	return s
}

func safeEvent(e Event) Event {
	if e.Kind != KindDialSuccess && e.Kind != KindDialError {
		return Event{At: e.At, Kind: KindOtherWarning, Level: "warning", ErrorKind: "unparsed", Summary: errorSummary("unparsed")}
	}
	host, ip, err := normalizeHost(e.Host)
	if err != nil {
		return Event{At: e.At, Kind: KindOtherWarning, Level: "warning", ErrorKind: "unparsed", Summary: errorSummary("unparsed")}
	}
	e.Host, e.IsIP = host, ip
	if e.Network != "TCP" && e.Network != "UDP" {
		e.Network = ""
	}
	if e.Port < 0 || e.Port > 65535 {
		e.Port = 0
	}
	e.Process, e.Policy, e.RulePayload = metadataText(e.Process), metadataText(e.Policy), metadataText(e.RulePayload)
	if !validRuleType(e.Rule) {
		e.Rule = ""
	}
	if e.Kind == KindDialSuccess {
		e.ErrorKind, e.Level, e.Summary = "", "info", "Outbound dial succeeded; application success is unknown."
	} else {
		e.Level = "warning"
		switch e.ErrorKind {
		case "dns", "timeout", "refused", "reset", "unreachable", "tls", "rejected", "canceled", "eof":
		default:
			e.ErrorKind = "other"
		}
		e.Summary = errorSummary(e.ErrorKind)
	}
	return e
}

func groupKey(host string, ip bool) string {
	if host == "" {
		return "other"
	}
	if ip {
		return "ip:" + host
	}
	return "domain:" + host
}

func variantKey(v Variant) string {
	// Length prefixes prevent user-controlled names from creating collisions.
	var b strings.Builder
	for _, p := range []string{v.Kind, v.Network, fmt.Sprint(v.Port), v.Process, v.Rule, v.RulePayload, v.Policy, v.ErrorKind} {
		fmt.Fprintf(&b, "%d:%s", len(p), p)
	}
	return b.String()
}

func updateTimes(first, last *time.Time, at time.Time) {
	if first.IsZero() || at.Before(*first) {
		*first = at
	}
	if last.IsZero() || at.After(*last) {
		*last = at
	}
}

func addSample(samples []string, text string) []string {
	for _, existing := range samples {
		if existing == text {
			return samples
		}
	}
	if len(samples) < MaxSamples {
		return append(samples, text)
	}
	return samples
}

func safeGapReason(reason string) string {
	s := strings.ToLower(reason)
	switch {
	case strings.Contains(s, "target"):
		return "Target changed; collection for the previous target ended."
	case strings.Contains(s, "quit"), strings.Contains(s, "close"), strings.Contains(s, "stop"):
		return "Collector stopped; the following interval was not observed."
	case strings.Contains(s, "capacity"), strings.Contains(s, "drop"), strings.Contains(s, "limit"):
		return "Observation capacity was exceeded."
	default:
		return "Controller stream was unavailable; this interval is incomplete."
	}
}
