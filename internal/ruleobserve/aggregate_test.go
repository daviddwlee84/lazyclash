package ruleobserve

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

func TestExactHostAggregationPreservesVariantsAndObservationCounts(t *testing.T) {
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	a := New("desktop", at)
	for i := 0; i < 10; i++ {
		a.Observe(core.Object{"type": "warning", "payload": "[TCP] dial Final (match Match/) 127.0.0.1:10 --> API.Example.com.:443 error: timeout"}, at.Add(time.Duration(i)*time.Second))
	}
	a.Observe(core.Object{"type": "info", "payload": "[TCP] 127.0.0.1:10 --> api.example.com:443 match Match using Final[DIRECT]"}, at.Add(11*time.Second))
	a.Observe(core.Object{"type": "warning", "payload": "[UDP] dial DIRECT (match Domain/api.example.com) 127.0.0.1:12 --> api.example.com:53 error: refused"}, at.Add(12*time.Second))
	a.Add(Event{At: at, Kind: KindDialError, Host: "other.example.com", ErrorKind: "timeout"})
	a.Add(Event{At: at, Kind: KindDialError, Host: "203.0.113.8", ErrorKind: "timeout"})
	a.Observe(core.Object{"type": "warning", "payload": "unknown.example failed SECRET"}, at)
	s := a.Snapshot(at.Add(time.Minute))
	if len(s.Groups) != 4 || s.Observed != 15 || s.Unparsed != 1 || s.Groups[0].Host != "api.example.com" {
		t.Fatalf("snapshot: %+v", s)
	}
	g := s.Groups[0]
	if g.Count != 12 || g.ErrorCount != 11 || g.SuccessCount != 1 || len(g.Variants) != 3 || g.FirstSeen != at || g.LastSeen != at.Add(12*time.Second) {
		t.Fatalf("group: %+v", g)
	}
	if s.UpdatedAt != at.Add(time.Minute) {
		t.Fatal("quiet window end lost")
	}
	// Snapshots must not alias live state or each other.
	s.Groups[0].Variants[0].Samples[0] = "changed"
	s.Groups[0].Host = "changed"
	if next := a.Snapshot(at); next.Groups[0].Host == "changed" || next.Groups[0].Variants[0].Samples[0] == "changed" {
		t.Fatal("snapshot aliases accumulator")
	}
}

func TestCapacityAndGapAccounting(t *testing.T) {
	at := time.Now()
	a := New("desktop", at)
	for i := 0; i < MaxGroups+2; i++ {
		a.Add(Event{At: at, Kind: KindDialError, Host: fmt.Sprintf("host-%d.example", i), ErrorKind: "timeout"})
	}
	// Existing groups still accumulate after new-group capacity is exhausted.
	a.Add(Event{At: at, Kind: KindDialError, Host: "host-0.example", ErrorKind: "timeout"})
	for i := 0; i < MaxGapDetails+2; i++ {
		a.Gap(at, "stream error: https://user:password@example.com?token=SECRET")
	}
	s := a.Snapshot(at)
	if len(s.Groups) != MaxGroups || s.Dropped != 2 || s.Gaps != MaxGapDetails+2 || len(s.GapDetails) != MaxGapDetails || s.Groups[0].Count != 2 {
		t.Fatalf("bounds: groups=%d dropped=%d gaps=%d details=%d", len(s.Groups), s.Dropped, s.Gaps, len(s.GapDetails))
	}
	if strings.Contains(s.GapDetails[0].Reason, "SECRET") {
		t.Fatal("raw gap error leaked")
	}
	b := New("desktop", at)
	for i := 0; i < MaxVariants+2; i++ {
		b.Add(Event{At: at, Kind: KindDialError, Host: "example.com", Port: i + 1, ErrorKind: "timeout"})
	}
	r := b.Snapshot(at)
	if len(r.Groups[0].Variants) != MaxVariants || r.Groups[0].DroppedVariants != 2 || r.Dropped != 2 || r.Groups[0].Count != MaxVariants+2 {
		t.Fatalf("variant bounds: %+v", r)
	}
}

func TestAccumulatorConcurrentReadersAndWriters(t *testing.T) {
	at := time.Now()
	a := New("desktop", at)
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				a.Add(Event{At: at, Kind: KindDialError, Host: "example.com", ErrorKind: "timeout"})
				_ = a.Snapshot(at)
			}
		}()
	}
	wg.Wait()
	if s := a.Snapshot(at); s.Observed != 400 || s.Groups[0].ErrorCount != 400 {
		t.Fatalf("lost observations: %+v", s)
	}
}

func TestHealthyExplicitMatchesDoNotDisplaceAnomalies(t *testing.T) {
	at := time.Now()
	a := New("desktop", at)
	a.Add(Event{At: at, Kind: KindDialSuccess, Host: "explicit.example", Rule: "Domain"})
	if s := a.Snapshot(at); s.Observed != 0 || len(s.Groups) != 0 {
		t.Fatal("ordinary successful match retained")
	}
	for i := 0; i < MaxGroups; i++ {
		a.Add(Event{At: at, Kind: KindDialSuccess, Host: fmt.Sprintf("healthy-%d.example", i), Rule: "Match"})
	}
	a.Add(Event{At: at, Kind: KindDialError, Host: "new-anomaly.example", Rule: "Match", ErrorKind: "timeout"})
	s := a.Snapshot(at)
	if len(s.Groups) != MaxGroups || s.Groups[0].Host != "new-anomaly.example" || s.Groups[0].ErrorCount != 1 || s.Dropped != 1 {
		t.Fatalf("healthy capacity hid anomaly: %+v", s.Groups[0])
	}
}
