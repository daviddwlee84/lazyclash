package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
)

func federationQuery() analytics.Query {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	return analytics.Query{From: now.Add(-time.Hour), To: now, Timezone: "UTC", GroupBy: "source", Limit: 50}
}
func federationFixture(id string, up int64) analytics.Report {
	return analytics.Report{Timezone: "UTC", Resolution: "minute", Rows: []analytics.ReportRow{{SourceID: id, Key: id, UploadBytes: up, BytesAvailable: true}}, Coverage: []analytics.Coverage{{SourceID: id, Status: analytics.SourceStatus{SourceID: id, Source: &analytics.SourceConfig{ID: id}}}}}
}
func federationReader(r analytics.Report, err error) func(context.Context, analytics.Query) (analytics.Report, error) {
	return func(context.Context, analytics.Query) (analytics.Report, error) { return r, err }
}

func TestFederationSeparatesDuplicateSourceIDsAndPreservesMixedResolution(t *testing.T) {
	first := federationFixture("proxy", 10)
	second := federationFixture("proxy", 20)
	second.Resolution = "day"
	second.Warnings = []string{"native daily buckets"}
	r, err := federatedAnalytics(context.Background(), federationQuery(), []analyticsCollector{{ID: "local", Load: federationReader(first, nil)}, {ID: "vm1", Load: federationReader(second, nil)}})
	if err != nil || len(r.Rows) != 2 || r.Rows[0].SourceID != "vm1::proxy" || r.Rows[0].UploadBytes != 20 || r.Rows[1].SourceID != "local::proxy" || r.Resolution != "mixed" {
		t.Fatalf("sources were combined or lost: %#v %v", r, err)
	}
	if r.Rows[0].Key != "vm1::proxy" || r.Coverage[0].Status.SourceID != "local::proxy" || r.Coverage[0].Status.Source.ID != "local::proxy" {
		t.Fatalf("nested source IDs not namespaced: %#v", r)
	}
	if first.Coverage[0].Status.Source.ID != "proxy" {
		t.Fatal("federation mutated a cached input report")
	}
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "[vm1] native daily buckets") {
		t.Fatal("warning lost collector provenance")
	}
}

func TestFederationNamespaceRoutesExactCollectorAndSource(t *testing.T) {
	q := federationQuery()
	q.SourceID = "vm1::same"
	var local, remote atomic.Int64
	collectors := []analyticsCollector{{ID: "local", Load: func(context.Context, analytics.Query) (analytics.Report, error) {
		local.Add(1)
		return analytics.Report{}, nil
	}}, {ID: "vm1", Load: func(_ context.Context, received analytics.Query) (analytics.Report, error) {
		remote.Add(1)
		if received.SourceID != "same" {
			t.Errorf("namespace not stripped: %q", received.SourceID)
		}
		r := federationFixture("same", 1)
		r.Rows = append(r.Rows, analytics.ReportRow{SourceID: "same-prefix", UploadBytes: 9})
		return r, nil
	}}}
	r, err := federatedAnalytics(context.Background(), q, collectors)
	if err != nil || local.Load() != 0 || remote.Load() != 1 || len(r.Rows) != 1 || r.Rows[0].SourceID != "vm1::same" {
		t.Fatalf("namespace filter failed: %#v %v", r, err)
	}
	q.SourceID = "missing::same"
	if _, err = federatedAnalytics(context.Background(), q, collectors); err == nil {
		t.Fatal("missing collector became empty zero report")
	}
	if remote.Load() != 1 {
		t.Fatal("invalid namespace contacted collectors")
	}
	q.SourceID = "same"
	_, err = federatedAnalytics(context.Background(), q, collectors)
	if err != nil || local.Load() != 1 || remote.Load() != 2 {
		t.Fatalf("plain ID should query all collectors: %v", err)
	}
}

func TestFederationUnavailablePartialAndWholeFailureKeepRows(t *testing.T) {
	partial := federationFixture("old", 1)
	r, err := federatedAnalytics(context.Background(), federationQuery(), []analyticsCollector{{ID: "good", Load: federationReader(federationFixture("s", 2), nil)}, {ID: "bad", Load: federationReader(partial, errors.New("secret transport details"))}})
	if err != nil || len(r.Rows) != 2 {
		t.Fatalf("partial failure discarded good rows: %#v %v", r, err)
	}
	found := false
	for _, c := range r.Coverage {
		if c.SourceID == "bad::(unavailable)" {
			found = c.Partial && c.Status.State == "unavailable"
		}
	}
	if !found || strings.Contains(strings.Join(r.Warnings, "\n"), "secret transport") {
		t.Fatal("missing unavailable coverage or leaked raw error")
	}
	r, err = federatedAnalytics(context.Background(), federationQuery(), []analyticsCollector{{ID: "bad", Load: federationReader(partial, errors.New("offline"))}})
	if err == nil || len(r.Rows) != 1 || r.Rows[0].SourceID != "bad::old" {
		t.Fatalf("whole failure must keep returned partial rows: %#v %v", r, err)
	}
}

func TestFederationGlobalLimitStableSortAndDuplicateCollectors(t *testing.T) {
	q := federationQuery()
	q.Limit = 2
	var reads atomic.Int64
	reader := func(context.Context, analytics.Query) (analytics.Report, error) {
		reads.Add(1)
		r := federationFixture("a", 10)
		r.Rows = append(r.Rows, analytics.ReportRow{SourceID: "b", Key: "b", UploadBytes: 20, Connections: 2})
		return r, nil
	}
	r, err := federatedAnalytics(context.Background(), q, []analyticsCollector{{ID: "one", Load: reader}, {ID: "two", Load: reader}, {ID: "one", Load: reader}})
	if err != nil || reads.Load() != 2 || len(r.Rows) != 2 || !r.Truncated || r.Rows[0].SourceID != "one::b" || r.Rows[1].SourceID != "two::b" {
		t.Fatalf("global limit/dedup failed: %#v %v", r, err)
	}
	var tooMany []analyticsCollector
	for i := 0; i < 9; i++ {
		tooMany = append(tooMany, analyticsCollector{ID: fmt.Sprint(i), Load: reader})
	}
	if _, err = federatedAnalytics(context.Background(), q, tooMany); err == nil {
		t.Fatal("unbounded collector count accepted")
	}
}

func TestFederationCancellationAndBoundedWorkers(t *testing.T) {
	var active, peak atomic.Int64
	started := make(chan struct{}, 8)
	load := func(ctx context.Context, _ analytics.Query) (analytics.Report, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if old >= n || peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-ctx.Done()
		return analytics.Report{}, ctx.Err()
	}
	collectors := make([]analyticsCollector, 8)
	for i := range collectors {
		collectors[i] = analyticsCollector{ID: fmt.Sprint(i), Load: load}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := federatedAnalytics(ctx, federationQuery(), collectors); done <- err }()
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	if peak.Load() != 4 {
		t.Fatalf("expected bounded four workers, got %d", peak.Load())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation was lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("federation ignored cancellation")
	}
	if peak.Load() > 4 {
		t.Fatal("more than four concurrent loads")
	}
}

func TestFederationEmptyLocalReportNeedsNoStore(t *testing.T) {
	r, err := federatedAnalytics(context.Background(), federationQuery(), []analyticsCollector{{ID: "local", Load: federationReader(analytics.Report{}, nil)}})
	if err != nil || len(r.Rows) != 0 || len(r.Coverage) != 0 {
		t.Fatalf("empty local reader became a fake zero source: %#v %v", r, err)
	}
}
