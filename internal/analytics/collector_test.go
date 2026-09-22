package analytics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type collectorTestCloser struct{}

func (collectorTestCloser) Close() error { return nil }

func TestCollectorDurationDisabledAndHealth(t *testing.T) {
	store := collectorTestStore(t)
	cfg := DefaultConfig()
	cfg.Timezone = "UTC"
	cfg.Sources = []SourceConfig{{ID: "disabled", Kind: "mihomo", Target: "missing", Enabled: false}, {ID: "active", Kind: "mihomo", Target: "test", Enabled: true}}
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, `{"uploadTotal":100,"downloadTotal":200,"connections":[]}`)
	}))
	defer server.Close()
	open := func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if target.ID != "test" || !readOnly {
			t.Errorf("wrong source or writable connection")
		}
		c, err := core.New(core.Options{Endpoint: server.URL, ReadOnly: readOnly})
		return c, collectorTestCloser{}, err
	}
	if err := RunCollector(context.Background(), cfg, store, []config.Target{{ID: "test", Controller: server.URL}}, CollectorOptions{Duration: 150 * time.Millisecond, Open: open}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected collection calls: %d", calls.Load())
	}
	status, ok, err := store.SourceStatus(context.Background(), "active")
	if err != nil || !ok || status.State != "baseline" {
		t.Fatalf("status not saved: %#v %v", status, err)
	}
	health, err := CollectorHealth(store.Path())
	if err != nil || health.PID != os.Getpid() || health.Polls != 1 || health.State != "stopped" || health.HeapBytes == 0 {
		t.Fatalf("health not persisted: %#v %v", health, err)
	}
	if _, ok, err = store.Checkpoint(context.Background(), "active", "counters"); err != nil || !ok {
		t.Fatal("checkpoint not saved", err)
	}
}

func TestSlowSourceDoesNotStarveOthersAndCancellation(t *testing.T) {
	store := collectorTestStore(t)
	cfg := DefaultConfig()
	cfg.Sources = []SourceConfig{{ID: "slow", Kind: "mihomo", Target: "slow", Enabled: true}, {ID: "fast", Kind: "mihomo", Target: "fast", Enabled: true}}
	fastCalled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case fastCalled <- struct{}{}:
		default:
		}
		_, _ = io.WriteString(w, `{"uploadTotal":0,"downloadTotal":0,"connections":[]}`)
	}))
	defer server.Close()
	open := func(ctx context.Context, target config.Target, _ bool) (*core.Client, io.Closer, error) {
		if target.ID == "slow" {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		}
		c, err := core.New(core.Options{Endpoint: server.URL})
		return c, collectorTestCloser{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunCollector(ctx, cfg, store, []config.Target{{ID: "slow"}, {ID: "fast"}}, CollectorOptions{Open: open})
	}()
	select {
	case <-fastCalled:
	case <-time.After(time.Second):
		t.Fatal("slow source blocked healthy source")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("external cancellation must be distinguishable: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("collector did not honor cancellation")
	}
}

func TestDoctorAndRunRejectRemoteSSHWithoutOpening(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sources = []SourceConfig{{ID: "s", Kind: "mihomo", Target: "remote", Enabled: true}}
	targets := []config.Target{{ID: "remote", SSHHost: "fixture-host"}}
	open := func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("must not open SSH-backed target")
		return nil, nil, nil
	}
	caps := DoctorWithOptions(context.Background(), cfg, targets, CollectorOptions{Open: open})
	if len(caps) != 1 || caps[0].State != "remote-target" || caps[0].Available {
		t.Fatalf("bad capabilities: %#v", caps)
	}
	store := collectorTestStore(t)
	if err := RunCollector(context.Background(), cfg, store, targets, CollectorOptions{Open: open}); err == nil || !strings.Contains(err.Error(), "node-local") {
		t.Fatalf("remote collection was not rejected: %v", err)
	}
}

func TestCollectorLockExcludesSecondWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "analytics.db")
	unlock, err := lockCollector(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := lockCollector(path); err == nil {
		other()
		unlock()
		t.Fatal("second collector acquired writer lock")
	}
	unlock()
	again, err := lockCollector(path)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func TestCollectorPinsResolvedEndpointBeforeOpening(t *testing.T) {
	store := collectorTestStore(t)
	cfg := DefaultConfig()
	cfg.Sources = []SourceConfig{{ID: "s", Kind: "mihomo", Target: "fixture", Enabled: true}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"uploadTotal":0,"downloadTotal":0,"connections":[]}`)
	}))
	defer server.Close()
	open := func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		c, err := core.New(core.Options{Endpoint: server.URL})
		return c, collectorTestCloser{}, err
	}
	if err := RunCollector(context.Background(), cfg, store, []config.Target{{ID: "fixture", Controller: server.URL}}, CollectorOptions{Open: open, Duration: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	opened := false
	open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		opened = true
		return nil, nil, errors.New("must not be reached")
	}
	err := RunCollector(context.Background(), cfg, store, []config.Target{{ID: "fixture", Controller: "http://127.0.0.1:9999"}}, CollectorOptions{Open: open, Duration: time.Millisecond})
	if err == nil || opened {
		t.Fatalf("retargeted source was not rejected before opening: %v opened=%v", err, opened)
	}
}

func TestCompactCounterFallbackRetainsBytesWithoutAttribution(t *testing.T) {
	now := time.Now()
	b := Batch{SourceID: "s", Kind: "mihomo", At: now, Events: []Event{{ID: "e", At: now, Count: 1}}, Deltas: []Delta{{ID: "one", Start: now.Add(-time.Second), End: now, UploadBytes: 10, DownloadBytes: 20, Domain: "one.example", ClientIP: "192.0.2.1"}, {ID: "two", Start: now.Add(-time.Second), End: now, UploadBytes: 30, DownloadBytes: 40, Domain: "two.example"}}}
	c, ok := compactCounterBatch(b)
	if !ok || !c.Compact || len(c.Events) != 0 || len(c.Deltas) != 1 || c.Deltas[0].UploadBytes != 40 || c.Deltas[0].DownloadBytes != 60 || c.Deltas[0].Domain != "" || c.Deltas[0].ClientIP != "" {
		t.Fatalf("bad compact measured totals: %#v", c)
	}
	b.Deltas = nil
	c, ok = compactCounterBatch(b)
	if !ok || len(c.Deltas) != 0 {
		t.Fatal("missing counter data must remain absent, never a fabricated zero")
	}
	b.Kind = "xray-access"
	if _, ok = compactCounterBatch(b); ok {
		t.Fatal("access events have no counter totals to compact")
	}
}

func TestCollectorPressureTriesCompactMeasuredAggregate(t *testing.T) {
	store := collectorTestStore(t)
	cfg := DefaultConfig()
	var sequence atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := sequence.Add(1)
		fmt.Fprintf(w, `{"uploadTotal":%d,"downloadTotal":%d,"connections":[]}`, n*100, n*200)
	}))
	defer server.Close()
	targets := []config.Target{{ID: "fixture", Controller: server.URL}}
	source := SourceConfig{ID: "pressure", Kind: "mihomo", Target: "fixture", Enabled: true}
	cfg.Sources = []SourceConfig{source}
	open := func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		c, err := core.New(core.Options{Endpoint: server.URL})
		return c, collectorTestCloser{}, err
	}
	s := &collectionSource{config: source, status: SourceStatus{SourceID: source.ID, Kind: source.Kind, Scope: "client"}}
	defer s.close()
	if err := pollCollectionSource(context.Background(), cfg, store, s, targets, open); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.pressure = true
	store.mu.Unlock()
	if err := pollCollectionSource(context.Background(), cfg, store, s, targets, open); err != nil {
		t.Fatal("reserved compact write failed", err)
	}
	if s.status.State != "storage-pressure" {
		t.Fatalf("attribution degradation not marked: %#v", s.status)
	}
	var up, down int64
	var domain, route string
	if err := store.db.QueryRow("SELECT SUM(up),SUM(down),domain,route FROM metrics WHERE resolution='minute'").Scan(&up, &down, &domain, &route); err != nil {
		t.Fatal(err)
	}
	if up != 100 || down != 200 || domain != "" || route != "" {
		t.Fatalf("compact counters lost or counted twice: %d/%d domain=%q route=%q", up, down, domain, route)
	}
	if s.tracker.last.IsZero() {
		t.Fatal("successful compact persistence should retain the next baseline")
	}
}
