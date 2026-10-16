package rulediscovery

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func TestMain(m *testing.M) {
	if code, handled := discoveryguard.HandleHelper(); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func passiveTarget() config.Target {
	return config.Target{ID: "fixture", Controller: "http://127.0.0.1:1"}
}

func awaitSession(t *testing.T, s *Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("session did not finish")
	}
}

func stopSession(t *testing.T, s *Session) ruleobserve.Snapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	snap, err := s.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestQuietPassiveSessionExpiresAndFreezesObservationWindow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "observations")
	s, err := Start(context.Background(), passiveTarget(), Options{StateDir: dir, Duration: 70 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	awaitSession(t, s)
	first := stopSession(t, s)
	if first.Status != "completed" || first.Observed != 0 || first.Gaps != 1 || first.FinishedAt.IsZero() || first.FinishedAt.Before(s.Deadline()) {
		t.Fatalf("quiet session: %+v", first)
	}
	time.Sleep(10 * time.Millisecond)
	second := s.Snapshot()
	if !first.UpdatedAt.Equal(second.UpdatedAt) {
		t.Fatal("reading finished session extended its observed interval")
	}
	stored, err := ruleobserve.Load(dir, s.ID())
	if err != nil || stored.Status != "completed" || !stored.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("stored session: %+v %v", stored, err)
	}
}

func TestPassiveContextCancellationPersistsCompletion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "observations")
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, passiveTarget(), Options{StateDir: dir, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	awaitSession(t, s)
	if snap := stopSession(t, s); snap.Status != "completed" {
		t.Fatalf("canceled collection: %+v", snap)
	}
	before, _ := os.ReadDir(dir)
	if _, err := Start(ctx, passiveTarget(), Options{StateDir: dir, Duration: time.Hour}); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled startup: %v", err)
	}
	after, _ := os.ReadDir(dir)
	if len(before) != len(after) {
		t.Fatal("already canceled startup persisted new work")
	}
}

func TestConcurrentObserveCheckpointAndStopKeepFinalSnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "observations")
	s, err := Start(context.Background(), passiveTarget(), Options{StateDir: dir, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	record := core.Object{"type": "warning", "payload": "[TCP] dial Final (match Match/) 127.0.0.1:123 --> example.com:443 error: i/o timeout"}
	s.Observe(record, time.Now())
	var workers sync.WaitGroup
	for i := 0; i < 6; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				s.Observe(record, time.Now())
				if j%25 == 0 {
					_ = s.Save()
				}
			}
		}()
	}
	s.RequestStop()
	workers.Wait()
	final := stopSession(t, s)
	s.Observe(record, time.Now())
	s.Gap(time.Now(), "late event")
	after := s.Snapshot()
	if after.Observed != final.Observed || after.Gaps != final.Gaps || after.UpdatedAt != final.UpdatedAt {
		t.Fatal("post-stop observation changed the final snapshot")
	}
	stored, err := ruleobserve.Load(dir, s.ID())
	if err != nil || stored.Observed != final.Observed || stored.Status != final.Status {
		t.Fatalf("final checkpoint lost accepted observations: %+v %+v %v", final, stored, err)
	}
}

func TestCheckpointFailureStopsCollectionAndRetainsError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "observations")
	s, err := Start(context.Background(), passiveTarget(), Options{StateDir: dir, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-before-failure"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("path is no longer a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual periodic checkpoint, without an explicit Stop.
	awaitSession(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	snap, err := s.Stop(ctx)
	if err == nil || snap.Status != "failed" {
		t.Fatalf("checkpoint failure became success: %+v %v", snap, err)
	}
}

func directFixture(t *testing.T) (config.Target, string, *testcore.Controller) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("native independent helper integration is exercised on macOS/Linux; Windows job policy requires native validation")
	}
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	handler := testcore.NewHandler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target := config.Target{ID: "fixture", Controller: server.URL}
	settings := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(settings, []byte(fmt.Sprintf("[[targets]]\nid = 'fixture'\ncontroller = %q\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	return target, settings, handler
}

func TestDirectSessionStopRestoresAndPersistsGuardLink(t *testing.T) {
	target, settings, _ := directFixture(t)
	plan, err := discoveryguard.Preview(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "observations")
	s, err := Start(context.Background(), target, Options{SettingsPath: settings, StateDir: dir, Duration: time.Minute, Direct: true, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	snap := stopSession(t, s)
	if snap.GuardID == "" || snap.Status != "completed" || snap.Mode != "fallback_direct" {
		t.Fatalf("direct snapshot: %+v", snap)
	}
	guards, err := discoveryguard.List(settings)
	if err != nil || len(guards) != 1 || !guards[0].Restored || guards[0].ID != snap.GuardID {
		t.Fatalf("guard link: %+v %v", guards, err)
	}
	stored, err := ruleobserve.Load(dir, s.ID())
	if err != nil || stored.GuardID != snap.GuardID || stored.Status != "completed" {
		t.Fatalf("persisted guard link: %+v %v", stored, err)
	}
}

func TestFailedDirectStartupStillPersistsGuardID(t *testing.T) {
	target, settings, _ := directFixture(t)
	plan, err := discoveryguard.Preview(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	c, closer, err := connection.Open(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	if err := c.Select(context.Background(), testcore.Selector, testcore.Tokyo); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "observations")
	s, err := Start(context.Background(), target, Options{SettingsPath: settings, StateDir: dir, Duration: time.Minute, Direct: true, Plan: plan})
	if err == nil || s == nil {
		t.Fatalf("stale direct start: session=%v err=%v", s, err)
	}
	awaitSession(t, s)
	snap, loadErr := ruleobserve.Load(dir, s.ID())
	if loadErr != nil || snap.GuardID == "" || snap.Status != "failed" {
		t.Fatalf("failed helper link lost: %+v %v", snap, loadErr)
	}
	proxies, err := c.Proxies(context.Background())
	if err != nil || proxies[testcore.Selector].Now != testcore.Tokyo {
		t.Fatal("failed direct startup changed the selection")
	}
}

func TestDirectCheckpointFailureReleasesLeaseBeforeSaving(t *testing.T) {
	target, settings, _ := directFixture(t)
	plan, err := discoveryguard.Preview(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "observations")
	s, err := Start(context.Background(), target, Options{SettingsPath: settings, StateDir: dir, Duration: time.Minute, Direct: true, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-before-failure"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err == nil {
		t.Fatal("checkpoint unexpectedly succeeded")
	}
	awaitSession(t, s)
	guards, err := discoveryguard.List(settings)
	if err != nil || len(guards) != 1 || !guards[0].Restored {
		t.Fatalf("checkpoint failure stranded DIRECT: %+v %v", guards, err)
	}
	if snap := s.Snapshot(); snap.Status != "failed" || snap.GuardID == "" {
		t.Fatalf("failure status lost: %+v", snap)
	}
}
