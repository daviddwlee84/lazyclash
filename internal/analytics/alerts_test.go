package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func hostBytes(t *testing.T, s *Store, id string, at time.Time, bytes int64) {
	t.Helper()
	ingest(t, s, Batch{SourceID: "host", Kind: "interface", Scope: "host", At: at, Deltas: []Delta{{ID: id, Start: at.Add(-time.Minute), End: at, UploadBytes: bytes}}})
}
func enabledAlerts() AlertConfig { c := DefaultConfig().Alerts; c.Enabled = true; return c }
func TestAlertsGreatestTierDurableDaySuppressionAndScope(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00+08:00")
	hostBytes(t, s, "first", at, 55<<30)
	cfg := enabledAlerts()
	got, err := s.EvaluateAlerts(context.Background(), cfg, at)
	if err != nil || len(got) != 1 || got[0].ThresholdGiB != 50 {
		t.Fatalf("initial alerts %+v %v", got, err)
	}
	second, err := OpenStore(s.Path(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	got, err = second.EvaluateAlerts(context.Background(), cfg, at)
	if err != nil || len(got) != 0 {
		t.Fatalf("restart duplicated tier %+v %v", got, err)
	}
	hostBytes(t, s, "second", at.Add(time.Minute), 60<<30)
	got, err = s.EvaluateAlerts(context.Background(), cfg, at.Add(time.Minute))
	if err != nil || len(got) != 1 || got[0].ThresholdGiB != 100 {
		t.Fatalf("greatest tier %+v %v", got, err)
	}
	list, _ := s.Alerts(context.Background(), 10)
	if len(list) != 2 || list[1].State != "superseded" {
		t.Fatalf("queued lower tier not suppressed %+v", list)
	}
	next := at.AddDate(0, 0, 1)
	hostBytes(t, s, "new-day", next, 21<<30)
	got, err = s.EvaluateAlerts(context.Background(), cfg, next)
	if err != nil || len(got) != 1 || got[0].ThresholdGiB != 20 {
		t.Fatalf("next day %+v %v", got, err)
	}
	ingest(t, s, Batch{SourceID: "client", Kind: "mihomo", Scope: "client", At: at})
	cfg.SourceIDs = []string{"client"}
	if _, err = s.EvaluateAlerts(context.Background(), cfg, at); err == nil {
		t.Fatal("client source allowed for host daily egress alert")
	}
}
func TestAlertDeliveryClaimsAreDurableAndDoNotRedirect(t *testing.T) {
	s := testStore(t)
	at := time.Now()
	hostBytes(t, s, "notify", at, 30<<30)
	cfg := enabledAlerts()
	cfg.WebhookEnv = "LAZYCLASH_TEST_WEBHOOK"
	if _, err := s.EvaluateAlerts(context.Background(), cfg, at); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	t.Setenv(cfg.WebhookEnv, server.URL)
	other, err := OpenStore(s.Path(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, st := range []*Store{s, other} {
		wg.Add(1)
		go func(st *Store) { defer wg.Done(); errs <- st.DeliverAlerts(context.Background(), cfg) }(st)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate delivery: %d", calls.Load())
	}
	alerts, _ := s.Alerts(context.Background(), 10)
	if alerts[0].State != "sent" || alerts[0].Attempts != 1 {
		t.Fatalf("delivery %+v", alerts)
	}
	hostBytes(t, s, "next-tier", at.Add(time.Second), 30<<30)
	if _, err = s.EvaluateAlerts(context.Background(), cfg, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL+"/secret", http.StatusFound)
	}))
	defer redirect.Close()
	t.Setenv(cfg.WebhookEnv, redirect.URL+"/credential")
	if err = s.DeliverAlerts(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("followed webhook redirect")
	}
	alerts, _ = s.Alerts(context.Background(), 10)
	if alerts[0].State != "failed" || alerts[0].NextAttempt.IsZero() || alerts[0].LastError != "Notification returned HTTP 302" {
		t.Fatalf("failure state %+v", alerts[0])
	}
	if err = s.DeliverAlerts(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	again, _ := s.Alerts(context.Background(), 10)
	if again[0].Attempts != 1 {
		t.Fatal("retry backoff ignored")
	}
}

func TestSlowNotificationDoesNotBlockIngest(t *testing.T) {
	s := testStore(t)
	at := time.Now()
	hostBytes(t, s, "first", at, 30<<30)
	cfg := enabledAlerts()
	cfg.WebhookEnv = "LAZYCLASH_TEST_SLOW_WEBHOOK"
	if _, err := s.EvaluateAlerts(context.Background(), cfg, at); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(204) }))
	defer server.Close()
	t.Setenv(cfg.WebhookEnv, server.URL)
	done := make(chan error, 1)
	go func() { done <- s.DeliverAlerts(context.Background(), cfg) }()
	<-entered
	ingested := make(chan error, 1)
	go func() {
		ingested <- s.Ingest(context.Background(), Batch{SourceID: "other", Kind: "interface", Scope: "host", At: at, Status: &SourceStatus{State: "baseline"}})
	}()
	select {
	case err := <-ingested:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("network delivery blocked collection")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExhaustedOrDelayedAlertsCannotStarveNewDueAlerts(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	for i := 0; i < 9; i++ {
		a := Alert{ID: fmt.Sprint(i), SourceID: "host", Day: "2026-09-22", CreatedAt: now.Add(time.Duration(i-20) * time.Minute), State: "failed", Attempts: 6}
		if i >= 4 {
			a.Attempts = 1
			a.NextAttempt = now.Add(time.Hour)
		}
		if i == 8 {
			a.State = "pending"
			a.Attempts = 0
			a.NextAttempt = time.Time{}
		}
		raw, _ := json.Marshal(a)
		if _, err := s.db.Exec("INSERT INTO alerts(id,source_id,day,threshold,payload,state,created,attempts,next_attempt) VALUES(?,?,?,?,?,?,?,?,?)", a.ID, a.SourceID, a.Day, 20, raw, a.State, millis(a.CreatedAt), a.Attempts, millis(a.NextAttempt)); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	cfg := enabledAlerts()
	cfg.WebhookEnv = "LAZYCLASH_TEST_DUE_WEBHOOK"
	t.Setenv(cfg.WebhookEnv, server.URL)
	if err := s.DeliverAlerts(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("due alert starved: calls=%d", calls.Load())
	}
	list, err := s.Alerts(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].ID != "8" || list[0].State != "sent" {
		t.Fatalf("new alert not sent: %+v", list[0])
	}
}
