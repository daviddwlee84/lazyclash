package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
	"github.com/daviddwlee84/lazyclash/internal/rulediscovery"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
)

// Exercise the same independent helper dispatch used by the production binary.
func TestMain(m *testing.M) {
	if code, handled := discoveryguard.HandleHelper(); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

type discoveryCLIFixture struct {
	settings string
	target   config.Target
	mu       sync.Mutex
	selected string
	quiet    bool
	requests atomic.Int64
	writes   atomic.Int64
	logs     atomic.Int64
}

func newDiscoveryCLIFixture(t *testing.T, quiet bool) *discoveryCLIFixture {
	t.Helper()
	settings := isolated(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	f := &discoveryCLIFixture{settings: settings, selected: "Proxy", quiet: quiet}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != http.MethodGet {
			f.writes.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(core.Object{"version": "discovery-fixture"})
		case "/configs":
			_ = json.NewEncoder(w).Encode(core.Object{"mode": "rule", "log-level": "warning"})
		case "/rules":
			_ = json.NewEncoder(w).Encode(core.Object{"rules": []core.Object{{"type": "Match", "payload": "", "proxy": "Actual fallback"}}})
		case "/proxies":
			f.mu.Lock()
			selected := f.selected
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(core.Object{"proxies": map[string]core.Proxy{"Actual fallback": {Name: "Actual fallback", Type: "Selector", All: []string{"DIRECT", "Proxy"}, Now: selected}, "DIRECT": {Name: "DIRECT", Type: "Direct"}, "Proxy": {Name: "Proxy", Type: "Direct"}}})
		case "/proxies/Actual fallback":
			var body struct {
				Name string `json:"name"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			f.selected = body.Name
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case "/logs":
			f.logs.Add(1)
			if r.URL.Query().Get("level") != "info" {
				t.Error("discovery did not request success and error evidence")
			}
			if quiet {
				<-r.Context().Done()
				return
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-ticker.C:
					_ = json.NewEncoder(w).Encode(core.Object{"type": "warning", "payload": "[TCP] dial Actual fallback (match Match/) 127.0.0.1:5678 --> api.example.com:443 error: i/o timeout https://user:private@error.example/path?token=SECRET_QUERY"})
					w.(http.Flusher).Flush()
				}
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	f.target = config.Target{ID: "observe", Controller: server.URL}
	cfg, err := config.Load(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = []config.Target{f.target}
	cfg.DefaultTarget = f.target.ID
	if err = config.Save(settings, cfg); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRuleDiscoveryCLIRejectsSyntaxBeforeConnecting(t *testing.T) {
	f := newDiscoveryCLIFixture(t, true)
	for _, args := range [][]string{
		{"start", "--duration", "0s"}, {"start", "--duration", "-1s"}, {"start", "--duration", "25h"}, {"start", "--duration", "invalid"},
		{"start", "--yes"}, {"start", "--direct", "--yes", "--dry-run"}, {"start", "extra"}, {"review", "bad", "--interactive", "--json"}, {"recover", "bad", "--yes", "--dry-run"},
	} {
		if _, _, err := run(t, Dependencies{}, append([]string{"rules", "discover"}, args...)...); err == nil {
			t.Fatal("invalid flags accepted", args)
		}
	}
	if f.requests.Load() != 0 {
		t.Fatal("syntax validation contacted controller", f.requests.Load())
	}
}

func TestRuleDiscoveryCLIPassiveCapturePersistsStructuredJSON(t *testing.T) {
	f := newDiscoveryCLIFixture(t, false)
	out, diagnostic, err := run(t, Dependencies{}, "rules", "discover", "start", "--duration", "200ms", "--json")
	var snapshot ruleobserve.Snapshot
	if err != nil || json.Unmarshal([]byte(out), &snapshot) != nil || snapshot.Mode != "normal" || snapshot.Status != "completed" || snapshot.Observed == 0 || len(snapshot.Groups) != 1 {
		t.Fatal(out, diagnostic, err)
	}
	if snapshot.Groups[0].Host != "api.example.com" || snapshot.Groups[0].ErrorCount != snapshot.Observed || snapshot.TargetIdentity != rulediscovery.TargetIdentity(f.target) {
		t.Fatal(snapshot)
	}
	if f.writes.Load() != 0 || f.logs.Load() != 1 || diagnostic != "" || strings.Contains(out, "SECRET_QUERY") || strings.Contains(out, "user:private") {
		t.Fatal("passive capture mutated runtime or leaked raw errors", out, diagnostic, f.writes.Load())
	}
	loaded, err := ruleobserve.Load("", snapshot.ID)
	if err != nil || loaded.Observed != snapshot.Observed {
		t.Fatal(loaded, err)
	}
	listed, _, err := run(t, Dependencies{}, "rules", "discover", "list", "--json")
	var list struct {
		Observations []ruleobserve.Snapshot  `json:"observations"`
		Restorations []discoveryguard.Status `json:"restorations"`
	}
	if err != nil || json.Unmarshal([]byte(listed), &list) != nil || len(list.Observations) != 1 || len(list.Restorations) != 0 {
		t.Fatal(listed, err)
	}
	reviewed, _, err := run(t, Dependencies{}, "rules", "discover", "review", snapshot.ID, "--json")
	if err != nil || json.Unmarshal([]byte(reviewed), &loaded) != nil || loaded.ID != snapshot.ID {
		t.Fatal(reviewed, err)
	}
}

func TestRuleDiscoveryCLIQuietStreamStillHonorsDuration(t *testing.T) {
	f := newDiscoveryCLIFixture(t, true)
	start := time.Now()
	out, _, err := run(t, Dependencies{}, "rules", "discover", "start", "--duration", "50ms", "--json", "--read-only")
	var snapshot ruleobserve.Snapshot
	if err != nil || json.Unmarshal([]byte(out), &snapshot) != nil || snapshot.Status != "completed" || snapshot.Observed != 0 || snapshot.Gaps == 0 {
		t.Fatal(out, err)
	}
	if time.Since(start) > 2*time.Second || f.writes.Load() != 0 {
		t.Fatal("quiet unflushed stream escaped session bound")
	}
}

func TestRuleDiscoveryCLINoninteractiveDirectOnlyPreviews(t *testing.T) {
	f := newDiscoveryCLIFixture(t, true)
	out, _, err := run(t, Dependencies{}, "rules", "discover", "start", "--direct", "--duration", "1m", "--json")
	var result struct {
		Direct bool                `json:"direct"`
		Plan   discoveryguard.Plan `json:"plan"`
	}
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || !result.Direct || result.Plan.Group != "Actual fallback" || result.Plan.Previous != "Proxy" {
		t.Fatal(out, err)
	}
	if f.logs.Load() != 0 || f.writes.Load() != 0 {
		t.Fatal("preview collected or mutated runtime")
	}
	snapshots, err := ruleobserve.List("")
	if err != nil || len(snapshots) != 0 {
		t.Fatal("preview created observation", snapshots, err)
	}
	out, _, err = run(t, Dependencies{}, "rules", "discover", "start", "--direct", "--yes", "--read-only", "--json")
	if err == nil || f.writes.Load() != 0 || f.logs.Load() != 0 {
		t.Fatal("read-only accepted DIRECT start", out, err)
	}
}

func saveDiscoveryCLIJournal(t *testing.T, f *discoveryCLIFixture) string {
	t.Helper()
	plan, err := discoveryguard.Preview(context.Background(), f.target)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	status := discoveryguard.Status{ID: id, TargetID: f.target.ID, Phase: "recovery_pending", Group: plan.Group, Previous: plan.Previous, Deadline: time.Now().Add(-time.Minute), UpdatedAt: time.Now()}
	data, err := json.Marshal(map[string]any{"version": 1, "settings_path": f.settings, "plan": plan, "status": status, "need_restore": true})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(os.Getenv("XDG_STATE_HOME"), "lazyclash", "discovery-guards")
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.selected = "DIRECT"
	f.mu.Unlock()
	return id
}

func TestRuleDiscoveryCLIRecoveryPreviewReadOnlyAndOneJSONResult(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("independent helper is supported on macOS/Linux")
	}
	f := newDiscoveryCLIFixture(t, true)
	id := saveDiscoveryCLIJournal(t, f)
	before := f.requests.Load()
	out, _, err := run(t, Dependencies{}, "rules", "discover", "recover", id, "--json")
	var status discoveryguard.Status
	if err != nil || json.Unmarshal([]byte(out), &status) != nil || status.Phase != "recovery_pending" || f.requests.Load() != before {
		t.Fatal("recovery preview contacted controller", out, err)
	}
	_, _, err = run(t, Dependencies{}, "rules", "discover", "recover", id, "--yes", "--read-only", "--json")
	if err == nil || f.requests.Load() != before || f.writes.Load() != 0 {
		t.Fatal("read-only recovery touched controller", err)
	}
	out, _, err = run(t, Dependencies{}, "rules", "discover", "recover", id, "--yes", "--json")
	if err != nil || json.Unmarshal([]byte(out), &status) != nil || !status.Restored || status.Phase != "restored" || f.writes.Load() != 1 {
		t.Fatal("recovery did not produce one final JSON object", out, err)
	}
}

func TestRuleDiscoveryReviewGuardsMismatchReadOnlyAndPendingRestore(t *testing.T) {
	f := newDiscoveryCLIFixture(t, true)
	snapshot := ruleobserve.New(f.target.ID, time.Now()).Snapshot(time.Now())
	snapshot.TargetIdentity = rulediscovery.TargetIdentity(f.target)
	if _, err := ruleobserve.Save("", snapshot); err != nil {
		t.Fatal(err)
	}
	_, _, err := run(t, Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }}, "--target", "other", "rules", "discover", "review", snapshot.ID, "--interactive")
	if err == nil || !strings.Contains(err.Error(), "belongs to target") {
		t.Fatal("interactive review lost target identity", err)
	}
	o := &options{readOnly: true}
	opts := o.ruleReviewOptions(context.Background(), f.target, snapshot, f.settings)
	if _, err = opts.Apply(context.Background(), []string{quickCLIRule}, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatal("review bypassed read-only service guard", err)
	}
	changed := f.target
	changed.Controller = "http://127.0.0.1:1"
	opts = o.ruleReviewOptions(context.Background(), changed, snapshot, f.settings)
	if _, err = opts.Preview(context.Background(), []string{quickCLIRule}); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal("review rebound observation to changed target", err)
	}
	guardID := saveDiscoveryCLIJournal(t, f)
	opts = o.ruleReviewOptions(context.Background(), f.target, snapshot, f.settings)
	if _, err = opts.Preview(context.Background(), []string{quickCLIRule}); err == nil || !strings.Contains(err.Error(), guardID) {
		t.Fatal("review ignored pending restore", err)
	}
	if f.writes.Load() != 0 {
		t.Fatal(fmt.Sprint("review guards mutated controller: ", f.writes.Load()))
	}
}
