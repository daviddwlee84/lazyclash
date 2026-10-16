//go:build linux || darwin

package discoveryguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestMain(m *testing.M) {
	if code, handled := HandleHelper(); handled {
		os.Exit(code)
	}
	if os.Getenv("LAZYCLASH_GUARD_TEST_FOREGROUND") == "1" {
		path := os.Getenv("LAZYCLASH_GUARD_TEST_SETTINGS")
		target, err := loadTarget(path, "fixture")
		if err != nil {
			os.Exit(3)
		}
		plan, err := Preview(context.Background(), target)
		if err != nil {
			os.Exit(4)
		}
		h, err := Start(context.Background(), path, target, plan, time.Minute)
		if err != nil {
			os.Exit(5)
		}
		_ = json.NewEncoder(os.Stdout).Encode(h.Status())
		for {
			time.Sleep(time.Hour)
		}
	}
	os.Exit(m.Run())
}

type fixture struct {
	mu         sync.Mutex
	server     *httptest.Server
	target     config.Target
	settings   string
	mode       string
	policy     string
	now        string
	groupType  string
	all        []string
	extraRule  bool
	writes     []string
	dropSwitch bool
	authDenied bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	f := &fixture{mode: "rule", policy: "Final", now: "Proxy", groupType: "Selector", all: []string{"DIRECT", "Proxy", "Other"}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.target = config.Target{ID: "fixture", Controller: f.server.URL}
	f.settings = filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(f.settings, []byte(fmt.Sprintf("[[targets]]\nid = 'fixture'\ncontroller = %q\n", f.server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.authDenied {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/version":
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "fixture-1"})
	case "/configs":
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": f.mode})
	case "/rules":
		rules := []any{}
		if f.extraRule {
			rules = append(rules, map[string]any{"type": "Domain", "payload": "example.com", "proxy": f.policy})
		}
		rules = append(rules, map[string]any{"type": "Match", "payload": "", "proxy": f.policy})
		_ = json.NewEncoder(w).Encode(map[string]any{"rules": rules})
	case "/proxies":
		_ = json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"Final": map[string]any{"type": f.groupType, "name": "Final", "all": f.all, "now": f.now}, "DIRECT": map[string]any{"type": "Direct"}, "Parent": map[string]any{"type": "Selector", "all": []string{"Final"}, "now": "Final"}}})
	case "/proxies/Final":
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		f.now = body.Name
		f.writes = append(f.writes, body.Name)
		if body.Name == "DIRECT" && f.dropSwitch {
			f.dropSwitch = false
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(404)
	}
}

func (f *fixture) preview(t *testing.T) Plan {
	t.Helper()
	plan, err := Preview(context.Background(), f.target)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func (f *fixture) selected() (string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now, append([]string(nil), f.writes...)
}

func stopGuard(t *testing.T, h *Handle) Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := h.Stop(ctx)
	if err != nil {
		t.Fatalf("Stop: %v (status %+v)", err, s)
	}
	if !s.Restored || s.Phase != "restored" {
		t.Fatalf("not restored: %+v", s)
	}
	return s
}

func TestGuardSwitchStopAndPrivateJournal(t *testing.T) {
	f := newFixture(t)
	f.extraRule = true
	plan := f.preview(t)
	if plan.Group != "Final" || plan.Previous != "Proxy" || len(plan.Warnings) != 3 {
		t.Fatalf("plan: %+v", plan)
	}
	h, err := Start(context.Background(), f.settings, f.target, plan, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if now, _ := f.selected(); now != "DIRECT" {
		t.Fatal("helper did not switch")
	}
	alias := f.target
	alias.ID = "same-controller-alias"
	if err := CheckIdle(alias); err == nil {
		t.Fatal("controller alias bypassed active discovery guard")
	}
	status := stopGuard(t, h)
	if err := CheckIdle(alias); err != nil {
		t.Fatalf("restored controller remained blocked: %v", err)
	}
	if now, writes := f.selected(); now != "Proxy" || strings.Join(writes, ",") != "DIRECT,Proxy" {
		t.Fatalf("selection=%s writes=%v", now, writes)
	}
	items, err := List(f.settings)
	if err != nil || len(items) != 1 || items[0].ID != status.ID || items[0].Pending() {
		t.Fatalf("journals=%+v err=%v", items, err)
	}
	root, _ := stateRoot(false)
	info, err := os.Stat(filepath.Join(root, status.ID+".json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("journal mode: %v %v", info, err)
	}
}

func TestGuardDeadlineAndParentContextCancelRestore(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			duration := time.Minute
			if mode == "deadline" {
				duration = time.Second
			}
			h, err := Start(ctx, f.settings, f.target, f.preview(t), duration)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case <-h.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("helper did not restore")
			}
			if now, _ := f.selected(); now != "Proxy" || !h.Status().Restored {
				t.Fatalf("selection=%s status=%+v", now, h.Status())
			}
		})
	}
}

func TestGuardRejectsStalePlanAndTransientBindingBeforeWrite(t *testing.T) {
	f := newFixture(t)
	p := f.preview(t)
	f.mu.Lock()
	f.now = "Other"
	f.mu.Unlock()
	h, err := Start(context.Background(), f.settings, f.target, p, time.Minute)
	if err == nil {
		if h != nil {
			stopGuard(t, h)
		}
		t.Fatal("stale plan accepted")
	}
	if _, writes := f.selected(); len(writes) != 0 {
		t.Fatalf("stale plan wrote: %v", writes)
	}
	for _, ttype := range []string{"transient", "override", "secret"} {
		target := f.target
		switch ttype {
		case "transient":
			target.Transient = true
		case "override":
			target.TransportOverride = true
		case "secret":
			target.Secret = "PRIVATE-SECRET"
		}
		if _, err := Start(context.Background(), f.settings, target, p, time.Minute); err == nil {
			t.Fatal("temporary target accepted")
		}
	}
}

func TestGuardAlreadyDirectNeverWrites(t *testing.T) {
	for _, literal := range []bool{false, true} {
		t.Run(fmt.Sprint(literal), func(t *testing.T) {
			f := newFixture(t)
			f.now = "DIRECT"
			if literal {
				f.policy = "DIRECT"
			}
			p := f.preview(t)
			if !p.AlreadyDirect {
				t.Fatal("already DIRECT missed")
			}
			h, err := Start(context.Background(), f.settings, f.target, p, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			stopGuard(t, h)
			if _, writes := f.selected(); len(writes) != 0 {
				t.Fatalf("unnecessary writes: %v", writes)
			}
		})
	}
}

func TestPreviewRejectsUnsupportedFallbacksAndMode(t *testing.T) {
	for _, kind := range []string{"global", "automatic", "nested"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "global":
				f.mode = "global"
			case "automatic":
				f.groupType = "URLTest"
			case "nested":
				f.all = []string{"Proxy", "Other"}
			}
			if _, err := Preview(context.Background(), f.target); err == nil {
				t.Fatal("unsupported automatic fallback switch accepted")
			}
			if _, writes := f.selected(); len(writes) != 0 {
				t.Fatal("preview mutated controller")
			}
		})
	}
}

func TestHelperPreflightsOwnControllerBeforeMutation(t *testing.T) {
	f := newFixture(t)
	p := f.preview(t)
	f.mu.Lock()
	f.authDenied = true
	f.mu.Unlock()
	if _, err := Start(context.Background(), f.settings, f.target, p, time.Minute); err == nil {
		t.Fatal("helper reused foreground authentication evidence")
	}
	if _, writes := f.selected(); len(writes) != 0 {
		t.Fatal("failed independent preflight changed the controller")
	}
}

func TestRecoveryPreservesChangedRulesAndSavedBinding(t *testing.T) {
	for _, kind := range []string{"rules", "binding"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			h, err := Start(context.Background(), f.settings, f.target, f.preview(t), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			original, _ := os.ReadFile(f.settings)
			if kind == "rules" {
				f.mu.Lock()
				f.extraRule = true
				f.mu.Unlock()
			} else {
				if err := os.WriteFile(f.settings, append(original, []byte("secret_env = 'CHANGED_CREDENTIAL_REFERENCE'\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := h.Stop(ctx)
			if err == nil || s.Phase != "conflict" {
				t.Fatalf("changed %s was not guarded: %+v %v", kind, s, err)
			}
			if now, writes := f.selected(); now != "DIRECT" || len(writes) != 1 {
				t.Fatalf("changed context was overwritten: %s %v", now, writes)
			}
			f.mu.Lock()
			f.extraRule = false
			f.mu.Unlock()
			if err := os.WriteFile(f.settings, original, 0600); err != nil {
				t.Fatal(err)
			}
			if s, err := Recover(ctx, f.settings, h.ID()); err != nil || !s.Restored {
				t.Fatalf("recovery after restoring context: %+v %v", s, err)
			}
		})
	}
}

func TestJournalNeverContainsResolvedSecret(t *testing.T) {
	f := newFixture(t)
	const secret = "PRIVATE-CONTROLLER-CREDENTIAL-UNIQUE"
	t.Setenv("LAZYCLASH_GUARD_FIXTURE_SECRET", secret)
	f.target.SecretEnv = "LAZYCLASH_GUARD_FIXTURE_SECRET"
	original, _ := os.ReadFile(f.settings)
	if err := os.WriteFile(f.settings, append(original, []byte("secret_env = 'LAZYCLASH_GUARD_FIXTURE_SECRET'\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := Start(context.Background(), f.settings, f.target, f.preview(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stopGuard(t, h)
	root, _ := stateRoot(false)
	data, err := os.ReadFile(filepath.Join(root, h.ID()+".json"))
	if err != nil || strings.Contains(string(data), secret) {
		t.Fatalf("journal exposed resolved credential: %v", err)
	}
}

func TestGuardPreservesExternalSelectionAndCanRecoverLater(t *testing.T) {
	f := newFixture(t)
	h, err := Start(context.Background(), f.settings, f.target, f.preview(t), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.now = "Other"
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := h.Stop(ctx)
	if err == nil || s.Phase != "conflict" {
		t.Fatalf("external edit: %+v %v", s, err)
	}
	if now, writes := f.selected(); now != "Other" || len(writes) != 1 {
		t.Fatalf("external selection overwritten: %s %v", now, writes)
	}
	if _, err := Start(ctx, f.settings, f.target, f.preview(t), time.Minute); err == nil {
		t.Fatal("pending journal did not block another session")
	}
	f.mu.Lock()
	f.now = "DIRECT"
	f.mu.Unlock()
	s, err = Recover(ctx, f.settings, h.ID())
	if err != nil || !s.Restored {
		t.Fatalf("recovery: %+v %v", s, err)
	}
	if now, _ := f.selected(); now != "Proxy" {
		t.Fatal("recover did not restore")
	}
}

func TestGuardLiveControllerLockAndUnknownSwitchResponse(t *testing.T) {
	t.Run("lock", func(t *testing.T) {
		f := newFixture(t)
		h, err := Start(context.Background(), f.settings, f.target, f.preview(t), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		defer stopGuard(t, h)
		if _, err := Start(context.Background(), f.settings, f.target, f.preview(t), time.Minute); err == nil {
			t.Fatal("overlapping session accepted")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := Recover(ctx, f.settings, h.ID()); err == nil {
			t.Fatal("live recovery accepted")
		}
	})
	t.Run("unknown switch", func(t *testing.T) {
		f := newFixture(t)
		f.dropSwitch = true
		h, err := Start(context.Background(), f.settings, f.target, f.preview(t), time.Minute)
		if err == nil {
			stopGuard(t, h)
			t.Fatal("unconfirmed activation accepted")
		}
		if h == nil || !h.Status().Restored {
			t.Fatalf("unknown write not recovered: %v %+v", err, h)
		}
		if now, writes := f.selected(); now != "Proxy" || strings.Join(writes, ",") != "DIRECT,Proxy" {
			t.Fatalf("unknown write: %s %v", now, writes)
		}
	})
}

func TestGuardRestoresAfterForegroundSIGKILL(t *testing.T) {
	f := newFixture(t)
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "LAZYCLASH_GUARD_TEST_FOREGROUND=1", "LAZYCLASH_GUARD_TEST_SETTINGS="+f.settings)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	ready := make(chan Status, 1)
	go func() { var s Status; _ = json.NewDecoder(stdout).Decode(&s); ready <- s }()
	var status Status
	select {
	case status = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("foreground did not activate")
	}
	if status.Phase != "active" {
		t.Fatalf("foreground status: %+v", status)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		items, err := List(f.settings)
		if now, _ := f.selected(); err == nil && now == "Proxy" && len(items) == 1 && items[0].Restored {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	now, writes := f.selected()
	t.Fatalf("foreground crash stranded selection: %s %v", now, writes)
}

func TestWatchLeaseExpiresWithoutHeartbeatsAndHonorsEOF(t *testing.T) {
	for _, eofFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		pulses, eof := make(chan struct{}, 1), make(chan struct{})
		go watchLease(ctx, cancel, pulses, eof, time.Now().Add(time.Hour), 40*time.Millisecond)
		if eofFirst {
			close(eof)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("lease did not expire")
		}
		cancel()
	}
}
