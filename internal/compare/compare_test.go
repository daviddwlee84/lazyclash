package compare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

const manualGroup = "🚀 手動 / Proxy"

type fixture struct {
	mu           sync.Mutex
	server       *httptest.Server
	version      string
	settings     core.Object
	proxies      map[string]core.Proxy
	writes       []string
	secret       string
	failGroup    bool
	failReadBack bool
	wrongAuth    bool
}

func newFixture(t *testing.T, mode, level, selected string) *fixture {
	t.Helper()
	f := &fixture{version: "v1.19.29", settings: core.Object{"mode": mode, "log-level": level, "mixed-port": 7890, "tun": core.Object{"enable": true}, "authentication": []string{"PRIVATE_AUTH"}}, proxies: map[string]core.Proxy{
		manualGroup: {Name: manualGroup, Type: "Selector", All: []string{"alpha", "beta"}, Now: selected},
		"Auto":      {Name: "Auto", Type: "URLTest", All: []string{"alpha", "beta"}, Now: selected},
		"alpha":     {Name: "alpha", Type: "Direct", History: []core.DelayRecord{{Delay: 10}}},
		"beta":      {Name: "beta", Type: "Direct"},
	}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secret != "" && r.Header.Get("Authorization") != "Bearer "+f.secret {
		f.wrongAuth = true
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	write := func(value any) { _ = json.NewEncoder(w).Encode(value) }
	switch {
	case r.URL.Path == "/version":
		write(core.Object{"version": f.version})
	case r.URL.Path == "/configs" && r.Method == http.MethodGet:
		if f.failReadBack && len(f.writes) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		write(f.settings)
	case r.URL.Path == "/configs" && r.Method == http.MethodPatch:
		var patch core.Object
		_ = json.NewDecoder(r.Body).Decode(&patch)
		for _, key := range sortedKeys(patch) {
			f.writes = append(f.writes, "field:"+key)
			f.settings[key] = patch[key]
		}
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/proxies" && r.Method == http.MethodGet:
		write(core.Object{"proxies": f.proxies})
	case strings.HasPrefix(r.URL.Path, "/proxies/") && r.Method == http.MethodPut:
		name := strings.TrimPrefix(r.URL.Path, "/proxies/")
		f.writes = append(f.writes, "group:"+name)
		if f.failGroup {
			w.WriteHeader(http.StatusServiceUnavailable)
			write(core.Object{"message": "PRIVATE_CONTROLLER_ERROR"})
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		group := f.proxies[name]
		group.Now = body.Name
		f.proxies[name] = group
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fixture) change(fn func()) { f.mu.Lock(); defer f.mu.Unlock(); fn() }
func (f *fixture) target(id string) config.Target {
	return config.Target{ID: id, Controller: f.server.URL}
}
func (f *fixture) mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.writes...)
}

func pair(t *testing.T) (*fixture, *fixture, config.Target, config.Target) {
	t.Helper()
	a, b := newFixture(t, "global", "debug", "alpha"), newFixture(t, "rule", "info", "beta")
	return a, b, a.target("source"), b.target("destination")
}

func TestDiffRedactsBeforeComparisonAndUsesOwnCredentials(t *testing.T) {
	a, b, source, destination := pair(t)
	a.secret, b.secret = "SOURCE_SECRET", "DEST_SECRET"
	t.Setenv("COMPARE_SOURCE_SECRET", a.secret)
	t.Setenv("COMPARE_DEST_SECRET", b.secret)
	source.SecretEnv, destination.SecretEnv = "COMPARE_SOURCE_SECRET", "COMPARE_DEST_SECRET"
	b.change(func() {
		b.settings["authentication"] = []string{"DIFFERENT_PRIVATE_AUTH"}
		b.settings["tun"] = core.Object{"enable": false, "password": "NESTED_PRIVATE"}
	})
	result, err := Diff(context.Background(), source, destination, Options{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	for _, forbidden := range []string{"PRIVATE_AUTH", "NESTED_PRIVATE", "SOURCE_SECRET", "DEST_SECRET"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("sensitive data in comparison: %s", encoded)
		}
	}
	if !slices.Contains(result.NotCompared, "/authentication") || !slices.Contains(result.NotCompared, "/tun/password") {
		t.Fatalf("redacted fields claimed comparable: %+v", result.NotCompared)
	}
	for _, field := range result.Fields {
		if field.Path == "/authentication" || field.Path == "/tun/password" {
			t.Fatalf("credential difference escaped exclusion: %+v", field)
		}
	}
	if result.Equal || len(result.Groups) != 1 || result.Groups[0].Name != manualGroup || a.wrongAuth || b.wrongAuth {
		t.Fatalf("wrong comparison: %+v", result)
	}
	if len(a.mutations())+len(b.mutations()) != 0 {
		t.Fatal("diff mutated a core")
	}
}

func TestDiffIgnoresAutomaticChoicesHealthAndMemberOrder(t *testing.T) {
	_, b, source, destination := pair(t)
	b.change(func() {
		b.settings["mode"], b.settings["log-level"] = "global", "debug"
		group := b.proxies[manualGroup]
		group.Now, group.All = "alpha", []string{"beta", "alpha"}
		b.proxies[manualGroup] = group
		leaf := b.proxies["alpha"]
		leaf.History = []core.DelayRecord{{Delay: 999}}
		b.proxies["alpha"] = leaf
	})
	result, err := Diff(context.Background(), source, destination, Options{})
	if err != nil || !result.Equal || len(result.Fields) != 0 || len(result.Groups) != 0 {
		t.Fatalf("noisy diff: %+v %v", result, err)
	}
	b.change(func() { b.version = "v1.19.30" })
	result, err = Diff(context.Background(), source, destination, Options{})
	if err != nil || result.Equal || result.Source.Version == result.Destination.Version {
		t.Fatalf("core version difference hidden: %+v %v", result, err)
	}
}

func TestCopyPreflightsAllAndEnforcesExplicitAllowlist(t *testing.T) {
	_, b, source, destination := pair(t)
	for _, selection := range []Selection{{}, {Fields: []string{"tun"}}, {Fields: []string{"mixed-port"}}, {Groups: []string{"Auto"}}, {Groups: []string{"missing"}}} {
		_, err := Preview(context.Background(), source, destination, selection, Options{})
		var invalid *ValidationError
		if !errors.As(err, &invalid) {
			t.Fatalf("accepted unsupported selection %+v: %v", selection, err)
		}
	}
	selection := Selection{Fields: []string{"log-level"}, Groups: []string{manualGroup}}
	plan, err := Preview(context.Background(), source, destination, selection, Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	b.change(func() {
		group := b.proxies[manualGroup]
		group.All = []string{"beta"}
		b.proxies[manualGroup] = group
	})
	if _, err = Apply(context.Background(), source, destination, selection, plan.Digest, Options{}); err == nil {
		t.Fatal("missing group member passed all-fields preflight")
	}
	if len(b.mutations()) != 0 {
		t.Fatalf("log-level changed before invalid group was found: %v", b.mutations())
	}
}

func TestCopyOrderReadbackAndReadOnly(t *testing.T) {
	a, b, source, destination := pair(t)
	selection := Selection{Fields: []string{"mode", "log-level", "mode"}, Groups: []string{manualGroup}}
	plan, err := Preview(context.Background(), source, destination, selection, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.mutations())+len(b.mutations()) != 0 || len(plan.Steps) != 3 {
		t.Fatalf("preview mutated or duplicated steps: %+v", plan)
	}
	_, err = Apply(context.Background(), source, destination, selection, plan.Digest, Options{ReadOnly: true})
	var apiErr *core.Error
	if !errors.As(err, &apiErr) || apiErr.Kind != core.KindReadOnly || len(b.mutations()) > 0 {
		t.Fatalf("read-only apply: %v", err)
	}
	result, err := Apply(context.Background(), source, destination, selection, plan.Digest, Options{})
	if err != nil || result.Status != "applied" {
		t.Fatalf("apply: %+v %v", result, err)
	}
	if got := b.mutations(); !slices.Equal(got, []string{"field:log-level", "group:" + manualGroup, "field:mode"}) || len(a.mutations()) != 0 {
		t.Fatalf("wrong mutation scope/order: source=%v destination=%v", a.mutations(), got)
	}
	for _, step := range result.Steps {
		if step.Status != "applied" {
			t.Fatalf("step was not verified: %+v", step)
		}
	}
	plan, err = Preview(context.Background(), source, destination, selection, Options{})
	if err != nil {
		t.Fatal(err)
	}
	result, err = Apply(context.Background(), source, destination, selection, plan.Digest, Options{})
	if err != nil || len(b.mutations()) != 3 {
		t.Fatalf("unchanged settings were rewritten: %+v %v", result, err)
	}
	for _, step := range result.Steps {
		if step.Status != "unchanged" {
			t.Fatalf("no-op receipt: %+v", step)
		}
	}
}

func TestCopyDigestDetectsSelectedStateChangesButNotHealth(t *testing.T) {
	for _, change := range []string{"source field", "destination field", "version", "members", "health"} {
		t.Run(change, func(t *testing.T) {
			a, b, source, destination := pair(t)
			selection := Selection{Fields: []string{"mode"}, Groups: []string{manualGroup}}
			plan, err := Preview(context.Background(), source, destination, selection, Options{})
			if err != nil {
				t.Fatal(err)
			}
			a.change(func() {
				switch change {
				case "source field":
					a.settings["mode"] = "direct"
				case "version":
					a.version = "v1.19.99"
				case "members":
					group := a.proxies[manualGroup]
					group.All = append(group.All, "gamma")
					a.proxies[manualGroup] = group
				case "health":
					group := a.proxies[manualGroup]
					group.History = []core.DelayRecord{{Delay: 333}}
					a.proxies[manualGroup] = group
				}
			})
			if change == "destination field" {
				b.change(func() { b.settings["mode"] = "direct" })
			}
			result, err := Apply(context.Background(), source, destination, selection, plan.Digest, Options{})
			if change == "health" {
				if err != nil {
					t.Fatalf("health invalidated preview: %v", err)
				}
			} else if !errors.Is(err, ErrStale) || result.Status != "stale" || len(b.mutations()) != 0 {
				t.Fatalf("stale apply: %+v %v writes=%v", result, err, b.mutations())
			}
		})
	}
}

func TestCopyStopsOnFailureAndPreservesUncertainReceipt(t *testing.T) {
	for _, failure := range []string{"group rejection", "readback"} {
		t.Run(failure, func(t *testing.T) {
			_, b, source, destination := pair(t)
			selection := Selection{Fields: []string{"mode", "log-level"}, Groups: []string{manualGroup}}
			plan, err := Preview(context.Background(), source, destination, selection, Options{})
			if err != nil {
				t.Fatal(err)
			}
			b.change(func() { b.failGroup, b.failReadBack = failure == "group rejection", failure == "readback" })
			result, err := Apply(context.Background(), source, destination, selection, plan.Digest, Options{})
			if err == nil || result.Status != "stopped" || result.Steps[2].Status != "pending" {
				t.Fatalf("failed batch continued: %+v %v", result, err)
			}
			if strings.Contains(err.Error(), "PRIVATE_CONTROLLER_ERROR") {
				t.Fatal("controller body leaked")
			}
			if failure == "readback" {
				var apiErr *core.Error
				if result.Steps[0].Status != "unknown" || !errors.As(err, &apiErr) || apiErr.Kind != core.KindUnknownWrite || len(b.mutations()) != 1 {
					t.Fatalf("unknown result was retried/lost: %+v %v %v", result, err, b.mutations())
				}
			} else if result.Steps[0].Status != "applied" || result.Steps[1].Status != "failed" || len(b.mutations()) != 2 {
				t.Fatalf("partial receipt was lost: %+v %v", result, b.mutations())
			}
		})
	}
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestTargetValidationAndClientCleanup(t *testing.T) {
	_, _, source, destination := pair(t)
	opened, closed := 0, 0
	opts := Options{Open: func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		opened++
		if !readOnly {
			t.Fatal("diff opened writable client")
		}
		if target.ID == destination.ID {
			return nil, nil, errors.New("offline")
		}
		client, err := core.New(core.Options{Endpoint: target.Controller, ReadOnly: readOnly})
		return client, closeFunc(func() error { closed++; return nil }), err
	}}
	if _, err := Diff(context.Background(), source, destination, opts); err == nil || opened != 2 || closed != 1 {
		t.Fatalf("cleanup: %v opened=%d closed=%d", err, opened, closed)
	}
	for _, same := range []config.Target{source, {ID: "alias", Controller: source.Controller + "/"}, {ID: "temp", Controller: destination.Controller, Transient: true}} {
		if _, err := Diff(context.Background(), source, same, Options{}); err == nil {
			t.Fatalf("accepted target pair: %+v", same)
		}
	}
	if got := normalizedController("http://LOCALHOST"); got != normalizedController("http://localhost:80/") {
		t.Fatal(got)
	}
}
