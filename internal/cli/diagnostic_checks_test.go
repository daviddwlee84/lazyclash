package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
)

func TestDiagnosticChecksCRUDIsTargetScopedAndPassive(t *testing.T) {
	path := isolated(t)
	deps := Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("saved check edit/list opened controller")
		return nil, nil, nil
	}}
	for _, id := range []string{"a", "b"} {
		if _, _, err := run(t, deps, "targets", "add", id, "--controller", "http://127.0.0.1:9090"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := run(t, deps, "--target", "a", "diagnostics", "checks", "add", "claude", "--name", "Claude API", "--url", "https://api.anthropic.com/", "--status", "404"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, deps, "--target", "a", "diagnostics", "checks", "add", "web", "--url", "https://example.com/"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, deps, "--target", "a", "diagnostics", "checks", "add", "claude", "--url", "https://api.anthropic.com/"); err == nil {
		t.Fatal("duplicate check silently replaced")
	}
	if _, _, err := run(t, deps, "--target", "a", "diagnostics", "checks", "add", "claude", "--url", "https://api.anthropic.com/", "--status", "401,404", "--replace"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	out, _, err := run(t, deps, "--target", "a", "--read-only", "diagnostics", "checks", "--json")
	var saved struct {
		TargetID string                   `json:"target_id"`
		Checks   []config.DiagnosticCheck `json:"checks"`
	}
	if err != nil || json.Unmarshal([]byte(out), &saved) != nil || saved.TargetID != "a" || len(saved.Checks) != 2 || len(saved.Checks[0].ExpectedStatuses) != 2 {
		t.Fatalf("list: %s %v", out, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("list modified settings")
	}
	for _, args := range [][]string{{"add", "new", "--url", "https://example.com/"}, {"remove", "web"}, {"run", "--all"}} {
		if _, _, err := run(t, deps, append([]string{"--target", "a", "--read-only", "diagnostics", "checks"}, args...)...); err == nil {
			t.Fatalf("read-only accepted %v", args)
		}
	}
	if _, _, err := run(t, deps, "--target", "a", "diagnostics", "checks", "remove", "web"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets[0].Checks) != 1 || len(cfg.Targets[1].Checks) != 0 {
		t.Fatalf("changed other target: %+v", cfg.Targets)
	}
	for _, args := range [][]string{{"add", "missing-url"}, {"add", "credential", "--url", "https://user:password@example.com/"}, {"run"}, {"run", "claude", "--all"}} {
		if _, _, err := run(t, deps, append([]string{"--target", "a", "diagnostics", "checks"}, args...)...); err == nil {
			t.Fatalf("invalid invocation accepted: %v", args)
		}
	}
}

func TestDiagnosticChecksRunReportsHTTPExpectationIndependently(t *testing.T) {
	path := isolated(t)
	var heads atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heads.Add(1)
		if r.Method != "HEAD" {
			t.Error("not HEAD")
		}
		if r.URL.Path == "/api" {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(403)
		}
	}))
	defer proxy.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "a", "--controller", "http://127.0.0.1:1", "--probe-proxy", proxy.URL); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"api", "--url", "http://service.invalid/api", "--status", "404"}, {"blocked", "--url", "http://service.invalid/"}} {
		if _, _, err := run(t, Dependencies{}, append([]string{"diagnostics", "checks", "add"}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.ReadFile(path)
	deps := Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, errors.New("offline")
	}}
	out, _, err := run(t, deps, "diagnostics", "checks", "run", "--all", "--json")
	var report diagnostics.CheckReport
	if !errors.Is(err, diagnostics.ErrPartial) || json.Unmarshal([]byte(out), &report) != nil || report.Completed != 2 || report.Passed != 1 || heads.Load() != 2 {
		t.Fatalf("run: %s %v", out, err)
	}
	if !report.Checks[0].TransportReachable || !report.Checks[1].TransportReachable || *report.Checks[0].ExpectedStatusMatched != true || *report.Checks[1].ExpectedStatusMatched != false || report.Checks[0].ApplicationAccess != "not-tested" || report.Checks[0].Route.Status != "unknown" {
		t.Fatalf("ambiguous application/route result: %+v", report)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("running checks modified settings")
	}
}

func TestDiagnosticChecksResolveOnlySelectedRuntimeDataPortInMemory(t *testing.T) {
	path := isolated(t)
	var heads atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { heads.Add(1); w.WriteHeader(200) }))
	defer proxy.Close()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(proxy.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/configs":
			fmt.Fprintf(w, `{"mode":"rule","mixed-port":%d}`, port)
		case "/connections":
			fmt.Fprint(w, `{"connections":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer controller.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "selected", "--controller", controller.URL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, Dependencies{}, "diagnostics", "checks", "add", "web", "--url", "http://service.invalid/"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOCAL_PROXY_URL", "http://127.0.0.1:1")
	before, _ := os.ReadFile(path)
	deps := Dependencies{Open: func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if target.ID != "selected" || !readOnly {
			t.Fatalf("wrong target or mutable client: %+v", target)
		}
		c, e := core.New(core.Options{Endpoint: controller.URL, ReadOnly: true})
		return c, nil, e
	}}
	out, _, err := run(t, deps, "--target", "selected", "diagnostics", "checks", "run", "web", "--json")
	if err != nil || heads.Load() != 1 || !strings.Contains(out, `"transport_reachable":true`) {
		t.Fatalf("runtime endpoint not resolved: %s %v", out, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("derived runtime port persisted into settings")
	}
	cfg, err := config.Load(path, true)
	if err != nil || cfg.Targets[0].ProbeProxy != "" {
		t.Fatal("data proxy binding changed")
	}
}
