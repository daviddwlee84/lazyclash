package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
	"github.com/daviddwlee84/lazyclash/internal/tui"
)

func TestTargetConnectivityIsReadOnlyAndDoesNotSave(t *testing.T) {
	path := isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "test", "--controller", server.URL); err != nil {
		t.Fatal(err)
	}
	before, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Open: func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if !readOnly {
			t.Fatal("connectivity test has write-enabled client")
		}
		c, err := core.New(core.Options{Endpoint: target.Controller, ReadOnly: readOnly})
		return c, nil, err
	}}
	out, _, err := run(t, deps, "targets", "test", "test", "--read-only", "--json")
	var result diagnostics.TestResult
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || !result.Connected || !result.ConfigsReadable {
		t.Fatalf("test: %s %v", out, err)
	}
	after, err := config.Load(path, true)
	if err != nil || after.DefaultTarget != before.DefaultTarget || len(after.Targets) != len(before.Targets) {
		t.Fatalf("changed settings: %+v %v", after, err)
	}
}

func TestDiagnosticsIndependentOfControllerAndPartialJSON(t *testing.T) {
	isolated(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			io.WriteString(w, `{"ip":"203.0.113.5","country":"Example"}`)
		case "/ok":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer proxy.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "offline", "--controller", "http://127.0.0.1:1", "--probe-proxy", proxy.URL); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("data probe opened controller")
			return nil, nil, nil
		},
		Diagnostics: diagnostics.Options{IPURL: "http://destination.invalid/ip", Sites: []diagnostics.Site{{Name: "ok", URL: "http://destination.invalid/ok"}, {Name: "bad", URL: "http://destination.invalid/bad"}}},
	}
	out, _, err := run(t, deps, "--target", "offline", "diagnostics", "ip", "--json")
	if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "203.0.113.5") {
		t.Fatalf("IP: %s %v", out, err)
	}
	out, _, err = run(t, deps, "--target", "offline", "diagnostics", "latency", "--json")
	var result diagnostics.LatencyResult
	if err == nil || ExitCode(err) != 1 || json.Unmarshal([]byte(out), &result) != nil || len(result.Sites) != 2 {
		t.Fatalf("partial: %s %v", out, err)
	}
	if result.Sites[0].Error != "" || result.Sites[1].StatusCode != 503 || result.Sites[1].Error == "" {
		t.Fatalf("results: %+v", result.Sites)
	}
	for _, name := range []string{"ip", "latency"} {
		out, _, err := run(t, deps, "--target", "offline", "--read-only", "diagnostics", name, "--json")
		if err == nil || out != "" {
			t.Fatalf("read-only %s: %s %v", name, out, err)
		}
	}
}

func TestProbeFlagsRoundTripAndCredentialExclusion(t *testing.T) {
	path := isolated(t)
	for _, args := range [][]string{
		{"targets", "add", "a", "--controller", "http://127.0.0.1:9090", "--probe-proxy", "socks5h://127.0.0.1:7890", "--probe-password-env", "PROXY_PASS", "--probe-username", "user"},
		{"targets", "edit", "a", "--probe-password-file", "/tmp/proxy.password", "--probe-ca-cert", "/tmp/proxy.ca"},
	} {
		if _, _, err := run(t, Dependencies{}, args...); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Targets[0]
	if got.ProbePasswordEnv != "" || got.ProbePasswordFile != "/tmp/proxy.password" || got.ProbeCAFile != "/tmp/proxy.ca" {
		t.Fatalf("wrong fields: %+v", got)
	}
	if _, _, err := run(t, Dependencies{}, "targets", "edit", "a", "--probe-password-env", "A", "--probe-password-file", "/tmp/b"); err == nil {
		t.Fatal("accepted conflicting references")
	}
}

func TestRootPageMouseOverrides(t *testing.T) {
	isolated(t)
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, RunTUI: func(_ context.Context, opts tui.Options, _ io.Reader, _ io.Writer) error {
		if opts.StartPage != "logs" || opts.Mouse == nil || *opts.Mouse {
			t.Fatalf("overrides: %+v", opts)
		}
		return nil
	}}
	if _, _, err := run(t, deps, "--page", "logs", "--mouse=false"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, deps, "--page", "typo"); err == nil || ExitCode(err) != 2 {
		t.Fatalf("invalid page: %v", err)
	}
}

func TestTUITemporaryTransportAndCredentialOverridesAreDistinct(t *testing.T) {
	isolated(t)
	if _, _, e := run(t, Dependencies{}, "targets", "add", "saved", "--controller", "http://127.0.0.1:9090"); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		args      []string
		transport bool
	}{
		{[]string{"--target", "saved", "--ssh", "other-host"}, true},
		{[]string{"--controller", "http://127.0.0.1:9999"}, true},
		{[]string{"--target", "saved", "--secret-env", "TEMP_SECRET"}, false},
	} {
		seen := false
		deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, RunTUI: func(_ context.Context, opts tui.Options, _ io.Reader, _ io.Writer) error {
			for _, target := range opts.Config.Targets {
				if target.ID == opts.InitialTarget {
					seen = true
					if target.TransportOverride != tc.transport {
						t.Fatalf("%v: %+v", tc.args, target)
					}
				}
			}
			return nil
		}}
		if _, _, e := run(t, deps, tc.args...); e != nil || !seen {
			t.Fatalf("%v: %v %t", tc.args, e, seen)
		}
	}
}
