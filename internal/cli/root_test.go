package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
	"github.com/daviddwlee84/lazyclash/internal/tui"
)

func isolated(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	for _, name := range []string{"LAZYCLASH_CONFIG", "LAZYCLASH_SERVERS_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"} {
		t.Setenv(name, "")
	}
	return filepath.Join(dir, "lazyclash", "config.toml")
}

func TestDiscoveryKeepsExplicitCredentialOverrides(t *testing.T) {
	isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	discover := func(context.Context, string) ([]config.Target, error) {
		return []config.Target{{ID: "found", Controller: server.URL, SecretEnv: "OLD"}}, nil
	}
	deps := Dependencies{Discover: discover, Open: func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if target.SecretEnv != "NEW" || target.SecretFile != "" {
			t.Fatalf("override lost: %+v", target)
		}
		c, e := core.New(core.Options{Endpoint: target.Controller})
		return c, nil, e
	}}
	if _, _, err := run(t, deps, "--secret-env", "NEW", "status"); err != nil {
		t.Fatal(err)
	}
	deps.Terminal = func(io.Reader, io.Writer) bool { return true }
	deps.RunTUI = func(ctx context.Context, opts tui.Options, in io.Reader, out io.Writer) error {
		found, err := opts.Discover(ctx)
		if err != nil {
			return err
		}
		if len(found) != 1 || found[0].SecretEnv != "NEW" {
			t.Fatalf("TUI override lost: %+v", found)
		}
		return nil
	}
	if _, _, err := run(t, deps, "--secret-env", "NEW"); err != nil {
		t.Fatal(err)
	}
}

func TestTemporaryIDCollisionAndConflictingCredentials(t *testing.T) {
	path := isolated(t)
	if _, _, err := run(t, Dependencies{}, "targets", "add", "temporary", "--controller", "http://127.0.0.1:9090", "--secret-env", "ORIGINAL"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, _, err := run(t, Dependencies{}, "targets", "edit", "temporary", "--secret-file", "/tmp/secret", "--secret-env", "NEW"); ExitCode(err) != 2 {
		t.Fatalf("credential conflict not rejected: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("conflicting flags modified credentials")
	}
	if _, _, err := run(t, Dependencies{}, "--target", "temporary", "configs", "add", "work", "--path", "/core/work.yaml"); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, RunTUI: func(ctx context.Context, opts tui.Options, in io.Reader, out io.Writer) error {
		if len(opts.Config.Targets) != 2 || opts.InitialTarget == "temporary" || opts.Config.Targets[0].Controller != "http://127.0.0.1:9090" {
			t.Fatalf("temporary target collision: %+v", opts)
		}
		return nil
	}}
	if _, _, err := run(t, deps, "--controller", "http://127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
}

type brokenWriter struct{ err error }

func (w brokenWriter) Write(p []byte) (int, error) { return 0, w.err }

func TestLogsStopOnOutputFailure(t *testing.T) {
	isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	failure := errors.New("output closed")
	cmd := NewCommand()
	cmd.SetArgs([]string{"--controller", server.URL, "logs", "--json"})
	cmd.SetOut(brokenWriter{failure})
	cmd.SetErr(io.Discard)
	cmd.SetIn(strings.NewReader(""))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, failure) {
			t.Fatalf("wrong output failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("log stream continued after output failed")
	}
}

func TestRuntimeOutputRedactsCredentials(t *testing.T) {
	isolated(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/version" {
			io.WriteString(w, `{"version":"fixture","meta":true}`)
			return
		}
		io.WriteString(w, `{"mode":"rule","authentication":["user:private-password"],"ss-config":"ss-secret","tuic-server":{"users":{"id":"tuic-secret"}}}`)
	}))
	defer server.Close()
	for _, args := range [][]string{{"status"}, {"configs", "show"}} {
		out, _, err := run(t, Dependencies{}, append([]string{"--controller", server.URL, "--json"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private-password", "ss-secret", "tuic-secret"} {
			if strings.Contains(out, secret) {
				t.Fatalf("credential leaked: %s", out)
			}
		}
		if !json.Valid([]byte(out)) {
			t.Fatal("redaction broke JSON")
		}
	}
}

func run(t *testing.T, deps Dependencies, args ...string) (string, string, error) {
	t.Helper()
	cmd := New(deps)
	var out, diagnostics bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&diagnostics)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), diagnostics.String(), err
}

func TestHelpAndInvalidIntentDoNotDiscoverOrCreateSettings(t *testing.T) {
	path := isolated(t)
	deps := Dependencies{Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("unexpected discovery")
		return nil, nil
	}}
	for _, args := range [][]string{{}, {"--help"}, {"targets"}, {"--config", "/does/not/exist", "--help"}} {
		out, _, err := run(t, deps, args...)
		if err != nil || !strings.Contains(out, "Usage:") {
			t.Fatalf("%v: %s %v", args, out, err)
		}
	}
	for _, args := range [][]string{{"--json"}, {"targets", "add", "partial"}, {"targets", "add", "invalid ID", "--controller", "http://127.0.0.1:9090"}, {"--unknown"}, {"unknown-command"}, {"--target", "a", "--controller", "http://localhost:9090", "status"}, {"mode", "typo"}} {
		_, _, err := run(t, deps, args...)
		if err == nil || ExitCode(err) != 2 {
			t.Fatalf("%v: expected usage error, got %v", args, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("settings created during read/invalid command: %v", err)
	}
}

func TestTargetsAndConfigsRoundTrip(t *testing.T) {
	path := isolated(t)
	commands := [][]string{
		{"targets", "add", "a", "--controller", "http://127.0.0.1:9090", "--name", "本機"},
		{"targets", "add", "b", "--controller", "http://127.0.0.1:9097", "--ssh", "home-server"},
		{"targets", "move", "b", "first"},
		{"targets", "default", "b"},
		{"targets", "edit", "a", "--name", "新名字"},
		{"--target", "a", "configs", "add", "work", "--path", "/etc/mihomo/work.yaml"},
	}
	for _, args := range commands {
		if out, _, err := run(t, Dependencies{}, args...); err != nil {
			t.Fatalf("%v: %s %v", args, out, err)
		}
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultTarget != "b" || cfg.Targets[0].ID != "b" || cfg.Targets[1].Name != "新名字" || len(cfg.Targets[1].Configs) != 1 {
		t.Fatalf("wrong saved state: %+v", cfg)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %v", info.Mode())
	}
	for _, args := range [][]string{{"--target", "a", "configs", "remove", "work"}, {"targets", "remove", "b"}} {
		if _, _, err := run(t, Dependencies{}, args...); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err = config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DefaultTarget != "a" || len(cfg.Targets) != 1 || len(cfg.Targets[0].Configs) != 0 {
		t.Fatalf("remove result %+v", cfg)
	}
}

func TestOperationsUseSameCoreAndReadBack(t *testing.T) {
	isolated(t)
	handler := testcore.NewHandler()
	server := httptest.NewServer(handler)
	defer server.Close()
	base := []string{"--controller", server.URL, "--json"}
	commands := [][]string{{"status"}, {"proxies", "list"}, {"proxies", "select", testcore.Selector, testcore.Tokyo}, {"proxies", "delay", testcore.Tokyo}, {"mode", "global"}, {"tun", "on"}, {"allow-lan", "on"}, {"connections", "list"}, {"rules", "list", "--filter", "example"}, {"providers", "list", "proxies"}, {"providers", "update", "rules", testcore.RuleProvider}, {"providers", "healthcheck", testcore.ProxyProvider}, {"connections", "close", "--all", "--yes"}}
	for _, args := range commands {
		full := append(append([]string(nil), base...), args...)
		out, diag, err := run(t, Dependencies{}, full...)
		if err != nil {
			t.Fatalf("%v: %s %v", full, out, err)
		}
		if diag != "" {
			t.Fatalf("unexpected diagnostic: %s", diag)
		}
		if !json.Valid([]byte(out)) {
			t.Fatalf("not JSON for %v: %q", args, out)
		}
	}
	client, _ := core.New(core.Options{Endpoint: server.URL})
	defer client.Close()
	proxies, err := client.Proxies(context.Background())
	if err != nil || proxies[testcore.Selector].Now != testcore.Tokyo {
		t.Fatalf("switch not applied %v %v", proxies, err)
	}
	settings, _ := client.Config(context.Background())
	if settings["mode"] != "global" {
		t.Fatalf("mode did not change: %v", settings)
	}
}

func TestConfirmationAndReadOnlyFailBeforeOpeningCore(t *testing.T) {
	isolated(t)
	deps := Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("must not open core")
		return nil, nil, nil
	}}
	for _, args := range [][]string{{"connections", "close", "--all"}, {"connections", "close", ""}, {"connections", "close", "  "}, {"--read-only", "mode", "global"}, {"--read-only", "proxies", "delay", "x"}, {"connections", "close", "x", "--all", "--yes"}} {
		_, _, err := run(t, deps, args...)
		if err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}

func TestRegisteredYAMLApplyUsesCorePathAndForce(t *testing.T) {
	isolated(t)
	handler := testcore.NewHandler()
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, args := range [][]string{{"targets", "add", "fake", "--controller", server.URL}, {"configs", "add", "work", "--path", "/core/host/work.yaml"}} {
		if _, _, err := run(t, Dependencies{}, args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := run(t, Dependencies{}, "configs", "apply", "work"); ExitCode(err) != 2 {
		t.Fatalf("confirmation required: %v", err)
	}
	if handler.LastApplied() != "" {
		t.Fatal("applied without confirmation")
	}
	out, _, err := run(t, Dependencies{}, "configs", "apply", "work", "--yes", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if handler.LastApplied() != "/core/host/work.yaml" || !strings.Contains(out, "last_confirmed_apply") {
		t.Fatalf("wrong apply %s %q", handler.LastApplied(), out)
	}
}

func TestExplicitTargetWinsEnvironmentAndNeverDiscovers(t *testing.T) {
	isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "saved", "--controller", server.URL); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAZYCLASH_CONTROLLER", "https://unrelated.example")
	t.Setenv("CLASH_SECRET", "must-not-cross-targets")
	deps := Dependencies{Discover: func(context.Context, string) ([]config.Target, error) { t.Fatal("fallback discovery"); return nil, nil }, Open: func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if target.ID != "saved" || target.Controller != server.URL || target.SecretEnv != "" {
			t.Fatalf("wrong target %+v", target)
		}
		c, e := core.New(core.Options{Endpoint: target.Controller})
		return c, nil, e
	}}
	if _, _, err := run(t, deps, "--target", "saved", "status"); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardRepeatedSavesAndTemporaryOverrides(t *testing.T) {
	path := isolated(t)
	if _, _, err := run(t, Dependencies{}, "targets", "add", "saved", "--controller", "http://127.0.0.1:9090"); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, RunTUI: func(ctx context.Context, opts tui.Options, in io.Reader, out io.Writer) error {
		if !opts.Config.Targets[0].Transient {
			t.Fatal("override not marked temporary")
		}
		cfg := opts.Config
		cfg.Targets = append(cfg.Targets, config.Target{ID: "new", Controller: "http://127.0.0.1:9097"})
		if err := opts.SaveTargets(cfg); err != nil {
			return err
		}
		cfg.DefaultTarget = "new"
		if err := opts.SaveTargets(cfg); err != nil {
			return err
		}
		// An external editor must still be detected after multiple successful saves.
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, _ = f.WriteString("\n# external edit\n")
		f.Close()
		if err := opts.SaveTargets(cfg); !errors.Is(err, config.ErrConflict) {
			t.Fatalf("lost conflict detection: %v", err)
		}
		return nil
	}}
	if _, _, err := run(t, deps, "--target", "saved", "--ssh", "temporary-hop"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Targets[0].SSHHost != "" || cfg.DefaultTarget != "new" || len(cfg.Targets) != 2 {
		t.Fatalf("temporary flag persisted or save lost: %+v", cfg)
	}
}
