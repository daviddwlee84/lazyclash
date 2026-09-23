package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func proxyIsolated(t *testing.T) string {
	t.Helper()
	path := isolated(t)
	t.Setenv("LOCAL_PROXY_URL", "")
	t.Setenv("LOCAL_PROXY_SOCKS_URL", "")
	t.Setenv("LAZYCLASH_PROXY_SESSION", "")
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "state"))
	return path
}

func TestProxyCLIEnvExecAndDockerPreview(t *testing.T) {
	proxyIsolated(t)
	out, _, err := run(t, Dependencies{}, "proxy", "env", "--endpoint", "http://127.0.0.1:7897", "--shell", "bash")
	if err != nil || !strings.Contains(out, "export http_proxy='http://127.0.0.1:7897'") {
		t.Fatalf("env %s %v", out, err)
	}
	child := []string{"sh", "-c", `printf '%s' "$http_proxy"; exit 37`}
	if runtime.GOOS == "windows" {
		child = []string{"pwsh", "-NoProfile", "-NonInteractive", "-Command", `[Console]::Write($env:http_proxy); exit 37`}
	}
	out, _, err = run(t, Dependencies{}, append([]string{"proxy", "exec", "--endpoint", "http://127.0.0.1:7897", "--"}, child...)...)
	if ExitCode(err) != 37 || out != "http://127.0.0.1:7897" {
		t.Fatalf("child exit: %q %v", out, err)
	}
	if _, _, err = run(t, Dependencies{}, "proxy", "exec", "--json", "--endpoint", "http://127.0.0.1:7897", "--", "echo", "never"); ExitCode(err) != 2 {
		t.Fatalf("json exec: %v", err)
	}
	out, _, err = run(t, Dependencies{}, "proxy", "docker", "render", "--endpoint", "http://host.docker.internal:7897", "--format", "compose", "--service", "web")
	if err != nil || !strings.Contains(out, "services:") || !strings.Contains(out, "environment:") {
		t.Fatalf("Docker %s %v", out, err)
	}
	if _, _, err = run(t, Dependencies{}, "proxy", "docker", "render"); ExitCode(err) != 2 {
		t.Fatal("guessed docker endpoint")
	}
}

func TestProxyCLILocalDefaultAmbiguityAndJSONNoPrompt(t *testing.T) {
	path := proxyIsolated(t)
	cfg := config.Config{DefaultTarget: "remote", Targets: []config.Target{{ID: "remote", Controller: "http://127.0.0.1:9090", SSHHost: "fixture", ProbeProxy: "http://127.0.0.1:7890"}, {ID: "local1", Controller: "http://127.0.0.1:9091", ProbeProxy: "http://127.0.0.1:7891"}, {ID: "local2", Controller: "http://127.0.0.1:9092", ProbeProxy: "http://127.0.0.1:7892"}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { t.Fatal("JSON checked terminal for prompting"); return true }}
	_, _, err := run(t, deps, "proxy", "env", "--json")
	if err == nil || !strings.Contains(err.Error(), "multiple local") {
		t.Fatalf("ambiguity: %v", err)
	}
	out, _, err := run(t, Dependencies{}, "proxy", "env", "--json", "--target", "local1")
	var result struct {
		Proxy proxyenv.Plan `json:"proxy"`
	}
	decodeErr := json.Unmarshal([]byte(out), &result)
	if err != nil || decodeErr != nil || result.Proxy.TargetID != "local1" {
		t.Fatalf("target: %s %v", out, err)
	}
}

func TestProxyCLITunnelLocalStartRenderAndCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	proxyIsolated(t)
	id, _ := proxyenv.NewID()
	out, _, err := run(t, Dependencies{}, "proxy", "tunnel", "start", "--endpoint", "http://127.0.0.1:7897", "--lease", id, "--json")
	if err != nil {
		t.Fatalf("start %s %v", out, err)
	}
	var object map[string]any
	if err = json.Unmarshal([]byte(out), &object); err != nil || object["state"] != "ready" {
		t.Fatalf("start JSON %s %v", out, err)
	}
	out, _, err = run(t, Dependencies{}, "proxy", "env", "--session", id)
	if err != nil || !strings.Contains(out, "7897") {
		t.Fatalf("session env %s %v", out, err)
	}
	if _, _, err = run(t, Dependencies{}, "proxy", "tunnel", "stop", id); err != nil {
		t.Fatal(err)
	}
	_, _, err = run(t, Dependencies{}, "proxy", "env", "--session", id)
	if err == nil {
		t.Fatal("stopped session still rendered")
	}
}

func TestProxyCLIShellInitNoConfigOrNetwork(t *testing.T) {
	proxyIsolated(t)
	missing := filepath.Join(t.TempDir(), "missing.toml")
	out, _, err := run(t, Dependencies{Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("init discovered network")
		return nil, nil
	}}, "--config", missing, "proxy", "shell-init", "bash")
	if err != nil || !strings.Contains(out, "lazyclash-proxy-on") {
		t.Fatalf("init %s %v", out, err)
	}
	if _, err = os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("init touched config")
	}
}

func TestProxyReadOnlyDoesNotCreateState(t *testing.T) {
	proxyIsolated(t)
	var out, errOut bytes.Buffer
	code := execute(context.Background(), []string{"--read-only", "proxy", "tunnel", "start", "--endpoint", "http://127.0.0.1:7897"}, strings.NewReader(""), &out, &errOut, Dependencies{})
	if code != 2 {
		t.Fatalf("read-only code %d %s", code, errOut.String())
	}
	dir, _ := proxyenv.SessionDirectory()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("read-only wrote state")
	}
}
