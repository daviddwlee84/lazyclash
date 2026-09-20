package proxyenv

import (
	"bytes"
	"context"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveLocalPreferenceAndExplicitRemote(t *testing.T) {
	cfg := config.Config{DefaultTarget: "remote", Targets: []config.Target{{ID: "remote", Controller: "http://127.0.0.1:9090", SSHHost: "remote", ProbeProxy: "http://127.0.0.1:7890"}, {ID: "local", Controller: "http://127.0.0.1:9091", ProbeProxy: "http://127.0.0.1:7897"}}}
	opts := Options{Getenv: func(string) string { return "" }}
	p, err := Resolve(context.Background(), cfg, Request{}, opts)
	if err != nil || p.TargetID != "local" {
		t.Fatalf("local preference: %+v %v", p, err)
	}
	p, err = Resolve(context.Background(), cfg, Request{TargetID: "remote"}, opts)
	if err != nil || p.SSHHost != "remote" {
		t.Fatalf("explicit remote: %+v %v", p, err)
	}
	cfg.Targets = append(cfg.Targets, config.Target{ID: "local2", Controller: "unix:///tmp/core.sock", ProbeProxy: "http://127.0.0.1:7898"})
	_, err = Resolve(context.Background(), cfg, Request{}, opts)
	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("ambiguous: %v", err)
	}
	cfg.DefaultTarget = "local2"
	p, err = Resolve(context.Background(), cfg, Request{}, opts)
	if err != nil || p.TargetID != "local2" {
		t.Fatalf("saved local default: %+v %v", p, err)
	}
	_, err = Resolve(context.Background(), config.Config{Targets: []config.Target{{ID: "wan", Controller: "https://example.invalid:443"}}}, Request{TargetID: "wan"}, opts)
	if err == nil {
		t.Fatal("guessed remote data port")
	}
}

func TestResolveRuntimeMixedSplitAndSeparateCredentials(t *testing.T) {
	for _, data := range []string{`{"mixed-port":7897}`, `{"port":7890,"socks-port":7891}`, `{"socks-port":7891}`} {
		t.Run(data, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/configs" {
					t.Errorf("unexpected API %s", r.URL.Path)
				}
				io.WriteString(w, data)
			}))
			defer server.Close()
			cfg := config.Config{Targets: []config.Target{{ID: "local", Controller: server.URL, SecretEnv: "CONTROLLER_SECRET"}}}
			opts := Options{Getenv: func(string) string { return "" }, Open: func(_ context.Context, target config.Target, readonly bool) (*core.Client, io.Closer, error) {
				if !readonly {
					t.Fatal("writable open")
				}
				client, err := core.New(core.Options{Endpoint: target.Controller})
				return client, nil, err
			}}
			p, err := Resolve(context.Background(), cfg, Request{}, opts)
			if err != nil {
				t.Fatal(err)
			}
			if p.PasswordEnv != "" {
				t.Fatal("controller secret reused for proxy")
			}
			if !strings.Contains(p.All, "socks5h://") {
				t.Fatalf("SOCKS DNS protocol missing: %+v", p)
			}
		})
	}
}

func TestProxyEnvQuotingAndExecutionNeverRetry(t *testing.T) {
	t.Setenv("PROXY_TEST_PASSWORD", "a'\"$()`;&")
	p := Plan{Source: "fixture", HTTP: "http://127.0.0.1:7890", All: "socks5h://127.0.0.1:7891", Username: "fixture", PasswordEnv: "PROXY_TEST_PASSWORD"}
	values, err := Values(p)
	if err != nil {
		t.Fatal(err)
	}
	script, err := RenderEnv(p, "bash")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "--noprofile", "--norc", "-c", script+`printf '%s' "$https_proxy"`)
	out, err := cmd.Output()
	if err != nil || string(out) != values["https_proxy"] {
		t.Fatalf("quote: %s %v", out, err)
	}
	var outbuf, errbuf bytes.Buffer
	err = Exec(context.Background(), p, []string{"sh", "-c", `printf once; exit 27`}, nil, &outbuf, &errbuf)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 27 || outbuf.String() != "once" {
		t.Fatalf("exec: %s %+v", outbuf.String(), err)
	}
	if _, err = RenderEnv(Plan{HTTP: p.HTTP, All: p.All, SSHHost: "host"}, "sh"); !errors.Is(err, ErrRemoteEnv) {
		t.Fatalf("remote env: %v", err)
	}
}

func TestProxyTestIgnoresInheritedProxyAndNoProxy(t *testing.T) {
	calls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "HEAD" {
			t.Error("not HEAD")
		}
		w.WriteHeader(204)
	}))
	defer proxy.Close()
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "*")
	result, err := Test(context.Background(), Plan{HTTP: proxy.URL, All: proxy.URL}, "http://example.invalid/test?private=value")
	if err != nil || calls != 1 || result.HTTPStatus != 204 || strings.Contains(result.URL, "private") {
		t.Fatalf("probe: %+v %v calls=%d", result, err, calls)
	}
}

func TestArtifactNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.env")
	if err := WriteArtifact(path, "first"); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifact(path, "second"); err == nil {
		t.Fatal("overwrote existing file")
	}
	data, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if string(data) != "first" || info.Mode().Perm() != 0600 {
		t.Fatalf("artifact: %q %v", data, info.Mode())
	}
}
