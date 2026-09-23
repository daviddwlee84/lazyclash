package serverprobe

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

var testNode = []byte("name: test\ntype: vless\nserver: proxy.example\nport: 443\nuuid: 123e4567-e89b-12d3-a456-426614174000\ntls: true\n")

func testOptions(t *testing.T, endpoint string, roots *x509.CertPool, fail bool, stopped *atomic.Bool, configFile *string) Options {
	t.Helper()
	return Options{Binary: "fake-mihomo", Endpoint: endpoint, RootCAs: roots, Validate: func(_ context.Context, _ string, path string) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || !privatefs.Private(path) {
			return fmt.Errorf("nonprivate config")
		}
		return nil
	}, Start: func(_ context.Context, _ string, path string) (func(), <-chan struct{}, error) {
		*configFile = path
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		var cfg struct {
			Port  int            `yaml:"mixed-port"`
			Auth  []string       `yaml:"authentication"`
			Rules []string       `yaml:"rules"`
			TUN   map[string]any `yaml:"tun"`
		}
		if err = yaml.Unmarshal(data, &cfg); err != nil {
			return nil, nil, err
		}
		if len(cfg.Auth) != 1 || len(cfg.Rules) != 1 || cfg.Rules[0] != "MATCH,LAZYCLASH-VERIFY" || len(cfg.TUN) > 0 {
			return nil, nil, fmt.Errorf("unsafe isolated config")
		}
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", cfg.Port))
		if err != nil {
			return nil, nil, err
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "CONNECT" || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(cfg.Auth[0])) {
				w.WriteHeader(407)
				return
			}
			if fail {
				w.WriteHeader(502)
				return
			}
			upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
			if err != nil {
				w.WriteHeader(502)
				return
			}
			client, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
			go func() { defer upstream.Close(); defer client.Close(); _, _ = io.Copy(upstream, client) }()
			go func() { defer upstream.Close(); defer client.Close(); _, _ = io.Copy(client, upstream) }()
		})}
		go server.Serve(listener)
		exited := make(chan struct{})
		return func() { stopped.Store(true); _ = server.Close(); close(exited) }, exited, nil
	}}
}

func TestAuthenticatedTunnelAndCleanup(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"ip":"203.0.113.42"}`)
	}))
	defer endpoint.Close()
	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	var stopped atomic.Bool
	var path string
	ip, err := ProbeWithOptions(context.Background(), testNode, testOptions(t, endpoint.URL, roots, false, &stopped, &path))
	if err != nil || ip != "203.0.113.42" {
		t.Fatalf("probe: %q %v", ip, err)
	}
	if requests.Load() != 1 || !stopped.Load() {
		t.Fatal("did not verify and stop isolated client")
	}
	if _, err = os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("retained secret config after probe")
	}
}

func TestExplicitInterfaceOnlyAffectsPrivateVerificationClient(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("no local interface available")
	}
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ip":"203.0.113.42"}`)
	}))
	defer endpoint.Close()
	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	var stopped atomic.Bool
	var path string
	opts := testOptions(t, endpoint.URL, roots, false, &stopped, &path)
	opts.InterfaceName = interfaces[0].Name
	start := opts.Start
	opts.Start = func(ctx context.Context, binary, path string) (func(), <-chan struct{}, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		var profile map[string]any
		if err = yaml.Unmarshal(data, &profile); err != nil {
			return nil, nil, err
		}
		if profile["interface-name"] != opts.InterfaceName || profile["tun"] != nil {
			t.Fatal("interface binding enabled TUN or was not scoped to the verifier")
		}
		return start(ctx, binary, path)
	}
	ip, err := ProbeWithOptions(context.Background(), testNode, opts)
	if err != nil || ip != "203.0.113.42" || !stopped.Load() {
		t.Fatalf("explicit interface broke authenticated verification: %q %v", ip, err)
	}
	if _, err = os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("private verification configuration was retained")
	}
	called := false
	_, err = ProbeWithOptions(context.Background(), testNode, Options{InterfaceName: "lazyclash-nonexistent-interface", ResolveBinary: func(context.Context, string) (string, error) {
		called = true
		return "", nil
	}})
	if err == nil || called {
		t.Fatal("invalid interface reached client acquisition")
	}
}

func TestFailureNeverFallsBackToDirect(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"ip":"203.0.113.42"}`)
	}))
	defer endpoint.Close()
	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	var stopped atomic.Bool
	var path string
	_, err := ProbeWithOptions(context.Background(), testNode, testOptions(t, endpoint.URL, roots, true, &stopped, &path))
	if err == nil || requests.Load() != 0 || !stopped.Load() {
		t.Fatalf("failure fell back or leaked client: %v count=%d", err, requests.Load())
	}
	if strings.Contains(err.Error(), "123e4567") {
		t.Fatal("credential in error")
	}
}

func TestRejectInvalidNodeBeforeStarting(t *testing.T) {
	called := false
	_, err := ProbeWithOptions(context.Background(), []byte("bad"), Options{ResolveBinary: func(context.Context, string) (string, error) { called = true; return "", nil }})
	if err == nil || called {
		t.Fatal("invalid node started client acquisition")
	}
}

func TestExitIPResponses(t *testing.T) {
	for _, test := range []struct{ body, want string }{
		{`{"ip":"203.0.113.42"}`, "203.0.113.42"},
		{"fl=123\nip=2001:db8::1\ntls=TLSv1.3\n", "2001:db8::1"},
		{"ip=203.0.113.1\nip=203.0.113.2\n", ""},
		{"<html>203.0.113.1</html>", ""},
		{`{"ip":"127.0.0.1"}`, ""},
	} {
		got, err := exitIP([]byte(test.body))
		if test.want == "" && err == nil || test.want != "" && (err != nil || got != test.want) {
			t.Fatalf("exit IP parser: %q -> %q %v", test.body, got, err)
		}
	}
}

func TestExitedClientCannotBeReplacedByUnownedListener(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"ip":"203.0.113.42"}`) }))
	defer endpoint.Close()
	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	var stopped atomic.Bool
	var path string
	opts := testOptions(t, endpoint.URL, roots, false, &stopped, &path)
	start := opts.Start
	opts.Start = func(ctx context.Context, binary, path string) (func(), <-chan struct{}, error) {
		stop, _, err := start(ctx, binary, path)
		if err != nil {
			return nil, nil, err
		}
		// A replacement listener works, but the owned child has already exited.
		exited := make(chan struct{})
		close(exited)
		return stop, exited, nil
	}
	_, err := ProbeWithOptions(context.Background(), testNode, opts)
	if err == nil || !strings.Contains(err.Error(), "client exited") || !stopped.Load() {
		t.Fatalf("accepted replacement listener or leaked process: %v", err)
	}
}
