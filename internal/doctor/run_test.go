package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
)

func fixtureOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Load:          func(string, bool) (config.Config, error) { return config.Config{}, nil },
		DiscoverLocal: func(context.Context) ([]config.Target, error) { return nil, nil },
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Error("unexpected controller open")
			return nil, nil, errors.New("unexpected")
		},
		Getenv:      func(string) string { return "" },
		Environment: func() map[string]any { return map[string]any{"variables": map[string]string{}, "no_proxy_set": false} },
		ReadSystemProxy: func(_ context.Context, host string, _ []string) (networkcheck.SystemProxySnapshot, error) {
			if host != "" {
				t.Error("SSH system proxy")
			}
			return networkcheck.SystemProxySnapshot{Protocol: 1, Unavailable: "unsupported"}, nil
		},
		Inspect: func(_ context.Context, host string, _ networkcheck.InspectOptions) (networkcheck.Report, error) {
			if host != "" {
				t.Error("SSH inventory")
			}
			return networkcheck.Report{}, connection.ErrPythonUnavailable
		},
	}
}

func checkStatus(t *testing.T, r Report, id string, want Status) {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			if c.Status != want {
				t.Errorf("%s: got %s, want %s (%s)", id, c.Status, want, c.Message)
			}
			return
		}
	}
	t.Fatalf("missing check %s", id)
}

func fakeController(t *testing.T, configs string) (string, *[]string, *sync.Mutex) {
	t.Helper()
	var calls []string
	mu := new(sync.Mutex)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method != "GET" {
			t.Errorf("mutation: %s", r.Method)
		}
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"version":"v1.19.32"}`)
		case "/configs":
			io.WriteString(w, configs)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, &calls, mu
}

func TestRunLocalDefaultPassiveAndOptionalUnknown(t *testing.T) {
	endpoint, calls, mu := fakeController(t, `{"mode":"rule","mixed-port":7897,"tun":{"enable":true,"device":"utun8"},"secret":"never-output"}`)
	opts := fixtureOptions(t)
	opts.Open = connection.Open
	opts.Load = func(string, bool) (config.Config, error) {
		return config.Config{DefaultTarget: "remote", Targets: []config.Target{{ID: "remote", SSHHost: "never-ssh", Controller: endpoint}, {ID: "local", Controller: endpoint}}}, nil
	}
	opts.DiscoverLocal = func(context.Context) ([]config.Target, error) {
		t.Error("discovered with registered local")
		return nil, nil
	}
	r := Run(context.Background(), Request{}, opts)
	if r.Summary.ExitCode != 0 || !r.Summary.Complete || r.Selection.TargetID != "local" || r.Runtime == nil || r.Runtime.MixedPort != 7897 {
		t.Fatalf("report: %+v", r)
	}
	checkStatus(t, r, "system_proxy", Unknown)
	checkStatus(t, r, "network", Unknown)
	checkStatus(t, r, "egress", Skip)
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(*calls, []string{"GET /version", "GET /configs"}) {
		t.Fatalf("requests: %v", *calls)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "never-output") {
		t.Fatal("raw runtime leaked")
	}
}

func TestRunSelectionRules(t *testing.T) {
	local1 := config.Target{ID: "one", Controller: "http://127.0.0.1:9090"}
	local2 := config.Target{ID: "two", Controller: "http://[::1]:9097"}
	remote := config.Target{ID: "remote", Controller: "https://example.invalid:9443", SSHHost: "never-ssh"}
	for _, tc := range []struct {
		name                   string
		cfg                    config.Config
		request                Request
		found                  []config.Target
		wantID                 string
		wantOpen, wantDiscover bool
	}{
		{name: "local default", cfg: config.Config{DefaultTarget: "two", Targets: []config.Target{local1, local2}}, wantID: "two", wantOpen: true},
		{name: "ambiguous", cfg: config.Config{Targets: []config.Target{local1, local2}}},
		{name: "remote default discovers local", cfg: config.Config{DefaultTarget: "remote", Targets: []config.Target{remote}}, found: []config.Target{local1}, wantID: "one", wantOpen: true, wantDiscover: true},
		{name: "explicit remote", cfg: config.Config{Targets: []config.Target{local1, remote}}, request: Request{TargetID: "remote"}},
		{name: "explicit remote controller", request: Request{Controller: "http://example.invalid:9090"}},
		{name: "explicit ssh", request: Request{SSHHost: "never-ssh"}},
		{name: "explicit absent", cfg: config.Config{Targets: []config.Target{local1}}, request: Request{TargetID: "missing"}},
		{name: "no candidates", wantDiscover: true},
		{name: "untrusted discovery remote", found: []config.Target{remote}, wantDiscover: true},
		{name: "unix", request: Request{Controller: "unix:///tmp/test.sock"}, wantID: "temporary", wantOpen: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := fixtureOptions(t)
			opts.Load = func(string, bool) (config.Config, error) { return tc.cfg, nil }
			opened, discovered := false, false
			opts.Open = func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
				opened = true
				if !readOnly || !proxyenv.IsLocalTarget(target) || target.SSHHost != "" {
					t.Error("unsafe open")
				}
				return nil, nil, errors.New("fixture offline")
			}
			opts.DiscoverLocal = func(context.Context) ([]config.Target, error) { discovered = true; return tc.found, nil }
			r := Run(context.Background(), tc.request, opts)
			if opened != tc.wantOpen || discovered != tc.wantDiscover || r.Selection.TargetID != tc.wantID {
				t.Errorf("open=%v discover=%v selection=%+v", opened, discovered, r.Selection)
			}
			if r.Summary.ExitCode != 1 {
				t.Errorf("exit=%d", r.Summary.ExitCode)
			}
			checkStatus(t, r, "environment", Pass)
		})
	}
}

func TestRunBadAndMissingSettingsStillReports(t *testing.T) {
	for _, tc := range []struct {
		name, contents    string
		missing, explicit bool
		want              Status
	}{
		{"bad TOML", "secret = [password", false, true, Fail},
		{"invalid settings", "default_target = 'missing'", false, true, Fail},
		{"explicit missing", "", true, true, Fail},
		{"default missing", "", true, false, Warn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.toml")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			opts := fixtureOptions(t)
			opts.Load = config.Load
			r := Run(context.Background(), Request{SettingsPath: path, ExplicitSettings: tc.explicit}, opts)
			checkStatus(t, r, "settings", tc.want)
			checkStatus(t, r, "environment", Pass)
			checkStatus(t, r, "system_proxy", Unknown)
			if tc.missing {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("settings were created")
				}
			} else {
				got, _ := os.ReadFile(path)
				if string(got) != tc.contents {
					t.Fatal("settings changed")
				}
			}
			encoded, _ := json.Marshal(r)
			if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), path) {
				t.Fatal("settings/error data leaked")
			}
		})
	}
}

func TestRunAuthOfflineAndRedaction(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(strconvStatus(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/version" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(status)
				io.WriteString(w, "response-body-password")
			}))
			defer server.Close()
			opts := fixtureOptions(t)
			opts.Open = connection.Open
			r := Run(context.Background(), Request{Controller: server.URL}, opts)
			checkStatus(t, r, "controller", Fail)
			checkStatus(t, r, "environment", Pass)
			if r.Summary.ExitCode != 1 || strings.Contains(Format(r), "response-body-password") {
				t.Fatal("bad auth report")
			}
		})
	}
	t.Run("missing secret", func(t *testing.T) {
		opts := fixtureOptions(t)
		opts.Open = connection.Open
		missingEnv := "DOCTOR_" + "ABSENT_TEST_ENV"
		t.Setenv(missingEnv, "") // Restore any previous value after the test.
		if err := os.Unsetenv(missingEnv); err != nil {
			t.Fatal(err)
		}
		r := Run(context.Background(), Request{Controller: "http://127.0.0.1:1", SecretEnv: missingEnv}, opts)
		checkStatus(t, r, "controller", Fail)
		if strings.Contains(Format(r), missingEnv) {
			t.Fatal("raw error leaked")
		}
	})
	t.Run("offline", func(t *testing.T) {
		opts := fixtureOptions(t)
		opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			return nil, nil, &core.Error{Kind: core.KindUnreachable}
		}
		r := Run(context.Background(), Request{Controller: "http://127.0.0.1:9090"}, opts)
		checkStatus(t, r, "controller", Fail)
		if !strings.Contains(Format(r), "connectivity remains unknown") {
			t.Fatal("conflated controller and data")
		}
	})
}

func strconvStatus(status int) string {
	if status == 401 {
		return "401"
	}
	return "403"
}

func TestRunEnvironmentDataAndPACRedaction(t *testing.T) {
	endpoint, _, _ := fakeController(t, `{"mode":"direct","mixed-port":7897,"tun":{"enable":true}}`)
	opts := fixtureOptions(t)
	opts.Open = connection.Open
	opts.Environment = proxyenv.EnvironmentStatus
	for _, key := range proxyenv.Variables {
		t.Setenv(key, "")
	}
	t.Setenv("https_proxy", "http://user:env-password@127.0.0.1:7897/private?token=env-query#fragment")
	opts.Getenv = func(key string) string {
		if key == "LOCAL_PROXY_URL" {
			return "http://user:data-password@127.0.0.1:8888/path?token=data-query"
		}
		return ""
	}
	opts.Load = func(string, bool) (config.Config, error) {
		return config.Config{Targets: []config.Target{{ID: "local", Controller: endpoint}}}, nil
	}
	opts.ReadSystemProxy = func(context.Context, string, []string) (networkcheck.SystemProxySnapshot, error) {
		return networkcheck.SystemProxySnapshot{Protocol: 1, Backend: "macos-networksetup", Services: []networkcheck.SystemProxyState{{Service: "Wi-Fi", HTTP: networkcheck.ProxyListener{Enabled: true, Host: "127.0.0.1", Port: 7897}, PACEnabled: true, PACURL: "https://user:pac-password@example.invalid/path?token=pac-query", Exceptions: []string{"private-domain"}}}}, nil
	}
	r := Run(context.Background(), Request{}, opts)
	checkStatus(t, r, "consistency", Warn)
	if r.DataEndpoint.Source != "LOCAL_PROXY_URL" || r.DataEndpoint.HTTP != "http://127.0.0.1:8888" || r.Summary.ExitCode != 0 {
		t.Fatalf("data=%+v summary=%+v", r.DataEndpoint, r.Summary)
	}
	encoded, _ := json.Marshal(r)
	for _, output := range []string{string(encoded), Format(r)} {
		for _, secret := range []string{"env-password", "env-query", "data-password", "data-query", "pac-password", "pac-query", "private-domain", "fragment"} {
			if strings.Contains(output, secret) {
				t.Errorf("leaked %s", secret)
			}
		}
	}
	// Explicit local selection ignores the shell default endpoint.
	r = Run(context.Background(), Request{TargetID: "local"}, opts)
	if r.DataEndpoint.Source != "core runtime ports" {
		t.Fatal("endpoint overrode explicit target")
	}
}

func TestRunMissingDefaultAndPartialHostEvidence(t *testing.T) {
	endpoint, _, _ := fakeController(t, `{"mixed-port":7897}`)
	opts := fixtureOptions(t)
	opts.Open = connection.Open
	opts.Load = func(string, bool) (config.Config, error) { return config.Config{}, os.ErrNotExist }
	opts.DiscoverLocal = func(context.Context) ([]config.Target, error) {
		return []config.Target{{ID: "found", Controller: endpoint}}, nil
	}
	opts.Inspect = func(context.Context, string, networkcheck.InspectOptions) (networkcheck.Report, error) {
		return networkcheck.Report{OS: "Darwin", Capabilities: []networkcheck.Capability{{Name: "interfaces", Available: true}, {Name: "optional", Available: false}}, Interfaces: []networkcheck.Interface{{Name: "utun8"}}, Routes: []networkcheck.Route{{Destination: "default", Interface: "utun8"}}, Resolvers: []networkcheck.Resolver{{Domains: []string{"private-domain"}, Servers: []string{"127.0.0.1"}}}, Conflicts: []networkcheck.Finding{{Level: "conflict", Message: "pre-TUN-only-finding"}}}, nil
	}
	r := Run(context.Background(), Request{}, opts)
	if r.Summary.ExitCode != 0 || r.Network == nil || len(r.Network.DefaultRoutes) != 1 || len(r.Network.DNSServers) != 1 {
		t.Fatalf("partial evidence: %+v", r)
	}
	checkStatus(t, r, "settings", Warn)
	checkStatus(t, r, "network", Warn)
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "pre-TUN-only-finding") || strings.Contains(string(encoded), "private-domain") {
		t.Fatal("copied pre-TUN analysis or unnecessary private metadata")
	}
}

func TestRunEndpointIntentSurvivesMissingController(t *testing.T) {
	opts := fixtureOptions(t)
	opts.Getenv = func(key string) string {
		if key == "LOCAL_PROXY_URL" {
			return "http://user:private@127.0.0.1:7897/path?token=hidden"
		}
		return ""
	}
	r := Run(context.Background(), Request{}, opts)
	if r.DataEndpoint.Source != "LOCAL_PROXY_URL" || r.DataEndpoint.HTTP != "http://127.0.0.1:7897" || r.DataEndpoint.Tested {
		t.Fatalf("endpoint evidence: %+v", r.DataEndpoint)
	}
	checkStatus(t, r, "selection", Fail)
}

func TestRunConfigFailureKeepsControllerIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("mutation")
		}
		if r.URL.Path == "/version" {
			io.WriteString(w, `{"version":"v1"}`)
			return
		}
		if r.URL.Path != "/configs" {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "body-secret")
	}))
	defer server.Close()
	opts := fixtureOptions(t)
	opts.Open = connection.Open
	r := Run(context.Background(), Request{Controller: server.URL}, opts)
	checkStatus(t, r, "controller", Pass)
	checkStatus(t, r, "runtime", Fail)
	checkStatus(t, r, "environment", Pass)
	if r.Runtime == nil || !r.Runtime.IdentityVerified || r.Summary.ExitCode != 1 || strings.Contains(Format(r), "body-secret") {
		t.Fatalf("partial report: %+v", r)
	}
}

func TestRunTUNAndEndpointComparison(t *testing.T) {
	for _, tc := range []struct {
		name, configs, env string
		want               Status
	}{
		{"TUN only", `{"mode":"rule","tun":{"enable":true,"device":"utun8"}}`, "http://127.0.0.1:9999", Skip},
		{"same", `{"mixed-port":7897}`, "http://localhost:7897", Pass},
		{"different", `{"mixed-port":7897}`, "http://127.0.0.1:7890", Warn},
		{"remote incomparable", `{"mixed-port":7897}`, "http://proxy.example.invalid:7890", Skip},
		{"none", `{"mixed-port":7897}`, "", Skip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, _, _ := fakeController(t, tc.configs)
			opts := fixtureOptions(t)
			opts.Open = connection.Open
			opts.Environment = func() map[string]any { return map[string]any{"variables": map[string]string{"http_proxy": tc.env}} }
			r := Run(context.Background(), Request{Controller: endpoint}, opts)
			checkStatus(t, r, "consistency", tc.want)
			if r.Summary.ExitCode != 0 {
				t.Fatalf("summary=%+v", r.Summary)
			}
		})
	}
}

func TestRunTimeoutCancellationAndCleanup(t *testing.T) {
	opts := fixtureOptions(t)
	var closed atomic.Bool
	endpoint, _, _ := fakeController(t, `{}`)
	opts.Open = func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		client, closer, err := connection.Open(ctx, target, readOnly)
		return client, closeFunc(func() error { closed.Store(true); return closer.Close() }), err
	}
	r := Run(context.Background(), Request{Controller: endpoint}, opts)
	if r.Summary.ExitCode != 0 || !closed.Load() {
		t.Fatal("client not closed")
	}
	opts.Open = func(ctx context.Context, _ config.Target, _ bool) (*core.Client, io.Closer, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	start := time.Now()
	r = Run(context.Background(), Request{Controller: endpoint, Timeout: 30 * time.Millisecond}, opts)
	if time.Since(start) > time.Second || !r.Summary.TimedOut || r.Summary.ExitCode != 1 {
		t.Fatalf("timeout report %+v", r.Summary)
	}
	checkStatus(t, r, "environment", Pass)
	checkStatus(t, r, "settings", Pass)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = Run(ctx, Request{}, opts)
	if r.Summary.ExitCode != 130 || !r.Summary.Canceled {
		t.Fatalf("cancel %+v", r.Summary)
	}
	// Even an uncooperative optional collector must not hold the report hostage.
	release := make(chan struct{})
	defer close(release)
	opts.Inspect = func(context.Context, string, networkcheck.InspectOptions) (networkcheck.Report, error) {
		<-release
		return networkcheck.Report{}, nil
	}
	opts.Open = connection.Open
	r = Run(context.Background(), Request{Controller: endpoint, Timeout: 30 * time.Millisecond}, opts)
	if !r.Summary.TimedOut || r.Summary.ExitCode != 0 {
		t.Fatalf("optional deadline %+v", r.Summary)
	}
	checkStatus(t, r, "network", Unknown)
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestRunUnixAndIPv6(t *testing.T) {
	for _, network := range []string{"unix", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "[::1]:0"
			if network == "unix" {
				address = filepath.Join(t.TempDir(), "core.sock")
			}
			ln, err := net.Listen(network, address)
			if err != nil {
				t.Skipf("%s unavailable: %v", network, err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("mutation")
				}
				switch r.URL.Path {
				case "/version":
					io.WriteString(w, `{"version":"v1"}`)
				case "/configs":
					io.WriteString(w, `{"mixed-port":7897}`)
				default:
					t.Errorf("request %s", r.URL.Path)
				}
			})}
			go server.Serve(ln)
			defer server.Close()
			endpoint := "http://" + ln.Addr().String()
			if network == "unix" {
				endpoint = "unix://" + address
			}
			opts := fixtureOptions(t)
			opts.Open = connection.Open
			r := Run(context.Background(), Request{Controller: endpoint}, opts)
			if r.Summary.ExitCode != 0 {
				t.Fatalf("%+v", r)
			}
			if network == "tcp6" && r.DataEndpoint.HTTP != "http://[::1]:7897" {
				t.Fatalf("IPv6 endpoint %+v", r.DataEndpoint)
			}
		})
	}
}
