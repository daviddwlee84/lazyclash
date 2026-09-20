package diagnostics

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

func TestIPUsesOnlyExplicitProxyWithSeparateCredentials(t *testing.T) {
	var explicit, environmental atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { environmental.Add(1); w.WriteHeader(500) }))
	defer trap.Close()
	t.Setenv("HTTP_PROXY", trap.URL)
	t.Setenv("HTTPS_PROXY", trap.URL)
	t.Setenv("ALL_PROXY", trap.URL)
	t.Setenv("PROBE_PASSWORD", "PRIVATE_PASSWORD")
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		explicit.Add(1)
		if r.URL.Host != "never-resolve.invalid" || r.Method != http.MethodGet {
			t.Errorf("unexpected proxy request: %s %s", r.Method, r.URL)
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("probe-user:PRIVATE_PASSWORD"))
		if r.Header.Get("Proxy-Authorization") != want {
			t.Error("missing separate data proxy credentials")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("controller credential sent to data destination")
		}
		fmt.Fprint(w, `{"ip":"203.0.113.8","country":"Taiwan","city":"\u001b[31mTaipei\u001b[0m","asn":64500}`)
	}))
	defer proxy.Close()
	target := config.Target{ID: "remote", Controller: "http://offline.invalid:9090", Secret: "CONTROLLER_SECRET", ProbeProxy: proxy.URL, ProbeUsername: "probe-user", ProbePasswordEnv: "PROBE_PASSWORD"}
	result, err := IP(context.Background(), target, Options{IPURL: "http://never-resolve.invalid/geoip", Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("IP probe opened controller")
		return nil, nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IP != "203.0.113.8" || result.City != "Taipei" || result.ASN != "64500" || result.Organization != "unknown" || result.Route != proxy.URL {
		t.Fatalf("result: %+v", result)
	}
	if explicit.Load() != 1 || environmental.Load() != 0 {
		t.Fatalf("explicit=%d environment=%d", explicit.Load(), environmental.Load())
	}
	if strings.Contains(fmt.Sprintf("%+v", result), "PRIVATE") {
		t.Fatal("password in result")
	}
}

func TestIPRejectsUnsafePayloadsAndRedirects(t *testing.T) {
	for name, payload := range map[string]string{"missing": `{}`, "invalid_ip": `{"ip":"private-token"}`, "extra_json": `{"ip":"203.0.113.1"}{}`, "not_object": `[]`, "oversize": strings.Repeat(" ", 64*1024+1)} {
		t.Run(name, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, payload) }))
			defer proxy.Close()
			_, err := IP(context.Background(), config.Target{ProbeProxy: proxy.URL}, Options{IPURL: "http://ip.invalid/"})
			if err == nil || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("unsafe response accepted or leaked: %v", err)
			}
		})
	}
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "http://redirect.invalid/")
		w.WriteHeader(302)
	}))
	defer proxy.Close()
	_, err := IP(context.Background(), config.Target{ProbeProxy: proxy.URL}, Options{IPURL: "http://ip.invalid/"})
	if err == nil || !strings.Contains(err.Error(), "302") || requests.Load() != 1 {
		t.Fatalf("redirect followed: %v requests=%d", err, requests.Load())
	}
}

func TestActiveProbesFailClosedBeforeOpeningAnything(t *testing.T) {
	opts := Options{ReadOnly: true, OpenTunnel: func(context.Context, string, string) (string, io.Closer, error) {
		t.Fatal("opened tunnel in read-only")
		return "", nil, nil
	}}
	target := config.Target{SSHHost: "host", ProbeProxy: "http://proxy.invalid:7890", ProbePasswordFile: "/missing/password"}
	if _, err := IP(context.Background(), target, opts); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("IP: %v", err)
	}
	if _, err := Latency(context.Background(), target, opts); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("latency: %v", err)
	}
	if _, err := IP(context.Background(), config.Target{Controller: "http://127.0.0.1:7890"}, Options{}); !errors.Is(err, ErrNoProxy) {
		t.Fatalf("inferred controller as proxy: %v", err)
	}
	if _, err := Latency(context.Background(), config.Target{}, Options{}); !errors.Is(err, ErrNoProxy) {
		t.Fatalf("direct fallback: %v", err)
	}
}

func TestLatencyFreshConnectionsBoundedConcurrencyAndPartialResults(t *testing.T) {
	var active, peak atomic.Int32
	var mu sync.Mutex
	connections := map[string]bool{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		mu.Lock()
		connections[r.RemoteAddr] = true
		mu.Unlock()
		if r.Method != http.MethodHead {
			t.Errorf("method %s", r.Method)
		}
		time.Sleep(25 * time.Millisecond)
		switch r.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "http://site.invalid/final")
			w.WriteHeader(302)
		case "/bad":
			w.WriteHeader(503)
		default:
			w.WriteHeader(204)
		}
	}))
	defer proxy.Close()
	sites := []Site{{"one", "http://site.invalid/one"}, {"redirect", "http://site.invalid/redirect"}, {"bad", "http://site.invalid/bad"}, {"four", "http://site.invalid/four"}, {"five", "http://site.invalid/five"}, {"six", "http://site.invalid/six"}}
	result, err := Latency(context.Background(), config.Target{ProbeProxy: proxy.URL}, Options{Sites: sites})
	if !errors.Is(err, ErrPartial) {
		t.Fatalf("partial error: %v", err)
	}
	if len(result.Sites) != len(sites) || result.Sites[1].StatusCode != 302 || result.Sites[1].Error != "HTTP 302" || result.Sites[2].Error != "HTTP 503" {
		t.Fatalf("results: %+v", result)
	}
	for i, result := range result.Sites {
		if result.Name != sites[i].Name || result.Milliseconds <= 0 {
			t.Errorf("result %d: %+v", i, result)
		}
	}
	if peak.Load() > 3 || peak.Load() < 2 || len(connections) != len(sites) {
		t.Fatalf("peak=%d fresh connections=%d", peak.Load(), len(connections))
	}
}

func TestSSHTunnelUsesRemoteProxyAndClosesOnCompletionAndCancel(t *testing.T) {
	for _, cancelBatch := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelBatch), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cancelBatch {
					cancel()
					<-r.Context().Done()
					return
				}
				w.WriteHeader(204)
			}))
			defer proxy.Close()
			u, _ := url.Parse(proxy.URL)
			var closed atomic.Int32
			opts := Options{Sites: []Site{{"test", "http://site.invalid/"}}, OpenTunnel: func(ctx context.Context, host, endpoint string) (string, io.Closer, error) {
				if host != "remote-alias" || endpoint != "http://remote-only.invalid:7890" {
					t.Errorf("wrong remote route %q %q", host, endpoint)
				}
				return u.Host, closeFunc(func() error { closed.Add(1); return nil }), nil
			}}
			result, err := Latency(ctx, config.Target{SSHHost: "remote-alias", ProbeProxy: "http://remote-only.invalid:7890"}, opts)
			if cancelBatch && !errors.Is(err, context.Canceled) || !cancelBatch && err != nil {
				t.Fatalf("error: %v", err)
			}
			if closed.Load() != 1 || !strings.Contains(result.Route, "remote-only.invalid:7890 via SSH remote-alias") {
				t.Fatalf("closed=%d result=%+v", closed.Load(), result)
			}
		})
	}
}

func TestHTTPSProxyUsesProxyCAWithoutControllerCA(t *testing.T) {
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"ip":"2001:db8::8"}`) }))
	defer proxy.Close()
	ca := filepath.Join(t.TempDir(), "proxy.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	target := config.Target{ProbeProxy: proxy.URL, CAFile: "/missing/controller.pem", ProbeCAFile: ca}
	result, err := IP(context.Background(), target, Options{IPURL: "http://ip.invalid/"})
	if err != nil || result.IP != "2001:db8::8" {
		t.Fatalf("HTTPS proxy: %+v %v", result, err)
	}
	target.ProbeCAFile = ""
	_, err = IP(context.Background(), target, Options{IPURL: "http://ip.invalid/"})
	if err == nil || strings.Contains(err.Error(), proxy.URL) {
		t.Fatalf("untrusted proxy accepted/leaked: %v", err)
	}
}

func TestSOCKSUsesRemoteDNSAndCredentials(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		read := func(n int) ([]byte, error) { b := make([]byte, n); _, err := io.ReadFull(conn, b); return b, err }
		header, err := read(2)
		if err != nil {
			done <- err
			return
		}
		if _, err = read(int(header[1])); err != nil {
			done <- err
			return
		}
		_, _ = conn.Write([]byte{5, 2})
		header, err = read(2)
		if err != nil {
			done <- err
			return
		}
		user, err := read(int(header[1]))
		if err != nil {
			done <- err
			return
		}
		length, err := read(1)
		if err != nil {
			done <- err
			return
		}
		pass, err := read(int(length[0]))
		if err != nil {
			done <- err
			return
		}
		if string(user) != "socks-user" || string(pass) != "SOCKS_SECRET" {
			done <- errors.New("incorrect SOCKS authentication")
			return
		}
		_, _ = conn.Write([]byte{1, 0})
		header, err = read(5)
		if err != nil {
			done <- err
			return
		}
		if header[3] != 3 {
			done <- errors.New("SOCKS request did not preserve destination hostname")
			return
		}
		host, err := read(int(header[4]))
		if err != nil {
			done <- err
			return
		}
		if _, err = read(2); err != nil {
			done <- err
			return
		}
		if string(host) != "never-resolve.invalid" {
			done <- errors.New("incorrect SOCKS destination")
			return
		}
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			done <- err
			return
		}
		if req.Header.Get("Proxy-Authorization") != "" {
			done <- errors.New("SOCKS credentials leaked as an HTTP header")
			return
		}
		body := `{"ip":"203.0.113.5"}`
		_, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		done <- err
	}()
	t.Setenv("SOCKS_PASSWORD", "SOCKS_SECRET")
	target := config.Target{ProbeProxy: "socks5h://" + listener.Addr().String(), ProbeUsername: "socks-user", ProbePasswordEnv: "SOCKS_PASSWORD"}
	result, err := IP(context.Background(), target, Options{IPURL: "http://never-resolve.invalid/geoip"})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.IP != "203.0.113.5" {
		t.Fatalf("result: %+v", result)
	}
}
