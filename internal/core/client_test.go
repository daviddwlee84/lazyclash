package core

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeClient(t *testing.T, handler http.HandlerFunc, options Options) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	options.Endpoint = server.URL
	client, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func requireKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *core.Error %s, got %v", want, err)
	}
	if apiErr.Kind != want {
		t.Fatalf("expected %s, got %s: %v", want, apiErr.Kind, err)
	}
}

func writeJSON(w http.ResponseWriter, object any) { _ = json.NewEncoder(w).Encode(object) }

func TestReadEndpointsAuthenticationAndUnknownFields(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer local-private-secret" {
			t.Error("missing bearer authentication")
		}
		switch r.URL.Path {
		case "/version":
			writeJSON(w, Object{"version": "test", "future": Object{"enabled": true}})
		case "/configs":
			writeJSON(w, Object{"mode": "rule", "tun": Object{"enable": false}})
		case "/proxies":
			writeJSON(w, Object{"proxies": Object{"DIRECT": Object{"type": "Direct", "future": 42}}})
		case "/connections":
			writeJSON(w, Object{"connections": []any{}, "uploadTotal": 123})
		case "/rules":
			writeJSON(w, Object{"rules": []any{Object{"type": "Match", "payload": "", "proxy": "DIRECT"}}})
		case "/providers/proxies", "/providers/rules":
			writeJSON(w, Object{"providers": Object{}})
		default:
			t.Errorf("unexpected URL: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}, Options{Secret: "local-private-secret"})
	ctx := context.Background()
	if got, err := client.Version(ctx); err != nil || got["version"] != "test" {
		t.Fatalf("version: %v %v", got, err)
	}
	if got, err := client.Config(ctx); err != nil || got["mode"] != "rule" {
		t.Fatalf("config: %v %v", got, err)
	}
	if got, err := client.Proxies(ctx); err != nil || got["DIRECT"].Name != "DIRECT" {
		t.Fatalf("proxies: %v %v", got, err)
	}
	if got, err := client.Connections(ctx); err != nil || got["uploadTotal"] != float64(123) {
		t.Fatalf("connections: %v %v", got, err)
	}
	if _, err := client.Rules(ctx); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"proxies", "rules"} {
		if _, err := client.Providers(ctx, kind); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Providers(ctx, "other"); err == nil {
		t.Fatal("accepted unknown provider kind")
	}
}

func TestSelectValidatesAndEscapesSinglePathSegment(t *testing.T) {
	group, member := "選擇/🇹🇼 %?&+雪", "節點/🚀"
	current := "DIRECT"
	var writes atomic.Int32
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path != "/proxies" {
				t.Errorf("unexpected read path: %s", r.URL.Path)
			}
			writeJSON(w, Object{"proxies": Object{group: Object{"type": "Selector", "all": []string{"DIRECT", member}, "now": current}}})
		case http.MethodPut:
			writes.Add(1)
			if want := "/proxies/" + url.PathEscape(group); r.URL.EscapedPath() != want {
				t.Errorf("escaped path = %s, want %s", r.URL.EscapedPath(), want)
			}
			if r.URL.RawQuery != "" {
				t.Error("proxy name became query")
			}
			var payload Object
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			current, _ = payload["name"].(string)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected request")
		}
	}, Options{})
	ctx := context.Background()
	if err := client.Select(ctx, group, member); err != nil {
		t.Fatal(err)
	}
	if current != member || writes.Load() != 1 {
		t.Fatal("selection was not applied exactly once")
	}
	for _, test := range [][2]string{{group, "missing"}, {"missing", member}} {
		requireKind(t, client.Select(ctx, test[0], test[1]), KindInvalid)
	}
	if writes.Load() != 1 {
		t.Fatal("validation failure performed a write")
	}
}

func TestSelectRejectsUnselectableAndReadbackMismatch(t *testing.T) {
	for _, proxyType := range []string{"LoadBalance", "Relay", "Selector"} {
		t.Run(proxyType, func(t *testing.T) {
			var writes atomic.Int32
			client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					writes.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				writeJSON(w, Object{"proxies": Object{"group": Object{"type": proxyType, "all": []string{"a", "b"}, "now": "a"}}})
			}, Options{})
			want := KindInvalid
			if proxyType == "Selector" {
				want = KindRejected
			}
			requireKind(t, client.Select(context.Background(), "group", "b"), want)
			if proxyType != "Selector" && writes.Load() != 0 {
				t.Error("wrote to unselectable group")
			}
		})
	}
}

func TestSetConfig204RequiresReadback(t *testing.T) {
	var enabled atomic.Bool
	var patches atomic.Int32
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, Object{"mode": "rule", "tun": Object{"enable": enabled.Load(), "device": "utun"}})
	}, Options{})
	got, err := client.SetConfig(context.Background(), Object{"tun": Object{"enable": true}})
	requireKind(t, err, KindRejected)
	if got["tun"].(map[string]any)["enable"] != false {
		t.Fatal("lost actual state after failed verification")
	}
	enabled.Store(true)
	if _, err := client.SetConfig(context.Background(), Object{"tun": Object{"enable": true}}); err != nil {
		t.Fatal(err)
	}
	if patches.Load() != 2 {
		t.Fatal("unexpected patch retry")
	}
}

func TestWriteReadbackFailureIsUnknown(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}, Options{})
	_, err := client.SetConfig(context.Background(), Object{"mode": "rule"})
	requireKind(t, err, KindUnknownWrite)
}

func TestApplyConfigForceAbsoluteCorePathAndNoRetryAfterTimeout(t *testing.T) {
	var writes atomic.Int32
	release := make(chan struct{})
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Error("unexpected request after ambiguous apply")
			return
		}
		writes.Add(1)
		if r.URL.Path != "/configs" || r.URL.Query().Get("force") != "true" {
			t.Errorf("incorrect apply URL: %s", r.URL)
		}
		var payload Object
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload["path"] != "/remote/core/config.yaml" {
			t.Errorf("wrong core-host path: %v", payload)
		}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}, Options{Timeout: 30 * time.Millisecond})
	defer close(release)
	if _, err := client.ApplyConfig(context.Background(), "relative.yaml"); err == nil {
		t.Fatal("relative path accepted")
	}
	_, err := client.ApplyConfig(context.Background(), "/remote/core/config.yaml")
	requireKind(t, err, KindUnknownWrite)
	if writes.Load() != 1 {
		t.Fatalf("write count: %d", writes.Load())
	}
}

func TestApplyConfigSuccessReadsRuntimeSettings(t *testing.T) {
	var writes atomic.Int32
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, Object{"mode": "global"})
	}, Options{})
	result, err := client.ApplyConfig(context.Background(), "/core/config.yaml")
	if err != nil || result["mode"] != "global" || writes.Load() != 1 {
		t.Fatalf("apply: %v %v", result, err)
	}
}

func TestReadOnlyBlocksEverySideEffectIncludingGETTests(t *testing.T) {
	var requests atomic.Int32
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1); writeJSON(w, Object{}) }, Options{ReadOnly: true})
	if !client.IsReadOnly() {
		t.Fatal("read-only flag not exposed")
	}
	ctx := context.Background()
	operations := []func() error{
		func() error { return client.Select(ctx, "group", "proxy") },
		func() error { _, err := client.Delay(ctx, "proxy"); return err },
		func() error { _, err := client.SetConfig(ctx, Object{"mode": "rule"}); return err },
		func() error { return client.CloseConnections(ctx, "") },
		func() error { return client.CloseConnections(ctx, "id") },
		func() error { return client.UpdateProvider(ctx, "proxies", "provider") },
		func() error { return client.UpdateProvider(ctx, "rules", "provider") },
		func() error { return client.HealthcheckProvider(ctx, "provider") },
		func() error { _, err := client.ApplyConfig(ctx, "/core/config.yaml"); return err },
	}
	for _, operation := range operations {
		requireKind(t, operation(), KindReadOnly)
	}
	if requests.Load() != 0 {
		t.Fatal("read-only operation reached controller")
	}
}

func TestRemainingMutationRoutesAndNoContent(t *testing.T) {
	var seen []string
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.EscapedPath())
		if strings.HasSuffix(r.URL.Path, "/delay") {
			if r.URL.Query().Get("timeout") != "2500" || r.URL.Query().Get("url") != "https://example.test/204" {
				t.Errorf("delay query: %s", r.URL.RawQuery)
			}
			writeJSON(w, Object{"delay": 42})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}, Options{DelayURL: "https://example.test/204", DelayTimeout: 2500 * time.Millisecond})
	ctx := context.Background()
	if _, err := client.Delay(ctx, "node/1"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseConnections(ctx, "conn/1"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseConnections(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProvider(ctx, "proxies", "provider/1"); err != nil {
		t.Fatal(err)
	}
	if err := client.UpdateProvider(ctx, "rules", "provider/1"); err != nil {
		t.Fatal(err)
	}
	if err := client.HealthcheckProvider(ctx, "provider/1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /proxies/node%2F1/delay", "DELETE /connections/conn%2F1", "DELETE /connections", "PUT /providers/proxies/provider%2F1", "PUT /providers/rules/provider%2F1", "GET /providers/proxies/provider%2F1/healthcheck"}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("routes: %v", seen)
	}
}

func TestHTTPErrorClassificationDoesNotLeakSecrets(t *testing.T) {
	for status, kind := range map[int]ErrorKind{401: KindAuth, 403: KindAuth, 404: KindUnsupported, 405: KindUnsupported, 501: KindUnsupported, 400: KindInvalid, 422: KindInvalid, 500: KindRejected} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("Bearer leaked-private-secret\x1b]52;c;payload\a"))
			}, Options{Secret: "leaked-private-secret"})
			_, err := client.Version(context.Background())
			requireKind(t, err, kind)
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "\x1b") {
				t.Fatalf("unsafe error: %q", err)
			}
		})
	}
}

func TestNeverFollowsRedirectsOrEnvironmentProxy(t *testing.T) {
	var leaked atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); writeJSON(w, Object{}) }))
	defer receiver.Close()
	t.Setenv("HTTP_PROXY", receiver.URL)
	t.Setenv("HTTPS_PROXY", receiver.URL)
	t.Setenv("ALL_PROXY", receiver.URL)
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, receiver.URL, http.StatusTemporaryRedirect)
	}, Options{Secret: "private-secret"})
	if client.transport.Proxy != nil {
		t.Fatal("transport uses an environment proxy")
	}
	_, err := client.Version(context.Background())
	requireKind(t, err, KindRejected)
	if leaked.Load() != 0 {
		t.Fatal("credentials were forwarded through redirect/proxy")
	}
}

func TestTLSAndCustomCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, Object{"version": "tls"}) }))
	defer server.Close()
	client, err := New(Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Version(context.Background())
	requireKind(t, err, KindTLS)
	certificate := server.Certificate()
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "controller-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	trusted, err := New(Options{Endpoint: server.URL, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	defer trusted.Close()
	if result, err := trusted.Version(context.Background()); err != nil || result["version"] != "tls" {
		t.Fatalf("custom CA: %v %v", result, err)
	}
}

func TestCustomDialPreservesControllerHostAndTLSName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:9443" {
			t.Errorf("changed controller host: %s", r.Host)
		}
		writeJSON(w, Object{"version": "ssh"})
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "controller-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	var dialedHost string
	client, err := New(Options{Endpoint: "https://example.com:9443", CAFile: caFile, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		dialedHost = address
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Version(context.Background()); err != nil {
		t.Fatal(err)
	}
	if dialedHost != "example.com:9443" {
		t.Fatalf("custom dial got %q", dialedHost)
	}
}

func TestUnixSocketController(t *testing.T) {
	// macOS limits sockaddr_un paths to 104 bytes, so use the short OS temp root.
	dir, err := os.MkdirTemp("/tmp", "lc-core-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "controller.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, Object{"version": "unix"}) })}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	client, err := New(Options{Endpoint: (&url.URL{Scheme: "unix", Path: socket}).String()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if result, err := client.Version(context.Background()); err != nil || result["version"] != "unix" {
		t.Fatalf("Unix socket: %v %v", result, err)
	}
}

func TestStreamHasNoWholeBodyDeadlineAndCancels(t *testing.T) {
	client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logs" || r.URL.Query().Get("level") != "debug" {
			t.Errorf("stream request: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, Object{"type": "info", "payload": "first"})
		w.(http.Flusher).Flush()
		select {
		case <-time.After(60 * time.Millisecond):
			writeJSON(w, Object{"type": "debug", "payload": "second"})
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
		<-r.Context().Done()
	}, Options{Timeout: 30 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var seen []Object
	err := client.Stream(ctx, "logs", url.Values{"level": {"debug"}}, func(object Object) {
		seen = append(seen, object)
		if len(seen) == 2 {
			cancel()
		}
	})
	if len(seen) != 2 {
		t.Fatalf("stream stopped at ordinary request timeout: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("stream cancellation: %v", err)
	}
}

func TestStreamDisconnectMalformedAndBoundedFrames(t *testing.T) {
	for _, test := range []struct {
		name, payload string
		kind          ErrorKind
	}{
		{"disconnect", "{\"up\":1,\"down\":2}\n", KindUnreachable},
		{"malformed", "not JSON\n", KindInvalid},
		{"null", "null\n", KindInvalid},
		{"bounded", strings.Repeat("a", maxStreamLineBytes+1), KindUnreachable},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, test.payload) }, Options{})
			err := client.Stream(context.Background(), "traffic", nil, func(Object) {})
			requireKind(t, err, test.kind)
		})
	}
}

func TestResponseSizeAndJSONBoundaries(t *testing.T) {
	for _, response := range []string{"[]", "null", "{}{}", strings.Repeat(" ", maxResponseBytes+1)} {
		client := fakeClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, response) }, Options{})
		_, err := client.Version(context.Background())
		requireKind(t, err, KindInvalid)
	}
}

func TestInvalidConnectionSettingsDoNotExposeCredentials(t *testing.T) {
	for _, endpoint := range []string{"http://user:private-secret@localhost:9090", "http://localhost:9090?token=private-secret", "http://localhost:9090#private-secret", "ftp://localhost", "http://", "unix://remote/tmp/api.sock", ":bad"} {
		_, err := New(Options{Endpoint: endpoint})
		requireKind(t, err, KindInvalid)
		if strings.Contains(err.Error(), "private-secret") {
			t.Error("endpoint credential leaked")
		}
	}
	_, err := New(Options{Endpoint: "http://localhost", Secret: "unsafe\nsecret"})
	requireKind(t, err, KindInvalid)
}

func TestSanitizeKeepsUnicodeAndRemovesTerminalSequences(t *testing.T) {
	for input, want := range map[string]string{
		"節點 🇹🇼 e\u0301":                                                "節點 🇹🇼 e\u0301",
		"\x1b[31mred\x1b[0m":                                           "red",
		"before\x1b]52;c;secret\aafter":                                "beforeafter",
		"before\x1b]8;;https://evil.test\x1b\\link\x1b]8;;\x1b\\after": "beforelinkafter",
		"a\x1bPpayload\x1b\\b":                                         "ab",
		"line\roverwrite\b!\x00\n\tend":                                "lineoverwrite!\n\tend",
		"safe\u202eevil":                                               "safeevil",
		"a\u009b31mb":                                                  "ab",
		"a\u009dtitle\u009cb":                                          "ab",
	} {
		if got := Sanitize(input); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDotProxyNamesCannotBecomeTraversalComponents(t *testing.T) {
	client, err := New(Options{Endpoint: "http://localhost:9090/controller"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for name, escaped := range map[string]string{".": "%2E", "..": "%2E%2E", "../node": "..%2Fnode"} {
		got := client.endpoint([]string{"proxies", name, "delay"}, nil)
		want := "http://localhost:9090/controller/proxies/" + escaped + "/delay"
		if got != want {
			t.Errorf("endpoint(%q) = %q, want %q", name, got, want)
		}
	}
}
