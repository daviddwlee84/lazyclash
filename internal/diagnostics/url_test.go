package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func fixtureHost(context.Context, string, HostRequest) (HostEvidence, error) {
	return HostEvidence{Protocol: 1, Scope: "local process", DNS: DNSResult{Source: "host native resolver", Addresses: []string{"203.0.113.7"}}, Requests: []RequestEvidence{}}, nil
}

func TestURLSeparateContextsPrivacyAndReadOnlyCoreOperations(t *testing.T) {
	var source string
	var mu sync.Mutex
	var writes, dns, delay, heads atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heads.Add(1)
		if r.Method != "HEAD" || r.URL.RawQuery != "token=PRIVATE_QUERY" {
			t.Errorf("wrong destination request %s", r.Method)
		}
		mu.Lock()
		source = r.RemoteAddr
		mu.Unlock()
		time.Sleep(600 * time.Millisecond)
		w.WriteHeader(403)
	}))
	defer proxy.Close()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes.Add(1)
			w.WriteHeader(500)
			return
		}
		switch r.URL.Path {
		case "/version":
			fmt.Fprint(w, `{"version":"test"}`)
		case "/configs":
			fmt.Fprint(w, `{"mode":"rule","tun":{"enable":true},"secret":"PRIVATE_SECRET"}`)
		case "/proxies":
			fmt.Fprint(w, `{"proxies":{"DIRECT":{"type":"Direct"},"Chosen":{"type":"Selector","all":["Leaf"],"now":"Leaf"},"Leaf":{"type":"Shadowsocks"}}}`)
		case "/dns/query":
			dns.Add(1)
			fmt.Fprint(w, `{"Answer":[{"data":"198.18.0.2"}]}`)
		case "/proxies/DIRECT/delay":
			delay.Add(1)
			w.WriteHeader(504)
		case "/proxies/Leaf/delay":
			delay.Add(1)
			if !strings.Contains(r.URL.Query().Get("url"), "PRIVATE_QUERY") {
				t.Error("URLTest destination query lost")
			}
			fmt.Fprint(w, `{"delay":12}`)
		case "/proxies/Chosen/delay":
			t.Error("tested group instead of selected leaf")
			w.WriteHeader(500)
		case "/connections":
			mu.Lock()
			tuple := source
			mu.Unlock()
			if tuple == "" {
				fmt.Fprint(w, `{"connections":[]}`)
				return
			}
			ip, port, _ := net.SplitHostPort(tuple)
			fmt.Fprintf(w, `{"connections":[{"id":"matching","metadata":{"host":"diagnostic.invalid","sourceIP":%q,"sourcePort":%q,"destinationIP":"203.0.113.7","destinationPort":"80"},"rule":"Domain","rulePayload":"diagnostic.invalid","chains":["Leaf","Chosen"]}]}`, ip, port)
		case "/logs":
			w.Header().Set("Content-Type", "application/x-ndjson")
			fmt.Fprintln(w, `{"type":"debug","payload":"diagnostic.invalid/path?token=PRIVATE_QUERY password=PRIVATE_SECRET"}`)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer controller.Close()
	opts := URLOptions{Via: "Chosen", HostCollector: fixtureHost, Options: Options{Open: func(_ context.Context, _ config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if readOnly {
			t.Error("active diagnostics got readonly client")
		}
		client, err := core.New(core.Options{Endpoint: controller.URL})
		return client, nil, err
	}}}
	result, err := RunURL(context.Background(), config.Target{ID: "fixture", Controller: controller.URL, ProbeProxy: proxy.URL}, "http://diagnostic.invalid/path?token=PRIVATE_QUERY", opts)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(FormatURL(result), "PRIVATE") {
		t.Fatalf("private content leaked: %s", encoded)
	}
	if result.ExplicitProxy.HTTPStatus != 403 || result.ExplicitProxy.Status != "http-response" {
		t.Fatalf("HTTP status treated as network timeout: %+v", result.ExplicitProxy)
	}
	if writes.Load() != 0 || dns.Load() != 2 || delay.Load() != 2 || heads.Load() != 1 {
		t.Fatalf("writes=%d DNS=%d delay=%d HEAD=%d", writes.Load(), dns.Load(), delay.Load(), heads.Load())
	}
	if result.Recommendation != nil {
		t.Fatalf("recommended a rule for an already observed proxied route: %+v", result.Recommendation)
	}
	if len(result.Connections) != 1 || result.Connections[0].Confidence != "observed" || len(result.Connections[0].Chains) != 2 {
		t.Fatalf("connections: %+v", result.Connections)
	}
	if len(result.Logs) != 1 || result.Logs[0].Confidence != "unknown" {
		t.Fatalf("logs: %+v", result.Logs)
	}
	if result.Core.DNS[0].Addresses[0] == result.Local.DNS.Addresses[0] {
		t.Fatal("resolver contexts were merged")
	}
}

func TestDomainRecommendationsRequireRuleModeAndCorePathEvidence(t *testing.T) {
	base := URLResult{Host: "Example.invalid", Core: CoreEvidence{Mode: "rule", Outbounds: []OutboundEvidence{{Policy: "DIRECT", Leaf: "DIRECT", Status: "failed"}, {Policy: "Chosen", Leaf: "Node", Status: "response-sample"}}}}
	proxies := map[string]core.Proxy{"Chosen": {Name: "Chosen"}}
	for _, tc := range []struct {
		name       string
		mode       string
		connection *ConnectionEvidence
		noProxy    bool
		want       bool
	}{
		{name: "failed dials need no flow", mode: "rule", want: true},
		{name: "global", mode: "global"},
		{name: "direct mode", mode: "direct"},
		{name: "unknown mode"},
		{name: "already proxied", mode: "rule", connection: &ConnectionEvidence{Confidence: "observed", Chains: []string{"Node", "Chosen"}}},
		{name: "observed DIRECT", mode: "rule", connection: &ConnectionEvidence{Confidence: "observed", Chains: []string{"DIRECT"}}, want: true},
		{name: "unknown old route", mode: "rule", connection: &ConnectionEvidence{Confidence: "unknown", Chains: []string{"Node", "Chosen"}}, want: true},
		{name: "no proxy caveat", mode: "rule", noProxy: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			r.Core.Mode = tc.mode
			r.Local.Environment.NoProxyMatches = tc.noProxy
			if tc.connection != nil {
				r.Connections = []ConnectionEvidence{*tc.connection}
			}
			got := recommendDomain(r, "Chosen", proxies)
			if (got != nil) != tc.want {
				t.Fatalf("recommendation=%+v", got)
			}
			if got != nil && (got.Rule != "DOMAIN,example.invalid,Chosen" || got.Confidence != "tentative" || !strings.Contains(got.Reason, "core paths only") || tc.noProxy && !strings.Contains(got.Reason, "NO_PROXY")) {
				t.Fatalf("unsafe recommendation=%+v", got)
			}
		})
	}
	base.Core.Outbounds[1].Leaf = "DIRECT"
	if got := recommendDomain(base, "Chosen", proxies); got != nil {
		t.Fatalf("recommended a group resolving to DIRECT: %+v", got)
	}
}

func TestURLObserveOnlyNeverRunsActiveRequests(t *testing.T) {
	var active atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			fmt.Fprint(w, `{"version":"test"}`)
		case "/configs":
			fmt.Fprint(w, `{"mode":"rule"}`)
		case "/proxies":
			fmt.Fprint(w, `{"proxies":{}}`)
		case "/connections":
			fmt.Fprint(w, `{"connections":[]}`)
		default:
			active.Add(1)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	opts := URLOptions{ObserveOnly: true, Options: Options{ReadOnly: true, Open: func(_ context.Context, _ config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if !readOnly {
			t.Error("observe-only opened writable client")
		}
		client, err := core.New(core.Options{Endpoint: server.URL, ReadOnly: readOnly})
		return client, nil, err
	}}, HostCollector: func(ctx context.Context, host string, req HostRequest) (HostEvidence, error) {
		if !req.ObserveOnly {
			t.Error("host helper active")
		}
		return fixtureHost(ctx, host, req)
	}}
	result, err := RunURL(context.Background(), config.Target{Controller: server.URL, ProbeProxy: server.URL}, "https://example.invalid/", opts)
	if err != nil || active.Load() != 0 || len(result.Core.DNS) != 0 || len(result.Core.Outbounds) != 0 || result.ExplicitProxy.Status != "not-run" {
		t.Fatalf("observe-only=%+v error=%v active=%d", result, err, active.Load())
	}
	opts.ObserveOnly = false
	if _, err := RunURL(context.Background(), config.Target{}, "https://example.invalid/", opts); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only active request: %v", err)
	}
}

func TestURLControllerOfflineDoesNotBlockExplicitDataProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer proxy.Close()
	opts := URLOptions{HostCollector: fixtureHost, Options: Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, errors.New("PRIVATE controller error")
	}}}
	result, err := RunURL(context.Background(), config.Target{ProbeProxy: proxy.URL}, "http://example.invalid/?token=PRIVATE", opts)
	if err != nil || result.Core.Available || result.ExplicitProxy.Status != "http-response" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "PRIVATE") {
		t.Fatal("leaked offline error/query")
	}
}

func TestURLValidationAndCancellation(t *testing.T) {
	for _, endpoint := range []string{"ftp://example.com/", "https://alice:PRIVATE@example.com/", "https://example.com/#PRIVATE", "https://example.com:99999/", "https://example.com/\nPRIVATE", "https://例子.測試/"} {
		_, err := RunURL(context.Background(), config.Target{}, endpoint, URLOptions{})
		if err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("unsafe URL %q accepted/leaked: %v", endpoint, err)
		}
	}
	opts := URLOptions{Timeout: 30 * time.Millisecond, HostCollector: func(ctx context.Context, _ string, _ HostRequest) (HostEvidence, error) {
		<-ctx.Done()
		return HostEvidence{}, ctx.Err()
	}, Options: Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, errors.New("offline")
	}}}
	_, err := RunURL(context.Background(), config.Target{}, "https://example.invalid/", opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline lost: %v", err)
	}
	for _, opts := range []URLOptions{{ReferenceDoH: "http://dns.invalid/query"}, {ReferenceDoH: "https://dns.invalid/query?token=PRIVATE"}, {ReferenceDoH: "https://dns.invalid/query", ObserveOnly: true}} {
		if _, err := RunURL(context.Background(), config.Target{ProbeProxy: "http://localhost:7890"}, "https://example.invalid/", opts); err == nil {
			t.Fatal("unsafe/active reference DoH accepted")
		}
	}
}

func TestURLCorrelationDoesNotOverstateSSHOrAmbiguousEvidence(t *testing.T) {
	now := time.Now()
	capture := &urlCapture{connections: map[string]capturedConnection{"new": {evidence: ConnectionEvidence{ID: "new", SourceAddress: "127.0.0.1:1234", Host: "example.invalid"}, firstSeen: now}}}
	request := RequestEvidence{Source: "explicit data proxy", LocalAddress: "127.0.0.1:1234", StartedAt: now.Add(-time.Second), FinishedAt: now.Add(time.Second)}
	result := URLResult{ExplicitProxy: request}
	got, _ := correlateURL(capture, result, true)
	if got[0].Confidence != "probable" {
		t.Fatalf("SSH tuple overclaimed: %+v", got)
	}
	result.Local.Requests = []RequestEvidence{request}
	got, _ = correlateURL(capture, result, true)
	if got[0].Confidence != "unknown" {
		t.Fatalf("ambiguous request overclaimed: %+v", got)
	}
	entry := capture.connections["new"]
	entry.baseline = true
	capture.connections["new"] = entry
	got, _ = correlateURL(capture, URLResult{ExplicitProxy: request}, false)
	if got[0].Confidence != "unknown" {
		t.Fatalf("baseline connection claimed as request: %+v", got)
	}
	entry.baseline = false
	capture.connections["new"] = entry
	second := entry
	second.evidence.ID = "other"
	capture.connections["other"] = second
	got, _ = correlateURL(capture, URLResult{ExplicitProxy: request}, true)
	if len(got) != 2 || got[0].Confidence != "unknown" || got[1].Confidence != "unknown" {
		t.Fatalf("multiple connections claimed as unique: %+v", got)
	}
}

func TestURLRequestPhasesAreSerializedAndCollectorErrorsRecorded(t *testing.T) {
	var active, peak atomic.Int32
	var order []string
	var mu sync.Mutex
	opts := URLOptions{Options: Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, errors.New("offline")
	}}, HostCollector: func(ctx context.Context, host string, req HostRequest) (HostEvidence, error) {
		if !req.RequestOnly {
			return HostEvidence{}, errors.New("PRIVATE helper error")
		}
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		mu.Lock()
		order = append(order, host+"/"+req.RequestKind)
		mu.Unlock()
		time.Sleep(time.Millisecond)
		return HostEvidence{Requests: []RequestEvidence{{Source: req.RequestKind, Status: "failed"}}}, nil
	}}
	result, err := RunURL(context.Background(), config.Target{SSHHost: "remote"}, "https://example.invalid/", opts)
	if err != nil || peak.Load() != 1 || len(order) != 4 {
		t.Fatalf("request phases overlapped: %v peak=%d err=%v", order, peak.Load(), err)
	}
	if result.Local.Error == "" || result.Remote == nil || result.Remote.Error == "" {
		t.Fatalf("collector errors lost: %+v", result)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "PRIVATE") {
		t.Fatal("collector raw error leaked")
	}
	if !strings.Contains(FormatURL(result), "TUN=unknown") {
		t.Fatal("missing TUN value treated as false")
	}
}

func TestTopologyUsesStrongestDeterministicEvidence(t *testing.T) {
	r := URLResult{Host: "example.invalid", Connections: []ConnectionEvidence{{ID: "a", Confidence: "probable", Rule: "weaker"}, {ID: "z", Confidence: "observed", Rule: "strong", InboundType: "Tun", Network: "tcp"}}}
	for _, nodes := range [][]ConnectionEvidence{r.Connections, {r.Connections[1], r.Connections[0]}} {
		r.Connections = nodes
		topology := urlTopology(config.Target{}, r)
		data, _ := json.Marshal(topology)
		if strings.Contains(string(data), "weaker") || !strings.Contains(string(data), "strong") || !strings.Contains(string(data), "Tun tcp") {
			t.Fatalf("wrong route chosen: %s", data)
		}
	}
	r.Connections = nil
	topology := urlTopology(config.Target{}, r)
	data, _ := json.Marshal(topology)
	if !strings.Contains(string(data), "route unknown") {
		t.Fatalf("missing unknown route: %s", data)
	}
}
