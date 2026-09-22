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

func TestSavedChecksSingleSequentialHEADAndObservedRoute(t *testing.T) {
	var heads, writes, active, maxActive, compares atomic.Int32
	var mu sync.Mutex
	source, path := "", ""
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heads.Add(1)
		n := active.Add(1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		defer active.Add(-1)
		if r.Method != "HEAD" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("check sent application credentials or was not HEAD")
		}
		mu.Lock()
		source, path = r.RemoteAddr, r.URL.Path
		mu.Unlock()
		defer func() { mu.Lock(); source = ""; mu.Unlock() }()
		time.Sleep(220 * time.Millisecond)
		switch r.URL.Path {
		case "/api":
			w.WriteHeader(404)
		case "/redirect":
			w.Header().Set("Location", "http://must-not-follow.invalid/")
			w.WriteHeader(302)
		case "/bad":
			w.WriteHeader(503)
		default:
			w.WriteHeader(200)
		}
	}))
	defer proxy.Close()
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			writes.Add(1)
			w.WriteHeader(500)
			return
		}
		switch r.URL.Path {
		case "/configs":
			fmt.Fprint(w, `{"mode":"rule","tun":{"enable":false}}`)
		case "/proxies":
			fmt.Fprint(w, `{"proxies":{"Compare":{"type":"Selector","all":["Alternative"],"now":"Alternative"},"Alternative":{"type":"Shadowsocks"}}}`)
		case "/proxies/Alternative/delay":
			compares.Add(1)
			fmt.Fprint(w, `{"delay":9}`)
		case "/connections":
			mu.Lock()
			s, p := source, path
			mu.Unlock()
			if s == "" {
				fmt.Fprint(w, `{"connections":[]}`)
				return
			}
			ip, port, _ := net.SplitHostPort(s)
			fmt.Fprintf(w, `{"connections":[{"id":%q,"metadata":{"host":"service.invalid","sourceIP":%q,"sourcePort":%q,"destinationIP":"192.0.2.1","destinationPort":"80"},"rule":"DomainSuffix","rulePayload":"service.invalid","chains":["Oracle node","PROXY"]}]}`, p, ip, port)
		default:
			t.Errorf("unexpected context probe: %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer controller.Close()
	opened := 0
	opts := CheckOptions{Options: Options{Open: func(_ context.Context, _ config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		opened++
		if readOnly {
			t.Error("optional URLTest requires active client")
		}
		c, e := core.New(core.Options{Endpoint: controller.URL})
		return c, nil, e
	}}}
	checks := []config.DiagnosticCheck{{ID: "api", URL: "http://service.invalid/api", ExpectedStatuses: []int{404}}, {ID: "web", URL: "http://service.invalid/", Via: "Compare"}, {ID: "redirect", URL: "http://service.invalid/redirect"}, {ID: "bad", URL: "http://service.invalid/bad"}}
	report, err := RunChecks(context.Background(), config.Target{ID: "target", Controller: controller.URL, ProbeProxy: proxy.URL}, checks, opts)
	if !errors.Is(err, ErrPartial) || report.Completed != 4 || report.Passed != 3 || opened != 1 || heads.Load() != 4 || maxActive.Load() != 1 || writes.Load() != 0 || compares.Load() != 1 {
		t.Fatalf("checks repeated contexts, mutated settings or wrong summary: %+v err=%v opens=%d heads=%d concurrency=%d writes=%d compares=%d", report, err, opened, heads.Load(), maxActive.Load(), writes.Load(), compares.Load())
	}
	for i, r := range report.Checks {
		if !r.TransportReachable || r.ExpectedStatusMatched == nil || (*r.ExpectedStatusMatched != (i != 3)) || r.ApplicationAccess != "not-tested" || r.Route.Status != "observed" || r.Route.Rule != "DomainSuffix" || len(r.Route.Chains) != 2 || r.Route.Chains[0] != "Oracle node" {
			t.Fatalf("check evidence incorrect: %+v", r)
		}
	}
	if report.Checks[1].PolicyComparison.Leaf != "Alternative" || report.Checks[1].Route.Chains[0] == "Alternative" {
		t.Fatal("policy comparison replaced the observed request route")
	}
	if !strings.Contains(FormatChecks(report), "core chain (leaf first)") || !strings.Contains(FormatChecks(report), "Authentication / application access: not tested") {
		t.Fatal("human evidence labels missing")
	}
}

func TestSavedChecksReadOnlyValidationAndNoDirectFallback(t *testing.T) {
	var calls atomic.Int32
	opts := CheckOptions{Options: Options{ReadOnly: true, Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		calls.Add(1)
		return nil, nil, nil
	}}}
	check := []config.DiagnosticCheck{{ID: "a", URL: "http://example.invalid/"}}
	if _, err := RunChecks(context.Background(), config.Target{}, check, opts); !errors.Is(err, ErrReadOnly) || calls.Load() != 0 {
		t.Fatal("read-only active checks contacted the target")
	}
	opts.ReadOnly = false
	if _, err := RunChecks(context.Background(), config.Target{}, check, opts); !errors.Is(err, ErrNoProxy) || calls.Load() != 0 {
		t.Fatal("missing data proxy opened controller")
	}
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	proxy := httptest.NewServer(http.NotFoundHandler())
	endpoint := proxy.URL
	proxy.Close()
	opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, errors.New("private-controller-error")
	}
	r, err := RunChecks(context.Background(), config.Target{ProbeProxy: endpoint}, []config.DiagnosticCheck{{ID: "offline", URL: destination.URL}}, opts)
	if !errors.Is(err, ErrPartial) || calls.Load() != 0 || r.Checks[0].TransportReachable || r.Checks[0].ExpectedStatusMatched != nil {
		t.Fatalf("failed proxy fell back or fabricated status: %+v %v", r, err)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "private-controller-error") {
		t.Fatal("raw controller failure leaked")
	}
}

func TestSavedChecksCancellationRetainsPartialResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var heads atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { heads.Add(1); cancel(); <-r.Context().Done() }))
	defer proxy.Close()
	opts := CheckOptions{Options: Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, errors.New("offline")
	}}}
	r, err := RunChecks(ctx, config.Target{ProbeProxy: proxy.URL}, []config.DiagnosticCheck{{ID: "first", URL: "http://service.invalid/"}, {ID: "second", URL: "http://service.invalid/"}}, opts)
	if !errors.Is(err, context.Canceled) || !r.Canceled || len(r.Checks) != 2 || r.Checks[0].Status != "canceled" || r.Checks[1].Status != "not-run" || heads.Load() != 1 {
		t.Fatalf("cancellation lost results or ran remaining check: %+v %v heads=%d", r, err, heads.Load())
	}
}

func TestSavedChecksRouteRequiresUniqueExactObservation(t *testing.T) {
	base := ConnectionEvidence{Confidence: "observed", RequestSource: "explicit data proxy", Rule: "Domain", Chains: []string{"node", "PROXY"}}
	if got := observedCheckRoute([]ConnectionEvidence{base}); got.Status != "observed" {
		t.Fatal("exact observed route lost")
	}
	for _, confidence := range []string{"probable", "unknown"} {
		x := base
		x.Confidence = confidence
		if got := observedCheckRoute([]ConnectionEvidence{x}); got.Status != "unknown" || got.Rule != "" || len(got.Chains) != 0 {
			t.Fatal("host/time or SSH guess promoted to observed route")
		}
	}
	if got := observedCheckRoute([]ConnectionEvidence{base, base}); got.Status != "unknown" {
		t.Fatal("ambiguous exact observations promoted")
	}
}

func TestSavedChecksProbableRoutingIsVisibleWithoutBecomingObserved(t *testing.T) {
	event := ConnectionEvidence{Confidence: "probable", RequestSource: "explicit data proxy", Rule: "DomainSuffix", RulePayload: "anthropic.com", Chains: []string{"Oracle node", "PROXY"}}
	r := CheckReport{Checks: []CheckResult{{ID: "api", Route: observedCheckRoute([]ConnectionEvidence{event}), Connections: []ConnectionEvidence{event}}}}
	text := FormatChecks(r)
	if r.Checks[0].Route.Status != "unknown" || !strings.Contains(text, "Possible connection (not confirmed for this probe)") || strings.Contains(text, "Observed rule:") {
		t.Fatalf("probable routing hidden or promoted: %s", text)
	}
	r.Checks[0].Connections = append(r.Checks[0].Connections, event)
	text = FormatChecks(r)
	if strings.Contains(text, "Possible connection") || !strings.Contains(text, "2 matching-host core connections") {
		t.Fatalf("ambiguous candidate promoted: %s", text)
	}
}

func TestSavedChecksTransportBudgetDefaultsAndExplicitOverride(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer proxy.Close()
	for _, tc := range []struct {
		name, ssh      string
		override, want time.Duration
	}{
		{name: "local-default", want: 10 * time.Second},
		{name: "ssh-default", ssh: "fixture-ssh", want: 30 * time.Second},
		{name: "ssh-explicit", ssh: "fixture-ssh", override: 2 * time.Second, want: 2 * time.Second},
		{name: "local-explicit", override: 2 * time.Second, want: 2 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnelCalls := 0
			assertDeadline := func(ctx context.Context, want time.Duration) {
				t.Helper()
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > want || remaining < want-time.Second {
					t.Fatalf("deadline budget=%s, want near %s (present=%v)", remaining, want, ok)
				}
			}
			opts := CheckOptions{Timeout: tc.override, Options: Options{
				Open: func(ctx context.Context, _ config.Target, _ bool) (*core.Client, io.Closer, error) {
					assertDeadline(ctx, tc.want+15*time.Second)
					return nil, nil, errors.New("fixture controller offline")
				},
				OpenTunnel: func(ctx context.Context, host, endpoint string) (string, io.Closer, error) {
					tunnelCalls++
					if host != tc.ssh || endpoint != proxy.URL {
						t.Fatal("tunnel scope changed")
					}
					assertDeadline(ctx, tc.want)
					return strings.TrimPrefix(proxy.URL, "http://"), nil, nil
				},
			}}
			report, err := RunChecks(context.Background(), config.Target{ID: "fixture", ProbeProxy: proxy.URL, SSHHost: tc.ssh}, []config.DiagnosticCheck{{ID: "website", URL: "http://service.invalid/"}}, opts)
			if err != nil || report.Passed != 1 || report.Checks[0].Request.HTTPStatus != 204 || (tunnelCalls == 1) != (tc.ssh != "") {
				t.Fatalf("budget changed the actual request route/result: %+v %v (tunnels=%d)", report, err, tunnelCalls)
			}
		})
	}
}

func TestSavedChecksSSHBudgetStillHonorsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	opts := CheckOptions{Options: Options{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			return nil, nil, errors.New("fixture controller offline")
		},
		OpenTunnel: func(checkCtx context.Context, _, _ string) (string, io.Closer, error) {
			deadline, ok := checkCtx.Deadline()
			if !ok || !deadline.Equal(parentDeadline) {
				t.Fatal("SSH default extended its parent's deadline")
			}
			cancel()
			<-checkCtx.Done()
			return "", nil, checkCtx.Err()
		},
	}}
	report, err := RunChecks(ctx, config.Target{ProbeProxy: "http://127.0.0.1:7890", SSHHost: "fixture-ssh"}, []config.DiagnosticCheck{{ID: "first", URL: "http://service.invalid/", Via: "Compare"}, {ID: "second", URL: "http://service.invalid/"}}, opts)
	if !errors.Is(err, context.Canceled) || !report.Canceled || report.Checks[0].Status != "canceled" || report.Checks[1].Status != "not-run" {
		t.Fatalf("parent cancellation was replaced by a comparison timeout: %+v %v", report, err)
	}
}

func TestSavedChecksComparisonTimeoutRetainsSuccessfulHTTP(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer proxy.Close()
	var comparisons atomic.Int32
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/configs":
			fmt.Fprint(w, `{"mode":"rule"}`)
		case "/proxies":
			fmt.Fprint(w, `{"proxies":{"Compare":{"type":"Selector","all":["Alternative"],"now":"Alternative"},"Alternative":{"type":"Shadowsocks"}}}`)
		case "/connections":
			fmt.Fprint(w, `{"connections":[]}`)
		case "/proxies/Alternative/delay":
			comparisons.Add(1)
			<-r.Context().Done()
		default:
			t.Errorf("unexpected controller request: %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer controller.Close()
	opts := CheckOptions{Timeout: 500 * time.Millisecond, Options: Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		client, err := core.New(core.Options{Endpoint: controller.URL})
		return client, nil, err
	}}}
	report, err := RunChecks(context.Background(), config.Target{ProbeProxy: proxy.URL}, []config.DiagnosticCheck{{ID: "api", URL: "http://service.invalid/", ExpectedStatuses: []int{404}, Via: "Compare"}}, opts)
	result := report.Checks[0]
	if !errors.Is(err, ErrPartial) || report.Canceled || result.Status != "comparison-timeout" || !result.TransportReachable || result.ExpectedStatusMatched == nil || !*result.ExpectedStatusMatched || result.Request.Status != "http-response" || result.Request.HTTPStatus != 404 || comparisons.Load() != 1 {
		t.Fatalf("comparison timeout obscured the successful HTTP response: %+v %v", report, err)
	}
	if result.PolicyComparison == nil || result.PolicyComparison.Status != "timeout" || !strings.Contains(result.PolicyComparison.Error, "HTTP result is retained") {
		t.Fatal("comparison deadline evidence missing", result.PolicyComparison)
	}
	text := FormatChecks(report)
	if !strings.Contains(text, "[comparison-timeout]: transport reachable · HTTP 404 (matched)") || !strings.Contains(text, "HTTP result is retained") {
		t.Fatal("human output mislabels successful HTTP as network failure", text)
	}
}
