package diagnostics

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// The production client/transport run on in-memory sockets and a virtual clock:
// a six-second response proves removal of the old five-second cap without a
// six-second wall-clock sleep or any request to an external site.
func TestSavedCheckHTTPUsesOuterBudgetWhileURLDiagnosisKeepsFiveSeconds(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		deadlineOnly               bool
		responseAfter, wantElapsed time.Duration
		wantResponse               bool
	}{
		{"saved-check-six-second-response", true, 6 * time.Second, 6 * time.Second, true},
		{"ordinary-url-keeps-five-second-cap", false, 6 * time.Second, 5 * time.Second, false},
		{"saved-check-stops-at-outer-deadline", true, 9 * time.Second, 8 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				client, p, err := newURLProbe(ctx, config.Target{ProbeProxy: "http://proxy.invalid:7890"}, Options{}, tc.deadlineOnly)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				if tc.deadlineOnly {
					if client.Timeout != 0 || p.transport.TLSHandshakeTimeout != 0 || p.transport.ResponseHeaderTimeout != 0 {
						t.Fatal("an inner HTTP/TLS/header timer can still truncate the outer check budget")
					}
				} else if client.Timeout != 5*time.Second || p.transport.TLSHandshakeTimeout != 5*time.Second || p.transport.ResponseHeaderTimeout != 8*time.Second {
					t.Fatal("ordinary URL diagnostics changed their existing bounds")
				}
				serverDone := make(chan struct{})
				p.transport.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
					if network != "tcp" || address != "proxy.invalid:7890" {
						t.Fatalf("unexpected data route: %s %s", network, address)
					}
					local, peer := net.Pipe()
					go func() {
						defer close(serverDone)
						defer peer.Close()
						request, err := http.ReadRequest(bufio.NewReader(peer))
						if err != nil {
							t.Error(err)
							return
						}
						request.Body.Close()
						if request.Method != http.MethodHead || request.URL.Host != "service.invalid" {
							t.Error("unexpected proxy request")
						}
						time.Sleep(tc.responseAfter)
						fmt.Fprint(peer, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
					}()
					return local, nil
				}
				request, _ := http.NewRequestWithContext(ctx, http.MethodHead, "http://service.invalid/", nil)
				started := time.Now()
				response, err := client.Do(request)
				defer func() { <-serverDone }()
				if response != nil {
					response.Body.Close()
				}
				if (err == nil) != tc.wantResponse || time.Since(started) != tc.wantElapsed {
					t.Fatalf("response=%v error=%v elapsed=%s, want response=%v elapsed=%s", response, err, time.Since(started), tc.wantResponse, tc.wantElapsed)
				}
				if !tc.wantResponse && !requestTimedOut(ctx, err) {
					t.Fatal("timeout lost its classification", err)
				}
			})
		})
	}
}

func TestSavedCheckHTTPRequiresABoundedContextBeforeOpeningTunnel(t *testing.T) {
	opts := Options{OpenTunnel: func(context.Context, string, string) (string, io.Closer, error) {
		t.Fatal("unbounded check opened its data proxy")
		return "", nil, nil
	}}
	_, _, err := newURLProbe(context.Background(), config.Target{SSHHost: "fixture", ProbeProxy: "http://proxy.invalid:7890"}, opts, true)
	if err == nil || !strings.Contains(err.Error(), "bounded context") {
		t.Fatal("unbounded saved-check request accepted", err)
	}
}

func TestSavedCheckRequestTimeoutKeepsEndpointAvailabilityUnknown(t *testing.T) {
	for _, setupTimeout := range []bool{false, true} {
		t.Run(fmt.Sprint(setupTimeout), func(t *testing.T) {
			var requests, closed atomic.Int32
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				<-r.Context().Done()
			}))
			defer proxy.Close()
			opts := CheckOptions{Timeout: 200 * time.Millisecond, Options: Options{
				Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
					return nil, nil, errors.New("fixture controller offline")
				},
				OpenTunnel: func(ctx context.Context, _, _ string) (string, io.Closer, error) {
					if setupTimeout {
						<-ctx.Done()
						return "", nil, ctx.Err()
					}
					select {
					case <-time.After(50 * time.Millisecond):
					case <-ctx.Done():
						return "", nil, ctx.Err()
					}
					return strings.TrimPrefix(proxy.URL, "http://"), closeFunc(func() error { closed.Add(1); return nil }), nil
				},
			}}
			parent, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			report, err := RunChecks(parent, config.Target{SSHHost: "fixture", ProbeProxy: proxy.URL}, []config.DiagnosticCheck{{ID: "site", URL: "http://service.invalid/"}}, opts)
			if !errors.Is(err, ErrPartial) || report.Canceled || len(report.Checks) != 1 {
				t.Fatalf("request deadline became batch cancellation: %+v %v", report, err)
			}
			result := report.Checks[0]
			if result.Status != "request-timeout" || result.Request.Status != "timeout" || result.TransportReachable || result.ExpectedStatusMatched != nil || result.Request.HTTPStatus != 0 {
				t.Fatal("timeout became a down/reachable/HTTP-status claim", result)
			}
			if !strings.Contains(result.Request.Error, "availability remains unknown") || !strings.Contains(FormatChecks(report), "[request-timeout]: transport unconfirmed") {
				t.Fatal("timeout evidence was not clear", FormatChecks(report))
			}
			if setupTimeout {
				if requests.Load() != 0 || closed.Load() != 0 || !strings.Contains(result.Request.Error, "proxy setup") {
					t.Fatal("setup timeout attempted an HTTP request")
				}
			} else if requests.Load() != 1 || closed.Load() != 1 || !strings.Contains(result.Request.Error, "response headers") {
				t.Fatal("HTTP deadline leaked a tunnel or discarded phase evidence", requests.Load(), closed.Load())
			}
		})
	}
}
