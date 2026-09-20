package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func TestConnectivityAlwaysReadOnlyAndChecksConfigAccess(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(fmt.Sprint(denied), func(t *testing.T) {
			var configReads, closed atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("diagnostic write: %s", r.Method)
					w.WriteHeader(500)
					return
				}
				switch r.URL.Path {
				case "/version":
					fmt.Fprint(w, `{"version":"v1.19.29"}`)
				case "/configs":
					configReads.Add(1)
					if denied {
						w.WriteHeader(403)
					} else {
						fmt.Fprint(w, `{"mode":"rule","secret":"never-return-config-body"}`)
					}
				default:
					t.Errorf("unexpected resource %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			opts := Options{Open: func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
				if !readOnly {
					t.Error("connectivity opened a writable core client")
				}
				client, closer, err := connection.Open(ctx, target, readOnly)
				if err != nil {
					return nil, nil, err
				}
				return client, closeFunc(func() error { closed.Add(1); return closer.Close() }), nil
			}}
			result, err := Test(context.Background(), config.Target{ID: "test", Controller: server.URL}, opts)
			if (err != nil) != denied || !result.Connected || result.ConfigsReadable == denied || result.Version != "v1.19.29" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if configReads.Load() != 1 || closed.Load() != 1 {
				t.Fatalf("reads=%d closes=%d", configReads.Load(), closed.Load())
			}
		})
	}
}

func TestAuthHandoffPreservesTypedError(t *testing.T) {
	auth := &connection.AuthRequiredError{Host: "my-alias"}
	opts := Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) { return nil, nil, auth }, OpenTunnel: func(context.Context, string, string) (string, io.Closer, error) { return "", nil, auth }}
	target := config.Target{Controller: "http://localhost:9090", ProbeProxy: "http://localhost:7890", SSHHost: "my-alias"}
	if _, err := Test(context.Background(), target, opts); !errors.Is(err, auth) || !connection.IsAuthRequired(err) {
		t.Fatalf("controller auth: %v", err)
	}
	if _, err := IP(context.Background(), target, opts); !errors.Is(err, auth) || !connection.IsAuthRequired(err) {
		t.Fatalf("proxy auth: %v", err)
	}
}

func TestConnectivityClosesClientWithoutTransportCloser(t *testing.T) {
	closed := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"version":"test"}`)
		} else {
			fmt.Fprint(w, `{}`)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	opts := Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		client, err := core.New(core.Options{Endpoint: server.URL, ReadOnly: true})
		return client, nil, err
	}}
	if _, err := Test(context.Background(), config.Target{Controller: server.URL}, opts); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("connectivity test left its client connection idle")
	}
}
