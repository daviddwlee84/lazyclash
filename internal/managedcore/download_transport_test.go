package managedcore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

type downloadCloser struct{ closed *atomic.Int32 }

func (c downloadCloser) Close() error { c.closed.Add(1); return nil }
func TestDownloadRouteIsExplicitAndClosedOnce(t *testing.T) {
	var calls, closed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("artifact")) }))
	defer server.Close()
	opts := Options{DownloadClient: func(ctx context.Context, id string) (*http.Client, io.Closer, error) {
		calls.Add(1)
		if id != "bootstrap" {
			t.Fatal(id)
		}
		return server.Client(), downloadCloser{&closed}, nil
	}}
	req := Request{ID: "new", BootstrapTarget: "bootstrap"}
	ctx, cleanup, err := withDownloadClient(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	nested, done, err := withDownloadClient(ctx, req, opts)
	if err != nil {
		t.Fatal(err)
	}
	response, err := downloadHTTPClient(nested).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	done()
	cleanup()
	if calls.Load() != 1 || closed.Load() != 1 {
		t.Fatalf("calls=%d close=%d", calls.Load(), closed.Load())
	}
	if _, _, err = withDownloadClient(context.Background(), Request{ID: "same", BootstrapTarget: "same"}, opts); err == nil {
		t.Fatal("self-bootstrap accepted")
	}
}
func TestDefaultDownloadDoesNotUseEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client := downloadHTTPClient(context.Background())
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("downloads inherited proxy environment")
	}
}
func TestDownloadRedirectProtectsCredentialAndTLSBoundary(t *testing.T) {
	origin, _ := http.NewRequest("GET", "https://origin.example/private", nil)
	next := &http.Request{URL: &url.URL{Scheme: "https", Host: "asset.example"}, Header: http.Header{"Authorization": {"private"}, "Cookie": {"private"}}}
	if err := safeDownloadRedirect(next, []*http.Request{origin}); err != nil {
		t.Fatal(err)
	}
	if next.Header.Get("Authorization") != "" || next.Header.Get("Cookie") != "" {
		t.Fatal("cross-origin credentials leaked")
	}
	next.URL.Scheme = "http"
	if safeDownloadRedirect(next, []*http.Request{origin}) == nil {
		t.Fatal("HTTPS downgraded")
	}
}
