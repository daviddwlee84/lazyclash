package selfupdate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLatestReleaseValidatesStableMetadata(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		valid      bool
	}{
		{"stable", `{"tag_name":"v0.1.2","draft":false,"prerelease":false,"html_url":"https://untrusted.invalid"}`, 200, true},
		{"draft", `{"tag_name":"v0.1.2","draft":true}`, 200, false},
		{"prerelease", `{"tag_name":"v0.1.2","prerelease":true}`, 200, false},
		{"unstable tag", `{"tag_name":"v0.1.2-beta.1"}`, 200, false},
		{"injection tag", `{"tag_name":"v0.1.2;echo unsafe"}`, 200, false},
		{"invalid json", `no`, 200, false},
		{"limited", `unsafe credentials`, 429, false},
		{"forbidden", `unsafe credentials`, 403, false},
		{"missing", `unsafe credentials`, 404, false},
		{"large", strings.Repeat("x", 1<<20+1), 200, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("User-Agent") != "lazyclash-upgrade" || r.Header.Get("Accept") != "application/vnd.github+json" {
					t.Errorf("unexpected request: %s %v", r.Method, r.Header)
				}
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer server.Close()
			result, err := fetchLatestRelease(context.Background(), server.Client(), server.URL)
			if (err == nil) != test.valid {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if test.valid && (result.Version != "v0.1.2" || result.URL != "https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.2") {
				t.Fatal("unexpected release:", result)
			}
			if err != nil && strings.Contains(err.Error(), "unsafe") {
				t.Fatal("leaked response body:", err)
			}
		})
	}
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("https://alice:unsafe@proxy.invalid?token=unsafe\x1b[2J")
}

func TestReleaseNetworkErrorDoesNotLeakProxyCredentials(t *testing.T) {
	_, err := fetchLatestRelease(context.Background(), &http.Client{Transport: failTransport{}}, "https://api.github.com")
	if err == nil || strings.Contains(err.Error(), "unsafe") || strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "\x1b") {
		t.Fatal("leaked error:", err)
	}
}

func TestReleaseCancellationAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fetchLatestRelease(ctx, server.Client(), server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost:", err)
	}
	client := server.Client()
	client.Timeout = 20 * time.Millisecond
	_, err = fetchLatestRelease(context.Background(), client, server.URL)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("timeout lost:", err)
	}
}
