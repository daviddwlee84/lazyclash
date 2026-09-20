package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLDiagnosticCoreMethodsAreBoundedAndRespectReadOnly(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" {
			t.Error("unexpected write method")
		}
		if strings.HasSuffix(r.URL.Path, "/delay") {
			if !strings.Contains(r.RequestURI, "node%2Fone") || r.URL.Query().Get("url") != "https://example.invalid/?key=PRIVATE" || r.URL.Query().Get("timeout") != "5000" {
				t.Error("URLTest arguments changed")
			}
			fmt.Fprint(w, `{"delay":7}`)
		} else {
			if r.URL.Path != "/dns/query" || r.URL.Query().Get("type") != "AAAA" {
				t.Error("unexpected DNS request")
			}
			fmt.Fprint(w, `{"Answer":[]}`)
		}
	}))
	defer server.Close()
	client, err := New(Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.URLDelay(context.Background(), "node/one", "https://example.invalid/?key=PRIVATE", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DNSQuery(context.Background(), "example.invalid", "AAAA"); err != nil {
		t.Fatal(err)
	}
	ro, err := New(Options{Endpoint: server.URL, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, err := ro.URLDelay(context.Background(), "DIRECT", "https://example.invalid/", time.Second); err == nil {
		t.Fatal("readonly URLTest accepted")
	}
	if _, err := ro.DNSQuery(context.Background(), "example.invalid", "A"); err == nil {
		t.Fatal("readonly DNS probe accepted")
	}
	if calls.Load() != 2 {
		t.Fatalf("readonly caused network calls: %d", calls.Load())
	}
}
