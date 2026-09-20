package diagnostics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHostHelperVersionedSafeEnvironmentAndBoundedHEAD(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "HEAD" {
			t.Error("not HEAD")
		}
		w.Header().Set("Location", "http://never-follow.invalid/?secret=PRIVATE")
		w.WriteHeader(302)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	t.Setenv("https_proxy", "http://user:PRIVATE_PASSWORD@localhost:9999?token=PRIVATE_QUERY")
	t.Setenv("HTTP_PROXY", "http://user:PRIVATE_PASSWORD@localhost:8888")
	t.Setenv("NO_PROXY", "127.0.0.1")
	t.Setenv("no_proxy", "127.0.0.1")
	result, err := CollectHost(context.Background(), "", HostRequest{URL: server.URL + "/path?token=PRIVATE_QUERY", Host: u.Hostname(), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	if result.Protocol != 1 || len(result.Requests) != 2 || requests.Load() != 2 {
		t.Fatalf("result=%+v requests=%d", result, requests.Load())
	}
	for _, request := range result.Requests {
		if request.HTTPStatus != 302 || request.Status != "http-response" {
			t.Fatalf("redirect/error misclassified: %+v", request)
		}
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "PRIVATE") {
		t.Fatalf("helper leak: %s", encoded)
	}
	if !result.Environment.NoProxyMatches {
		t.Fatal("no_proxy match missing")
	}
	before := requests.Load()
	result, err = CollectHost(context.Background(), "", HostRequest{URL: server.URL, Host: u.Hostname(), Port: port, ObserveOnly: true})
	if err != nil || requests.Load() != before || len(result.Requests) != 0 || len(result.DNS.Addresses) != 0 {
		t.Fatalf("observe-only sent traffic: %+v %v", result, err)
	}
	capabilities := map[string]bool{}
	for _, capability := range result.Capabilities {
		capabilities[capability.Name] = true
	}
	if !capabilities["dns-config"] || !capabilities["interfaces"] {
		t.Fatal("passive DNS/interface capabilities missing")
	}
}
