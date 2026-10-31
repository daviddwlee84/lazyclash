package connection

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestLocalCandidatesFilterBeforeProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/version" {
			t.Errorf("unexpected discovery request: %s %s", r.Method, r.URL.Path)
		}
		io.WriteString(w, `{"version":"fixture"}`)
	}))
	defer server.Close()
	// Both runtime YAML and process listeners can advertise nonlocal endpoints.
	// Only the filtered list is ever passed into the network-probing stage.
	runtime, err := parseRuntime([]byte("external-controller: 'example.invalid:9090'\nexternal-controller-tls: '192.0.2.1:9443'\n"))
	if err != nil {
		t.Fatal(err)
	}
	candidates := []config.Target{{ID: "local", Controller: server.URL}, {ID: "remote-ssh", Controller: server.URL, SSHHost: "never-ssh"}}
	for _, endpoint := range append(runtime.controllers(), parseListeners("p123\nn203.0.113.9:9090\n", []string{"123"})...) {
		candidates = append(candidates, config.Target{ID: "remote", Controller: endpoint})
	}
	filtered := localCandidates(candidates)
	if len(filtered) != 1 || filtered[0].ID != "local" {
		t.Fatalf("nonlocal candidate reached probe boundary: %+v", filtered)
	}
	found := probeBatch(context.Background(), filtered)
	if len(found) != 1 || found[0].ID != "local" {
		t.Fatalf("local probe: %+v", found)
	}
	if len(candidates) != 5 {
		t.Fatal("filter mutated original candidates")
	}
}

func TestLocalCandidatesLoopbackUnixAndInvalid(t *testing.T) {
	var candidates []config.Target
	for _, endpoint := range []string{"http://127.0.0.1:9090", "http://127.3.2.1:9090", "http://[::1]:9090", "https://LOCALHOST:9443", "unix:///tmp/core.sock", "http://localhost.example.invalid:9090", "http://192.168.1.2:9090", "http://0.0.0.0:9090", "unix://remote/tmp/core.sock", "http://user:secret@localhost:9090", "http://localhost:9090/?token=secret", "file:///tmp/core"} {
		candidates = append(candidates, config.Target{Controller: endpoint})
	}
	filtered := localCandidates(candidates)
	if !reflect.DeepEqual(filtered, candidates[:5]) {
		t.Fatalf("filter = %+v", filtered)
	}
}
