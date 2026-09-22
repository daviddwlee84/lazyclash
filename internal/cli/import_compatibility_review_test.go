package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestNoninteractiveProxyImportRejectsClassicBeforeSourceBinding(t *testing.T) {
	isolated(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" || r.Method != "GET" {
			t.Errorf("unexpected classic controller access: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":"v1.18.0"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.toml")
	input := filepath.Join(dir, "node.yaml")
	cfg := config.Config{DefaultTarget: "classic", Targets: []config.Target{{ID: "classic", Controller: server.URL}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(input, []byte("name: Oracle\ntype: vless\nserver: example.test\nport: 443\nuuid: private-fixture-credential\n"), 0600)
	out, stderr, err := run(t, Dependencies{}, "--config", path, "--target", "classic", "proxies", "import", "--file", input, "--json")
	if err == nil || !strings.Contains(err.Error(), "classic Clash") || strings.Contains(err.Error(), "bind a node/group") {
		t.Fatalf("wrong early failure: %v output=%s stderr=%s", err, out, stderr)
	}
	if strings.Contains(out+stderr+err.Error(), "private-fixture-credential") {
		t.Fatal("private node credential in diagnostic")
	}
}
