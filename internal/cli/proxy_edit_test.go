package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"go.yaml.in/yaml/v3"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceCLIFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "source.yaml")
	os.WriteFile(source, []byte("proxies:\n- {name: n, type: trojan, server: example.test, port: 443, password: hidden-secret, x-future: keep}\nproxy-groups:\n- {name: G, type: select, proxies: [n]}\nrules: [MATCH,G]\n"), 0600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("preview/export mutated core")
		}
		if r.URL.Path == "/version" {
			json.NewEncoder(w).Encode(map[string]any{"version": "fixture", "meta": true})
		} else {
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	settings := filepath.Join(dir, "settings.toml")
	target := config.Target{ID: "saved", Controller: server.URL, Configs: []config.CoreConfig{{ID: "main", Path: source}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/no-execute", Home: dir}}
	if e := config.Save(settings, config.Config{DefaultTarget: "saved", Targets: []config.Target{target}}); e != nil {
		t.Fatal(e)
	}
	return settings, dir
}
func TestSourceCLIPreviewAndIntentionalExport(t *testing.T) {
	settings, dir := sourceCLIFixture(t)
	patch := filepath.Join(dir, "patch.yaml")
	os.WriteFile(patch, []byte("password: new-hidden-secret\n"), 0600)
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), []string{"--config", settings, "proxies", "edit", "n", "--file", patch, "--json"}, strings.NewReader(""), &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "\"digest\"") {
		t.Fatalf("%d %s %s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), "hidden-secret") {
		t.Fatal("normal preview leaked secret")
	}
	out.Reset()
	errOut.Reset()
	code = Execute(context.Background(), []string{"--config", settings, "proxies", "export", "n", "--format", "json"}, strings.NewReader(""), &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "hidden-secret") || !strings.Contains(out.String(), "x-future") {
		t.Fatalf("intentional raw export lost fields: %d %s %s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	code = Execute(context.Background(), []string{"--config", settings, "proxies", "export", "n", "--format", "url"}, strings.NewReader(""), &out, &errOut)
	if code == 0 || out.Len() != 0 || strings.Contains(errOut.String(), "hidden-secret") {
		t.Fatal("lossy URI export accepted or secret leaked")
	}
}
func TestSourceCLIJSONNeverPrompts(t *testing.T) {
	settings, _ := sourceCLIFixture(t)
	for _, args := range [][]string{{"proxies", "add"}, {"proxies", "edit", "n"}, {"proxies", "export", "n", "--interactive"}, {"configs", "source", "set", "--interactive"}} {
		var out, diagnostics bytes.Buffer
		argv := append([]string{"--config", settings, "--json"}, args...)
		code := Execute(context.Background(), argv, strings.NewReader(""), &out, &diagnostics)
		if code == 0 || out.Len() != 0 {
			t.Fatalf("%v: %d %s", args, code, out.String())
		}
		if strings.Contains(diagnostics.String(), "hidden-secret") {
			t.Fatal("credentials in diagnostic")
		}
	}
}
func TestCommonGroupFieldsRetainUnknownYAMLAndOrderedMembers(t *testing.T) {
	base := []byte("# group comment\nname: G\ntype: select\nproxies: [old, DIRECT]\nuse: [provider]\nfilter: old-filter\nx-future:\n  feature: kept\n")
	var original map[string]any
	if e := yaml.Unmarshal(base, &original); e != nil {
		t.Fatal(e)
	}
	draft := map[string]string{"name": "G", "type": "url-test", "proxies": "東京\nold\nDIRECT", "use": "provider\nsecond", "filter": "", "url": "https://example.test/check", "interval": "300", "timeout": "5000", "tolerance": "25"}
	raw, e := commonGroupDraft(base, original, draft)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "# group comment") || !strings.Contains(string(raw), "x-future") {
		t.Fatal("common form lost unknown fields or comments")
	}
	var out map[string]any
	yaml.Unmarshal(raw, &out)
	if _, exists := out["filter"]; exists {
		t.Fatal("explicit cleared filter retained")
	}
	members := out["proxies"].([]any)
	if members[0] != "東京" || members[1] != "old" {
		t.Fatal("membership order lost")
	}
	if out["interval"] != 300 || out["timeout"] != 5000 || out["tolerance"] != 25 {
		t.Fatal("delay fields not typed")
	}
	draft["interval"] = "not-a-number"
	if _, e = commonGroupDraft(base, original, draft); e == nil {
		t.Fatal("invalid interval accepted")
	}
}
