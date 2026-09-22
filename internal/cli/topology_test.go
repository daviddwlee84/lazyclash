package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/topology"
)

func TestTopologyOfflineDoesNotLoadSettingsOrConnect(t *testing.T) {
	dir := t.TempDir()
	yaml := filepath.Join(dir, "core.yaml")
	settings := filepath.Join(dir, "broken.toml")
	os.WriteFile(yaml, []byte("secret: PRIVATE\nproxies:\n- {name: leaf, type: trojan, password: SECRET}\nproxy-groups:\n- {name: PROXY, type: select, proxies: [leaf]}\nrules:\n- MATCH,PROXY\n"), 0600)
	os.WriteFile(settings, []byte("broken["), 0600)
	for _, flags := range [][]string{{"--json"}, {"--format", "mermaid"}, {"--view", "relations", "--focus", "leaf"}, {}} {
		root := New(Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("offline API connection")
			return nil, nil, nil
		}})
		out, diag := &bytes.Buffer{}, &bytes.Buffer{}
		root.SetIn(strings.NewReader(""))
		root.SetOut(out)
		root.SetErr(diag)
		root.SetArgs(append([]string{"--config", settings, "topology", "--file", yaml}, flags...))
		if err := root.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String()+diag.String(), "PRIVATE") || strings.Contains(out.String()+diag.String(), "SECRET") {
			t.Fatal("credentials leaked")
		}
		if len(flags) > 0 && flags[0] == "--json" {
			var g topology.Graph
			if json.Unmarshal(out.Bytes(), &g) != nil || len(g.Nodes) == 0 {
				t.Fatal(out.String())
			}
		}
		if len(flags) > 0 && flags[0] == "--format" && !strings.HasPrefix(out.String(), "flowchart LR\n") {
			t.Fatal("Mermaid stdout polluted")
		}
	}
}

func TestTopologyAndBatchFlagConflictsNeverPrompt(t *testing.T) {
	for _, args := range [][]string{
		{"topology", "--file", "-", "--live"},
		{"topology", "--file", "-", "--target", "saved"},
		{"topology", "--file", "-", "--format", "svg"},
		{"topology", "--file", "-", "--json", "--interactive"},
		{"topology", "--file", "-", "--json", "--format", "mermaid"},
		{"proxies", "import", "--destinations", "missing.json", "--target", "saved"},
		{"proxies", "import", "--destinations", "missing.json", "--group", "PROXY"},
	} {
		out, diag := &bytes.Buffer{}, &bytes.Buffer{}
		code := Execute(context.Background(), args, strings.NewReader("rules: []"), out, diag)
		if code != 2 || out.Len() != 0 {
			t.Fatalf("%v: %d %s %s", args, code, out.String(), diag.String())
		}
	}
}

func TestDestinationResolutionKeepsIndependentCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.toml")
	cfg := config.Config{Targets: []config.Target{{ID: "a", Controller: "http://127.0.0.1:1", SecretEnv: "A"}, {ID: "b", Controller: "http://127.0.0.1:2", SecretEnv: "B"}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	cmd := New(Dependencies{})
	cmd.PersistentFlags().Set("config", path)
	o := &options{path: path, target: "a", secretEnv: "OVERRIDE"}
	r, err := o.resolveDestinations(cmd, configwork.Request{}, []configwork.Destination{{TargetID: "a"}, {TargetID: "b"}})
	if err != nil || r.Destinations[0].Target.SecretEnv != "OVERRIDE" || r.Destinations[1].Target.SecretEnv != "B" {
		t.Fatalf("%+v %v", r, err)
	}
	cmd.PersistentFlags().Set("secret-env", "GLOBAL")
	o.target = ""
	if _, err = o.resolveDestinations(cmd, configwork.Request{}, []configwork.Destination{{TargetID: "b"}}); err == nil {
		t.Fatal("ambiguous credential override accepted")
	}
}

func TestBatchCLIUsesDestinationsAndDoesNotWritePreview(t *testing.T) {
	settings, dir := sourceCLIFixture(t)
	file := filepath.Join(dir, "destinations.json")
	os.WriteFile(file, []byte(`[{"target":"saved","groups":["G"],"create_groups":["Private, 東京"]}]`), 0600)
	var out, diag bytes.Buffer
	code := Execute(context.Background(), []string{"--config", settings, "proxies", "import", "--uri", "trojan://private@example.test:443?remarks=new", "--destinations", file, "--json"}, strings.NewReader(""), &out, &diag)
	var p configwork.BatchPlan
	if code != 0 || json.Unmarshal(out.Bytes(), &p) != nil || len(p.Plans) != 1 || len(p.Digest) != 64 {
		t.Fatalf("%d %s %s", code, out.String(), diag.String())
	}
	if strings.Contains(out.String(), "private@example") {
		t.Fatal("input URL leaked")
	}
}

func TestTopologyCompletionIsOffline(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"topology", "--format", ""}, "mermaid"}, {[]string{"topology", "--view", ""}, "relations"}} {
		out, _, err := run(t, Dependencies{}, append([]string{"__complete"}, tc.args...)...)
		if err != nil || !strings.Contains(out, tc.want) || !strings.Contains(out, ":4") {
			t.Fatalf("%q %v", out, err)
		}
	}
}
