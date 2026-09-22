package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
)

func TestSetupCloneUsesFreshSourceWithoutChangingIt(t *testing.T) {
	deps, _, calls := managedCLIFixture(t)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("clone mutated source controller")
			w.WriteHeader(500)
			return
		}
		switch r.URL.Path {
		case "/proxies":
			fmt.Fprint(w, `{"proxies":{"PROXY":{"type":"Selector","all":["node"],"now":"node"},"node":{"type":"Shadowsocks"}}}`)
		case "/configs":
			fmt.Fprint(w, `{"mode":"rule"}`)
		case "/version":
			fmt.Fprint(w, `{"version":"v1.19.31","meta":true}`)
		default:
			t.Error("unexpected source query", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer controller.Close()
	home := t.TempDir()
	input := filepath.Join(home, "config.yaml")
	before := []byte("secret: source-management-private\nproxies:\n  - {name: node, type: ss, server: example.test, port: 443, cipher: aes-128-gcm, password: node-private-value}\nproxy-groups:\n  - {name: PROXY, type: select, proxies: [node]}\nrules: [MATCH,PROXY]\n")
	// A quoted MATCH rule is one item, not two YAML sequence values.
	before = []byte(strings.Replace(string(before), "[MATCH,PROXY]", "['MATCH,PROXY']", 1))
	if err := os.WriteFile(input, before, 0600); err != nil {
		t.Fatal(err)
	}
	path, _ := config.DefaultPath()
	cfg, err := config.Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = []config.Target{{ID: "source", Controller: controller.URL, Configs: []config.CoreConfig{{ID: "main", Path: input}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/fixture/mihomo", Home: home}, Checks: []config.DiagnosticCheck{{ID: "web", URL: "https://example.com/"}}}}
	if err = config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	args := []string{"setup", "destination", "--from-target", "source", "--json"}
	out, diagnostic, err := run(t, deps, args...)
	var first managedcore.Plan
	if err != nil || json.Unmarshal([]byte(out), &first) != nil {
		t.Fatal(err, diagnostic, out)
	}
	if first.Request.CloneSourceID != "source" || first.Request.CloneSourceSHA256 == "" || first.Request.CloneSelections["PROXY"] != "node" || len(first.Request.CloneChecks) != 1 || first.Request.Preset != "preserve" || *calls != 1 {
		t.Fatalf("clone metadata missing: %+v calls=%d", first.Request, *calls)
	}
	if strings.Contains(out, "source-management-private") || strings.Contains(out, "node-private-value") {
		t.Fatal("preview leaked private configuration")
	}
	after, _ := os.ReadFile(input)
	if string(after) != string(before) {
		t.Fatal("source file changed during preview")
	}
	if err = os.WriteFile(input, append(before, []byte("log-level: debug\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, err = run(t, deps, args...)
	var second managedcore.Plan
	if err != nil || json.Unmarshal([]byte(out), &second) != nil || second.Digest == first.Digest {
		t.Fatal("source edit did not invalidate the deployment preview", err)
	}
	if _, err = os.Stat(deps.Managed.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview created a deployment record", err)
	}
	writes := 0
	execute := deps.Managed.Execute
	deps.Managed.Execute = func(ctx context.Context, host string, privileged bool, raw []byte) ([]byte, error) {
		var request map[string]any
		_ = json.Unmarshal(raw, &request)
		if request["op"] != "facts" {
			writes++
		}
		return execute(ctx, host, privileged, raw)
	}
	_, _, err = run(t, deps, append(args, "--yes", "--expect", first.Digest)...)
	if err == nil || !strings.Contains(err.Error(), "preview changed") || writes != 0 {
		t.Fatal("stale source digest reached a destination mutation", err, writes)
	}
}

func TestManagedRegistrationPreservesDestinationChecks(t *testing.T) {
	path := isolated(t)
	o := &options{path: path}
	cmd := New(Dependencies{})
	register := o.managedOptions(cmd).Register
	target := config.Target{ID: "clone", ManagedCoreID: "clone", Controller: "http://127.0.0.1:9097", Checks: []config.DiagnosticCheck{{ID: "original", URL: "https://example.com/"}}}
	if err := register(target); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].Checks = []config.DiagnosticCheck{{ID: "edited", URL: "https://github.com/"}}
	if err = config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err = register(target); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(path, true)
	if err != nil || len(cfg.Targets[0].Checks) != 1 || cfg.Targets[0].Checks[0].ID != "edited" {
		t.Fatal("lifecycle replayed cloned checks", cfg, err)
	}
}

func TestSetupCloneConflictsAndWindowsDispatch(t *testing.T) {
	deps, input, calls := managedCLIFixture(t)
	for _, args := range [][]string{
		{"setup", "new", "--from-target", "source", "--input", input, "--json"},
		{"setup", "new", "--from-target", "source", "--input-kind", "yaml", "--json"},
		{"setup", "new", "--client", "verge", "--core-version", "v1.19.31", "--input", input, "--json"},
	} {
		if _, _, err := run(t, deps, args...); err == nil {
			t.Fatal("ambiguous setup accepted", args)
		}
	}
	if *calls != 0 {
		t.Fatal("invalid setup contacted the destination")
	}
	deps.Managed.Execute = func(_ context.Context, _ string, privileged bool, data []byte) ([]byte, error) {
		var request map[string]any
		if json.Unmarshal(data, &request) != nil || request["host_os"] != "windows" || request["op"] != "facts" || privileged {
			t.Fatal("Windows setup used the POSIX helper or mutated the host")
		}
		return json.Marshal(map[string]any{"facts": managedcore.HostFacts{OS: "windows", Arch: "amd64", Home: `C:\Users\fixture`, LocalAppData: `C:\Users\fixture\AppData\Local`, ProgramFiles: `C:\Program Files`, VergeDataDir: `C:\Users\fixture\AppData\Roaming\Verge`, UserSID: "S-1-5-21-123-1001", InteractiveSession: 1, TaskScheduler: true, IsRoot: true}})
	}
	out, diagnostic, err := run(t, deps, "setup", "new", "--host-os", "windows", "--client", "verge", "--input", input, "--json")
	var plan managedcore.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil {
		t.Fatal(err, diagnostic, out)
	}
	if plan.Request.Client != "verge" || plan.Request.HostOS != "windows" || !plan.NeedsPrivilege || len(plan.Blockers) != 0 {
		t.Fatal(plan)
	}
	spec := setupSpec(managedcore.Request{CloneSourceID: "source", Client: "verge"}, "", "")
	fields := map[string]string{}
	for _, f := range spec.Fields {
		fields[f.Key] = f.Value
	}
	if fields["kind"] != "target" || fields["from_target"] != "source" || fields["client"] != "verge" {
		t.Fatal("clone wizard lost explicit choices", fields)
	}
}

func cloneWizardDraft() managedcore.Request {
	return managedcore.Request{
		ID: "destination", SSHHost: "old-host", HostOS: "windows",
		Client: "mihomo", ControllerPort: 9097, MixedPort: 7897,
		InputKind: "yaml", Input: []byte("private cloned profile"), InputBaseDir: "/old/private/bundle",
		CloneSourceID: "source-a", CloneSourceSHA256: "old-source-hash",
		CloneSelections: map[string]string{"PROXY": "old-node"},
		CloneChecks:     []config.DiagnosticCheck{{ID: "old-check", URL: "https://example.com/"}},
	}
}

func TestSetupWizardSwitchingSourceDiscardsDerivedCloneState(t *testing.T) {
	for _, choice := range []struct{ name, kind, source, wantSource string }{
		{"links", "links", "source-a", ""},
		{"yaml", "yaml", "source-a", ""},
		{"different-target", "target", "source-b", "source-b"},
		{"refresh-same-target", "target", "source-a", "source-a"},
	} {
		t.Run(choice.name, func(t *testing.T) {
			request := cloneWizardDraft()
			prepareSetupDraftTransition(&request, "", choice.kind, choice.source, "old-host", false)
			if request.CloneSourceID != choice.wantSource || request.CloneSourceSHA256 != "" || len(request.CloneSelections) != 0 || len(request.CloneChecks) != 0 || len(request.Input) != 0 || request.InputBaseDir != "" {
				t.Fatal("source transition retained an old clone snapshot or its private bundle")
			}
			if request.ID != "destination" || request.HostOS != "windows" || request.MixedPort != 7897 || request.ControllerPort != 9097 {
				t.Fatal("source transition changed destination choices")
			}
		})
	}
}

func TestSetupWizardHostChangesInvalidateOnlyAutomaticPlatform(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		request := cloneWizardDraft()
		prepareSetupDraftTransition(&request, "", "target", "source-a", "new-host", explicit)
		want := ""
		if explicit {
			want = "windows"
		}
		if request.HostOS != want {
			t.Fatal("host transition retained an automatic platform or lost explicit --host-os", explicit, request.HostOS)
		}
	}
}

func TestConfigureWizardRetainsIndependentDestinationSnapshot(t *testing.T) {
	request := cloneWizardDraft()
	before := cloneWizardDraft()
	prepareSetupDraftTransition(&request, "destination", "yaml", "", "edited-host", false)
	if !reflect.DeepEqual(request, before) {
		t.Fatal("configure discarded its saved destination snapshot or platform")
	}
	request = managedcore.Request{InputKind: "yaml", Input: []byte("existing input"), InputBaseDir: "/existing", SSHHost: "host", HostOS: "linux"}
	before = request
	prepareSetupDraftTransition(&request, "", "yaml", "", "host", false)
	if !reflect.DeepEqual(request, before) {
		t.Fatal("an unrelated setup draft lost its current file input")
	}
}
