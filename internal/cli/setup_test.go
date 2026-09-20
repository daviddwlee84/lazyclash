package cli

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func managedCLIFixture(t *testing.T) (Dependencies, string, *int) {
	t.Helper()
	isolated(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "nodes.txt")
	os.WriteFile(input, []byte("vless://123e4567-e89b-12d3-a456-426614174000@example.test:443?security=tls#fixture"), 0600)
	calls := 0
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return false }, Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("managed setup discovered an unrelated target")
		return nil, nil
	}}
	deps.Managed = managedcore.Options{StateDir: filepath.Join(dir, "state"), NetworkPlan: func(_ context.Context, _ string, n managedcore.NetworkOptions) (managedcore.NetworkOptions, []string, []string, error) {
		return n, nil, nil, nil
	}, ResolveArtifact: func(_ context.Context, r managedcore.Request, h managedcore.HostFacts) (managedcore.Artifact, error) {
		return managedcore.Artifact{Kind: "gzip", Version: r.Version, SHA256: strings.Repeat("a", 64), Platform: "linux/arm64"}, nil
	}, Execute: func(_ context.Context, _ string, _ bool, raw []byte) ([]byte, error) {
		calls++
		var request map[string]any
		json.Unmarshal(raw, &request)
		if request["op"] != "facts" {
			return nil, errors.New("unexpected write")
		}
		return json.Marshal(map[string]any{"facts": managedcore.HostFacts{OS: "linux", Arch: "arm64", Home: "/home/fixture", Systemd: true, Sandbox: true}})
	}}
	return deps, input, &calls
}
func TestSetupJSONPreviewIsCompleteAndDoesNotWrite(t *testing.T) {
	deps, input, calls := managedCLIFixture(t)
	out, diagnostic, err := run(t, deps, "setup", "demo", "--input", input, "--json")
	var plan managedcore.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil {
		t.Fatal(err, out, diagnostic)
	}
	if *calls != 1 || plan.Digest == "" || plan.Request.Preset != "cn-split" || plan.Artifact.Version != managedcore.DefaultVersion {
		t.Fatal(*calls, plan)
	}
	if strings.Contains(out, "123e4567") || strings.Contains(out, "vless://") {
		t.Fatal("preview leaked node credentials")
	}
	if _, err = os.Stat(deps.Managed.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview persisted state", err)
	}
}
func TestSetupMachineAndReadOnlyContracts(t *testing.T) {
	deps, input, calls := managedCLIFixture(t)
	for _, args := range [][]string{{"setup", "--json"}, {"setup", "demo", "--input", input, "--yes", "--json"}, {"setup", "--interactive", "--json"}, {"--read-only", "setup", "demo", "--input", input, "--json"}} {
		out, _, err := run(t, deps, args...)
		if err == nil || out != "" {
			t.Fatalf("%v %q %v", args, out, err)
		}
	}
	if *calls != 0 {
		t.Fatal("invalid setup contacted host", *calls)
	}
}
func TestSetupWizardAutoPresetAndScopedDefaults(t *testing.T) {
	spec := setupSpec(managedcore.Request{InputKind: "yaml"}, "input.yaml", "")
	fields := map[string]string{}
	for _, field := range spec.Fields {
		fields[field.Key] = field.Value
	}
	if fields["preset"] != "auto" || fields["scope"] != "user" || fields["version"] != managedcore.DefaultVersion {
		t.Fatal(fields)
	}
}
func TestManagedListAndPresetsWorkOffline(t *testing.T) {
	deps, _, calls := managedCLIFixture(t)
	for _, args := range [][]string{{"cores", "list", "--json"}, {"rules", "preset", "list", "--json"}} {
		out, _, err := run(t, deps, args...)
		if err != nil || !json.Valid([]byte(out)) {
			t.Fatal(err, out)
		}
	}
	if *calls != 0 {
		t.Fatal("offline inventory contacted host")
	}
}

func TestManagedCommandsRejectIgnoredConnectionOverridesBeforeHostAccess(t *testing.T) {
	deps, input, calls := managedCLIFixture(t)
	for _, args := range [][]string{
		{"--target", "other", "setup", "demo", "--input", input, "--json"},
		{"--controller", "http://127.0.0.1:9999", "setup", "demo", "--input", input, "--json"},
		{"--secret-env", "OTHER_SECRET", "setup", "demo", "--input", input, "--json"},
		{"--ssh", "other-host", "cores", "status", "demo", "--json"},
		{"--target", "other", "cores", "stop", "demo", "--json"},
		{"--controller", "http://127.0.0.1:9999", "rules", "preset", "apply", "simple", "--core", "demo", "--json"},
		{"--target", "other", "rules", "preset", "apply", "simple", "--core", "demo", "--json"},
	} {
		out, _, err := run(t, deps, args...)
		if err == nil || out != "" {
			t.Fatalf("ignored owner override %v: %q %v", args, out, err)
		}
	}
	if *calls != 0 {
		t.Fatal("invalid owner selection contacted host", *calls)
	}
}
