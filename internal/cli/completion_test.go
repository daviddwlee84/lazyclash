package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"io"
)

func TestNewSurfaceCompletionUsesOnlyOfflineMetadata(t *testing.T) {
	path := isolated(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := config.Config{Targets: []config.Target{{ID: "saved", Controller: "http://127.0.0.1:1", SSHHost: "saved-host", SecretEnv: "NEVER_READ_COMPLETION_SECRET", ManagedCoreID: "fixture-core", Checks: []config.DiagnosticCheck{{ID: "claude-api", URL: "https://api.example.test/", ExpectedStatuses: []int{404}}}}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("completion discovered targets")
		return nil, nil
	}, Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("completion connected to core")
		return nil, nil, nil
	}}
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"proxy", "shell-init", ""}, "bash"},
		{[]string{"proxy", "env", "--shell", ""}, "sh"},
		{[]string{"proxy", "env", "--consumer", ""}, "service"},
		{[]string{"proxy", "ssh", ""}, "saved-host"},
		{[]string{"proxy", "tunnel", "share", ""}, "saved-host"},
		{[]string{"proxy", "docker", "render", "--format", ""}, "compose"},
		{[]string{"proxy", "docker", "render", "--scope", ""}, "runtime"},
		{[]string{"proxy", "tunnel", "start", ""}, "saved"},
		{[]string{"configs", "source", "set", "--kind", ""}, "docker"},
		{[]string{"proxies", "copy", ""}, "saved"},
		{[]string{"proxies", "copy", "saved", ""}, "saved"},
		{[]string{"proxies", "export", "--format", ""}, "url"},
		{[]string{"proxies", "edit", ""}, ""},
		{[]string{"groups", "edit", ""}, ""},
		{[]string{"diagnostics", "network", ""}, ""},
		{[]string{"diagnostics", "checks", "run", ""}, "claude-api"},
		{[]string{"diagnostics", "checks", "remove", ""}, "claude-api"},
		{[]string{"targets", "service", "restart", ""}, "saved"},
		{[]string{"proxy", "docker", "test", "--container", ""}, ""},
	} {
		out, _, err := run(t, deps, append([]string{"__complete"}, test.args...)...)
		if err != nil || !strings.Contains(out, test.want) || !strings.Contains(out, ":4") {
			t.Fatalf("%v -> %q %v", test.args, out, err)
		}
	}
	for _, args := range [][]string{{"proxies", "import", "--file", ""}, {"proxies", "export", "--output", ""}, {"proxy", "docker", "render", "--output", ""}} {
		out, _, err := run(t, deps, append([]string{"__complete"}, args...)...)
		if err != nil || strings.Contains(out, ":4") {
			t.Fatalf("local filename completion lost: %v => %q %v", args, out, err)
		}
	}
	root := New(deps)
	if cmd, _, err := root.Find([]string{"setup"}); err == nil && cmd.Name() == "setup" {
		for _, test := range []struct {
			args []string
			want string
		}{{[]string{"setup", "--backend", ""}, "native"}, {[]string{"setup", "--input-kind", ""}, "subscription"}, {[]string{"setup", "--preset", ""}, "cn-split"}, {[]string{"setup", "--category", ""}, "media-hkmt"}, {[]string{"setup", "--service-scope", ""}, "system"}, {[]string{"cores", "configure", ""}, "fixture-core"}, {[]string{"rules", "preset", "apply", ""}, "simple"}, {[]string{"rules", "preset", "update", "--core", ""}, "fixture-core"}} {
			out, _, err := run(t, deps, append([]string{"__complete"}, test.args...)...)
			if err != nil || !strings.Contains(out, test.want) || !strings.Contains(out, ":4") {
				t.Fatalf("%v => %q %v", test.args, out, err)
			}
		}
	}
}

func TestCompletionInstallOwnershipAndStatus(t *testing.T) {
	isolated(t)
	dir := filepath.Join(t.TempDir(), "with space")
	args := []string{"completion", "install", "zsh", "--dir", dir, "--json"}
	out, _, err := run(t, Dependencies{}, args...)
	if err != nil {
		t.Fatal(err)
	}
	var got completionStatus
	if json.Unmarshal([]byte(out), &got) != nil || got.State != "current" {
		t.Fatalf("%s", out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "_lazyclash"))
	if err != nil || !strings.Contains(string(data), "__complete") {
		t.Fatalf("script: %v", err)
	}
	out, _, err = run(t, Dependencies{}, "completion", "status", "zsh", "--dir", dir, "--json")
	if err != nil || !strings.Contains(out, "current") {
		t.Fatalf("%s %v", out, err)
	}
	if err = os.WriteFile(got.Path, []byte("# mine\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = run(t, Dependencies{}, args...); err == nil {
		t.Fatal("replaced foreign file")
	}
	if _, _, err = run(t, Dependencies{}, append(args, "--force")...); err != nil {
		t.Fatal(err)
	}
	os.Remove(got.Path)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0600)
	os.Symlink(victim, got.Path)
	if _, _, err = run(t, Dependencies{}, append(args, "--force")...); err == nil {
		t.Fatal("followed symlink")
	}
	b, _ := os.ReadFile(victim)
	if string(b) != "keep" {
		t.Fatal("changed symlink referent")
	}
	if _, _, err = run(t, Dependencies{}, "completion", "zsh", "--json"); err == nil {
		t.Fatal("script mixed with json")
	}
}

func TestCompletionConfigSelectionAndValueFallback(t *testing.T) {
	path := isolated(t)
	contents := `[[targets]]
id="first"
controller="http://127.0.0.1:1"
secret_env="NEVER_RESOLVE_THIS_SECRET"
[[targets.configs]]
id="first-config"
path="/remote/first.yaml"
[[targets]]
id="second"
controller="http://127.0.0.1:2"
[[targets.configs]]
id="second-config"
path="/remote/second.yaml"
`
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args         []string
		want, absent string
	}{
		{[]string{"__complete", "configs", "apply", ""}, "first-config", "second-config"},
		{[]string{"__complete", "--target", "second", "configs", "apply", ""}, "second-config", "first-config"},
		{[]string{"__complete", "--controller", "http://127.0.0.1:3", "configs", "apply", ""}, "", "first-config"},
		{[]string{"__complete", "diagnostics", "url", "--reference-doh", ""}, "", "first-config"},
	} {
		out, _, err := run(t, Dependencies{}, tc.args...)
		if err != nil || !strings.Contains(out, tc.want) || strings.Contains(out, tc.absent) || !strings.Contains(out, ":4") {
			t.Fatalf("%v => %q %v", tc.args, out, err)
		}
	}
	t.Setenv("LAZYCLASH_CONTROLLER", "http://127.0.0.1:4")
	out, _, err := run(t, Dependencies{}, "__complete", "configs", "apply", "")
	if err != nil || strings.Contains(out, "first-config") {
		t.Fatalf("temporary environment selected saved configs: %q %v", out, err)
	}
	out, _, err = run(t, Dependencies{}, "__complete", "--target", "second", "configs", "apply", "")
	if err != nil || !strings.Contains(out, "second-config") {
		t.Fatalf("explicit target precedence: %q %v", out, err)
	}
	out, _, err = run(t, Dependencies{}, "__complete", "targets", "add", "--secret-file", "")
	if err != nil || strings.Contains(out, ":4") {
		t.Fatalf("local credential path lost filename completion: %q %v", out, err)
	}
}

func TestCompletionRelativeXDGAndConcurrentEmptyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "relative")
	path, err := completionPath("")
	if err != nil || path != filepath.Join(os.Getenv("HOME"), ".local", "share", "lazyclash", "completions", "zsh", "_lazyclash") {
		t.Fatalf("relative XDG fallback: %s %v", path, err)
	}
	path = filepath.Join(t.TempDir(), "_lazyclash")
	_, old, err := inspectCompletion(path, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeCompletion(path, []byte("new"), old); !errors.Is(err, config.ErrConflict) {
		t.Fatalf("new foreign empty file overwritten: %v", err)
	}
	data, _ := os.ReadFile(path)
	if len(data) != 0 {
		t.Fatal("foreign file changed")
	}
	_, old, err = inspectCompletion(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := path + ".another"
	if err := os.WriteFile(other, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, path); err != nil {
		t.Fatal(err)
	}
	if err := writeCompletion(path, []byte("new"), old); !errors.Is(err, config.ErrConflict) {
		t.Fatalf("replaced inode accepted: %v", err)
	}
}

func TestCompletionUsesRegistrationsWithoutConnections(t *testing.T) {
	path := isolated(t)
	if _, _, e := run(t, Dependencies{}, "targets", "add", "server", "--controller", "http://127.0.0.1:1", "--ssh", "example", "--secret-env", "DOES_NOT_EXIST"); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"__complete", "--target", ""}, "server"},
		{[]string{"__complete", "--ssh", ""}, "example"},
		{[]string{"__complete", "targets", "add", "new", "--ssh", ""}, "example"},
		{[]string{"__complete", "rules", "source", "set", "--data-dir", ""}, ""},
		{[]string{"__complete", "mode", ""}, "rule"},
		{[]string{"__complete", "--page", ""}, "overview"},
		{[]string{"__complete", "targets", "move", "server", ""}, "first"},
		{[]string{"__complete", "proxies", "select", ""}, ""},
	} {
		out, _, e := run(t, Dependencies{}, tc.args...)
		if e != nil || !strings.Contains(out, tc.want) || !strings.Contains(out, ":4") {
			t.Fatalf("%v: %q %v", tc.args, out, e)
		}
	}
	os.WriteFile(path, []byte("[broken"), 0600)
	out, _, e := run(t, Dependencies{}, "__complete", "mode", "")
	if e != nil || !strings.Contains(out, "rule") {
		t.Fatalf("%q %v", out, e)
	}
	out, _, e = run(t, Dependencies{}, "__complete", "--target", "")
	if e != nil || strings.Contains(out, "server") || !strings.Contains(out, ":4") {
		t.Fatalf("%q %v", out, e)
	}
}
