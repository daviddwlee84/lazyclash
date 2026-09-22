package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/clientservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestExistingServiceCLIRequiresReviewedBindingAndLifecycle(t *testing.T) {
	isolated(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.toml")
	cfg := config.Config{DefaultTarget: "fixture", Targets: []config.Target{{ID: "fixture", Controller: "http://127.0.0.1:9090", SSHHost: "fixture-ssh"}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	binding := config.ClientService{Kind: "docker", DockerHost: "unix:///fixture", Container: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), MountsSHA256: strings.Repeat("c", 64)}
	actions := []string{}
	deps := Dependencies{ClientServices: clientservice.Options{StateDir: filepath.Join(dir, "receipts"), Host: func(_ context.Context, target config.Target, r clientservice.Request) (clientservice.Status, error) {
		if target.SSHHost != "fixture-ssh" {
			t.Fatal("lost SSH owner")
		}
		actions = append(actions, r.Op)
		return clientservice.Status{Binding: binding, Running: r.Op != "stop", StateDigest: "stable"}, nil
	}}}
	args := []string{"--config", path, "targets", "service", "bind", "fixture", "--kind", "docker", "--docker-host", "unix:///fixture", "--container", "existing", "--json"}
	out, _, err := run(t, deps, args...)
	var p clientservice.Plan
	if err != nil || json.Unmarshal([]byte(out), &p) != nil {
		t.Fatal(out, err)
	}
	loaded, _ := config.Load(path, true)
	if loaded.Targets[0].Service != nil {
		t.Fatal("preview saved binding")
	}
	if _, _, err = run(t, deps, append(args, "--yes", "--expect", strings.Repeat("f", 64))...); err == nil {
		t.Fatal("wrong binding digest accepted")
	}
	if _, _, err = run(t, deps, append(args, "--yes", "--expect", p.Digest)...); err != nil {
		t.Fatal(err)
	}
	args = []string{"--config", path, "targets", "service", "stop", "fixture", "--disable-autostart", "--json"}
	out, _, err = run(t, deps, args...)
	if err != nil || json.Unmarshal([]byte(out), &p) != nil {
		t.Fatal(out, err)
	}
	if _, _, err = run(t, deps, append(args, "--yes", "--expect", strings.Repeat("f", 64))...); err == nil {
		t.Fatal("wrong action digest accepted")
	}
	for _, a := range actions {
		if a != "bind" && a != "status" {
			t.Fatal("preview or wrong digest mutated", actions)
		}
	}
	out, _, err = run(t, deps, append(args, "--yes", "--expect", p.Digest)...)
	if err != nil {
		t.Fatal(out, err)
	}
	if actions[len(actions)-1] != "stop" {
		t.Fatal(actions)
	}
	if _, err = os.Stat(filepath.Join(dir, "receipts")); err != nil {
		t.Fatal("missing receipt", err)
	}
	if _, _, err = run(t, deps, "--config", path, "targets", "edit", "fixture", "--controller", "http://127.0.0.1:9999"); err != nil {
		t.Fatal(err)
	}
	loaded, _ = config.Load(path, true)
	if loaded.Targets[0].Service != nil {
		t.Fatal("endpoint edit retained service authority")
	}
}
