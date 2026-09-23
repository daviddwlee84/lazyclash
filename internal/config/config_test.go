package config

import (
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "relative")
	path, err := DefaultPath()
	if err != nil || path != filepath.Join(home, ".config/lazyclash/config.toml") {
		t.Fatalf("path=%q error=%v", path, err)
	}
	xdg := filepath.Join(home, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	path, err = DefaultPath()
	if err != nil || path != filepath.Join(xdg, "lazyclash/config.toml") {
		t.Fatalf("path=%q error=%v", path, err)
	}
}

func TestLoadMissingDoesNotCreateDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.toml")
	cfg, err := Load(path, false)
	if err != nil || len(cfg.Targets) != 0 {
		t.Fatalf("missing default: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created directory: %v", err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("explicit missing path must fail")
	}
}

func TestSavePreservesCommentsUnknownFieldsAndOrderedTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := `# My controllers
favorite_color = "blue" # retained
 default_target = "first" # default explanation

[[targets]] # first core
id = "first"
controller = "http://localhost:9090" # endpoint explanation
future_option = "keep this"

[[targets.configs]] # profile explanation
id = "work"
name = "old"
path = "/srv/work.yaml"
future_profile = 17

[[targets]] # second core
id = "second"
controller = "http://localhost:9097"

[appearance]
theme = "dark" # app-independent field
`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].Controller = "https://core.example:9443"
	cfg.Targets[0].Configs[0].Name = "工作 🦊"
	cfg.Targets[0].Configs = append(cfg.Targets[0].Configs, CoreConfig{ID: "home", Path: "/srv/home.yaml"})
	cfg.Targets[0].Secret = "THIS-MUST-NOT-BE-WRITTEN"
	cfg.Targets[0].Name = "Main"
	cfg.Targets[0], cfg.Targets[1] = cfg.Targets[1], cfg.Targets[0]
	cfg.DefaultTarget = "second"
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# My controllers", "# endpoint explanation", "# default explanation", "# profile explanation", "# second core", "favorite_color = \"blue\"", "future_option = \"keep this\"", "future_profile = 17", "theme = \"dark\" # app-independent field", "工作 🦊"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("missing preserved content %q in:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), "THIS-MUST") {
		t.Fatal("secret persisted")
	}
	loaded, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Targets[0].ID != "second" || loaded.Targets[1].Name != "Main" || len(loaded.Targets[1].Configs) != 2 {
		t.Fatalf("incorrect saved state: %+v", loaded)
	}
	info, _ := os.Stat(path)
	if !info.Mode().IsRegular() || !privatefs.Private(path) {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestSaveConflictAndUnknownExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = []Target{{ID: "local", Controller: "http://localhost:9090"}}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale absent snapshot accepted: %v", err)
	}
	cfg, err = Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# changed by another writer\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); !errors.Is(err, ErrConflict) {
		t.Fatalf("concurrent writer accepted: %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "# changed by another writer\n" {
		t.Fatalf("other edit lost: %s", data)
	}
	if err := Save(path, Config{}); err == nil {
		t.Fatal("unloaded existing file must not be overwritten")
	}
}

func TestSaveDeleteAndAddRetainsUnrelatedTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := `[[targets]]
id="delete"
controller="http://127.0.0.1:9090"
[other]
value="keep"
[[targets]]
id="retain"
controller="http://127.0.0.1:9097"
["targets.configs"]
note="literal dot is unrelated"
`
	os.WriteFile(path, []byte(original), 0600)
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = append(cfg.Targets[1:], Target{ID: "new", Controller: "unix:///tmp/core.sock"})
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `value="keep"`) || !strings.Contains(string(data), `note="literal dot is unrelated"`) {
		t.Fatalf("unknown tables lost:\n%s", data)
	}
	loaded, err := Load(path, true)
	if err != nil || len(loaded.Targets) != 2 || loaded.Targets[0].ID != "retain" {
		t.Fatalf("load=%+v err=%v", loaded, err)
	}
}

func TestInlineTargetsRefusesLossyRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := `targets = [{ id = "local", controller = "http://localhost:9090" }] # mine`
	os.WriteFile(path, []byte(original), 0600)
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].Name = "changed"
	if err := Save(path, cfg); err == nil || !strings.Contains(err.Error(), "edit manually") {
		t.Fatalf("expected actionable error, got %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != original {
		t.Fatal("unsupported layout changed")
	}
}

func TestValidationAndRedaction(t *testing.T) {
	for _, controller := range []string{"", "ftp://a", "http://alice:MYSECRET@localhost:9090", "http://localhost:9090?token=MYSECRET", "unix://localhost/tmp/core.sock", "unix:///", "http://localhost:70000"} {
		t.Run(controller, func(t *testing.T) {
			err := ValidateTarget(Target{Controller: controller})
			if err == nil {
				t.Fatal("expected validation error")
			}
			if strings.Contains(err.Error(), "MYSECRET") {
				t.Fatal("secret in error")
			}
		})
	}
	for _, target := range []Target{
		{Controller: "http://localhost:9090", SecretEnv: "TOKEN", SecretFile: "/tmp/token"},
		{Controller: "http://localhost:9090", SSHHost: "-oProxyCommand=evil"},
		{Controller: "http://localhost:9090", SourceConfig: "relative"},
		{Controller: "http://localhost:9090", Configs: []CoreConfig{{ID: "x", Path: "relative"}}},
	} {
		if ValidateTarget(target) == nil {
			t.Errorf("invalid target accepted: %+v", target)
		}
	}
	if Validate(Config{DefaultTarget: "missing"}) == nil {
		t.Error("missing default target accepted")
	}
	if Validate(Config{Targets: []Target{{ID: "x", Controller: "http://localhost"}, {ID: "x", Controller: "http://localhost"}}}) == nil {
		t.Error("duplicate target accepted")
	}
	target := Target{ID: "local", Controller: "http://localhost", Secret: "DO-NOT-EXPOSE", Transient: true, AuthRequired: true}
	jsonData, _ := json.Marshal(target)
	tomlData, _ := toml.Marshal(target)
	for _, data := range [][]byte{jsonData, tomlData} {
		if strings.Contains(string(data), "DO-NOT-EXPOSE") || strings.Contains(string(data), "Transient") {
			t.Fatal("ephemeral field serialized")
		}
	}
}
