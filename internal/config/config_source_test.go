package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigSourceIndependentPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	text := "# preferences\n[[targets]]\nid='a'\ncontroller='http://127.0.0.1:9090'\nunknown='keep'\n[[targets.configs]]\nid='main'\npath='/core/config.yaml'\n[targets.rule_source]\nkind='mihomo'\nconfig_id='main'\nbinary='/bin/mihomo'\nhome='/core'\n"
	os.WriteFile(path, []byte(text), 0600)
	cfg, e := Load(path, true)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Targets[0].ConfigSource = &ConfigSource{Kind: "native", ConfigID: "main", Binary: "/bin/mihomo", Home: "/core"}
	cfg.Targets[0].ManagedCoreID = "desktop"
	if e = Save(path, cfg); e != nil {
		t.Fatal(e)
	}
	cfg, e = Load(path, true)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Targets[0].RuleSource == nil || cfg.Targets[0].ConfigSource == nil || cfg.Targets[0].ManagedCoreID != "desktop" {
		t.Fatal(cfg)
	}
	cfg.Targets[0].ConfigSource = &ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: "/verge", ProfileUID: "current"}
	if e = Save(path, cfg); e != nil {
		t.Fatal(e)
	}
	cfg, e = Load(path, true)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.Targets[0].ConfigSource.Binary != "" || cfg.Targets[0].RuleSource.Binary != "/bin/mihomo" {
		t.Fatal("independent scope lost")
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "unknown='keep'") || !strings.Contains(string(raw), "# preferences") {
		t.Fatal("unknown preferences lost")
	}
}
func TestDockerSourceRequiresHostContainerDistinction(t *testing.T) {
	target := Target{Controller: "http://127.0.0.1:9090", ConfigSource: &ConfigSource{Kind: "docker", Container: "core", HostPath: "/host/config.yaml", CorePath: "/etc/mihomo/config.yaml", Binary: "/mihomo", Home: "/etc/mihomo"}}
	if e := ValidateTarget(target); e != nil {
		t.Fatal(e)
	}
	target.ConfigSource.CorePath = ""
	if e := ValidateTarget(target); e == nil {
		t.Fatal("missing container path accepted")
	}
}
