package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleSourcePreservesNestedTablesAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	initial := "# preferences\n[[targets]]\nid = 'a'\ncontroller = 'http://127.0.0.1:9090'\nunknown = 'keep'\n[[targets.configs]]\nid = 'active'\npath = '/core/config.yaml'\n# preserve registered config\n[[targets]]\nid = 'b'\ncontroller = 'http://127.0.0.1:9091'\n"
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].RuleSource = &RuleSource{Kind: "mihomo", ConfigID: "active", Binary: "/usr/bin/mihomo", Home: "/core"}
	if err = Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Targets[0].RuleSource == nil || cfg.Targets[0].RuleSource.ConfigID != "active" || cfg.Targets[1].RuleSource != nil {
		t.Fatalf("wrong table binding: %+v", cfg.Targets)
	}
	cfg.Targets[0].RuleSource = &RuleSource{Kind: "verge", Version: "2.5.2", DataDir: "/verge", ProfileUID: "chosen"}
	if err = Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Targets[0].RuleSource.Version != "2.5.2" || cfg.Targets[0].RuleSource.Binary != "" {
		t.Fatalf("stale source fields %+v", cfg.Targets[0].RuleSource)
	}
	data, _ := os.ReadFile(path)
	for _, text := range []string{"# preferences", "unknown = 'keep'", "# preserve registered config"} {
		if !strings.Contains(string(data), text) {
			t.Errorf("lost %s", text)
		}
	}
}
