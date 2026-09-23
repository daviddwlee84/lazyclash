package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedRPiPersistsIndependentlyFromSourceClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	raw := []byte("# keep\ndefault_target='pi'\n[[targets]]\nid='pi'\ncontroller='https://192.0.2.1:9090'\nca_file='/private/ca.pem'\n[targets.managed_rpi]\nproject_dir='/project'\nconnection_file='/project/private/connection.json'\n[targets.config_source]\nkind='rpi-immortalwrt'\n[targets.rule_source]\nkind='rpi-immortalwrt'\n")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(path, true)
	if e != nil {
		t.Fatal(e)
	}
	c.Targets[0].ConfigSource = nil
	c.Targets[0].RuleSource = nil
	if e = Save(path, c); e != nil {
		t.Fatal(e)
	}
	c, e = Load(path, true)
	if e != nil {
		t.Fatal(e)
	}
	if c.Targets[0].ManagedRPi == nil {
		t.Fatal("source clear dropped owner capability gate")
	}
	c.Targets[0].ConfigSource = &ConfigSource{Kind: "native", ConfigID: "main", Binary: "/bin/mihomo", Home: "/home/mihomo"}
	if e = ValidateConfigSource(c.Targets[0]); e == nil {
		t.Fatal("managed target accepted generic source")
	}
	c.Targets[0].ConfigSource = nil
	c.Targets[0].Service = &ClientService{Kind: "systemd"}
	if e = ValidateTarget(c.Targets[0]); e == nil {
		t.Fatal("managed target accepted service takeover")
	}
}
