package rulework

import (
	"encoding/json"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestBindingPreservesLegacyReceiptsWithoutNewOwnerMetadata(t *testing.T) {
	target := config.Target{ID: "existing", Controller: "http://127.0.0.1:9090", SSHHost: "core-host", Configs: []config.CoreConfig{{ID: "main", Path: "/core/config.yaml"}}, RuleSource: &config.RuleSource{Kind: "mihomo", ConfigID: "main", Binary: "/core/mihomo", Home: "/core"}}
	legacy, err := json.Marshal(struct {
		ID, Controller, SSH string
		Source              *config.RuleSource
		ConfigPath          string
	}{target.ID, target.Controller, target.SSHHost, target.RuleSource, "/core/config.yaml"})
	if err != nil || binding(target) != sha(legacy) {
		t.Fatal("new optional owner fields invalidated a legacy receipt", err)
	}
	original := binding(target)
	target.HostOS, target.ManagedCoreID = "windows", "owned-windows"
	if binding(target) == original {
		t.Fatal("Windows owner is not bound")
	}
	windows := binding(target)
	target.ManagedCoreID = "other-owner"
	if binding(target) == windows {
		t.Fatal("changed Windows owner is not bound")
	}
	target.HostOS, target.ManagedCoreID = "", ""
	target.ManagedRPi = &config.ManagedRPi{ProjectDir: "/owner", ConnectionFile: "/owner/connection.toml"}
	if binding(target) == original {
		t.Fatal("managed RPi owner is not bound")
	}
}
