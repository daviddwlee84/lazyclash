package configwork

import (
	"encoding/json"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestBindingPreservesLegacyReceiptsWithoutNewOwnerMetadata(t *testing.T) {
	target := config.Target{ID: "existing", Controller: "http://127.0.0.1:9090", SSHHost: "core-host", ManagedCoreID: "existing", Configs: []config.CoreConfig{{ID: "main", Path: "/core/config.yaml"}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/core/mihomo", Home: "/core"}}
	// This is the exact pre-platform/managed-RPi binding schema. Existing
	// receipts and server provenance must remain verifiable after upgrading.
	legacy, err := json.Marshal(struct {
		ID, Controller, SSH, ManagedCoreID string
		Source                             *config.ConfigSource
		Configs                            []config.CoreConfig
		Service                            *config.ClientService `json:",omitempty"`
	}{target.ID, target.Controller, target.SSHHost, target.ManagedCoreID, target.ConfigSource, target.Configs, target.Service})
	if err != nil || Binding(target) != hash(legacy) {
		t.Fatal("new optional owner fields invalidated a legacy binding", err)
	}
	original := Binding(target)
	target.HostOS = "windows"
	if Binding(target) == original {
		t.Fatal("explicit host platform is not bound")
	}
	target.HostOS = ""
	target.ManagedRPi = &config.ManagedRPi{ProjectDir: "/owner", ConnectionFile: "/owner/connection.toml"}
	if Binding(target) == original {
		t.Fatal("managed RPi owner is not bound")
	}
}
