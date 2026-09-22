package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func connectionProvenanceFixture(t *testing.T) (serverstate.Store, serverstate.Inventory, config.Target, configwork.Definition, string) {
	t.Helper()
	dir := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}
	target := config.Target{ID: "client", Controller: "http://127.0.0.1:9090", ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/bin/mihomo", Home: "/tmp/home"}}
	defs, _, err := configwork.ParseImport([]byte("proxies:\n  - name: Oracle SG\n    type: socks5\n    server: example.test\n    port: 1080\n    username: secret-user\n    password: secret-password\n"))
	if err != nil || len(defs) != 1 {
		t.Fatalf("bad fixture: %v", err)
	}
	now := time.Now().UTC()
	inv := serverstate.Inventory{Version: 1, Hosts: []serverstate.Host{{ID: "vm", Provider: "oracle", Observation: &serverstate.CloudObservationBinding{Provider: "oracle", Region: "ap-singapore-1", ResourceID: "instance", AccountID: "account", VerifiedAt: now}}}, Deployments: []serverstate.Deployment{{ID: "proxy", HostID: "vm"}}}
	path, err := serverConnectionPath(store, "proxy", target)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	record := serverConnection{ServerID: "proxy", TargetID: target.ID, Binding: configwork.Binding(target), Digest: strings.Repeat("b", 64), Status: "verified", ReceiptID: id, StartedAt: now.Add(-time.Minute)}
	if err = saveServerConnection(path, record); err != nil {
		t.Fatal(err)
	}
	r := configwork.Receipt{ID: id, TargetID: target.ID, Binding: record.Binding, Kind: "proxy", Name: defs[0].Name, Status: "verified", CreatedAt: now, UpdatedAt: now, Definitions: map[string]string{"proxy/" + defs[0].Name: configwork.DefinitionDigest(defs[0])}, SourceVerified: true, RuntimeObserved: true}
	data, _ := json.Marshal(r)
	receipt := filepath.Join(filepath.Dir(path), "receipts", id, "receipt.json")
	if err = serverstate.WritePrivate(receipt, data); err != nil {
		t.Fatal(err)
	}
	return store, inv, target, defs[0], receipt
}

func TestServerConnectionProvenanceUsesPrivateReceiptAndSemanticSource(t *testing.T) {
	store, inv, target, def, _ := connectionProvenanceFixture(t)
	rows, err := storedServerConnections(store, inv, []config.Target{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].NodeName != "Oracle SG" || rows[0].ServerID != "proxy" || rows[0].HostID != "vm" || rows[0].ResourceID != "instance" || rows[0].SourceVerified || rows[0].Status != "recorded" {
		t.Fatalf("bad recorded mapping: %+v", rows)
	}
	if err = verifyServerConnectionSources(store, inv, target, configwork.Catalog{Proxies: []configwork.Definition{def}}, rows); err != nil {
		t.Fatal(err)
	}
	if !rows[0].SourceVerified || rows[0].Status != "source-matches" {
		t.Fatalf("semantic source not verified: %+v", rows)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), "secret-user") || strings.Contains(string(encoded), "secret-password") {
		t.Fatal("provenance exposed node credentials")
	}
	if err = verifyServerConnectionSources(store, inv, target, configwork.Catalog{}, rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "node-missing" {
		t.Fatal("missing node retained verified association")
	}
}

func TestServerConnectionProvenanceRejectsChangedSourceAndReceiptBinding(t *testing.T) {
	store, inv, target, _, receipt := connectionProvenanceFixture(t)
	rows, err := storedServerConnections(store, inv, []config.Target{target})
	if err != nil {
		t.Fatal(err)
	}
	defs, _, err := configwork.ParseImport([]byte("proxies:\n- name: Oracle SG\n  type: socks5\n  server: changed.test\n  port: 1080\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyServerConnectionSources(store, inv, target, configwork.Catalog{Proxies: defs}, rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "definition-changed" || rows[0].SourceVerified {
		t.Fatal("changed node presented as verified")
	}
	bad := configwork.Receipt{ID: strings.Repeat("a", 32), TargetID: target.ID, Binding: "other", Name: "Oracle SG", Kind: "proxy", DefinitionSHA256: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(bad)
	if err = serverstate.WritePrivate(receipt, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = storedServerConnections(store, inv, []config.Target{target}); err == nil {
		t.Fatal("mismatched receipt binding accepted")
	}
}

func TestServerConnectionProvenanceReadsLegacySingleDefinition(t *testing.T) {
	store, inv, target, def, receipt := connectionProvenanceFixture(t)
	r := configwork.Receipt{ID: strings.Repeat("a", 32), TargetID: target.ID, Binding: configwork.Binding(target), Kind: "proxy", Name: def.Name, DefinitionSHA256: configwork.DefinitionDigest(def), Status: "verified"}
	raw, _ := json.Marshal(r)
	if err := serverstate.WritePrivate(receipt, raw); err != nil {
		t.Fatal(err)
	}
	rows, err := storedServerConnections(store, inv, []config.Target{target})
	if err != nil || len(rows) != 1 || rows[0].NodeName != def.Name {
		t.Fatalf("legacy receipt lost: %+v %v", rows, err)
	}
}

func TestServerConnectionProvenanceSkipsOnlyConfirmedPrewriteFailures(t *testing.T) {
	for _, status := range []string{"failed-before-write", "applying"} {
		t.Run(status, func(t *testing.T) {
			store, inv, target, _, _ := connectionProvenanceFixture(t)
			inv.Deployments = append(inv.Deployments, serverstate.Deployment{ID: "rejected", HostID: "vm"})
			path, err := serverConnectionPath(store, "rejected", target)
			if err != nil {
				t.Fatal(err)
			}
			record := serverConnection{ServerID: "rejected", TargetID: target.ID, Binding: configwork.Binding(target), Status: status, StartedAt: time.Now().UTC()}
			if err = saveServerConnection(path, record); err != nil {
				t.Fatal(err)
			}
			rows, err := storedServerConnections(store, inv, []config.Target{target})
			if status == "failed-before-write" {
				if err != nil || len(rows) != 1 || rows[0].ServerID != "proxy" {
					t.Fatalf("safe rejected import hid valid provenance: %+v %v", rows, err)
				}
			} else if err == nil {
				t.Fatal("unknown write without receipt was silently ignored")
			}
		})
	}
}
