package managedcore

import (
	"context"
	"encoding/json"
	"go.yaml.in/yaml/v3"
	"strings"
	"testing"
)

func TestBundledPresetIntegrityAndOrder(t *testing.T) {
	manifest, err := verifiedRuleManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) == 0 {
		t.Fatal("empty manifest")
	}
	_, rules, resources, version, err := presetRules("cn-split", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(toStrings(rules), "\n")
	if !strings.HasSuffix(joined, "MATCH,PROXY") || !strings.Contains(joined, "cn-domain,DIRECT") || version == "" {
		t.Fatal(joined)
	}
	if len(resources) < 14 {
		t.Fatal("attribution or offline resources missing", len(resources))
	}
}
func TestProfileManagedListenersAndTUNAreExplicit(t *testing.T) {
	req := Request{ID: "demo", Backend: "docker", InputKind: "links", Input: []byte("vless://123e4567-e89b-12d3-a456-426614174000@example.test:443?security=tls#test"), Preset: "simple", ControllerPort: 19090, MixedPort: 17890, Network: NetworkOptions{TUN: true, ExcludedRoutes: []string{"100.64.0.0/10"}, DNSPolicies: map[string][]string{"+.tail.test": {"100.100.100.100"}}, FakeIPFilter: []string{"+.tail.test"}}}
	data, _, _, _, err := buildProfile(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if yaml.Unmarshal(data, &doc) != nil {
		t.Fatal("bad profile")
	}
	if doc["external-controller"] != "127.0.0.1:19090" || doc["secret"] != "__LAZYCLASH_GENERATED_SECRET__" {
		t.Fatal("controller not pinned")
	}
	tun := doc["tun"].(map[string]any)
	if tun["auto-route"] != true || tun["auto-redirect"] != false || tun["strict-route"] != false {
		t.Fatal(tun)
	}
	if _, exists := tun["dns-hijack"]; exists {
		t.Fatal("broad DNS hijack bypassed review")
	}
	req.Backend = "native"
	req.Network.ExcludedRoutes = []string{"invalid"}
	if _, _, _, _, err = buildProfile(context.Background(), req); err == nil {
		t.Fatal("invalid route accepted")
	}
}
func TestPublicInstancesOmitOwnerAndGuardSecrets(t *testing.T) {
	data, _ := json.Marshal(Instance{ID: "demo", OwnerToken: "private-owner", CoreGuardRef: "private-core-guard", ProxyGuardRef: "private-proxy-guard"})
	if strings.Contains(string(data), "private-") {
		t.Fatal(string(data))
	}
}

func TestManagedValidationDistinguishesTransportAndFilePaths(t *testing.T) {
	instance := Instance{Root: "/var/lib/lazyclash/cores/example", Backend: "native"}
	good := map[string]any{"proxies": []any{map[string]any{"ws-opts": map[string]any{"path": "/websocket"}}}, "proxy-providers": map[string]any{"nodes": map[string]any{"path": "./providers/nodes.yaml"}}}
	if err := validateOwnedResources(good, instance); err != nil {
		t.Fatal(err)
	}
	bad := map[string]any{"proxy-providers": map[string]any{"nodes": map[string]any{"path": "/etc/shadow"}}}
	if err := validateOwnedResources(bad, instance); err == nil {
		t.Fatal("outside provider accepted")
	}
}

func TestFullYAMLPresetReplacesGeodataAndKeepsDNSHijackVisible(t *testing.T) {
	request := Request{ID: "fixture", Backend: "native", InputKind: "yaml", Preset: "cn-split", ControllerPort: 19090, MixedPort: 17890, Network: NetworkOptions{TUN: true}, Input: []byte("proxies: []\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\nrules: [GEOIP,CN,DIRECT]\ntun:\n  enable: true\n  dns-hijack: [any:53]\ndns:\n  enable: true\n  nameserver: [https://example.test/dns-query]\n")}
	data, _, _, warnings, err := buildProfile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "any:53") || !strings.Contains(strings.Join(warnings, "\n"), "DNS hijack is preserved") {
		t.Fatal("DNS policy was silently erased", string(data), warnings)
	}
}
