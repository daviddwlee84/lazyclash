package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Imported content must not interpolate the controller's generated credential.
// The placeholder can legitimately occur in node fields or untrusted URLs.
func TestReviewInstallInjectsOnlyTopLevelControllerSecret(t *testing.T) {
	request, opts, _ := setupFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "provider.yaml"), []byte("proxies:\n- {name: provider-node, type: trojan, server: provider.test, port: 443, password: provider-secret}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request.InputKind = "yaml"
	request.InputBaseDir = dir
	request.Preset = "preserve"
	request.Input = []byte("secret: original-controller\nproxies:\n- {name: node, type: trojan, server: example.test, port: 443, password: __LAZYCLASH_GENERATED_SECRET__}\nproxy-providers:\n  remote:\n    type: http\n    url: https://example.invalid/sub?token=__LAZYCLASH_GENERATED_SECRET__\n    path: ./provider.yaml\nproxy-groups:\n- {name: PROXY, type: select, proxies: [node], use: [remote]}\nrules:\n- MATCH,PROXY\nx-opaque: __LAZYCLASH_GENERATED_SECRET__\n")
	execute := opts.Execute
	checked := false
	opts.Execute = func(ctx context.Context, host string, priv bool, data []byte) ([]byte, error) {
		var message hostRequest
		if err := json.Unmarshal(data, &message); err != nil {
			t.Fatal(err)
		}
		if message.Op == "install" {
			var profile map[string]any
			if err := yaml.Unmarshal(message.Profile, &profile); err != nil {
				t.Fatal(err)
			}
			if profile["secret"] == "__LAZYCLASH_GENERATED_SECRET__" || profile["secret"] == "original-controller" {
				t.Fatal("controller secret was not generated")
			}
			proxy := profile["proxies"].([]any)[0].(map[string]any)
			if proxy["password"] != "__LAZYCLASH_GENERATED_SECRET__" {
				t.Error("node password was changed while injecting controller secret")
			}
			provider := profile["proxy-providers"].(map[string]any)["remote"].(map[string]any)
			if provider["url"] != "https://example.invalid/sub?token=__LAZYCLASH_GENERATED_SECRET__" {
				t.Error("controller credential interpolated into a provider URL")
			}
			if profile["x-opaque"] != "__LAZYCLASH_GENERATED_SECRET__" {
				t.Error("unrelated imported field was changed")
			}
			checked = true
		}
		return execute(ctx, host, priv, data)
	}
	plan, err := Preview(context.Background(), request, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(context.Background(), request, plan.Digest, opts); err != nil {
		t.Fatal(err)
	}
	if !checked {
		t.Fatal("install profile was not inspected")
	}
}

func TestReviewPreserveCopiesGeodataReferencedOnlyByDNS(t *testing.T) {
	dir := t.TempDir()
	contents := []byte("fixture geosite bytes; native validation is tested separately")
	if err := os.WriteFile(filepath.Join(dir, "GeoSite.dat"), contents, 0600); err != nil {
		t.Fatal(err)
	}
	request := Request{ID: "dns-fixture", Backend: "native", InputKind: "yaml", InputBaseDir: dir, Preset: "preserve", ControllerPort: 19090, MixedPort: 17890,
		Input: []byte("proxies:\n- {name: node, type: trojan, server: example.test, port: 443, password: p}\nproxy-groups:\n- {name: PROXY, type: select, proxies: [node]}\nrules:\n- MATCH,PROXY\ndns:\n  enable: true\n  nameserver: [system]\n  nameserver-policy:\n    geosite:cn: [https://223.5.5.5/dns-query]\n")}
	_, resources, _, _, err := buildProfile(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(resources["GeoSite.dat"]) != string(contents) {
		t.Fatal("DNS-only geosite dependency was omitted from offline resources")
	}
}

// Metadata-changing subscriptions must not apply different node bytes under a
// digest approved for an earlier response.
func TestReviewChangedSubscriptionInvalidatesReviewedDigest(t *testing.T) {
	request, opts, calls := setupFixture(t)
	request.InputKind = "subscription"
	request.Input = []byte("https://fixture.invalid/nodes")
	request.BootstrapTarget = "existing"
	body := "trojan://first-password@example.test:443#node"
	opts.DownloadClient = func(context.Context, string) (*http.Client, io.Closer, error) {
		return &http.Client{Transport: reviewRoundTrip(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}, nil, nil
	}
	plan, err := Preview(context.Background(), request, opts)
	if err != nil {
		t.Fatal(err)
	}
	body = "trojan://changed-password@example.test:443#node"
	if _, err = Apply(context.Background(), request, plan.Digest, opts); err == nil {
		t.Fatal("changed subscription applied with stale reviewed digest")
	}
	for _, operation := range *calls {
		if operation != "facts" {
			t.Fatal("stale subscription mutated host:", operation)
		}
	}
}

type reviewRoundTrip func(*http.Request) (*http.Response, error)

func (r reviewRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return r(request) }
func TestReviewConfigureUsesFreshOwnedResourcesAndPreservesSecret(t *testing.T) {
	request, opts, _ := setupFixture(t)
	inputDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(inputDir, "cached.yaml"), []byte("proxies:\n- {name: provider-node, type: trojan, server: provider.test, port: 443, password: initial}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request.InputKind = "yaml"
	request.InputBaseDir = inputDir
	request.Preset = "preserve"
	request.BootstrapTarget = "existing"
	request.Network.ExcludedRoutes = []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "100.64.0.0/10"}
	request.Network.FakeIPFilter = []string{"+.tail.test", "+.tail.test"}
	request.Input = []byte(`proxies: []
proxy-providers:
  remote:
    type: http
    url: https://fixture.invalid/sub
    path: ./cached.yaml
proxy-groups:
- {name: PROXY, type: select, use: [remote]}
rules:
- DOMAIN,first.test,PROXY
- IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
- IP-CIDR,100.64.0.0/10,PROXY,no-resolve
- DOMAIN-SUFFIX,tail.test,PROXY
- IP-CIDR,100.64.0.0/10,DIRECT
- IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
- MATCH,PROXY
dns:
  fake-ip-filter: [user-first.test, +.tail.test, user-last.test, +.tail.test, user-first.test]
x-opaque: retained
`)
	fetches := 0
	opts.DownloadClient = func(context.Context, string) (*http.Client, io.Closer, error) {
		return &http.Client{Transport: reviewRoundTrip(func(*http.Request) (*http.Response, error) {
			fetches++
			return nil, errors.New("unexpected subscription refresh")
		})}, nil, nil
	}
	originalExecute := opts.Execute
	var ownedProfile []byte
	var ownedResources map[string][]byte
	ownerDigest := "host-digest"
	configureCount := 0
	opts.Execute = func(ctx context.Context, host string, priv bool, data []byte) ([]byte, error) {
		var message hostRequest
		if err := json.Unmarshal(data, &message); err != nil {
			t.Fatal(err)
		}
		switch message.Op {
		case "install":
			ownedProfile = append([]byte{}, message.Profile...)
			ownedResources = message.Resources
		case "status":
			return json.Marshal(hostResponse{Running: true, Digest: ownerDigest, Manifest: map[string]any{"profile_sha256": hashBytes(ownedProfile), "network": NetworkOptions{}}})
		case "snapshot":
			return json.Marshal(hostResponse{Profile: ownedProfile, Resources: ownedResources})
		case "configure":
			var old, next map[string]any
			yaml.Unmarshal(ownedProfile, &old)
			yaml.Unmarshal(message.Profile, &next)
			if next["secret"] != old["secret"] {
				t.Error("configure rotated/lost existing controller secret")
			}
			if next["x-live-owner"] != "current" {
				t.Error("configure used stale local profile rather than current owner bytes")
			}
			if next["x-opaque"] != "retained" {
				t.Error("unknown imported field was lost")
			}
			wantRules := []string{
				"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
				"IP-CIDR6,fd7a:115c:a1e0::/48,DIRECT,no-resolve",
				"DOMAIN-SUFFIX,tail.test,DIRECT",
				"DOMAIN,first.test,PROXY",
				"IP-CIDR,100.64.0.0/10,PROXY,no-resolve",
				"DOMAIN-SUFFIX,tail.test,PROXY",
				"IP-CIDR,100.64.0.0/10,DIRECT",
				"MATCH,PROXY",
			}
			if got := toStrings(next["rules"].([]any)); strings.Join(got, "\n") != strings.Join(wantRules, "\n") {
				t.Errorf("generated bypass rules duplicated or unrelated rules changed on configure %d: %q", configureCount+1, got)
			}
			dns := next["dns"].(map[string]any)
			if got := toStrings(dns["fake-ip-filter"].([]any)); strings.Join(got, ",") != "user-first.test,+.tail.test,user-last.test,user-first.test" {
				t.Errorf("generated DNS filter duplicated or unrelated filter order changed on configure %d: %q", configureCount+1, got)
			}
			foundCurrent := false
			for _, resource := range message.Resources {
				if strings.Contains(string(resource), "fresh-owner-cache") {
					foundCurrent = true
				}
			}
			if !foundCurrent {
				t.Error("configure used original/stale provider data")
			}
			ownedProfile = message.Profile
			ownedResources = message.Resources
			ownerDigest = "configured-host-digest"
			configureCount++
			return json.Marshal(hostResponse{Status: "running_unverified", Digest: ownerDigest})
		}
		return originalExecute(ctx, host, priv, data)
	}
	plan, err := Preview(context.Background(), request, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(context.Background(), request, plan.Digest, opts); err != nil {
		t.Fatal(err)
	}
	// This represents a verified update by the owning application on the host.
	var current map[string]any
	yaml.Unmarshal(ownedProfile, &current)
	current["x-live-owner"] = "current"
	ownedProfile, _ = yaml.Marshal(current)
	ownerDigest = "current-owner-digest"
	for name := range ownedResources {
		if strings.HasPrefix(name, "providers/") {
			ownedResources[name] = []byte("proxies:\n- {name: provider-node, type: trojan, server: provider.test, port: 443, password: fresh-owner-cache}\n")
		}
	}
	if err = os.RemoveAll(inputDir); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		saved, err := LoadRequest(request.ID, opts)
		if err != nil {
			t.Fatal(err)
		}
		saved.Name = "Updated fixture"
		next, err := PreviewConfigure(context.Background(), request.ID, saved, opts)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := Configure(context.Background(), request.ID, saved, next.Digest, opts)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Target.Name != "Updated fixture" {
			t.Fatal("reviewed display name was ignored")
		}
	}
	if configureCount != 2 {
		t.Fatal("repeated configure not exercised")
	}
	if fetches != 0 {
		t.Fatal("unrelated configure refreshed a remote subscription")
	}
}
