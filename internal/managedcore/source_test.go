package managedcore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedSourceBridgeKeepsOwnershipAndPrivateSnapshot(t *testing.T) {
	t.Setenv("LAZYCLASH_MANAGED_FIXTURE", "1")
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	opts := Options{StateDir: filepath.Join(t.TempDir(), "state")}
	opts.Execute = func(ctx context.Context, host string, priv bool, data []byte) ([]byte, error) {
		var req map[string]any
		json.Unmarshal(data, &req)
		req["fixture_root"] = base
		raw, _ := json.Marshal(req)
		return connection.ExecutePython(ctx, "", fullHostScript(), raw, 32<<20)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	zw.Write([]byte("fixture executable"))
	zw.Close()
	profile := []byte("mode: rule\nsecret: owner-secret\nproxies: []\nproxy-groups: []\nrules: [MATCH,DIRECT]\n")
	response, e := callHost(context.Background(), "", false, hostRequest{Op: "install", ID: "demo", Backend: "native", Version: DefaultVersion, ServiceScope: "user", OwnerToken: "owner", Ports: []int{19090, 17890}, Profile: profile, ProfileSHA256: hashBytes(profile), Artifact: compressed.Bytes(), ArtifactSHA256: hashBytes(compressed.Bytes()), Resources: map[string][]byte{"rules/test.list": []byte("DOMAIN,example.test")}}, opts)
	if e != nil {
		t.Fatal(e)
	}
	instance := Instance{ID: "demo", Backend: "native", Version: DefaultVersion, Root: filepath.Join(base, "demo"), ServiceScope: "user", OwnerToken: "owner", Digest: response.Digest, ProfileSHA256: hashBytes(profile), ResourceInventory: []string{"rules/test.list"}}
	path := filepath.Join(instance.Root, "home", "config.yaml")
	target := config.Target{ID: "demo", ManagedCoreID: "demo", Controller: "http://127.0.0.1:19090", ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "managed", Binary: filepath.Join(instance.Root, "bin", "mihomo"), Home: filepath.Join(instance.Root, "home")}}
	instance.Target = target
	request := Request{ID: "demo", Backend: "native", Version: DefaultVersion, ServiceScope: "user", ControllerPort: 19090, MixedPort: 17890, Input: profile, InputKind: "yaml", Preset: "preserve"}
	if e = saveInstance(instance, request, opts); e != nil {
		t.Fatal(e)
	}
	original, e := SourceOperation(context.Background(), target, configwork.HostRequest{Op: "read", Path: path}, opts)
	if e != nil {
		t.Fatal(e)
	}
	guard := configwork.HostGuard{Path: path, Fingerprint: original.File.Fingerprint}
	bad := bytes.ReplaceAll(profile, []byte("owner-secret"), []byte("different"))
	if _, e = SourceOperation(context.Background(), target, configwork.HostRequest{Op: "write", Path: path, Data: bad, Guards: []configwork.HostGuard{guard}}, opts); e == nil {
		t.Fatal("controller secret changed through node editor")
	}
	candidate := bytes.ReplaceAll(profile, []byte("proxies: []"), []byte("proxies: [{name: added, type: direct}]"))
	if _, e = SourceOperation(context.Background(), target, configwork.HostRequest{Op: "write", Path: path, Data: candidate, Guards: []configwork.HostGuard{guard}}, opts); e != nil {
		t.Fatal(e)
	}
	saved, e := LoadRequest("demo", opts)
	if e != nil || !bytes.Equal(saved.Input, candidate) || saved.Preset != "preserve" {
		t.Fatal("source snapshot lost", e)
	}
	if value, e := os.ReadFile(filepath.Join(saved.InputBaseDir, "rules/test.list")); e != nil || string(value) != "DOMAIN,example.test" {
		t.Fatal("provider snapshot missing", e)
	}
	target.Controller = "http://127.0.0.1:9999"
	if _, e = SourceOperation(context.Background(), target, configwork.HostRequest{Op: "read", Path: path}, opts); e == nil {
		t.Fatal("changed target controller accepted")
	}
}
func TestMutationLockSpansAllLocalStateCommits(t *testing.T) {
	opts := Options{StateDir: t.TempDir()}
	unlock, e := mutationLock("owned", opts)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := mutationLock("owned", opts); e == nil {
		second()
		t.Fatal("concurrent mutation accepted")
	}
	unlock()
	next, e := mutationLock("owned", opts)
	if e != nil {
		t.Fatal(e)
	}
	next()
}
func TestConfirmedPrecommitFailureRetainsDraftAndAllowsRetry(t *testing.T) {
	req, opts, _ := setupFixture(t)
	original := opts.Execute
	opts.Execute = func(ctx context.Context, host string, priv bool, raw []byte) ([]byte, error) {
		var request hostRequest
		json.Unmarshal(raw, &request)
		if request.Op == "install" {
			return json.Marshal(hostResponse{Error: "isolated validation failed", Status: "not_installed"})
		}
		return original(ctx, host, priv, raw)
	}
	plan, _ := Preview(context.Background(), req, opts)
	receipt, err := Apply(context.Background(), req, plan.Digest, opts)
	if err == nil || receipt.Status != "not_installed" {
		t.Fatal(receipt, err)
	}
	if _, err = GetInstance(req.ID, opts); !os.IsNotExist(err) {
		t.Fatal("failed install still reserves active ID", err)
	}
	if _, err = os.Stat(filepath.Join(opts.StateDir, "failed", receipt.ID, "input")); err != nil {
		t.Fatal("private failed draft lost", err)
	}
	opts.Execute = original
	plan, _ = Preview(context.Background(), req, opts)
	receipt, err = Apply(context.Background(), req, plan.Digest, opts)
	if err != nil || !strings.HasPrefix(receipt.Status, "running_") {
		t.Fatal(receipt, err)
	}
}
