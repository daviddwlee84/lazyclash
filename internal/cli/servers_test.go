package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/serverdeploy"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func serverCLIFixture(t *testing.T) (Dependencies, *[]string) {
	t.Helper()
	isolated(t)
	dir := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}
	if err := store.Update(func(inv *serverstate.Inventory) error {
		return inv.UpsertHost(serverstate.Host{ID: "vm", Provider: "ssh", SSHHost: "fixture-host", PublicHost: "203.0.113.10", Status: "registered"})
	}); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	deps := Dependencies{ServerStore: store, Terminal: func(io.Reader, io.Writer) bool { return false }, Discover: func(context.Context, string) ([]config.Target, error) {
		t.Fatal("server operation discovered a client controller")
		return nil, nil
	}}
	deps.Servers = serverdeploy.Options{Execute: func(_ context.Context, host string, r serverdeploy.RemoteRequest) (serverdeploy.RemoteResponse, error) {
		if host != "fixture-host" {
			t.Fatal("wrong SSH host", host)
		}
		calls = append(calls, r.Op)
		return serverdeploy.RemoteResponse{OK: true, Arch: "amd64", OS: "ubuntu", Service: "active", Owned: true}, nil
	}, Resolve: func(_ context.Context, r serverdeploy.Request, arch string) (serverdeploy.Artifact, error) {
		return serverdeploy.Artifact{Version: "v26.8.29", Arch: arch, URL: "https://github.com/XTLS/Xray-core/releases/download/v26.8.29/Xray-linux-64.zip", SHA256: strings.Repeat("a", 64), Image: "ghcr.io/xtls/xray-core@sha256:" + strings.Repeat("b", 64), Source: "fixture"}, nil
	}, Probe: func(context.Context, []byte) (string, error) { return "203.0.113.10", nil }}
	return deps, &calls
}

func deployedCLIServer(t *testing.T, deps Dependencies) serverdeploy.Plan {
	t.Helper()
	out, _, err := run(t, deps, "servers", "deploy", "demo", "--host", "vm", "--json")
	var p serverdeploy.Plan
	if err != nil || json.Unmarshal([]byte(out), &p) != nil {
		t.Fatal("preview", err, out)
	}
	out, _, err = run(t, deps, "servers", "deploy", "demo", "--host", "vm", "--yes", "--expect", p.Digest, "--json")
	var result serverdeploy.Result
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || result.Status != "ready" {
		t.Fatal("apply", err, out)
	}
	return p
}

func TestServerCLIInventoryAndRecipesAreOffline(t *testing.T) {
	deps, calls := serverCLIFixture(t)
	for _, args := range [][]string{{"servers", "list", "--json"}, {"servers", "recipes", "--json"}} {
		out, _, err := run(t, deps, args...)
		if err != nil || !json.Valid([]byte(out)) {
			t.Fatal(args, err, out)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("offline reads contacted SSH", calls)
	}
}

func TestServerCLIReviewedDeployAndServiceActions(t *testing.T) {
	deps, calls := serverCLIFixture(t)
	out, _, err := run(t, deps, "servers", "deploy", "demo", "--host", "vm", "--json")
	var p serverdeploy.Plan
	if err != nil || json.Unmarshal([]byte(out), &p) != nil {
		t.Fatal(err, out)
	}
	if p.Digest == "" || p.Backend != "native" || p.Recipe != "vless-reality" || strings.Contains(out, "private_key") || strings.Contains(out, "vless://") {
		t.Fatal("invalid or credential-bearing preview", out)
	}
	for _, call := range *calls {
		if call != "inspect" {
			t.Fatal("preview wrote remote state", calls)
		}
	}
	if _, err := os.Stat(deps.ServerStore.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview persisted state", err)
	}
	_, _, err = run(t, deps, "servers", "deploy", "demo", "--host", "vm", "--yes", "--expect", strings.Repeat("f", 64), "--json")
	if err == nil {
		t.Fatal("mismatched digest accepted")
	}
	for _, call := range *calls {
		if call != "inspect" {
			t.Fatal("wrong digest wrote remote state")
		}
	}
	deployedCLIServer(t, deps)
	out, _, err = run(t, deps, "servers", "stop", "demo", "--json")
	if err != nil || json.Unmarshal([]byte(out), &p) != nil {
		t.Fatal(err, out)
	}
	before := len(*calls)
	out, _, err = run(t, deps, "servers", "stop", "demo", "--yes", "--expect", p.Digest, "--json")
	if err != nil {
		t.Fatal(err, out)
	}
	if len(*calls) != before+1 || (*calls)[before] != "stop" {
		t.Fatal("stop did not use owned-service action", calls)
	}
	inv, err := deps.ServerStore.Load()
	if err != nil || len(inv.Hosts) != 1 || inv.Hosts[0].Status != "registered" || inv.Deployments[0].Status != "stopped" {
		t.Fatal("service stop changed VPS", inv, err)
	}
}

func TestServerCLIJSONAndInvalidInteractiveFlagsNeverPrompt(t *testing.T) {
	deps, calls := serverCLIFixture(t)
	deps.Terminal = func(io.Reader, io.Writer) bool { return true }
	for _, args := range [][]string{
		{"servers", "deploy", "--json"}, {"servers", "deploy", "demo", "--json"}, {"servers", "deploy", "--interactive", "--json"}, {"servers", "deploy", "--recipe", "invalid", "--interactive"}, {"servers", "deploy", "--backend", "docker", "--interactive"}, {"servers", "deploy", "--public-port", "0", "--interactive"}, {"servers", "deploy", "INVALID_ID", "--interactive"}, {"servers", "deploy", "--public-host", "https://invalid.test", "--interactive"}, {"servers", "deploy", "--version", "bogus", "--interactive"},
		{"servers", "deploy", "demo", "--host", "vm", "--yes", "--json"}, {"servers", "deploy", "demo", "--host", "vm", "--expect", strings.Repeat("a", 64), "--json"}, {"servers", "deploy", "demo", "--host", "vm", "--yes", "--expect", "short", "--json"},
		{"--read-only", "servers", "deploy", "demo", "--host", "vm", "--yes", "--expect", strings.Repeat("a", 64), "--json"}, {"servers", "status", "demo", "--interactive", "--json"}, {"servers", "export", "demo", "--format", "invalid", "--interactive"}, {"servers", "connect", "demo", "--interactive", "--json"},
		{"--ssh", "wrong-owner", "servers", "deploy", "demo", "--host", "vm", "--json"}, {"--controller", "http://127.0.0.1:9090", "servers", "status", "demo", "--json"},
	} {
		out, _, err := run(t, deps, args...)
		if err == nil || out != "" {
			t.Fatalf("%v: %v %q", args, err, out)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("invalid flags contacted SSH", calls)
	}
}

func TestServerCLIExportsPrivateFilesAndStructuredText(t *testing.T) {
	deps, _ := serverCLIFixture(t)
	deployedCLIServer(t, deps)
	for _, format := range []string{"uri", "mihomo", "starter", "client-bundle"} {
		out, _, err := run(t, deps, "servers", "export", "demo", "--format", format, "--json")
		var result struct {
			Content string `json:"content"`
		}
		if err != nil || json.Unmarshal([]byte(out), &result) != nil || result.Content == "" {
			t.Fatal(format, err, out)
		}
		if strings.Contains(result.Content, "private_key") {
			t.Fatal("client bundle leaked server key", format)
		}
	}
	for _, format := range []string{"qr", "admin-bundle"} {
		out, _, err := run(t, deps, "servers", "export", "demo", "--format", format, "--json")
		if err == nil || out != "" {
			t.Fatal("binary/private keys printed without file", format, err, out)
		}
	}
	path := filepath.Join(t.TempDir(), "node.png")
	if _, _, err := run(t, deps, "--read-only", "servers", "export", "demo", "--format", "qr", "--output", path, "--json"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("invalid QR", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("export is not private")
	}
	if _, _, err := run(t, deps, "servers", "export", "demo", "--output", path, "--json"); err == nil {
		t.Fatal("export overwrote file")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("existing export changed")
	}
}

func TestServerConnectPreviewUsesExistingClientSource(t *testing.T) {
	deps, _ := serverCLIFixture(t)
	deployedCLIServer(t, deps)
	settings, dir := sourceCLIFixture(t)
	before, err := os.ReadFile(filepath.Join(dir, "source.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, deps, "--config", settings, "--target", "saved", "servers", "connect", "demo", "--group", "G", "--json")
	var plan configwork.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil || plan.TargetID != "saved" || plan.Digest == "" {
		t.Fatal(err, out)
	}
	if strings.Contains(out, "private_key") || strings.Contains(out, "uuid\": \"") {
		t.Fatal("client preview leaked secret", out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "source.yaml"))
	if !bytes.Equal(before, after) {
		t.Fatal("client preview changed source")
	}
}

func TestServerConnectionRecoversInterruptedReceiptAndRefusesDuplicateApply(t *testing.T) {
	deps, _ := serverCLIFixture(t)
	target := config.Target{ID: "client", ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/usr/bin/true", Home: t.TempDir()}}
	path, err := serverConnectionPath(deps.ServerStore, "demo", target)
	if err != nil {
		t.Fatal(err)
	}
	record := serverConnection{ServerID: "demo", TargetID: target.ID, Binding: configwork.Binding(target), Digest: strings.Repeat("a", 64), Status: "applying", StartedAt: time.Now().UTC().Add(-time.Second)}
	if err = saveServerConnection(path, record); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(filepath.Dir(path), "receipts")
	id := strings.Repeat("a", 32)
	receipt := configwork.Receipt{ID: id, TargetID: target.ID, Binding: record.Binding, CreatedAt: time.Now().UTC(), Status: "write_result_unknown"}
	data, _ := json.Marshal(receipt)
	if err = serverstate.WritePrivate(filepath.Join(stateDir, id, "receipt.json"), data); err != nil {
		t.Fatal(err)
	}
	if recovered, err := recoverConnectionReceipt(record, stateDir); err != nil || recovered != id {
		t.Fatal("interrupted receipt not recovered", recovered, err)
	}
	_, err = applyServerConnection(context.Background(), deps.ServerStore, "demo", target, configwork.Request{}, record.Digest, path, configwork.Options{StateDir: stateDir, Validate: func(context.Context, config.Target, []byte, string) error {
		t.Fatal("duplicate imported again")
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "--verify") {
		t.Fatal("duplicate pending import not blocked", err)
	}
	receipt.ID = strings.Repeat("b", 32)
	data, _ = json.Marshal(receipt)
	if err = serverstate.WritePrivate(filepath.Join(stateDir, receipt.ID, "receipt.json"), data); err != nil {
		t.Fatal(err)
	}
	if _, err = recoverConnectionReceipt(record, stateDir); err == nil {
		t.Fatal("ambiguous receipt accepted")
	}
	if _, _, err = readServerConnection(path + "-missing"); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readServerConnection(path); err == nil {
		t.Fatal("public connection record accepted")
	}
}

func TestNewServerReadinessOnlyPollsSavedHostAndHonorsCancellation(t *testing.T) {
	host := serverstate.Host{ID: "created", ResourceID: "123", Status: "creating"}
	refreshes, probes := 0, 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ready, err := waitForServerHost(ctx, host, func(_ context.Context, id string) (serverstate.Host, error) {
		if id != "created" {
			t.Fatal("poll lost saved identity")
		}
		refreshes++
		next := host
		next.PublicHost = "203.0.113.10"
		next.SSHHost = "root@203.0.113.10"
		return next, nil
	}, func(context.Context, serverstate.Host) error {
		probes++
		if probes < 2 {
			return errors.New("SSH booting")
		}
		return nil
	}, 0)
	if err != nil || ready.ResourceID != "123" || refreshes != 2 || probes != 2 {
		t.Fatal("readiness polling", ready, refreshes, probes, err)
	}
	stopped, stop := context.WithCancel(context.Background())
	stop()
	retained, err := waitForServerHost(stopped, host, func(context.Context, string) (serverstate.Host, error) {
		t.Fatal("canceled readiness polled provider")
		return host, nil
	}, func(context.Context, serverstate.Host) error { t.Fatal("canceled readiness contacted SSH"); return nil }, 0)
	if !errors.Is(err, context.Canceled) || retained.ID != host.ID || retained.ResourceID != host.ResourceID {
		t.Fatal("cancellation lost existing resource", retained, err)
	}
}

func TestServerConnectPreservesUnknownImportAndRepeatOnlyVerifies(t *testing.T) {
	deps, _ := serverCLIFixture(t)
	deployedCLIServer(t, deps)
	dir := t.TempDir()
	source := filepath.Join(dir, "client.yaml")
	if err := os.WriteFile(source, []byte("proxies: []\nproxy-groups:\n- {name: G, type: select, proxies: [DIRECT]}\nrules: [MATCH,G]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int64
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "fixture", "meta": true})
		case "/configs":
			if r.Method == "PUT" {
				writes.Add(1)
				w.WriteHeader(http.StatusNoContent)
			} else {
				// The write succeeds, but the immediate readback is unavailable.
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case "/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"demo": map[string]any{"type": "VLESS"}, "G": map[string]any{"type": "Selector", "all": []string{"DIRECT", "demo"}}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controller.Close()
	validator := filepath.Join(dir, "validator")
	if err := os.WriteFile(validator, []byte("#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then printf 'Mihomo Meta fixture test\\n'; fi\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	target := config.Target{ID: "client", Controller: controller.URL, Configs: []config.CoreConfig{{ID: "main", Path: source}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Home: dir, Binary: validator}}
	settings := filepath.Join(dir, "config.toml")
	if err := config.Save(settings, config.Config{DefaultTarget: "client", Targets: []config.Target{target}}); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", settings, "--target", "client", "servers", "connect", "demo", "--group", "G", "--json"}
	out, _, err := run(t, deps, args...)
	var plan configwork.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil {
		t.Fatal(err, out)
	}
	out, _, err = run(t, deps, append(args, "--yes", "--expect", plan.Digest)...)
	var receipt configwork.Receipt
	if err == nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.ID == "" || !receipt.SourceVerified || receipt.Status != "runtime_result_unknown" {
		t.Fatal("unknown client import was not recorded", err, out)
	}
	if writes.Load() != 1 {
		t.Fatal("client runtime was not applied exactly once", writes.Load())
	}
	for _, suffix := range [][]string{nil, {"--verify"}} {
		recheck := []string{"--config", settings, "--target", "client", "servers", "connect", "demo", "--json"}
		recheck = append(recheck, suffix...)
		out, _, err = run(t, deps, recheck...)
		var verified configwork.Receipt
		if err != nil || json.Unmarshal([]byte(out), &verified) != nil || verified.ID != receipt.ID || !verified.SourceVerified || !verified.RuntimeObserved {
			t.Fatal("repeat did not verify saved receipt", err, out)
		}
	}
	if writes.Load() != 1 {
		t.Fatal("repeat performed another client write", writes.Load())
	}
}
