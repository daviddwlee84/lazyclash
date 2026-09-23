package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"go.yaml.in/yaml/v3"
)

type windowsFixture struct {
	ops        []string
	installs   int
	selections int
	current    string
	generated  []byte
	hostDigest string
	facts      HostFacts
	intercept  func(windowsRequest) error
}

func newWindowsFixture(t *testing.T) (Request, Options, *windowsFixture) {
	t.Helper()
	f := &windowsFixture{current: "DIRECT", hostDigest: "host-before", facts: HostFacts{OS: "windows", Arch: "amd64", UserSID: "S-1-5-21-1001", InteractiveSession: 1, TaskScheduler: true, IsRoot: true, LocalAppData: "C:/Users/david/AppData/Local", ProgramFiles: "C:/Program Files", VergeDataDir: "C:/Users/david/AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev", WindowsStateDigest: "facts-before", WindowsProxy: &WindowsProxyState{Enabled: 1, Server: "127.0.0.1:7891", AutoConfigURL: "https://PRIVATE-PAC.test/?token=PRIVATE"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"version":"v1.19.31","meta":true}`)
		case "/configs":
			io.WriteString(w, `{"mode":"rule","tun":{"enable":false}}`)
		case "/proxies":
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"PROXY": map[string]any{"type": "Selector", "now": f.current, "all": []string{"test", "DIRECT"}}}})
		case "/proxies/PROXY":
			f.selections++
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			f.current = v["name"]
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	artifact := []byte("verified windows fixture")
	req := Request{ID: "windows-fixture", SSHHost: "windows-alias", HostOS: "windows", Client: "mihomo", InputKind: "links", Input: []byte("vless://123e4567-e89b-12d3-a456-426614174000@example.test:443?security=tls#test"), Preset: "simple", ControllerPort: 9097, MixedPort: 7897, CloneSelections: map[string]string{"PROXY": "test"}}
	opts := Options{StateDir: filepath.Join(t.TempDir(), "state"), ResolveArtifact: func(_ context.Context, r Request, h HostFacts) (Artifact, error) {
		return Artifact{Kind: "zip", Version: r.Version, Size: int64(len(artifact)), SHA256: hashBytes(artifact), Platform: "windows/amd64"}, nil
	}, FetchArtifact: func(context.Context, Artifact) ([]byte, error) { return artifact, nil }, Probe: func(context.Context, config.Target) error { return nil }, FreshManagement: func(context.Context, string) error { return nil }, Open: func(_ context.Context, _ config.Target, ro bool) (*core.Client, io.Closer, error) {
		c, e := core.New(core.Options{Endpoint: server.URL, ReadOnly: ro})
		return c, nil, e
	}}
	opts.Execute = func(_ context.Context, host string, priv bool, raw []byte) ([]byte, error) {
		var r windowsRequest
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		f.ops = append(f.ops, r.Op)
		if host != req.SSHHost || priv || r.HostOS != "windows" {
			t.Fatalf("wrong Windows transport: %s %v", host, priv)
		}
		if f.intercept != nil {
			if err := f.intercept(r); err != nil {
				return nil, err
			}
		}
		response := windowsResponse{Status: "running_verified", Digest: f.hostDigest, Running: true, CoreVersion: DefaultVersion, Manifest: map[string]any{"gui_activated": true}}
		switch r.Op {
		case "facts":
			response.Facts = f.facts
		case "install":
			f.installs++
			f.generated = r.Profile
			saved, err := LoadRequest(req.ID, opts)
			if err != nil || len(saved.Input) == 0 || saved.InputBaseDir == "" {
				t.Fatalf("host mutation before private resumable snapshot: %v", err)
			}
			if _, err = os.Stat(filepath.Join(opts.StateDir, "receipts")); err != nil {
				t.Fatal("host mutation before receipt", err)
			}
			if r.BeforeProxy == nil || r.BeforeProxy.AutoConfigURL != f.facts.WindowsProxy.AutoConfigURL {
				t.Fatal("private rollback snapshot lost")
			}
			response.Status = "running_unverified"
			response.Manifest["gui_activated"] = false
		case "source":
			response.Source = configwork.HostResponse{File: configwork.HostFile{Path: r.Source.Path, Data: f.generated, SHA256: hashBytes(f.generated), Fingerprint: "guard"}}
		case "takeover":
			response.Manifest = map[string]any{"rollback_armed": true, "rollback_deadline": time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339), "gui_activated": true}
		case "verify-runtime":
			response.Manifest["loopback_listeners_verified"] = true
			if r.VerifyGenerated {
				response.Source = configwork.HostResponse{File: configwork.HostFile{Data: f.generated}}
			}
		case "activate-gui", "ack", "start", "restart", "resume", "activate-source", "status", "stop", "remove":
		default:
			t.Fatalf("unexpected Windows operation %s", r.Op)
		}
		return json.Marshal(response)
	}
	return req, opts, f
}
func installWindowsFixture(t *testing.T, r Request, o Options) Receipt {
	t.Helper()
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil || len(p.Blockers) > 0 {
		t.Fatalf("preview: %v %v", e, p.Blockers)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e != nil {
		t.Fatal(e)
	}
	return receipt
}
func TestWindowsPreviewStableDigestAndPrivatePAC(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Client = "verge"
	r.ClientVersion = "2.5.2"
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	again, e := PreviewWindows(context.Background(), r, o)
	if e != nil || again.Digest != p.Digest {
		t.Fatal("unstable preview", e)
	}
	if p.Request.ClientVersion != WindowsVergeVersion {
		t.Fatal(p.Request.ClientVersion)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "PRIVATE") || p.Host.WindowsProxy.AutoConfigURL != "" || !p.Host.WindowsProxy.PACConfigured {
		t.Fatal("public registry credentials")
	}
	if _, e = os.Stat(o.StateDir); !os.IsNotExist(e) {
		t.Fatal("preview mutated local state")
	}
	r.CloneSelections["PROXY"] = "DIRECT"
	changed, e := PreviewWindows(context.Background(), r, o)
	if e != nil || changed.Digest == p.Digest {
		t.Fatal("clone selection not guarded", e)
	}
	f.facts.WindowsStateDigest = "new-proxy-state"
	if _, e = ApplyWindows(context.Background(), r, changed.Digest, o); e == nil {
		t.Fatal("changed host facts accepted")
	}
	if f.installs != 0 {
		t.Fatal("stale plan installed")
	}
}
func TestWindowsInstallStoresPrivateSnapshotBeforeMutationAndRegistersLast(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Network.SystemProxy = true
	registered := false
	o.Register = func(target config.Target) error {
		registered = true
		if f.ops[len(f.ops)-1] != "ack" {
			t.Fatal("registered before ack")
		}
		return config.ValidateTarget(target)
	}
	receipt := installWindowsFixture(t, r, o)
	if receipt.Status != "running_verified" || receipt.NeedsACK || !receipt.ProxyHealthy || !registered {
		t.Fatalf("unverified registration %#v", receipt)
	}
	instance, e := loadInstance(r.ID, o)
	if e != nil || !instance.WindowsInitialized {
		t.Fatal("initial verification not persisted", e)
	}
	if f.selections != 1 {
		t.Fatal("cloned selection not restored", f.selections)
	}
	info, e := os.Stat(instance.Target.SecretFile)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("controller reference not private", e)
	}
	if _, e = loadInstance(r.ID, o); e != nil {
		t.Fatal(e)
	}
}
func TestWindowsRestartPreservesLaterSelectionAndEditedGeneratedConfig(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Client = "verge"
	f.facts.WindowsProxy.Enabled = 0
	f.facts.WindowsProxy.AutoConfigURL = ""
	installWindowsFixture(t, r, o)
	f.current = "DIRECT"
	f.generated = []byte("proxies: []\nproxy-groups: []\nrules: [MATCH,DIRECT]\n")
	beforeSelections := f.selections
	p, e := WindowsPreviewAction(context.Background(), r.ID, "restart", o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := WindowsLifecycle(context.Background(), r.ID, "restart", p.Digest, o)
	if e != nil || receipt.Status != "running_verified" {
		t.Fatal(e, receipt.Status)
	}
	if f.selections != beforeSelections || f.current != "DIRECT" {
		t.Fatal("restart overwrote later user selection")
	}
}
func TestWindowsFailedProxyCheckNeverTakesOverOrRegisters(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Network.SystemProxy = true
	o.Probe = func(context.Context, config.Target) error { return errors.New("fixture probe blocked") }
	o.Register = func(config.Target) error { t.Fatal("unverified target registered"); return nil }
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e == nil || receipt.Status != "running_proxy_unverified" {
		t.Fatal(e, receipt.Status)
	}
	for _, op := range f.ops {
		if op == "takeover" || op == "ack" {
			t.Fatal("failed health changed previous owner", f.ops)
		}
	}
}

func TestWindowsProbeFailureDetailsAndRestartReceipt(t *testing.T) {
	result := diagnostics.LatencyResult{Route: "http://PRIVATE:SECRET@proxy.test", Sites: []diagnostics.SiteResult{
		{Name: "Google", URL: "https://PRIVATE.test/?token=SECRET", StatusCode: 204, Milliseconds: 410},
		{Name: "GitHub", URL: "https://github.com", Error: "request timed out", Milliseconds: 5001},
	}}
	failure := windowsProbeError(result, diagnostics.ErrPartial)
	if !errors.Is(failure, diagnostics.ErrPartial) || !strings.Contains(failure.Error(), "Google: HTTP 204 (410 ms)") || !strings.Contains(failure.Error(), "GitHub: request timed out (5001 ms)") || strings.Contains(failure.Error(), "PRIVATE") || strings.Contains(failure.Error(), "SECRET") {
		t.Fatalf("unsafe or incomplete per-site failure: %v", failure)
	}
	r, o, f := newWindowsFixture(t)
	installWindowsFixture(t, r, o)
	probeCalls := 0
	o.Probe = func(context.Context, config.Target) error { probeCalls++; return failure }
	plan, err := WindowsPreviewAction(context.Background(), r.ID, "restart", o)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.ops)
	receipt, err := WindowsLifecycle(context.Background(), r.ID, "restart", plan.Digest, o)
	if !errors.Is(err, diagnostics.ErrPartial) || receipt.Status != "running_proxy_unverified" || receipt.ProxyHealthy || !strings.Contains(receipt.Message, "after restart") || !strings.Contains(receipt.Message, "GitHub: request timed out") || strings.Contains(receipt.Message, "staged") || strings.Contains(receipt.Message, "CFW") {
		t.Fatalf("restart health receipt misreported: %v %#v", err, receipt)
	}
	if !reflect.DeepEqual(f.ops[before:], []string{"status", "restart", "verify-runtime"}) {
		t.Fatalf("probe failure changed lifecycle state: %v", f.ops[before:])
	}
	if probeCalls != 1 || len(receipt.Warnings) != 0 {
		t.Fatal("caller-provided probe was retried")
	}
	stored, err := os.ReadFile(filepath.Join(o.StateDir, "receipts", receipt.ID+".json"))
	if err != nil || !strings.Contains(string(stored), "GitHub: request timed out") {
		t.Fatal("per-site details not saved", err)
	}
}

func TestWindowsLifecycleDefaultProbeRetriesOnceAndRetainsEvidence(t *testing.T) {
	failed := diagnostics.LatencyResult{Sites: []diagnostics.SiteResult{{Name: "GitHub", Error: "request timed out", Milliseconds: 5000}}}
	for _, succeeds := range []bool{true, false} {
		t.Run(fmt.Sprint(succeeds), func(t *testing.T) {
			receipt := Receipt{}
			calls := 0
			started := time.Now()
			err := windowsLifecycleProbe(context.Background(), config.Target{}, &receipt, func(context.Context, config.Target) (diagnostics.LatencyResult, error) {
				calls++
				if calls == 2 && succeeds {
					return diagnostics.LatencyResult{}, nil
				}
				return failed, diagnostics.ErrPartial
			})
			if calls != 2 || time.Since(started) < time.Second || len(receipt.Warnings) != 1 || !strings.Contains(receipt.Warnings[0], "first HTTPS verification attempt failed") || !strings.Contains(receipt.Warnings[0], "GitHub: request timed out") {
				t.Fatalf("retry evidence missing: %d %v %#v", calls, err, receipt.Warnings)
			}
			if succeeds && (err != nil || !strings.Contains(receipt.Warnings[0], "All sites passed")) || !succeeds && (!errors.Is(err, diagnostics.ErrPartial) || !strings.Contains(receipt.Warnings[0], "retry also failed")) {
				t.Fatalf("retry outcome changed: %v %#v", err, receipt.Warnings)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls := 0
	receipt := Receipt{}
	err := windowsLifecycleProbe(ctx, config.Target{}, &receipt, func(context.Context, config.Target) (diagnostics.LatencyResult, error) {
		calls++
		return failed, diagnostics.ErrPartial
	})
	if calls != 1 || !errors.Is(err, context.DeadlineExceeded) || len(receipt.Warnings) != 1 || !strings.Contains(receipt.Warnings[0], "deadline canceled") {
		t.Fatalf("deadline did not bound retry: %d %v", calls, err)
	}
	calls = 0
	err = windowsLifecycleProbe(context.Background(), config.Target{}, nil, func(context.Context, config.Target) (diagnostics.LatencyResult, error) {
		calls++
		return failed, diagnostics.ErrPartial
	})
	if calls != 1 || !errors.Is(err, diagnostics.ErrPartial) {
		t.Fatal("source activation unexpectedly retried")
	}
}
func TestWindowsFreshManagementFailureRetainsRollbackReceipt(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Network.SystemProxy = true
	o.FreshManagement = func(context.Context, string) error { return errors.New("fresh SSH unavailable") }
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e == nil || receipt.ProxyHealthy || !receipt.NeedsACK || receipt.RollbackDeadline.IsZero() {
		t.Fatal(e, receipt)
	}
	for _, op := range f.ops {
		if op == "ack" {
			t.Fatal("fresh management failure disarmed rollback")
		}
	}
}
func TestWindowsTransitionFailureDoesNotReuseStagedProxyHealth(t *testing.T) {
	for _, tc := range []struct{ name, transition, failure string }{
		{"takeover-probe", "takeover", "probe"},
		{"gui-probe", "activate-gui", "probe"},
		{"takeover-unknown", "takeover", "transition"},
		{"gui-unknown", "activate-gui", "transition"},
		{"fresh-management", "takeover", "management"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, o, f := newWindowsFixture(t)
			installWindowsFixture(t, r, o)
			instance, err := loadInstance(r.ID, o)
			if err != nil {
				t.Fatal(err)
			}
			instance.Client = "verge"
			instance.WindowsGUIActivated = false
			instance.Network.SystemProxy = tc.transition == "takeover"
			calls := 0
			o.Probe = func(context.Context, config.Target) error {
				calls++
				if calls == 2 && tc.failure == "probe" {
					return errors.New("post-transition probe failed")
				}
				return nil
			}
			o.FreshManagement = func(context.Context, string) error {
				if tc.failure == "management" {
					return errors.New("fresh management failed")
				}
				return nil
			}
			f.intercept = func(r windowsRequest) error {
				if r.Op == tc.transition && tc.failure == "transition" {
					return errors.New("transition outcome unknown")
				}
				return nil
			}
			before := len(f.ops)
			receipt, err := finishWindowsActivation(context.Background(), instance, r, newReceipt(instance, "resume", instance.Digest, o), o)
			if err == nil || receipt.ProxyHealthy {
				t.Fatalf("staged health reused after transition failure: %v %#v", err, receipt)
			}
			raw, e := os.ReadFile(filepath.Join(o.StateDir, "receipts", receipt.ID+".json"))
			var saved Receipt
			if e != nil || json.Unmarshal(raw, &saved) != nil || saved.ProxyHealthy {
				t.Fatal("saved transition receipt claims healthy proxy", e)
			}
			for _, op := range f.ops[before:] {
				if op == "ack" {
					t.Fatal("failed transition was acknowledged")
				}
			}
			wantCalls := 1
			if tc.failure == "probe" {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("health checks=%d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestWindowsUnknownInstallerResumeNeverInstallsAgain(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	f.intercept = func(r windowsRequest) error {
		if r.Op == "install" {
			return errors.New("transport interrupted after launch")
		}
		if r.Op == "resume" {
			return errors.New("partial installer needs inspection")
		}
		return nil
	}
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e == nil || receipt.Status != "unknown_host_result" {
		t.Fatal(e, receipt.Status)
	}
	if _, e = ResumeWindows(context.Background(), r.ID, o); e == nil {
		t.Fatal("unknown installer resumed blindly")
	}
	count := 0
	for _, op := range f.ops {
		if op == "install" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("installer retried", f.ops)
	}
}
func TestWindowsReadOnlyBlocksAllMutations(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	installWindowsFixture(t, r, o)
	instance, _ := loadInstance(r.ID, o)
	count := len(f.ops)
	o.ReadOnly = true
	if _, e := ApplyWindows(context.Background(), r, "digest", o); e == nil {
		t.Fatal("read-only install")
	}
	if _, e := WindowsLifecycle(context.Background(), r.ID, "restart", "digest", o); e == nil {
		t.Fatal("read-only lifecycle")
	}
	if _, e := ResumeWindows(context.Background(), r.ID, o); e == nil {
		t.Fatal("read-only resume")
	}
	if _, e := WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "write"}, o); e == nil {
		t.Fatal("read-only source")
	}
	if e := WindowsActivateSource(context.Background(), instance.Target, o); e == nil {
		t.Fatal("read-only activation")
	}
	if count != len(f.ops) {
		t.Fatal("read-only host mutation", f.ops)
	}
}
func TestWindowsVergeColdSeedHasExactNativeSettingsAndCompanions(t *testing.T) {
	r := Request{Name: "clone", ControllerPort: 19097, MixedPort: 17897, CloneSelections: map[string]string{"PROXY": "test"}}
	files, e := windowsVergeFiles(r, []byte("mode: rule\n"), "private-secret", "lc_test", nil)
	if e != nil {
		t.Fatal(e)
	}
	var owner, app, index map[string]any
	if yaml.Unmarshal(files["config.yaml"], &owner) != nil || yaml.Unmarshal(files["verge.yaml"], &app) != nil || yaml.Unmarshal(files["profiles.yaml"], &index) != nil {
		t.Fatal("invalid native seed")
	}
	if _, bad := files["clash.yaml"]; bad {
		t.Fatal("wrong Verge owner filename")
	}
	if owner["external-controller"] != "127.0.0.1:19097" || owner["secret"] != "private-secret" || owner["mixed-port"] != 17897 || app["verge_mixed_port"] != 17897 || app["enable_external_controller"] != true || app["enable_system_proxy"] != false || app["enable_builtin_enhanced"] != false {
		t.Fatal("owner overrides clone settings")
	}
	items := index["items"].([]any)
	profile := items[0].(map[string]any)
	if !reflect.DeepEqual(profile["selected"], []any{map[string]any{"name": "PROXY", "now": "test"}}) {
		t.Fatal("native selection not persisted", profile["selected"])
	}
	for _, suffix := range []string{"merge.yaml", "script.js", "rules.yaml", "proxies.yaml", "groups.yaml"} {
		if len(files["profiles/lc_test_"+suffix]) == 0 {
			t.Fatal("missing companion", suffix)
		}
	}
}

func TestWindowsSourceRejectsOwnerPreferencesAndNonNodeChanges(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Client = "verge"
	f.facts.WindowsProxy.Enabled = 0
	f.facts.WindowsProxy.AutoConfigURL = ""
	installWindowsFixture(t, r, o)
	instance, _ := loadInstance(r.ID, o)
	writes := 0
	f.intercept = func(r windowsRequest) error {
		if r.Op == "source" && r.Source.Op == "write" {
			writes++
		}
		return nil
	}
	for _, path := range []string{winJoin(instance.Target.ConfigSource.Home, "config.yaml"), winJoin(instance.Target.ConfigSource.Home, "verge.yaml"), winJoin(instance.Target.ConfigSource.Home, "profiles", instance.ProfileUID+"_script.js")} {
		if _, e := WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "write", Path: path, Data: []byte("enable_system_proxy: true\n")}, o); e == nil {
			t.Fatal("generic source modified owner preferences")
		}
	}
	path := instance.Target.Configs[0].Path
	var candidate map[string]any
	yaml.Unmarshal(f.generated, &candidate)
	candidate["mixed-port"] = 8888
	raw, _ := yaml.Marshal(candidate)
	if _, e := WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "write", Path: path, Data: raw}, o); e == nil {
		t.Fatal("generic node source modified listener")
	}
	if writes != 0 {
		t.Fatal("forbidden source reached host write")
	}
}
func TestWindowsSourceRejectsForeignResourceBeforeValidation(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	installWindowsFixture(t, r, o)
	instance, _ := loadInstance(r.ID, o)
	before := len(f.ops)
	bad := map[string]any{"proxy-providers": map[string]any{"read-private": map[string]any{"type": "file", "path": "C:/Users/david/.ssh/id_ed25519"}}}
	if _, e := WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "validate", Document: bad}, o); e == nil {
		t.Fatal("foreign private resource accepted")
	}
	if len(f.ops) != before {
		t.Fatal("unsafe candidate reached executable")
	}
}
func TestWindowsStatusReadsControllerWithoutMutation(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	installWindowsFixture(t, r, o)
	before := f.selections
	ops := len(f.ops)
	status, e := WindowsStatus(context.Background(), r.ID, o)
	if e != nil || !status.ControllerHealthy {
		t.Fatal(e, status.Message)
	}
	if f.selections != before || !reflect.DeepEqual(f.ops[ops:], []string{"status"}) {
		t.Fatal("status mutated runtime", f.ops[ops:])
	}
}
func TestWindowsValidationRejectsHostHooks(t *testing.T) {
	instance := Instance{Root: "C:/Users/david/AppData/Local/lazyclash/cores/x"}
	for _, doc := range []map[string]any{{"post-up": []any{"malicious"}}, {"nested": map[string]any{"post-down": "command"}}} {
		if validateWindowsOwnedResources(doc, instance) == nil {
			t.Fatal("executable host hook accepted")
		}
	}
}

func TestWindowsRestartDoesNotOverwriteRegisteredTargetSettings(t *testing.T) {
	r, o, _ := newWindowsFixture(t)
	registered := 0
	o.Register = func(config.Target) error { registered++; return nil }
	installWindowsFixture(t, r, o)
	p, e := WindowsPreviewAction(context.Background(), r.ID, "restart", o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = WindowsLifecycle(context.Background(), r.ID, "restart", p.Digest, o); e != nil {
		t.Fatal(e)
	}
	if registered != 1 {
		t.Fatal("restart re-registered stale target settings", registered)
	}
}

func TestWindowsVergeStagesCoreBeforeGUIAndChecksGeneratedAfterTakeover(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Client = "verge"
	r.Network.SystemProxy = true
	installWindowsFixture(t, r, o)
	want := []string{"facts", "facts", "install", "verify-runtime", "takeover", "verify-runtime", "ack"}
	if !reflect.DeepEqual(f.ops, want) {
		t.Fatal("GUI staging verification order", f.ops)
	}
	instance, e := loadInstance(r.ID, o)
	if e != nil || !instance.WindowsGUIActivated {
		t.Fatal("native GUI phase not persisted", e)
	}
}
func TestWindowsVergeCannotLaunchWithoutTakeoverOfActiveProxy(t *testing.T) {
	r, o, _ := newWindowsFixture(t)
	r.Client = "verge"
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Blockers) == 0 {
		t.Fatal("GUI would silently clear active old proxy")
	}
}
func TestWindowsVergeRejectsUntrackedRASProxySettings(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Client = "verge"
	r.Network.SystemProxy = true
	f.facts.WindowsRASEntries = 1
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Blockers) == 0 {
		t.Fatal("GUI would modify untracked RAS proxy settings")
	}
}
func TestWindowsRuntimeListenerProofRequiredBeforeTakeover(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Network.SystemProxy = true
	f.intercept = func(r windowsRequest) error {
		if r.Op == "verify-runtime" {
			return errors.New("listener exposed outside loopback")
		}
		return nil
	}
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ApplyWindows(context.Background(), r, p.Digest, o); e == nil {
		t.Fatal("unproven listener accepted")
	}
	for _, op := range f.ops {
		if op == "takeover" || op == "ack" {
			t.Fatal("listener proof failure changed prior client", f.ops)
		}
	}
}

func TestWindowsExpiredVerificationReserveDoesNotAcknowledge(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Network.SystemProxy = true
	base := o.Execute
	o.Execute = func(ctx context.Context, host string, priv bool, raw []byte) ([]byte, error) {
		response, e := base(ctx, host, priv, raw)
		if e != nil {
			return response, e
		}
		var request windowsRequest
		json.Unmarshal(raw, &request)
		if request.Op == "takeover" {
			var value windowsResponse
			json.Unmarshal(response, &value)
			value.Manifest["rollback_deadline"] = time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339Nano)
			return json.Marshal(value)
		}
		return response, nil
	}
	o.FreshManagement = func(ctx context.Context, _ string) error {
		if ctx.Err() == nil {
			t.Fatal("ACK reserve was consumed by verification")
		}
		return ctx.Err()
	}
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e == nil || !receipt.NeedsACK {
		t.Fatal(e, receipt.NeedsACK)
	}
	for _, op := range f.ops {
		if op == "ack" {
			t.Fatal("expired takeover was acknowledged")
		}
	}
}
