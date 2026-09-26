package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

type darwinFixture struct {
	ops       []string
	uploads   map[string][]byte
	facts     darwinVergeFacts
	current   string
	intercept func(darwinVergeRequest) error
	egress    string
}

const darwinFixtureData = "/Users/david/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"

func newDarwinFixture(t *testing.T) (Request, Options, *darwinFixture) {
	t.Helper()
	f := &darwinFixture{current: "DIRECT", uploads: map[string][]byte{}, egress: "204", facts: darwinVergeFacts{OS: "darwin", Arch: "arm64", Home: "/Users/david", UID: 501, User: "david", ConsoleUser: "david", Launchd: true, HDIUtil: true, DataDir: darwinFixtureData, SudoNonInteractive: true, CFWRunning: true, CFWDaemons: []string{"com.lbyczf.cfw.helper"}, StateDigest: "facts"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"version":"v1.19.14","meta":true}`)
		case "/configs":
			io.WriteString(w, `{"mode":"rule","tun":{"enable":false}}`)
		case "/proxies":
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"PROXY": map[string]any{"type": "Selector", "now": f.current, "all": []string{"test", "DIRECT"}}}})
		case "/proxies/PROXY":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			f.current = v["name"]
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	dmg := []byte("verified dmg fixture")
	req := Request{ID: "mac-verge", SSHHost: "mac-alias", HostOS: "darwin", Client: "verge", ClientVersion: "2.5.2", InputKind: "links", Input: []byte("vless://123e4567-e89b-12d3-a456-426614174000@example.test:443?security=tls#test"), Preset: "simple", ControllerPort: 9097, MixedPort: 7897, CloneSelections: map[string]string{"PROXY": "test"}, Network: NetworkOptions{TUN: true, SystemProxy: true}, Boot: true}
	opts := Options{StateDir: filepath.Join(t.TempDir(), "state"), NetworkPlan: func(_ context.Context, _ string, n NetworkOptions) (NetworkOptions, []string, []string, error) {
		return n, nil, nil, nil
	}, ResolveArtifact: func(context.Context, Request, HostFacts) (Artifact, error) {
		return Artifact{Kind: "dmg", Version: WindowsVergeVersion, Size: int64(len(dmg)), SHA256: hashBytes(dmg), Platform: "darwin/arm64"}, nil
	}, FetchArtifact: func(context.Context, Artifact) ([]byte, error) { return dmg, nil }, Probe: func(context.Context, config.Target) error { return nil }, FreshManagement: func(context.Context, string) error { return nil }, Open: func(_ context.Context, _ config.Target, ro bool) (*core.Client, io.Closer, error) {
		c, e := core.New(core.Options{Endpoint: server.URL, ReadOnly: ro})
		return c, nil, e
	}, Upload: func(_ context.Context, host, local, remote string) error {
		data, err := os.ReadFile(local)
		f.uploads[filepath.Base(remote)] = data
		return err
	}}
	opts.Execute = func(_ context.Context, host string, privileged bool, raw []byte) ([]byte, error) {
		var r darwinVergeRequest
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		f.ops = append(f.ops, r.Op)
		if host != req.SSHHost || privileged != darwinVergePrivileged[r.Op] {
			t.Fatalf("wrong macOS transport for %s: %s privileged=%v", r.Op, host, privileged)
		}
		if f.intercept != nil {
			if err := f.intercept(r); err != nil {
				return nil, err
			}
		}
		response := darwinVergeResponse{Status: r.Op, Digest: "host-" + r.Op, Running: true, CoreVersion: "v1.19.14", Manifest: map[string]any{"gui_activated": true, "service_installed": true}}
		switch r.Op {
		case "facts":
			response.Facts = f.facts
		case "prepare-transfer":
			response.TransferPath = "/Users/david/.cache/lazyclash/managed-transfers/" + r.ID + "-" + r.TransferID
		case "install":
			if _, err := os.Stat(filepath.Join(opts.StateDir, "receipts")); err != nil {
				t.Fatal("host mutation before receipt", err)
			}
			if hashBytes(f.uploads["payload.json"]) != r.PayloadSHA256 || hashBytes(f.uploads["verge.dmg"]) != r.DMGSHA256 {
				t.Fatal("install references different transfer bytes")
			}
		case "launch-staged", "takeover", "start", "restart":
			if r.HelperSource == "" {
				t.Fatal("watchdog-arming operation lacks its helper source")
			}
			response.AckToken, response.Deadline = "ack-"+r.Op, time.Now().Add(3*time.Minute).Unix()
		case "verify-runtime":
			response.Manifest["loopback_listeners_verified"] = true
		case "verify-egress":
			response.Manifest = map[string]any{"via_proxy": f.egress, "direct": "204"}
		case "ack":
			if !strings.HasPrefix(r.AckToken, "ack-") {
				t.Fatal("ack without the armed token")
			}
		case "privilege-check", "cleanup-transfer", "status", "stop", "remove", "activate-source":
		default:
			t.Fatalf("unexpected macOS operation %s", r.Op)
		}
		return json.Marshal(response)
	}
	return req, opts, f
}

func darwinMirrorContext() context.Context {
	files := map[string][]byte{
		"profiles.yaml":       []byte("current: SRC\nitems:\n- uid: SRC\n  type: remote\n  file: SRC.yaml\n  url: https://PRIVATE-SUB.test/?token=PRIVATE\n- uid: Merge\n  type: merge\n  file: Merge.yaml\n"),
		"profiles/SRC.yaml":   []byte("proxies: []\n"),
		"profiles/Merge.yaml": []byte("prepend-rules: []\n"),
		"config.yaml":         []byte("mixed-port: 7890\nallow-lan: true\nsecret: SOURCE-SECRET\nexternal-controller: 0.0.0.0:9090\nexternal-controller-unix: /tmp/verge/verge-mihomo.sock\ntun:\n  enable: true\n  stack: gvisor\n"),
		"verge.yaml":          []byte("enable_tun_mode: true\nenable_system_proxy: true\nenable_auto_launch: true\nwebdav_password: PRIVATE-WEBDAV\nstartup_script: /tmp/evil.sh\ntheme_mode: dark\n"),
		"dns_config.yaml":     []byte("dns:\n  enable: true\n"),
		"geosite.dat":         []byte("geo"),
	}
	mirror := NativeMirror{SourceID: "local-verge", ProfileUID: "SRC", SHA256: map[string]string{}, Files: files}
	for name, data := range files {
		mirror.SHA256[name] = hashBytes(data)
	}
	return WithNativeMirror(context.Background(), mirror)
}

func TestDarwinVergePreviewStableDigestAndBlockers(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	r.CloneMode = "native"
	ctx := darwinMirrorContext()
	p, err := Preview(ctx, r, o)
	if err != nil || len(p.Blockers) > 0 {
		t.Fatalf("preview: %v %v", err, p.Blockers)
	}
	again, err := Preview(ctx, r, o)
	if err != nil || again.Digest != p.Digest {
		t.Fatal("unstable macOS Verge preview", err)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "SOURCE-SECRET") {
		t.Fatal("preview leaked private mirror content")
	}
	if len(p.NativeSHA256) != 7 {
		t.Fatalf("mirror inventory not pinned: %v", p.NativeSHA256)
	}
	for _, mutate := range []func(*darwinVergeFacts){
		func(d *darwinVergeFacts) { d.Arch = "amd64" },
		func(d *darwinVergeFacts) { d.ConsoleUser = "someone-else" },
		func(d *darwinVergeFacts) { d.AppExisting = true },
		func(d *darwinVergeFacts) { d.ServiceExisting = true },
		func(d *darwinVergeFacts) { d.Existing = true },
		func(d *darwinVergeFacts) { d.BusyPorts = []int{9097} },
	} {
		saved := f.facts
		mutate(&f.facts)
		blocked, err := Preview(ctx, r, o)
		f.facts = saved
		if err != nil || len(blocked.Blockers) == 0 {
			t.Fatalf("expected a blocker: %v %v", err, blocked.Blockers)
		}
	}
	if _, err = Preview(context.Background(), r, o); err == nil {
		t.Fatal("native clone mode without a mirror must fail")
	}
}

func TestDarwinVergeInstallOrderMirrorRewriteRegistersLast(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	r.CloneMode = "native"
	ctx := darwinMirrorContext()
	var registered []config.Target
	o.Register = func(target config.Target) error {
		if !slices.Contains(f.ops, "ack") {
			t.Fatal("registered before acknowledgement")
		}
		registered = append(registered, target)
		return nil
	}
	p, err := Preview(ctx, r, o)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := Apply(ctx, r, p.Digest, o)
	if err != nil || receipt.Status != "running_verified" {
		t.Fatalf("apply: %v %+v", err, receipt)
	}
	want := []string{"facts", "privilege-check", "prepare-transfer", "install", "cleanup-transfer", "launch-staged", "verify-runtime", "takeover", "verify-runtime", "verify-egress", "ack"}
	if got := slices.DeleteFunc(slices.Clone(f.ops), func(s string) bool { return s == "facts" && false }); !slices.Equal(got[len(got)-len(want):], want) {
		t.Fatalf("operation order: %v", f.ops)
	}
	if len(registered) != 1 || registered[0].HostOS != "darwin" || registered[0].ConfigSource.Kind != "verge" || registered[0].ConfigSource.ProfileUID != "SRC" || registered[0].ConfigSource.DataDir != darwinFixtureData {
		t.Fatalf("registered target: %+v", registered)
	}
	var payload struct {
		Files  map[string][]byte `json:"files"`
		Staged []byte            `json:"verge_staged"`
		Final  []byte            `json:"verge_final"`
	}
	if err = json.Unmarshal(f.uploads["payload.json"], &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload.Files["verge.yaml"]; ok {
		t.Fatal("verge.yaml must travel as staged/final settings")
	}
	if !strings.Contains(string(payload.Files["profiles.yaml"]), "PRIVATE-SUB") || payload.Files["profiles/Merge.yaml"] == nil {
		t.Fatal("native mirror lost profiles or companions")
	}
	var clash map[string]any
	yaml.Unmarshal(payload.Files["config.yaml"], &clash)
	secret, _ := os.ReadFile(registered[0].SecretFile)
	if clash["secret"] == "SOURCE-SECRET" || clash["secret"] != strings.TrimSpace(string(secret)) || clash["allow-lan"] != false || clash["external-controller"] != "127.0.0.1:9097" || clash["mixed-port"] != 7897 {
		t.Fatalf("config.yaml not rewritten for the destination: %v", clash)
	}
	tun := clash["tun"].(map[string]any)
	if tun["enable"] != false || !slices.Contains(testStrings(tun["route-exclude-address"]), "100.64.0.0/10") {
		t.Fatalf("TUN settings lack Tailnet exclusion: %v", tun)
	}
	var staged, final map[string]any
	yaml.Unmarshal(payload.Staged, &staged)
	yaml.Unmarshal(payload.Final, &final)
	if staged["enable_tun_mode"] != false || staged["enable_system_proxy"] != false || staged["enable_auto_launch"] != false {
		t.Fatalf("staged settings must keep TUN/system proxy/autostart off: %v", staged)
	}
	if final["enable_tun_mode"] != true || final["enable_system_proxy"] != true || final["enable_auto_launch"] != true || final["theme_mode"] != "dark" {
		t.Fatalf("final settings differ from reviewed 1:1 intent: %v", final)
	}
	if _, ok := final["webdav_password"]; ok || final["startup_script"] != nil {
		t.Fatal("credential or host-executed Verge settings were copied")
	}
	if f.current != "test" {
		t.Fatal("cloned selection was not applied through the controller")
	}
	status, err := GetStatus(context.Background(), r.ID, o)
	if err != nil || !status.ControllerHealthy {
		t.Fatalf("status: %v %+v", err, status)
	}
}

func testStrings(value any) []string {
	out := []string{}
	for _, item := range value.([]any) {
		out = append(out, item.(string))
	}
	return out
}

func TestDarwinVergeSudoRefusedBeforeLocalState(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	f.intercept = func(req darwinVergeRequest) error {
		if req.Op == "privilege-check" {
			return ErrSudoRefused
		}
		return nil
	}
	p, err := Preview(context.Background(), r, o)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(context.Background(), r, p.Digest, o)
	if err == nil || !strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("expected clear sudo refusal: %v", err)
	}
	if _, e := os.Stat(filepath.Join(o.StateDir, "instances", r.ID)); !os.IsNotExist(e) {
		t.Fatal("local state written before administrator authorization")
	}
	if slices.Contains(f.ops, "install") || slices.Contains(f.ops, "prepare-transfer") {
		t.Fatal("host mutation after sudo refusal")
	}
}

func TestDarwinVergeStagedFailureNeverTakesOver(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	o.Probe = func(context.Context, config.Target) error { return errors.New("probe failed") }
	p, _ := Preview(context.Background(), r, o)
	receipt, err := Apply(context.Background(), r, p.Digest, o)
	if err == nil || receipt.Status != "running_proxy_unverified" {
		t.Fatalf("expected staged failure: %v %s", err, receipt.Status)
	}
	if slices.Contains(f.ops, "takeover") || slices.Contains(f.ops, "ack") {
		t.Fatalf("CFW takeover after failed staged verification: %v", f.ops)
	}
}

func TestDarwinVergeFreshSSHFailureLeavesRollbackArmed(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	o.FreshManagement = func(context.Context, string) error { return errors.New("ssh lost") }
	p, _ := Preview(context.Background(), r, o)
	receipt, err := Apply(context.Background(), r, p.Digest, o)
	if err == nil || receipt.Status != "proxy_pending_rollback" || !receipt.NeedsACK || receipt.RollbackDeadline.IsZero() {
		t.Fatalf("expected armed rollback: %v %+v", err, receipt)
	}
	if slices.Contains(f.ops, "ack") {
		t.Fatal("acknowledged without a fresh SSH login")
	}
}

func TestDarwinVergeEgressFailureDoesNotAck(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	f.egress = "000"
	p, _ := Preview(context.Background(), r, o)
	if receipt, err := Apply(context.Background(), r, p.Digest, o); err == nil || receipt.Status != "proxy_pending_rollback" {
		t.Fatalf("expected egress failure: %v %s", err, receipt.Status)
	}
	if slices.Contains(f.ops, "ack") {
		t.Fatal("acknowledged without egress")
	}
}

func TestDarwinVergeLifecycleStopAndStart(t *testing.T) {
	r, o, f := newDarwinFixture(t)
	p, _ := Preview(context.Background(), r, o)
	if _, err := Apply(context.Background(), r, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"stop", "start"} {
		f.ops = nil
		plan, err := PreviewAction(context.Background(), r.ID, op, o)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := ApplyAction(context.Background(), r.ID, op, plan.Digest, o)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if op == "stop" && (!slices.Contains(f.ops, "stop") || receipt.Status != "stop") {
			t.Fatalf("stop: %v %+v", f.ops, receipt)
		}
		if op == "start" && (!slices.Contains(f.ops, "start") || !slices.Contains(f.ops, "ack") || receipt.Status != "running_verified") {
			t.Fatalf("start must re-verify and acknowledge: %v %+v", f.ops, receipt)
		}
	}
	if _, err := PreviewConfigure(context.Background(), r.ID, r, o); err == nil {
		t.Fatal("whole-instance reconfiguration must be refused")
	}
}

func TestDarwinVergeSourceRestrictedToDataDir(t *testing.T) {
	r, o, _ := newDarwinFixture(t)
	p, _ := Preview(context.Background(), r, o)
	if _, err := Apply(context.Background(), r, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	instance, err := loadInstance(r.ID, o)
	if err != nil {
		t.Fatal(err)
	}
	target := instance.Target
	for _, path := range []string{"/etc/hosts", darwinFixtureData + "/../escape.yaml"} {
		if _, err = SourceOperation(context.Background(), target, configwork.HostRequest{Op: "read", Path: path}, o); err == nil || !strings.Contains(err.Error(), "data directory") {
			t.Fatalf("path %s escaped the data directory: %v", path, err)
		}
	}
	changed := target
	changed.Controller = "http://127.0.0.1:1"
	if _, err = SourceOperation(context.Background(), changed, configwork.HostRequest{Op: "read", Path: darwinFixtureData + "/config.yaml"}, o); err == nil {
		t.Fatal("changed binding accepted")
	}
}

func TestSnapshotVergeNativeGuardsAndExclusions(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700)
		os.WriteFile(filepath.Join(dir, name), []byte(data), 0600)
	}
	write("profiles.yaml", "current: A\nitems:\n- uid: A\n  type: local\n  file: A.yaml\n- uid: B\n  type: local\n  file: B.yaml\n- uid: C\n  type: local\n  file: missing.yaml\n")
	write("profiles/A.yaml", "proxies: []\n")
	write("profiles/B.yaml", "proxies: []\n")
	write("config.yaml", "mixed-port: 1\n")
	write("verge.yaml", "theme_mode: dark\n")
	write("cache.db", "bolt")
	write("clash-verge.yaml", "generated: true\n")
	write("logs/latest.log", "log")
	target := config.Target{ID: "src", Controller: "http://127.0.0.1:9097", ConfigSource: &config.ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: dir, ProfileUID: "A"}}
	mirror, err := SnapshotVergeNative(context.Background(), target, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"profiles.yaml", "profiles/A.yaml", "profiles/B.yaml", "config.yaml", "verge.yaml"} {
		if _, ok := mirror.Files[name]; !ok {
			t.Fatalf("missing %s: %v", name, mirror.SHA256)
		}
	}
	for _, name := range []string{"cache.db", "clash-verge.yaml", "logs/latest.log"} {
		if _, ok := mirror.Files[name]; ok {
			t.Fatalf("excluded file %s was mirrored", name)
		}
	}
	if len(mirror.Warnings) < 2 {
		t.Fatal("missing non-active profile was not reported")
	}
	write("profiles.yaml", "current: B\nitems: []\n")
	if _, err = SnapshotVergeNative(context.Background(), target, Options{}); err == nil {
		t.Fatal("stale binding accepted")
	}
	write("profiles.yaml", "current: A\nitems:\n- uid: A\n  type: local\n  file: ../../etc/passwd\n")
	if _, err = SnapshotVergeNative(context.Background(), target, Options{}); err == nil {
		t.Fatal("index path escape accepted")
	}
}

func TestDarwinVergeHelperCompiles(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(t.TempDir(), "helper.py")
	if err = os.WriteFile(path, []byte(darwinVergeHostScript), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(python, "-m", "py_compile", path).CombinedOutput(); err != nil {
		t.Fatalf("helper does not compile: %v %s", err, out)
	}
	// An unknown operation returns a protocol error rather than a traceback.
	cmd := exec.Command(python, "-c", compactHostScript(darwinVergeHostScript))
	cmd.Stdin = strings.NewReader(`{"op":"nope","id":"x"}`)
	out, err := cmd.Output()
	if err != nil || !strings.Contains(string(out), "LAZYCLASH_MANAGED_RESULT=") {
		t.Fatalf("helper protocol: %v %s", err, out)
	}
}
