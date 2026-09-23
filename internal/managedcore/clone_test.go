package managedcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"go.yaml.in/yaml/v3"
)

type cloneFixture struct {
	target        config.Target
	opts          Options
	home, profile string
	mu            sync.Mutex
	selected      string
	writes        int
}

func newCloneFixture(t *testing.T, verge bool) *cloneFixture {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &cloneFixture{home: home, selected: "node"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != "GET" {
			f.writes++
			w.WriteHeader(500)
			return
		}
		if r.URL.Path != "/proxies" {
			t.Errorf("unexpected source call: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, `{"proxies":{"PROXY":{"type":"Selector","all":["node","other"],"now":%q},"Auto":{"type":"URLTest","all":["node","other"],"now":"other"},"node":{"type":"Shadowsocks"},"other":{"type":"Http"}}}`, f.selected)
	}))
	t.Cleanup(server.Close)
	f.target = config.Target{ID: "source", Controller: server.URL, Secret: "PRIVATE_MANAGEMENT_SECRET", Checks: []config.DiagnosticCheck{{ID: "claude", URL: "https://api.anthropic.com/", ExpectedStatuses: []int{404}}}}
	f.opts = Options{ReadOnly: true, Open: func(_ context.Context, target config.Target, ro bool) (*core.Client, io.Closer, error) {
		if !ro || target.ID != "source" {
			t.Error("source clone opened mutable or wrong target")
		}
		client, e := core.New(core.Options{Endpoint: server.URL, ReadOnly: true})
		return client, nil, e
	}}
	f.profile = filepath.Join(home, "config.yaml")
	f.target.Configs = []config.CoreConfig{{ID: "main", Path: f.profile}}
	f.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/usr/bin/mihomo", Home: home}
	if verge {
		f.profile = filepath.Join(home, "clash-verge.yaml")
		f.target.Configs = nil
		f.target.ConfigSource = &config.ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: home, ProfileUID: "active"}
		cloneFixtureWrite(t, filepath.Join(home, "profiles.yaml"), []byte("current: active\nitems:\n- {uid: active, type: local, file: active.yaml, option: {proxies: p, groups: g, rules: r, script: s, with_proxy: false}}\n- {uid: p, type: proxies, file: p.yaml}\n- {uid: g, type: groups, file: g.yaml}\n- {uid: r, type: rules, file: r.yaml}\n- {uid: s, type: script, file: s.js}\n- {uid: Merge, type: merge, file: merge.yaml}\n"))
		for _, name := range []string{"active.yaml", "p.yaml", "g.yaml", "r.yaml", "merge.yaml"} {
			cloneFixtureWrite(t, filepath.Join(home, "profiles", name), []byte("# native companion\n{}\n"))
		}
		cloneFixtureWrite(t, filepath.Join(home, "profiles", "s.js"), []byte("throw new Error('PRIVATE_SCRIPT_MUST_NOT_RUN');"))
		cloneFixtureWrite(t, filepath.Join(home, "config.yaml"), []byte("mode: direct\nsecret: PRIVATE_OWNER_SECRET\n"))
		cloneFixtureWrite(t, filepath.Join(home, "verge.yaml"), []byte("enable_system_proxy: true\n"))
	}
	profile := `secret: PRIVATE_MANAGEMENT_SECRET
external-controller: 127.0.0.1:9097
external-controller-pipe: old-pipe
external-ui: /old/ui
mixed-port: 7897
mode: direct
allow-lan: true
authentication: ["old:PRIVATE_INBOUND_SECRET"]
interface-name: en1
routing-mark: 7
post-up: PRIVATE_EXECUTABLE_MUST_NOT_RUN
tun: {enable: true, device: old-tun, auto-route: true}
listeners: [{name: old, type: mixed, port: 9000}]
dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver: [system]
  nameserver-policy: {"geosite:private": system}
proxies:
  - {name: node, type: ss, server: example.invalid, port: 443, cipher: aes-128-gcm, password: PRIVATE_NODE_PASSWORD, interface-name: en1}
  - {name: other, type: http, server: other.invalid, port: 443, tls: true, ca: ./tls/ca.pem}
proxy-providers:
  subscription: {type: http, url: "https://subscription.invalid/PRIVATE_TOKEN", path: ./cache/subscription.yaml, interval: 86400}
rule-providers:
  local: {type: file, behavior: classical, path: ./cache/rules.yaml}
proxy-groups:
  - {name: PROXY, type: select, proxies: [node, other]}
  - {name: Auto, type: url-test, proxies: [node, other], url: "https://example.com/"}
rules: ["DOMAIN-SUFFIX,example.com,PROXY", "GEOIP,CN,DIRECT", "MATCH,PROXY"]
`
	cloneFixtureWrite(t, f.profile, []byte(profile))
	cloneFixtureWrite(t, filepath.Join(home, "cache", "subscription.yaml"), []byte("proxies:\n- {name: cached, type: ss, server: cached.invalid, port: 443, cipher: aes-128-gcm, password: PRIVATE_PROVIDER_PASSWORD}\n"))
	cloneFixtureWrite(t, filepath.Join(home, "cache", "rules.yaml"), []byte("payload: [DOMAIN-SUFFIX,example.com]\n"))
	cloneFixtureWrite(t, filepath.Join(home, "tls", "ca.pem"), []byte("-----BEGIN CERTIFICATE-----\nPRIVATE_CERTIFICATE\n-----END CERTIFICATE-----\n"))
	cloneFixtureWrite(t, filepath.Join(home, "Country.mmdb"), []byte("country-fixture"))
	cloneFixtureWrite(t, filepath.Join(home, "GeoSite.dat"), []byte("geosite-fixture"))
	return f
}

func cloneFixtureWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCloneSnapshotsFlattenedVergeWithoutExecutingOrLeakingSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	f := newCloneFixture(t, true)
	before, _ := os.ReadFile(f.profile)
	snapshot, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceID != "source" || snapshot.ProfileUID != "active" || snapshot.SourceKind != "verge" || snapshot.Hash == "" || len(snapshot.Resources) != 5 || len(snapshot.Guards) != 15 {
		t.Fatalf("incomplete snapshot metadata: resources=%d guards=%d err=%v", len(snapshot.Resources), len(snapshot.Guards), err)
	}
	metadata, _ := json.Marshal(snapshot)
	if bytes.Contains(metadata, []byte("PRIVATE_")) {
		t.Fatalf("private source bytes leaked in metadata: %s", metadata)
	}
	if bytes.Contains(snapshot.Profile, []byte("PRIVATE_MANAGEMENT_SECRET")) || bytes.Contains(snapshot.Profile, []byte("PRIVATE_OWNER_SECRET")) || bytes.Contains(snapshot.Profile, []byte("PRIVATE_INBOUND_SECRET")) || !bytes.Contains(snapshot.Profile, []byte("PRIVATE_NODE_PASSWORD")) {
		t.Fatal("management credentials copied or outbound credential lost")
	}
	var doc map[string]any
	if err = yaml.Unmarshal(snapshot.Profile, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"secret", "external-controller", "external-controller-pipe", "tun", "mixed-port", "interface-name", "routing-mark", "post-up", "listeners", "authentication"} {
		if _, ok := doc[key]; ok {
			t.Fatalf("host field %s survived", key)
		}
	}
	if doc["mode"] != "rule" || len(doc["rules"].([]any)) != 3 || len(doc["proxy-groups"].([]any)) != 2 || len(doc["proxies"].([]any)) != 2 {
		t.Fatal("portable policy changed")
	}
	if snapshot.Selections["PROXY"] != "node" || len(snapshot.Selections) != 1 || len(snapshot.Checks) != 1 {
		t.Fatal("manual selections/checks not preserved")
	}
	for _, data := range snapshot.Resources {
		if bytes.Contains(data, []byte("PRIVATE_SCRIPT_MUST_NOT_RUN")) {
			t.Fatal("GUI script was copied into resources")
		}
	}
	after, _ := os.ReadFile(f.profile)
	if !bytes.Equal(before, after) || f.writes != 0 {
		t.Fatal("source/runtime mutated")
	}
	if err = CheckCloneSnapshot(context.Background(), f.target, snapshot, f.opts); err != nil {
		t.Fatal(err)
	}
}

func TestCloneBuildRequestUsesPrivateBundleAndPinsOrigin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	f := newCloneFixture(t, false)
	snapshot, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, request, err := ApplyCloneToRequest(context.Background(), Request{ID: "destination", MixedPort: 7890, ControllerPort: 9090, Backend: "native"}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if request.InputKind != "yaml" || request.Preset != "preserve" || request.InputBaseDir != "" || request.CloneSourceSHA256 != snapshot.Hash || request.CloneSelections["PROXY"] != "node" {
		t.Fatal("clone request lost origin/policy")
	}
	// Destination build cannot read source files or fetch a replacement provider.
	if err = os.RemoveAll(f.home); err != nil {
		t.Fatal(err)
	}
	profile, resources, _, warnings, err := buildProfile(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != len(snapshot.Resources) || len(warnings) == 0 {
		t.Fatal("private bundle was not consumed")
	}
	for name, data := range snapshot.Resources {
		if !bytes.Equal(resources[name], data) {
			t.Fatalf("resource changed or was renamed twice: %s", name)
		}
	}
	if bytes.Contains(profile, []byte("PRIVATE_MANAGEMENT_SECRET")) || !bytes.Contains(profile, []byte("__LAZYCLASH_GENERATED_SECRET__")) {
		t.Fatal("destination controller identity was inherited")
	}
	request.CloneChecks[0].ExpectedStatuses[0] = 200
	if snapshot.Checks[0].ExpectedStatuses[0] != 404 {
		t.Fatal("request shares mutable source checks")
	}
	request.CloneSelections["PROXY"] = "other"
	if snapshot.Selections["PROXY"] != "node" {
		t.Fatal("request shares source selections")
	}
	snapshot.Profile[0] = '!'
	if _, _, err = ApplyCloneToRequest(context.Background(), Request{}, snapshot); err == nil {
		t.Fatal("tampered private profile accepted")
	}
}

func TestCloneSourceHashesGuardOwnerUIDResourcesAndSelections(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	f := newCloneFixture(t, true)
	initial, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	cloneFixtureWrite(t, filepath.Join(f.home, "profiles", "s.js"), []byte("// different native script; not executed"))
	next, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if next.Hash == initial.Hash || next.ProfileSHA256 != initial.ProfileSHA256 {
		t.Fatal("source-context-only change did not change clone origin")
	}
	if err = CheckCloneSnapshot(context.Background(), f.target, initial, f.opts); err == nil {
		t.Fatal("stale source accepted")
	}
	cloneFixtureWrite(t, filepath.Join(f.home, "cache", "rules.yaml"), []byte("payload: [DOMAIN,new.example]\n"))
	resourcesChanged, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil || resourcesChanged.Hash == next.Hash {
		t.Fatal("resource change not reflected")
	}
	f.mu.Lock()
	f.selected = "other"
	f.mu.Unlock()
	selected, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil || selected.Hash == resourcesChanged.Hash || selected.Selections["PROXY"] != "other" {
		t.Fatal("manual selection change not reflected")
	}
	index := filepath.Join(f.home, "profiles.yaml")
	raw, _ := os.ReadFile(index)
	cloneFixtureWrite(t, index, bytes.Replace(raw, []byte("current: active"), []byte("current: another"), 1))
	if _, err = SnapshotTarget(context.Background(), f.target, f.opts); err == nil {
		t.Fatal("changed active Verge UID accepted")
	}
}

func TestCloneRejectsChangingSourcesMissingCachesAndEscapingResources(t *testing.T) {
	for _, kind := range []string{"mid-read-change", "missing-provider", "outside-home", "symlink-escape", "invalid-selection"} {
		t.Run(kind, func(t *testing.T) {
			f := newCloneFixture(t, false)
			reader := func(_ context.Context, path string) (rulework.HostFile, error) { return cloneReadLocal(path) }
			switch kind {
			case "mid-read-change":
				count := 0
				reader = func(_ context.Context, path string) (rulework.HostFile, error) {
					if path == f.profile {
						count++
						if count == 2 {
							raw, _ := os.ReadFile(path)
							cloneFixtureWrite(t, path, append(raw, []byte("\n# changed")...))
						}
					}
					return cloneReadLocal(path)
				}
			case "missing-provider":
				os.Remove(filepath.Join(f.home, "cache", "subscription.yaml"))
			case "outside-home":
				raw, _ := os.ReadFile(f.profile)
				cloneFixtureWrite(t, f.profile, bytes.Replace(raw, []byte("./tls/ca.pem"), []byte("../private.pem"), 1))
			case "symlink-escape":
				outside := filepath.Join(t.TempDir(), "private.pem")
				cloneFixtureWrite(t, outside, []byte("outside"))
				os.Remove(filepath.Join(f.home, "tls", "ca.pem"))
				if err := os.Symlink(outside, filepath.Join(f.home, "tls", "ca.pem")); err != nil {
					t.Fatal(err)
				}
			case "invalid-selection":
				f.mu.Lock()
				f.selected = "absent"
				f.mu.Unlock()
			}
			if _, err := snapshotTarget(context.Background(), f.target, f.opts, reader); err == nil {
				t.Fatal("unsafe/incoherent clone accepted")
			}
		})
	}
}

func TestCloneRejectsMissingBundleAndSourceWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	f := newCloneFixture(t, false)
	snapshot, err := SnapshotTarget(context.Background(), f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	for name := range snapshot.Resources {
		delete(snapshot.Resources, name)
		break
	}
	if _, _, err = ApplyCloneToRequest(context.Background(), Request{}, snapshot); err == nil {
		t.Fatal("incomplete resource bundle accepted")
	}
	f.target.ConfigSource.Home = `C:\Users\User\mihomo`
	if _, err = SnapshotTarget(context.Background(), f.target, f.opts); err == nil || !strings.Contains(err.Error(), "Windows source") {
		t.Fatalf("unsupported Windows source not explicit: %v", err)
	}
}

func TestCloneDockerReadsContainerScopeRatherThanHostMount(t *testing.T) {
	f := newCloneFixture(t, false)
	originalHome := f.home
	f.target.ConfigSource = &config.ConfigSource{Kind: "docker", Container: "core", DockerHost: "unix:///var/run/docker.sock", HostPath: "/host/stale/config.yaml", CorePath: "/core/config.yaml", Home: "/core", Binary: "/mihomo"}
	f.target.Configs = nil
	reader := func(_ context.Context, path string) (rulework.HostFile, error) {
		if strings.HasPrefix(path, "/host/") {
			t.Fatal("read stale host bind mount")
		}
		relative, err := filepath.Rel("/core", path)
		if err != nil {
			return rulework.HostFile{}, err
		}
		file, err := cloneReadLocal(filepath.Join(originalHome, relative))
		file.Path = path
		file.Resolved = path
		return file, err
	}
	snapshot, err := snapshotTarget(context.Background(), f.target, f.opts, reader)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceKind != "docker" || len(snapshot.Resources) != 5 {
		t.Fatal("Docker dependency bundle incomplete")
	}
}

func TestCloneOwnedWindowsSourceUsesHostPathsAndPortableResources(t *testing.T) {
	f := newCloneFixture(t, false)
	f.target.HostOS = "windows"
	f.target.ManagedCoreID = "owned-source"
	f.target.Configs = []config.CoreConfig{{ID: "main", Path: "C:/owned/home/config.yaml"}}
	f.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "C:/owned/bin/mihomo.exe", Home: "C:/owned/home"}
	raw, _ := os.ReadFile(f.profile)
	raw = bytes.ReplaceAll(raw, []byte("./tls/ca.pem"), []byte("C:/owned/home/tls/ca.pem"))
	raw = bytes.ReplaceAll(raw, []byte("./cache/subscription.yaml"), []byte("C:/owned/home/cache/subscription.yaml"))
	cloneFixtureWrite(t, f.profile, raw)
	reader := func(_ context.Context, path string) (rulework.HostFile, error) {
		relative, err := hostpath.Rel("windows", "C:/owned/home", path)
		if err != nil {
			return rulework.HostFile{}, err
		}
		file, err := cloneReadLocal(filepath.Join(f.home, filepath.FromSlash(relative)))
		file.Path = path
		file.Resolved = path
		return file, err
	}
	snapshot, err := snapshotTarget(context.Background(), f.target, f.opts, reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 5 || bytes.Contains(snapshot.Profile, []byte("C:/owned")) {
		t.Fatal("Windows source paths were not relocated")
	}
	ctx, request, err := ApplyCloneToRequest(context.Background(), Request{ID: "destination", MixedPort: 7890, ControllerPort: 9090, Backend: "native"}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	profile, resources, _, _, err := buildProfile(ctx, request)
	if err != nil || len(resources) != 5 {
		t.Fatalf("Windows-derived portable bundle failed: %v", err)
	}
	var document map[string]any
	if err = yaml.Unmarshal(profile, &document); err != nil {
		t.Fatal(err)
	}
	if document["profile"].(map[string]any)["store-selected"] != true {
		t.Fatal("cloned selector choices would not persist")
	}
	f.target.ManagedCoreID = ""
	if _, err = SnapshotTarget(context.Background(), f.target, f.opts); err == nil {
		t.Fatal("unowned Windows source silently used Unix reader")
	}
}

func TestCloneFixedRemoteReaderIsBoundedAndDoesNotExecuteFileContent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is unavailable")
	}
	path := filepath.Join(t.TempDir(), "source.yaml")
	data := []byte("secret: PRIVATE_SOURCE_CONTENT\n# $(touch must-not-exist)\n")
	cloneFixtureWrite(t, path, data)
	file, err := cloneReadRemote(context.Background(), config.Target{}, path, false)
	if err != nil || !bytes.Equal(file.Data, data) || file.SHA256 != hashBytes(data) || file.Fingerprint == "" {
		t.Fatalf("fixed read helper failed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("fixed read helper changed its input")
	}
	oversize := filepath.Join(t.TempDir(), "oversize")
	f, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(cloneFileLimit + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cloneReadRemote(context.Background(), config.Target{}, oversize, false); err == nil {
		t.Fatal("oversized source accepted")
	}
}

// Explicitly opt-in and read-only: it never stages or applies a destination.
func TestCloneLiveSourceReadOnly(t *testing.T) {
	id := os.Getenv("LAZYCLASH_CLONE_LIVE_TARGET")
	if id == "" {
		t.Skip("set LAZYCLASH_CLONE_LIVE_TARGET for a read-only source snapshot audit")
	}
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	var target config.Target
	for _, candidate := range cfg.Targets {
		if candidate.ID == id {
			target = candidate
			break
		}
	}
	if target.ID == "" {
		t.Fatal("requested live source is not registered")
	}
	snapshot, err := SnapshotTarget(context.Background(), target, Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = yaml.Unmarshal(snapshot.Profile, &document); err != nil {
		t.Fatal(err)
	}
	count := func(key string) int { items, _ := document[key].([]any); return len(items) }
	t.Logf("read-only snapshot: source=%s nodes=%d groups=%d rules=%d resources=%d guards=%d selections=%d", snapshot.SourceID, count("proxies"), count("proxy-groups"), count("rules"), len(snapshot.Resources), len(snapshot.Guards), len(snapshot.Selections))
	if _, _, err = ApplyCloneToRequest(context.Background(), Request{ID: "snapshot-validation-only"}, snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestCloneSnapshotWindowsBudgetRemainsBoundedAndHonorsParent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		windows bool
		parent  bool
		want    time.Duration
	}{{"native", false, false, 2 * time.Minute}, {"owned-windows", true, false, 10 * time.Minute}, {"parent-deadline", true, true, 30 * time.Second}} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && !tc.windows {
				t.Skip("local POSIX source snapshot; Windows adapter cases still run")
			}
			f := newCloneFixture(t, false)
			if tc.windows {
				f.target.HostOS = "windows"
				f.target.ManagedCoreID = "owned-source"
				f.target.Configs = []config.CoreConfig{{ID: "main", Path: "C:/owned/home/config.yaml"}}
				f.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "C:/owned/bin/mihomo.exe", Home: "C:/owned/home"}
			}
			ctx := context.Background()
			if tc.parent {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.want)
				defer cancel()
			}
			inspected := false
			stop := errors.New("context inspected")
			reader := func(ctx context.Context, _ string) (rulework.HostFile, error) {
				inspected = true
				deadline, ok := ctx.Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining > tc.want || remaining < tc.want-5*time.Second {
					t.Fatalf("wrong bounded snapshot budget: %v", remaining)
				}
				return rulework.HostFile{}, stop
			}
			_, err := snapshotTarget(ctx, f.target, f.opts, reader)
			if !inspected || !errors.Is(err, stop) {
				t.Fatal("reader context was not checked", err)
			}
		})
	}
}
