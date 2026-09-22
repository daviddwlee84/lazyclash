package configwork

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

const sourceFixture = "# source comment\nsecret: never-in-output\nproxies:\n- name: node1\n  type: ss\n  server: example.test\n  port: 443\n  cipher: aes-128-gcm\n  password: original-secret\n  x-future: {mode: untouched}\nproxy-groups:\n- name: G1\n  type: select\n  proxies: [node1, DIRECT]\n  x-keep: yes\n- name: G2\n  type: fallback\n  proxies: [DIRECT, node1]\n  url: https://example.test/\n  interval: 300\nrules:\n- MATCH,G1\n"

type configFixture struct {
	target config.Target
	opts   Options
	base   string
	writes atomic.Int32
	reject bool
}

func newConfigFixture(t *testing.T, verge bool) *configFixture {
	t.Helper()
	dir := t.TempDir()
	f := &configFixture{}
	f.base = filepath.Join(dir, "config.yaml")
	if e := os.WriteFile(f.base, []byte(sourceFixture), 0600); e != nil {
		t.Fatal(e)
	}
	f.target = config.Target{ID: "fixture", Configs: []config.CoreConfig{{ID: "main", Path: f.base}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/not/executed", Home: dir}}
	if verge {
		home := filepath.Join(dir, "verge")
		os.MkdirAll(filepath.Join(home, "profiles"), 0700)
		manifest := "current: chosen\nitems:\n- uid: chosen\n  type: remote\n  file: base.yaml\n  option: {proxies: px, groups: gr}\n- {uid: px, type: proxies, file: proxies.yaml}\n- {uid: gr, type: groups, file: groups.yaml}\n"
		os.WriteFile(filepath.Join(home, "profiles.yaml"), []byte(manifest), 0600)
		f.base = filepath.Join(home, "profiles", "base.yaml")
		os.WriteFile(f.base, []byte(sourceFixture), 0600)
		for _, name := range []string{"proxies.yaml", "groups.yaml"} {
			os.WriteFile(filepath.Join(home, "profiles", name), []byte("# keep companion\nprepend: []\nappend: []\ndelete: []\n"), 0600)
		}
		f.target.ConfigSource = &config.ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: home, ProfileUID: "chosen"}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]any{"version": "fixture-version", "meta": true})
		case "/configs":
			if r.Method == "PUT" {
				f.writes.Add(1)
				if f.reject {
					w.WriteHeader(500)
					return
				}
				if r.URL.Query().Get("force") != "true" {
					t.Error("reload not force=true")
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"mode": "rule"})
		case "/proxies":
			s, e := inspect(context.Background(), f.target)
			if e != nil {
				t.Error(e)
				w.WriteHeader(500)
				return
			}
			entries := map[string]any{}
			for _, d := range append(s.Proxies, s.Groups...) {
				m := map[string]any{"name": d.Name, "type": d.Type}
				if d.Kind == "group" {
					var all []string
					for _, n := range membersContent(get(d.Node, "proxies")) {
						all = append(all, n.Value)
					}
					m["all"] = all
					m["type"] = d.Type
					if d.Type == "select" {
						m["type"] = "Selector"
					}
				}
				entries[d.Name] = m
			}
			json.NewEncoder(w).Encode(map[string]any{"proxies": entries})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	f.target.Controller = server.URL
	f.opts = Options{StateDir: filepath.Join(dir, "receipts"), Validate: func(_ context.Context, _ config.Target, raw []byte, version string) error {
		if version != "fixture-version" {
			return errors.New("wrong version")
		}
		_, e := decode(raw)
		return e
	}}
	return f
}
func TestNativeEditRetainsUnknownFieldsAndRestores(t *testing.T) {
	f := newConfigFixture(t, false)
	ctx := context.Background()
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: replacement-secret\n")}
	p, e := Preview(ctx, f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(p)
	for _, secret := range []string{"replacement-secret", "original-secret", "never-in-output"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("preview leaked credential")
		}
	}
	if _, e = os.Stat(f.opts.StateDir); !os.IsNotExist(e) {
		t.Fatal("preview wrote receipts")
	}
	r, e := Apply(ctx, f.target, req, p.Digest, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	if !r.SourceVerified || !r.RuntimeObserved {
		t.Fatalf("%+v", r)
	}
	data, _ := os.ReadFile(f.base)
	if !strings.Contains(string(data), "x-future") || !strings.Contains(string(data), "# source comment") || !strings.Contains(string(data), "replacement-secret") {
		t.Fatal("source loss")
	}
	r, e = Restore(ctx, f.target, r.ID, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Restored {
		t.Fatal(r)
	}
	data, _ = os.ReadFile(f.base)
	if string(data) != sourceFixture {
		t.Fatal("restore did not retain original exact bytes")
	}
}
func TestStalePreviewAndReadOnlyDoNotWrite(t *testing.T) {
	f := newConfigFixture(t, false)
	ctx := context.Background()
	req := Request{Kind: "group", Action: "edit", Name: "G1", Input: []byte("hidden: true\n")}
	p, e := Preview(ctx, f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(f.base, []byte(sourceFixture+"# external edit\n"), 0600)
	if _, e = Apply(ctx, f.target, req, p.Digest, f.opts); e == nil {
		t.Fatal("stale preview applied")
	}
	p, e = Preview(ctx, f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	f.opts.ReadOnly = true
	if _, e = Apply(ctx, f.target, req, p.Digest, f.opts); e == nil {
		t.Fatal("readonly applied")
	}
	if f.writes.Load() != 0 {
		t.Fatal("unexpected reload")
	}
}
func TestVergeReplacementCompensatesBothGroupsAndDoesNotTouchBase(t *testing.T) {
	f := newConfigFixture(t, true)
	ctx := context.Background()
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: replacement-secret\n")}
	p, e := Preview(ctx, f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Changes) != 2 || !strings.HasSuffix(p.Changes[0].Path, "groups.yaml") {
		t.Fatalf("need groups-first compensation: %+v", p.Changes)
	}
	if len(p.Warnings) < 2 {
		t.Fatal("missing group override warning")
	}
	for _, name := range []string{"G1", "G2"} {
		g, _ := find(p.source.Groups, name)
		if get(g.Node, "proxies") == nil {
			t.Fatal("group lost")
		}
	}
	r, e := Apply(ctx, f.target, req, p.Digest, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != "persisted_pending_owner_reload" || f.writes.Load() != 0 {
		t.Fatal(r)
	}
	base, _ := os.ReadFile(f.base)
	if string(base) != sourceFixture {
		t.Fatal("subscription source overwritten")
	}
	r, e = Verify(ctx, f.target, r.ID, f.opts)
	if e != nil || r.GeneratedVerified {
		t.Fatalf("missing generated file claimed verified: %+v %v", r, e)
	}
	s, e := inspect(ctx, f.target)
	if e != nil {
		t.Fatal(e)
	}
	generated, _ := encode(s.effective())
	os.WriteFile(filepath.Join(f.target.ConfigSource.DataDir, "clash-verge.yaml"), generated, 0600)
	r, e = Verify(ctx, f.target, r.ID, f.opts)
	if e != nil || !r.GeneratedVerified || !r.RuntimeObserved {
		t.Fatalf("%+v %v", r, e)
	}
	if _, e = Restore(ctx, f.target, r.ID, f.opts); e != nil {
		t.Fatal(e)
	}
	s, e = inspect(ctx, f.target)
	if e != nil {
		t.Fatal(e)
	}
	node, _ := find(s.Proxies, "node1")
	if scalar(node.Node, "password") != "original-secret" {
		t.Fatal("restore failed")
	}
}

func TestVergePreviewStableForUnchangedCompanions(t *testing.T) {
	f := newConfigFixture(t, true)
	ctx := context.Background()
	snapshot, err := inspectWithOptions(ctx, f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	// Reuse immutable file observations to isolate ordering from host metadata
	// and exercise many independent inspections without spawning host helpers.
	f.opts.Host = func(_ context.Context, _ config.Target, req HostRequest) (HostResponse, error) {
		if req.Op != "read" {
			t.Fatalf("preview attempted %s", req.Op)
		}
		file, ok := snapshot.files[req.Path]
		if !ok {
			t.Fatalf("unexpected source read %s", req.Path)
		}
		return HostResponse{File: file}, nil
	}
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: replacement-secret\n")}
	wantPaths := []string{filepath.Join(f.target.ConfigSource.DataDir, "profiles.yaml"), snapshot.proxies, snapshot.groups, snapshot.base}
	var digest string
	for i := 0; i < 100; i++ {
		plan, err := Preview(ctx, f.target, req, f.opts)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			digest = plan.Digest
		} else if plan.Digest != digest {
			t.Fatalf("unchanged source produced a different preview digest on iteration %d", i)
		}
		if len(plan.source.guards) != len(wantPaths) {
			t.Fatal("source guards missing")
		}
		for index, guard := range plan.source.guards {
			if guard.Path != wantPaths[index] {
				t.Fatalf("source guard order changed at %d: %s", index, guard.Path)
			}
		}
	}
	// A context-only fingerprint change must still invalidate review even when
	// the planned companion bytes are identical.
	manifest := snapshot.files[wantPaths[0]]
	manifest.Fingerprint += "-changed"
	snapshot.files[wantPaths[0]] = manifest
	changed, err := Preview(ctx, f.target, req, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Digest == digest {
		t.Fatal("changed source context did not invalidate preview")
	}
}
func TestVergeNewNodeOnlyEntersExplicitGroups(t *testing.T) {
	f := newConfigFixture(t, true)
	req := Request{Kind: "proxy", Action: "add", Input: []byte("trojan://password@new.example:443#new"), Groups: []string{"G2"}}
	p, e := Preview(context.Background(), f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	g1, _ := find(p.source.Groups, "G1")
	g2, _ := find(p.source.Groups, "G2")
	a, _ := encode(g1.Node)
	b, _ := encode(g2.Node)
	if strings.Contains(string(a), "new") || !strings.Contains(string(b), "new") {
		t.Fatalf("membership not compensated\n%s\n%s", a, b)
	}
}
func TestFailedReloadKeepsReceiptWithoutRetry(t *testing.T) {
	f := newConfigFixture(t, false)
	f.reject = true
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: changed\n")}
	p, e := Preview(context.Background(), f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Apply(context.Background(), f.target, req, p.Digest, f.opts)
	if e == nil || r.Status != "runtime_result_unknown" || f.writes.Load() != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	if _, e = loadReceipt(f.opts, r.ID); e != nil {
		t.Fatal(e)
	}
}
func TestVergeMissingAndChangedOwnerFailBeforeWrite(t *testing.T) {
	f := newConfigFixture(t, true)
	manifest := filepath.Join(f.target.ConfigSource.DataDir, "profiles.yaml")
	data, _ := os.ReadFile(manifest)
	os.WriteFile(manifest, []byte(strings.Replace(string(data), "current: chosen", "current: another", 1)), 0600)
	if _, e := Inspect(context.Background(), f.target, f.opts); e == nil {
		t.Fatal("changed active profile accepted")
	}
	os.WriteFile(manifest, data, 0600)
	os.Remove(filepath.Join(f.target.ConfigSource.DataDir, "profiles", "groups.yaml"))
	if _, e := Inspect(context.Background(), f.target, f.opts); e == nil {
		t.Fatal("missing companion accepted")
	}
}
func TestBatchImportIsOneReviewedSourceChange(t *testing.T) {
	f := newConfigFixture(t, false)
	req := Request{Kind: "proxy", Action: "import", Input: []byte("trojan://p@a.test:443#a\nhy2://p@b.test:443#b"), Groups: []string{"G1"}}
	p, e := Preview(context.Background(), f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.expected) != 2 || len(p.Changes) != 1 {
		t.Fatal(p)
	}
	r, e := Apply(context.Background(), f.target, req, p.Digest, f.opts)
	if e != nil || !r.RuntimeObserved {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestInlineProviderEditRetainsProviderAndVerifies(t *testing.T) {
	f := newConfigFixture(t, false)
	raw := sourceFixture + "proxy-providers:\n  manual:\n    type: inline\n    payload:\n    - {name: inline, type: trojan, server: inline.test, port: 443, password: before}\n"
	os.WriteFile(f.base, []byte(raw), 0600)
	req := Request{Kind: "proxy", Action: "edit", Name: "inline", Input: []byte("password: after\n")}
	p, e := Preview(context.Background(), f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Apply(context.Background(), f.target, req, p.Digest, f.opts)
	if e != nil || !r.GeneratedVerified || !r.RuntimeObserved {
		t.Fatalf("%+v %v", r, e)
	}
	n, e := decode(p.Changes[0].after)
	if e != nil {
		t.Fatal(e)
	}
	provider := get(get(n, "proxy-providers"), "manual")
	if scalar(provider, "type") != "inline" || len(get(provider, "payload").Content) != 1 {
		t.Fatal("provider definition lost")
	}
}
func TestRestoreRefusesInterveningEditAndPreservesBackup(t *testing.T) {
	f := newConfigFixture(t, false)
	req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: changed\n")}
	p, e := Preview(context.Background(), f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Apply(context.Background(), f.target, req, p.Digest, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(f.base)
	os.WriteFile(f.base, append(data, []byte("# newer user edit\n")...), 0600)
	if _, e = Restore(context.Background(), f.target, r.ID, f.opts); e == nil {
		t.Fatal("intervening change overwritten")
	}
	dir, e := receiptDir(f.opts, r.ID, false)
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filepath.Join(dir, "0.before.yaml"))
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup not private")
	}
}
func TestDuplicateUsesNewNameAndDiffMasksCredentials(t *testing.T) {
	f := newConfigFixture(t, false)
	req := Request{Kind: "proxy", Action: "duplicate", Name: "node1", NewName: "fixture duplicate qjkh", Groups: []string{"G1"}}
	p, e := Preview(context.Background(), f.target, req, f.opts)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := find(p.source.Proxies, req.NewName); !ok {
		t.Fatal("new definition not created")
	}
	encoded, _ := json.Marshal(p.Diff)
	if strings.Contains(string(encoded), "original-secret") {
		t.Fatal("diff leaked credentials")
	}
	hasPassword, hasMembers := false, false
	for _, change := range p.Diff {
		if change.Field == "password" {
			hasPassword = change.Masked && change.After == "[redacted]"
		}
		if change.Kind == "group" && change.Field == "proxies" {
			hasMembers = true
		}
	}
	if !hasPassword || !hasMembers {
		t.Fatalf("diff lacks meaningful masked changes: %s", encoded)
	}
	if _, e = Apply(context.Background(), f.target, req, p.Digest, f.opts); e != nil {
		t.Fatal(e)
	}
}
func TestManagedHostHookOwnsEverySourceOperation(t *testing.T) {
	for _, backend := range []string{"native", "docker"} {
		t.Run(backend, func(t *testing.T) {
			root := t.TempDir()
			path := "/owner-only/lazyclash-fixture/config.yaml"
			current := []byte(sourceFixture)
			var ops []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/version":
					json.NewEncoder(w).Encode(map[string]any{"version": "fixture-version", "meta": true})
				case "/configs":
					if r.Method == "PUT" {
						var req map[string]any
						json.NewDecoder(r.Body).Decode(&req)
						want := path
						if backend == "docker" {
							want = "/etc/mihomo/config.yaml"
						}
						if req["path"] != want {
							t.Errorf("reload path %v", req["path"])
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"mode": "rule"})
				case "/proxies":
					json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"node1": map[string]any{"name": "node1", "type": "Shadowsocks"}}})
				default:
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			target := config.Target{ID: "managed", ManagedCoreID: "managed", Controller: server.URL, Configs: []config.CoreConfig{{ID: "main", Path: path}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/owner-only/mihomo", Home: "/owner-only"}}
			if backend == "docker" {
				target.ConfigSource = &config.ConfigSource{Kind: "docker", HostPath: path, CorePath: "/etc/mihomo/config.yaml", Container: "managed", Binary: "/mihomo", Home: "/etc/mihomo"}
			}
			opts := Options{StateDir: filepath.Join(root, "receipts"), Host: func(ctx context.Context, got config.Target, request HostRequest) (HostResponse, error) {
				if got.ManagedCoreID != "managed" {
					t.Fatal("managed identity lost")
				}
				ops = append(ops, request.Op)
				file := func() HostFile {
					return HostFile{Path: path, Resolved: path, Data: append([]byte{}, current...), SHA256: hash(current), Fingerprint: hash(current), Mode: 0600}
				}
				guard := func() error {
					for _, g := range request.Guards {
						if g.Path != path || g.Fingerprint != hash(current) {
							return errors.New("managed guard mismatch")
						}
					}
					return nil
				}
				switch request.Op {
				case "read":
					if request.Path != path {
						return HostResponse{}, errors.New("foreign path")
					}
					return HostResponse{File: file()}, nil
				case "check":
					return HostResponse{}, guard()
				case "write":
					if e := guard(); e != nil {
						return HostResponse{}, e
					}
					current = append([]byte{}, request.Data...)
					return HostResponse{File: file()}, nil
				case "validate", "docker-validate":
					if request.Document == nil || request.Version != "fixture-version" {
						t.Fatal("validation payload missing")
					}
					return HostResponse{ContainerID: "owned-id", Image: "owned-image", SourceSHA256: hash(current)}, nil
				case "docker-inspect":
					return HostResponse{ContainerID: "owned-id", Image: "owned-image", SourceSHA256: hash(current)}, nil
				default:
					t.Fatalf("unknown hook op %q", request.Op)
				}
				return HostResponse{}, nil
			}}
			req := Request{Kind: "proxy", Action: "edit", Name: "node1", Input: []byte("password: changed\n")}
			plan, e := Preview(context.Background(), target, req, opts)
			if e != nil {
				t.Fatal(e)
			}
			receipt, e := Apply(context.Background(), target, req, plan.Digest, opts)
			if e != nil {
				t.Fatal(e)
			}
			if !receipt.SourceVerified {
				t.Fatal("owner source not verified")
			}
			if _, e = Restore(context.Background(), target, receipt.ID, opts); e != nil {
				t.Fatal(e)
			}
			if string(current) != sourceFixture {
				t.Fatal("managed bytes were not restored")
			}
			joined := strings.Join(ops, ",")
			for _, op := range []string{"read", "check", "write", "validate"} {
				if !strings.Contains(joined, op) {
					t.Fatal("operation bypassed managed hook", op)
				}
			}
		})
	}
}
