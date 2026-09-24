package configwork

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"go.yaml.in/yaml/v3"
)

func changesetFixture(t *testing.T, id string, verge bool) *configFixture {
	t.Helper()
	f := newConfigFixture(t, verge)
	f.target.ID = id
	if verge {
		home := f.target.ConfigSource.DataDir
		manifest := filepath.Join(home, "profiles.yaml")
		raw, _ := os.ReadFile(manifest)
		raw = []byte(strings.Replace(string(raw), "option: {proxies: px, groups: gr}", "option: {proxies: px, groups: gr, rules: ru, merge: mg}", 1) + "- {uid: ru, type: rules, file: rules.yaml}\n- {uid: mg, type: merge, file: merge.yaml}\n")
		os.WriteFile(manifest, raw, 0600)
		os.WriteFile(filepath.Join(home, "profiles", "rules.yaml"), []byte("prepend: []\nappend: []\ndelete: []\n"), 0600)
		os.WriteFile(filepath.Join(home, "profiles", "merge.yaml"), []byte("# native empty merge\n"), 0600)
	}
	f.target.RuleSource, _ = config.RuleSourceFromConfigSource(f.target)
	upstream, _ := url.Parse(f.target.Controller)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rules" && r.URL.Path != "/providers/rules" && r.URL.Path != "/providers/proxies" {
			proxy.ServeHTTP(w, r)
			return
		}
		if r.Method != "GET" {
			t.Errorf("unexpected provider/rules mutation: %s", r.Method)
			w.WriteHeader(405)
			return
		}
		s, err := inspect(context.Background(), f.target)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		root, err := changeSetEffective(s)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/rules" {
			rows := []map[string]any{}
			if rules := get(root, "rules"); rules != nil {
				for _, n := range rules.Content {
					parts := strings.Split(n.Value, ",")
					kind := map[string]string{"DOMAIN": "Domain", "DOMAIN-SUFFIX": "DomainSuffix", "IP-CIDR": "IPCIDR", "MATCH": "Match", "RULE-SET": "RuleSet"}[parts[0]]
					payload, policy := "", parts[1]
					if len(parts) > 2 {
						payload, policy = parts[1], parts[2]
					}
					rows = append(rows, map[string]any{"type": kind, "payload": payload, "proxy": policy})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"rules": rows})
			return
		}
		section := "rule-providers"
		if r.URL.Path == "/providers/proxies" {
			section = "proxy-providers"
		}
		providers := map[string]any{}
		if node := get(root, section); node != nil {
			for i := 0; i+1 < len(node.Content); i += 2 {
				providers[node.Content[i].Value] = map[string]any{"name": node.Content[i].Value}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"providers": providers})
	}))
	t.Cleanup(server.Close)
	f.target.Controller = server.URL
	return f
}

func changeSetEdit(t *testing.T, f *configFixture, edit func(*yaml.Node)) {
	t.Helper()
	raw, err := os.ReadFile(f.base)
	if err != nil {
		t.Fatal(err)
	}
	root, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	edit(root)
	raw, err = encode(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.base, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func changeSetSelect(t *testing.T, f *configFixture, kind, name string, replace bool) ObjectSelection {
	t.Helper()
	snapshot, err := SnapshotConfig(context.Background(), f.target, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range snapshot.Objects {
		if object.Kind == kind && object.Name == name {
			return ObjectSelection{ID: object.ID, Replace: replace}
		}
	}
	t.Fatalf("object not found %s/%s", kind, name)
	return ObjectSelection{}
}

func TestChangeSetCombinesDependenciesRulesAndOneReload(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
	changeSetEdit(t, from, func(root *yaml.Node) {
		sequence(root, "proxies").Content = append(sequence(root, "proxies").Content, mapNode(map[string]any{"name": "new-node", "type": "ss", "server": "new.test", "port": 443, "cipher": "aes-128-gcm", "password": "copied-private-secret"}))
		sequence(root, "proxy-groups").Content = append(sequence(root, "proxy-groups").Content, mapNode(map[string]any{"name": "NEW", "type": "select", "proxies": []string{"new-node", "DIRECT"}}))
		sequence(root, "rules").Content = append([]*yaml.Node{str("DOMAIN-SUFFIX,new.test,NEW")}, sequence(root, "rules").Content...)
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule", "DOMAIN-SUFFIX,new.test,NEW", false)}}
	before, _ := os.ReadFile(to.base)
	opts := to.opts
	validations := 0
	validate := opts.Validate
	opts.Validate = func(ctx context.Context, target config.Target, raw []byte, version string) error {
		validations++
		return validate(ctx, target, raw, version)
	}
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, opts)
	if err != nil || plan.Status != "ready" || len(plan.Changes) != 1 || len(plan.Composition.AutoSelected) != 2 || validations != 1 {
		t.Fatal(plan, err, validations)
	}
	jsonPlan, _ := json.Marshal(plan)
	if strings.Contains(string(jsonPlan), "copied-private-secret") {
		t.Fatal("preview exposed copied credentials")
	}
	receipt, err := ApplyChangeSet(context.Background(), from.target, to.target, selection, plan.Digest, opts)
	if err != nil || receipt.Status != "source_and_structure_verified" || to.writes.Load() != 1 || from.writes.Load() != 0 || validations != 2 {
		t.Fatal(receipt, err, to.writes.Load(), validations)
	}
	verified, err := Verify(context.Background(), to.target, receipt.ID, opts)
	if err != nil || verified.Status != "source_and_structure_verified" {
		t.Fatal(verified, err)
	}
	restored, err := Restore(context.Background(), to.target, receipt.ID, opts)
	if err != nil || restored.Status != "restored_runtime_apply_confirmed" || to.writes.Load() != 2 {
		t.Fatal(restored, err, to.writes.Load())
	}
	after, _ := os.ReadFile(to.base)
	if string(after) != string(before) {
		t.Fatal("restore did not preserve original bytes")
	}
}

func TestChangeSetRuleOnlyBindingAndEmptySelection(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
	changeSetEdit(t, from, func(root *yaml.Node) {
		sequence(root, "rules").Content = append([]*yaml.Node{str("DOMAIN,plain.test,DIRECT")}, sequence(root, "rules").Content...)
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule", "DOMAIN,plain.test,DIRECT", false)}}
	from.target.ConfigSource, to.target.ConfigSource = nil, nil
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
	if err != nil || plan.Status != "ready" {
		t.Fatal(plan, err)
	}
	empty, err := PreviewChangeSet(context.Background(), from.target, to.target, StructuralSelection{}, to.opts)
	if err != nil || empty.Status != "no_changes" || len(empty.Changes) != 0 {
		t.Fatal(empty, err)
	}
	if _, err = os.Stat(to.opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview created receipt state")
	}
}

func TestChangeSetProviderSnapshotsStageBeforeWritesAndRestore(t *testing.T) {
	for _, kind := range []string{"file", "http"} {
		t.Run(kind, func(t *testing.T) {
			from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
			resource := filepath.Join(from.target.ConfigSource.Home, "rules.yaml")
			seed := []byte("payload:\n  - +.provider.test\n")
			os.WriteFile(resource, seed, 0600)
			changeSetEdit(t, from, func(root *yaml.Node) {
				provider := map[string]any{"type": kind, "behavior": "domain", "path": resource}
				if kind == "http" {
					provider["url"] = "https://example.test/private?token=source-secret"
				}
				set(root, "rule-providers", mapNode(map[string]any{"P": provider}))
			})
			selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule-provider", "P", false)}}
			opts := to.opts
			opts.Validate = nil
			validations := 0
			opts.Host = func(ctx context.Context, target config.Target, request HostRequest) (HostResponse, error) {
				if request.Op == "validate" {
					validations++
					if len(request.Resources) != 1 {
						t.Fatal("provider snapshot not supplied to validation")
					}
					for path, data := range request.Resources {
						if string(data) != string(seed) {
							t.Fatal("wrong staged seed")
						}
						if _, err := os.Stat(path); !os.IsNotExist(err) {
							t.Fatal("validation wrote live resource before apply", err)
						}
					}
					return HostResponse{}, nil
				}
				return DefaultHostOperation(ctx, target, request)
			}
			plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, opts)
			if err != nil || len(plan.Resources) != 1 || len(plan.Changes) != 1 {
				t.Fatal(plan, err)
			}
			if _, err = os.Stat(plan.Resources[0].Path); !os.IsNotExist(err) {
				t.Fatal("preview created live provider resource")
			}
			r, err := ApplyChangeSet(context.Background(), from.target, to.target, selection, plan.Digest, opts)
			if err != nil || r.Status != "source_and_structure_verified" || to.writes.Load() != 1 || validations != 2 {
				t.Fatal(r, err, validations)
			}
			stored, _ := os.ReadFile(plan.Resources[0].Path)
			if string(stored) != string(seed) {
				t.Fatal("wrong provider bytes")
			}
			if kind == "http" {
				os.WriteFile(plan.Resources[0].Path, []byte("payload: [+.new-provider.test]\n"), 0600)
				verified, e := Verify(context.Background(), to.target, r.ID, to.opts)
				if e != nil || !verified.SourceVerified || verified.Composite.Resources[0].Status != "cache_evolved" {
					t.Fatal("HTTP cache evolution treated as corruption", verified, e)
				}
			}
			opts.Validate = to.opts.Validate
			restored, err := Restore(context.Background(), to.target, r.ID, opts)
			if err != nil || restored.Status != "restored_runtime_apply_confirmed" {
				t.Fatal(restored, err)
			}
			_, err = os.Stat(plan.Resources[0].Path)
			if kind == "file" && !os.IsNotExist(err) {
				t.Fatal("immutable resource not removed", err)
			}
			if kind == "http" && err != nil {
				t.Fatal("evolved HTTP cache removed", err)
			}
		})
	}
}

func TestChangeSetSourceRaceAndUnknownWriteHaveGuardedReceipts(t *testing.T) {
	for _, scenario := range []string{"source-race", "unknown-write"} {
		t.Run(scenario, func(t *testing.T) {
			from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
			changeSetEdit(t, from, func(root *yaml.Node) {
				sequence(root, "proxies").Content = append(sequence(root, "proxies").Content, mapNode(map[string]any{"name": "new-node", "type": "direct"}))
			})
			selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "proxy", "new-node", false)}}
			plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
			if err != nil {
				t.Fatal(err)
			}
			opts := to.opts
			if scenario == "source-race" {
				opts.Validate = func(context.Context, config.Target, []byte, string) error {
					raw, _ := os.ReadFile(from.base)
					return os.WriteFile(from.base, append(raw, []byte("# concurrent edit\n")...), 0600)
				}
			} else {
				opts.Host = func(ctx context.Context, target config.Target, request HostRequest) (HostResponse, error) {
					result, e := DefaultHostOperation(ctx, target, request)
					if e == nil && request.Op == "write" {
						return result, errors.New("lost write response")
					}
					return result, e
				}
			}
			r, err := ApplyChangeSet(context.Background(), from.target, to.target, selection, plan.Digest, opts)
			if err == nil || to.writes.Load() != 0 {
				t.Fatal(r, err, to.writes.Load())
			}
			if scenario == "source-race" {
				if r.ID != "" {
					t.Fatal("source race wrote receipt before guard")
				}
			} else {
				if r.ID == "" || r.Status != "write_result_unknown" {
					t.Fatal(r)
				}
				restored, e := Restore(context.Background(), to.target, r.ID, to.opts)
				if e != nil || restored.Status != "restored_runtime_apply_confirmed" {
					t.Fatal(restored, e)
				}
			}
		})
	}
}

func TestChangeSetVergePreservesCompanionsAndAcknowledgesOrderedOverride(t *testing.T) {
	for _, placement := range []string{"prepend", "anchored"} {
		t.Run(placement, func(t *testing.T) {
			from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", true)
			changeSetEdit(t, from, func(root *yaml.Node) {
				set(root, "rules", mapNode([]string{"DOMAIN,first.test,DIRECT", "DOMAIN,new.test,DIRECT", "MATCH,G1"}))
			})
			changeSetEdit(t, to, func(root *yaml.Node) { set(root, "rules", mapNode([]string{"DOMAIN,first.test,DIRECT", "MATCH,G1"})) })
			selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule", "DOMAIN,new.test,DIRECT", false)}, RulePlacement: placement}
			merge := filepath.Join(to.target.ConfigSource.DataDir, "profiles", "merge.yaml")
			before, _ := os.ReadFile(merge)
			plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
			if placement == "anchored" {
				if err == nil {
					t.Fatal("ordered override did not request acknowledgement")
				}
				selection.AllowVergeRulesOverride = true
				plan, err = PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
			}
			if err != nil || len(plan.Changes) != 1 {
				t.Fatal(plan, err)
			}
			want := "rules.yaml"
			if placement == "anchored" {
				want = "merge.yaml"
			}
			if filepath.Base(plan.Changes[0].Path) != want {
				t.Fatal("wrong owner companion", plan.Changes)
			}
			r, err := ApplyChangeSet(context.Background(), from.target, to.target, selection, plan.Digest, to.opts)
			if err != nil || r.Status != "persisted_pending_owner_reload" || to.writes.Load() != 0 {
				t.Fatal(r, err)
			}
			restored, err := Restore(context.Background(), to.target, r.ID, to.opts)
			if err != nil || restored.Status != "restored_pending_owner_reload" {
				t.Fatal(restored, err)
			}
			after, _ := os.ReadFile(merge)
			if string(after) != string(before) {
				t.Fatal("empty Merge backup was not restored exactly")
			}
		})
	}
}

func TestChangeSetVergeDeepMergeRejectsInheritedProviderFields(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", true)
	changeSetEdit(t, from, func(root *yaml.Node) {
		set(root, "rule-providers", mapNode(map[string]any{"P": map[string]any{"type": "inline", "behavior": "domain", "payload": []string{"+.new.test"}}}))
	})
	changeSetEdit(t, to, func(root *yaml.Node) {
		set(root, "rule-providers", mapNode(map[string]any{"P": map[string]any{"type": "inline", "behavior": "domain", "payload": []string{"+.old.test"}, "interval": 300}}))
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule-provider", "P", true)}}
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
	if err == nil || plan.Status != "blocked" || !strings.Contains(err.Error(), "deep merge") || to.writes.Load() != 0 {
		t.Fatal(plan, err)
	}
}

func TestChangeSetCompletesChangedVergeCompanionSchema(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", true)
	rulesPath := filepath.Join(to.target.ConfigSource.DataDir, "profiles", "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte("# minimal existing companion\nprepend: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changeSetEdit(t, from, func(root *yaml.Node) {
		sequence(root, "rules").Content = append([]*yaml.Node{str("DOMAIN,new.test,DIRECT")}, sequence(root, "rules").Content...)
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule", "DOMAIN,new.test,DIRECT", false)}, RulePlacement: "prepend"}
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
	if err != nil || len(plan.Changes) != 1 || plan.Changes[0].Path != rulesPath {
		t.Fatal(plan, err)
	}
	node, err := decode(plan.Changes[0].after)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"prepend", "append", "delete"} {
		value := get(node, key)
		if value == nil || value.Kind != yaml.SequenceNode {
			t.Fatalf("changed companion lacks required %s array", key)
		}
	}
	if !strings.Contains(string(plan.Changes[0].after), "minimal existing companion") {
		t.Fatal("companion comment lost")
	}
}

func TestResourceProtocolRejectsPathAndSymlinkEscapes(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "lazyclash-resources")
	outside := filepath.Join(dir, "outside")
	os.WriteFile(outside, []byte("private"), 0600)
	target := config.Target{}
	if _, err := defaultResourceOperation(context.Background(), target, HostRequest{Op: "resource-write", ResourceRoot: root, Path: outside, Data: []byte("x"), ExpectedSHA256: hash([]byte("x"))}); err == nil {
		t.Fatal("path escape accepted")
	}
	os.Mkdir(root, 0700)
	os.Symlink(outside, filepath.Join(root, "link"))
	if _, err := defaultResourceOperation(context.Background(), target, HostRequest{Op: "resource-inspect", ResourceRoot: root, Path: filepath.Join(root, "link")}); err == nil {
		t.Fatal("resource symlink accepted")
	}
	os.Symlink(outside, filepath.Join(dir, "source-link"))
	bounded := filepath.Join(dir, "bounded")
	os.Mkdir(bounded, 0700)
	os.Symlink(outside, filepath.Join(bounded, "escape"))
	if _, err := defaultResourceOperation(context.Background(), target, HostRequest{Op: "source-resource-read", ResourceRoot: bounded, Path: filepath.Join(bounded, "escape")}); err == nil {
		t.Fatal("source symlink escape accepted")
	}
}

func TestChangeSetRestoreRetainsChangedResourceAndRemovesOtherCreatedResource(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
	a, b := filepath.Join(from.target.ConfigSource.Home, "a.yaml"), filepath.Join(from.target.ConfigSource.Home, "b.yaml")
	os.WriteFile(a, []byte("payload: [+.a.test]\n"), 0600)
	os.WriteFile(b, []byte("payload: [+.b.test]\n"), 0600)
	changeSetEdit(t, from, func(root *yaml.Node) {
		set(root, "rule-providers", mapNode(map[string]any{"A": map[string]any{"type": "file", "behavior": "domain", "path": a}, "B": map[string]any{"type": "file", "behavior": "domain", "path": b}}))
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "rule-provider", "A", false), changeSetSelect(t, from, "rule-provider", "B", false)}}
	before, _ := os.ReadFile(to.base)
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
	if err != nil {
		t.Fatal(plan, err)
	}
	r, err := ApplyChangeSet(context.Background(), from.target, to.target, selection, plan.Digest, to.opts)
	if err != nil {
		t.Fatal(r, err)
	}
	paths := map[string]string{}
	for _, res := range r.Composite.Resources {
		paths[res.Provider] = res.Path
	}
	changed := []byte("payload: [+.user-edit.test]\n")
	if err = os.WriteFile(paths["A"], changed, 0600); err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(context.Background(), to.target, r.ID, to.opts)
	if err != nil || verified.SourceVerified {
		t.Fatal("changed active immutable resource went unnoticed", verified, err)
	}
	restored, err := Restore(context.Background(), to.target, r.ID, to.opts)
	if err != nil || restored.Status != "restored_runtime_apply_confirmed" || !restored.SourceVerified {
		t.Fatal(restored, err)
	}
	status := map[string]string{}
	for _, res := range restored.Composite.Resources {
		status[res.Provider] = res.Status
	}
	if status["A"] != "retained_changed" || status["B"] != "removed" {
		t.Fatal(status)
	}
	actual, _ := os.ReadFile(to.base)
	remaining, _ := os.ReadFile(paths["A"])
	if string(actual) != string(before) || string(remaining) != string(changed) {
		t.Fatal("restore overwrote user changes or lost original configuration")
	}
	if _, err = os.Stat(paths["B"]); !os.IsNotExist(err) {
		t.Fatal("unchanged created resource not removed")
	}
}

func TestChangeSetHTTPCacheDoesNotSilentlyReuseDialerByName(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
	cache := filepath.Join(from.target.ConfigSource.Home, "cache.yaml")
	os.WriteFile(cache, []byte("proxies:\n- {name: cached, type: direct, dialer-proxy: node1}\n"), 0600)
	changeSetEdit(t, from, func(root *yaml.Node) {
		set(root, "proxy-providers", mapNode(map[string]any{"HTTP": map[string]any{"type": "http", "url": "https://example.test/nodes", "path": cache}}))
		set(sequence(root, "proxies").Content[0], "password", str("different-source-secret"))
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "proxy-provider", "HTTP", false)}}
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
	if err == nil || len(plan.Composition.Blockers) == 0 || plan.Composition.Blockers[0].Code != "dependency_conflict" || plan.Status != "blocked" || to.writes.Load() != 0 {
		t.Fatal(plan, err)
	}
	selection.Dependencies = []DependencyDecision{{ID: changeSetSelect(t, from, "proxy", "node1", false).ID, Action: "reuse"}}
	plan, err = PreviewChangeSet(context.Background(), from.target, to.target, selection, to.opts)
	if err != nil || plan.Status != "ready" {
		t.Fatal("explicitly selected identical dependency was not accepted", plan, err)
	}
}

func TestChangeSetHTTPCacheChangeAfterDependencyClosureBlocksStaging(t *testing.T) {
	from, to := changesetFixture(t, "source", false), changesetFixture(t, "destination", false)
	cache := filepath.Join(from.target.ConfigSource.Home, "cache.yaml")
	os.WriteFile(cache, []byte("proxies:\n- {name: cached, type: direct}\n"), 0600)
	changeSetEdit(t, from, func(root *yaml.Node) {
		set(root, "proxy-providers", mapNode(map[string]any{"HTTP": map[string]any{"type": "http", "url": "https://example.test/nodes", "path": cache}}))
	})
	selection := StructuralSelection{Objects: []ObjectSelection{changeSetSelect(t, from, "proxy-provider", "HTTP", false)}}
	opts := to.opts
	reads, validations := 0, 0
	opts.Validate = func(context.Context, config.Target, []byte, string) error { validations++; return nil }
	opts.Host = func(ctx context.Context, target config.Target, request HostRequest) (HostResponse, error) {
		result, err := DefaultHostOperation(ctx, target, request)
		if err == nil && request.Op == "source-resource-read" && target.ID == from.target.ID && request.Path == cache {
			reads++
			if reads == 1 {
				if e := os.WriteFile(cache, []byte("proxies:\n- {name: cached, type: direct, dialer-proxy: node1}\n"), 0600); e != nil {
					return result, e
				}
			}
		}
		return result, err
	}
	plan, err := PreviewChangeSet(context.Background(), from.target, to.target, selection, opts)
	if err == nil || !strings.Contains(err.Error(), "changed after dependency composition") || plan.Status != "blocked" || validations != 0 || to.writes.Load() != 0 {
		t.Fatal(plan, err, reads, validations)
	}
	if _, err = os.Stat(filepath.Join(to.target.ConfigSource.Home, "lazyclash-resources")); !os.IsNotExist(err) {
		t.Fatal("stale provider plan installed resources")
	}
}
