package rulework

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type fixture struct {
	target config.Target
	opts   Options
	mu     sync.Mutex
	rules  []map[string]any
	writes int
	reject bool
	source []byte
}

func newFixture(t *testing.T, verge bool) *fixture {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX source helper; Windows host operations have separate injected fixtures")
	}
	return baseFixture(t, verge)
}
func baseFixture(t *testing.T, verge bool) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{rules: []map[string]any{{"type": "Match", "payload": "", "proxy": "DIRECT"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]any{"version": "v1.19.29", "meta": true})
		case "/proxies":
			json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{"PROXY": map[string]any{"name": "PROXY", "type": "Selector", "all": []string{"DIRECT"}, "now": "DIRECT"}, "DIRECT": map[string]any{"name": "DIRECT", "type": "Direct"}}})
		case "/configs":
			if r.Method == http.MethodPut {
				f.writes++
				if f.reject {
					w.WriteHeader(500)
					return
				}
				var body struct {
					Path string `json:"path"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				data, _ := os.ReadFile(body.Path)
				doc, err := decodeYAML(data)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				seq := mappingValue(doc.Content[0], "rules")
				f.rules = nil
				for _, item := range seq.Content {
					parts := strings.Split(item.Value, ",")
					entry := map[string]any{"type": "Match", "payload": "", "proxy": parts[len(parts)-1]}
					if parts[0] == "DOMAIN" {
						entry["type"] = "Domain"
						entry["payload"] = parts[1]
					}
					if parts[0] == "IP-CIDR" || parts[0] == "IP-CIDR6" {
						entry["type"] = "IPCIDR"
						entry["payload"] = parts[1]
						entry["proxy"] = parts[2]
					}
					f.rules = append(f.rules, entry)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"mode": "rule"})
		case "/rules":
			json.NewEncoder(w).Encode(map[string]any{"rules": f.rules})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	f.target = config.Target{ID: "fixture", Controller: server.URL}
	f.opts = Options{StateDir: filepath.Join(root, "receipts"), Validate: func(_ context.Context, _ config.Target, data []byte, version string) error {
		if version != "v1.19.29" {
			return errors.New("wrong validator version")
		}
		_, err := decodeYAML(data)
		return err
	}}
	if verge {
		home := filepath.Join(root, "verge")
		os.MkdirAll(filepath.Join(home, "profiles"), 0700)
		os.WriteFile(filepath.Join(home, "profiles.yaml"), []byte("current: chosen\nitems:\n  - uid: chosen\n    type: remote\n    option:\n      rules: owned-rules\n  - uid: owned-rules\n    type: rules\n    file: owned.yaml\n"), 0600)
		f.source = []byte("# keep this comment\nprepend: []\nappend: []\ndelete: []\n")
		os.WriteFile(filepath.Join(home, "profiles", "owned.yaml"), f.source, 0600)
		f.target.RuleSource = &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: home, ProfileUID: "chosen"}
	} else {
		path := filepath.Join(root, "core.yaml")
		f.source = []byte("# keep this comment\nsecret: do-not-expose-this\nrules:\n  - MATCH,DIRECT\n")
		os.WriteFile(path, f.source, 0640)
		f.target.Configs = []config.CoreConfig{{ID: "active", Path: path}}
		f.target.RuleSource = &config.RuleSource{Kind: "mihomo", ConfigID: "active", Home: root, Binary: filepath.Join(root, "mihomo")}
	}
	return f
}

func TestStandalonePreviewApplyVerifyRestore(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	p, err := Preview(ctx, f.target, "EXAMPLE.COM.", "PROXY", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.Domain != "example.com" || p.Digest == "" || p.NoChange {
		t.Fatal(p)
	}
	encoded, _ := json.Marshal(p)
	if strings.Contains(string(encoded), "do-not-expose-this") {
		t.Fatal("preview leaked source secret")
	}
	if _, err := os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview created state directory")
	}
	r, err := Apply(ctx, f.target, "example.com", "PROXY", p.Digest, f.opts)
	if err != nil || r.Status != "applied_verified" {
		t.Fatalf("%+v %v", r, err)
	}
	data, _ := os.ReadFile(r.File)
	if !strings.Contains(string(data), "# keep this comment") || !strings.Contains(string(data), "DOMAIN,example.com,PROXY") {
		t.Fatalf("unexpected YAML: %s", data)
	}
	info, _ := os.Stat(r.File)
	if info.Mode().Perm() != 0640 {
		t.Fatal("source permissions changed")
	}
	dir, _ := receiptDirectory(f.opts, r.ID, false)
	backup, _ := os.ReadFile(filepath.Join(dir, "before.yaml"))
	if string(backup) != string(f.source) {
		t.Fatal("backup not exact")
	}
	backupInfo, _ := os.Stat(filepath.Join(dir, "before.yaml"))
	if backupInfo.Mode().Perm() != 0600 {
		t.Fatal("backup not private")
	}
	again, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if err != nil || !again.NoChange {
		t.Fatalf("not idempotent: %+v %v", again, err)
	}
	r, err = Restore(ctx, f.target, r.ID, f.opts)
	if err != nil || r.Status != "restored_verified" {
		t.Fatalf("restore %+v %v", r, err)
	}
	data, _ = os.ReadFile(r.File)
	if string(data) != string(f.source) {
		t.Fatal("restore changed original bytes")
	}
	writes := f.writes
	r, err = Restore(ctx, f.target, r.ID, f.opts)
	if err != nil || r.Status != "restored_verified" || f.writes != writes {
		t.Fatalf("repeat restore should verify without reloading: %+v %v", r, err)
	}
}

func TestVergePersistsOnlyCompanionAndNeedsNativeReload(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	manifest := filepath.Join(f.target.RuleSource.DataDir, "profiles.yaml")
	before, _ := os.ReadFile(manifest)
	p, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ctx, f.target, "example.com", "PROXY", p.Digest, f.opts)
	if err != nil || r.Status != "persisted_pending_owner_reload" {
		t.Fatalf("%+v %v", r, err)
	}
	after, _ := os.ReadFile(manifest)
	if string(after) != string(before) || f.writes != 0 {
		t.Fatal("Verge manifest/runtime was modified")
	}
	r, err = Verify(ctx, f.target, r.ID, f.opts)
	if err != nil || r.RuntimeVerified {
		t.Fatalf("premature verification: %+v %v", r, err)
	}
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "Domain", "payload": "example.com", "proxy": "PROXY"}}
	f.mu.Unlock()
	r, err = Verify(ctx, f.target, r.ID, f.opts)
	if err != nil || !r.RuntimeVerified {
		t.Fatalf("native reload not recognized: %+v %v", r, err)
	}
	r, err = Restore(ctx, f.target, r.ID, f.opts)
	if err != nil || r.Status != "restored_pending_owner_reload" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestStalePreviewReadonlyAndValidationFailureDoNotWrite(t *testing.T) {
	for _, scenario := range []string{"stale", "read-only", "validation", "during-validation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			ctx := context.Background()
			p, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
			if err != nil {
				t.Fatal(err)
			}
			want := f.source
			switch scenario {
			case "stale":
				want = append([]byte("# other edit\n"), f.source...)
				os.WriteFile(p.Owner.File, want, 0640)
			case "read-only":
				f.opts.ReadOnly = true
			case "validation":
				f.opts.Validate = func(context.Context, config.Target, []byte, string) error {
					return errors.New("validation unavailable")
				}
			case "during-validation":
				want = append([]byte("# user edit\n"), f.source...)
				f.opts.Validate = func(context.Context, config.Target, []byte, string) error {
					return os.WriteFile(p.Owner.File, want, 0640)
				}
			}
			if _, err = Apply(ctx, f.target, "example.com", "PROXY", p.Digest, f.opts); err == nil {
				t.Fatal("apply should refuse")
			}
			got, _ := os.ReadFile(p.Owner.File)
			if string(got) != string(want) || f.writes != 0 {
				t.Fatal("refused edit changed source/runtime")
			}
			if _, err := os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
				t.Fatal("failed preflight created receipt")
			}
		})
	}
}

func TestUnknownRuntimeHasReceiptAndRestoreProtectsInterveningEdit(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	p, err := Preview(ctx, f.target, "example.com", "PROXY", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.reject = true
	f.mu.Unlock()
	r, err := Apply(ctx, f.target, "example.com", "PROXY", p.Digest, f.opts)
	if err == nil || r.ID == "" || r.Status != "runtime_result_unknown" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err = loadReceipt(f.opts, r.ID); err != nil {
		t.Fatal("missing uncertain-operation receipt", err)
	}
	changed := []byte("rules: [MATCH,DIRECT]\n# changed by user\n")
	os.WriteFile(r.File, changed, 0640)
	if _, err = Restore(ctx, f.target, r.ID, f.opts); err == nil {
		t.Fatal("restore overwrote intervening change")
	}
	got, _ := os.ReadFile(r.File)
	if string(got) != string(changed) {
		t.Fatal("intervening edit lost")
	}
}

func TestVergeOwnershipVersionAndTraversal(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	f.target.RuleSource.Version = "9.0.0"
	if _, err := InspectSource(ctx, f.target); err == nil {
		t.Fatal("unknown version accepted")
	}
	f.target.RuleSource.Version = "2.5.2"
	f.target.RuleSource.ProfileUID = "another"
	if _, err := InspectSource(ctx, f.target); err == nil {
		t.Fatal("inactive profile accepted")
	}
	if _, err := companionPath("/home/user/verge", "../../outside.yaml"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := companionPath("/home/user/verge", "/outside.yaml"); err == nil {
		t.Fatal("absolute companion accepted")
	}
}

func TestTransportOverrideBlocksBeforeHostAccess(t *testing.T) {
	target := config.Target{ID: "unsafe", Controller: "http://127.0.0.1:1", SSHHost: "must-never-contact.invalid", TransportOverride: true, RuleSource: &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: "/does-not-exist", ProfileUID: "selected"}}
	_, err := InspectSource(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "saved endpoint and SSH host") {
		t.Fatalf("transport override reached host: %v", err)
	}
}

func TestRejectsMalformedYAMLAndRuleInput(t *testing.T) {
	for _, source := range []string{"rules: []\nrules: []\n", "rules: []\n---\nrules: []\n", "rules: []\n---\n[bad", "rules: wrong\n"} {
		if _, _, err := addRule([]byte(source), "mihomo", "DOMAIN,example.com,PROXY"); err == nil {
			t.Errorf("accepted malformed source: %q", source)
		}
	}
	for _, host := range []string{"127.0.0.1", "https://example.com/", "-bad.example", "x\n.example", "a,b.example"} {
		if _, err := NormalizeDomain(host); err == nil {
			t.Errorf("accepted bad host %q", host)
		}
	}
}

func TestRuleDiffShowsReplacedPoliciesAndPositionsOnly(t *testing.T) {
	before := []byte("secret: NEVER_PRINT\nrules:\n  - DOMAIN,other.example,DIRECT\n  - DOMAIN,example.com,DIRECT\n  - DOMAIN,EXAMPLE.COM.,Old Policy\n  - MATCH,DIRECT\n")
	rule := "DOMAIN,example.com,PROXY"
	after, noChange, err := addRule(before, "mihomo", rule)
	if err != nil || noChange {
		t.Fatal(err)
	}
	diff := ruleDiff(before, "mihomo", rule, "example.com", false)
	for _, expected := range []string{"- [1] DOMAIN,example.com,DIRECT", "- [2] DOMAIN,EXAMPLE.COM.,Old Policy", "+ [0] DOMAIN,example.com,PROXY"} {
		if !strings.Contains(diff, expected) {
			t.Fatalf("missing concrete edit %q: %s", expected, diff)
		}
	}
	if strings.Contains(diff, "NEVER_PRINT") || strings.Contains(string(after), "Old Policy") {
		t.Fatal("diff leaked source secret or old policy was retained")
	}
	if !strings.Contains(string(after), "DOMAIN,other.example,DIRECT") {
		t.Fatal("unrelated rule removed")
	}
}

func TestOpenCoreClosesClientWithNilCloserAndOnError(t *testing.T) {
	for _, failOpen := range []bool{false, true} {
		t.Run(fmt.Sprint(failOpen), func(t *testing.T) {
			closed := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"version":"v1.19.29"}`) }))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			}
			server.Start()
			defer server.Close()
			client, err := core.New(core.Options{Endpoint: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.Version(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, cleanup, err := openCore(context.Background(), config.Target{}, true, Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
				if failOpen {
					return client, nil, errors.New("failed open")
				}
				return client, nil, nil
			}})
			if (err != nil) != failOpen {
				t.Fatal(err)
			}
			cleanup()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("client idle connection leaked")
			}
		})
	}
}
