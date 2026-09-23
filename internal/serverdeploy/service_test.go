package serverdeploy

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"go.yaml.in/yaml/v3"
)

func fixture(t *testing.T) (Options, *[]RemoteRequest) {
	t.Helper()
	dir := t.TempDir()
	o := Options{Store: serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}}
	if err := o.Store.Update(func(i *serverstate.Inventory) error {
		return i.UpsertHost(serverstate.Host{ID: "test-host", Name: "Fixture", Provider: "ssh", SSHHost: "fixture-alias", PublicHost: "203.0.113.10"})
	}); err != nil {
		t.Fatal(err)
	}
	calls := []RemoteRequest{}
	o.Execute = func(_ context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
		if host != "fixture-alias" {
			t.Errorf("unexpected host %s", host)
		}
		calls = append(calls, r)
		return RemoteResponse{OK: true, Arch: "arm64", OS: "ubuntu-24.04", Service: "running"}, nil
	}
	o.Resolve = func(_ context.Context, r Request, arch string) (Artifact, error) {
		return Artifact{Version: "v26.3.27", Arch: arch, URL: "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip", SHA256: strings.Repeat("a", 64), Image: "ghcr.io/xtls/xray-core@sha256:" + strings.Repeat("b", 64), NginxImage: "docker.io/library/nginx@sha256:" + strings.Repeat("c", 64), Source: "fixture"}, nil
	}
	o.Probe = func(_ context.Context, node []byte) (string, error) {
		defs, diag, err := configwork.ParseImport(node)
		if err != nil || len(defs) != 1 || len(diag) != 0 {
			t.Errorf("invalid probe node: %v %v", err, diag)
		}
		return "198.51.100.20", nil
	}
	return o, &calls
}
func request(recipe, backend string) Request {
	r := Request{ID: "test-server", HostID: "test-host", Recipe: recipe, Backend: backend}
	if recipe != "vless-reality" {
		r.Domain = "proxy.example.com"
	}
	return r
}

func TestPreviewIsNonMutatingAndBoundToReviewedHost(t *testing.T) {
	o, calls := fixture(t)
	ctx := context.Background()
	o.ReadOnly = true
	p, err := Preview(ctx, request("vless-reality", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(o.Store.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview wrote private state: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0].Op != "inspect" {
		t.Fatalf("unexpected preview operations: %#v", *calls)
	}
	if _, err = Apply(ctx, p, p.Digest, o); err == nil {
		t.Fatal("read-only apply succeeded")
	}
	o.ReadOnly = false
	if _, err = Apply(ctx, p, "wrong", o); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if err = o.Store.Update(func(i *serverstate.Inventory) error {
		h, _ := i.Host("test-host")
		h.PublicHost = "203.0.113.11"
		return i.UpsertHost(h)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(ctx, p, p.Digest, o); err == nil {
		t.Fatal("stale host binding accepted")
	}
}

func TestDeploymentRetriesKeepCredentialsAndPartialVerification(t *testing.T) {
	o, calls := fixture(t)
	ctx := context.Background()
	p, err := Preview(ctx, request("vless-reality", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	base := o.Execute
	fail := true
	o.Execute = func(ctx context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
		out, e := base(ctx, host, r)
		if r.Op == "deploy" && fail {
			fail = false
			return out, errors.New("simulated interrupted SSH")
		}
		return out, e
	}
	if _, err = Apply(ctx, p, p.Digest, o); err == nil {
		t.Fatal("expected interrupted deployment")
	}
	first, err := loadJournal(o, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	o.Probe = func(context.Context, []byte) (string, error) { return "", errors.New("blocked UDP/TCP") }
	got, err := Resume(ctx, p.ID, o)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "installed-unverified" {
		t.Fatalf("unverified service marked %s", got.Status)
	}
	second, _ := loadJournal(o, p.ID)
	if !reflect.DeepEqual(first.Credentials, second.Credentials) || first.Token != second.Token {
		t.Fatal("resume rotated credentials or ownership")
	}
	before := len(*calls)
	o.Probe = func(context.Context, []byte) (string, error) { return "198.51.100.21", nil }
	o.VerifyInterface = "fixture-interface"
	got, err = Resume(ctx, p.ID, o)
	if err != nil || got.Status != "ready" {
		t.Fatalf("resume verify: %v %+v", err, got)
	}
	for _, call := range (*calls)[before:] {
		if call.Op == "deploy" {
			t.Fatal("verification retry repeated deployment")
		}
	}
	j, _ := loadJournal(o, p.ID)
	if j.ObservedExitIP != "198.51.100.21" || j.VerifiedAt.IsZero() || j.VerificationInterface != "fixture-interface" {
		t.Fatal("missing verification evidence")
	}
	info, err := os.Stat(filepath.Join(o.Store.StateDir, "deployments", p.ID+".json"))
	if err != nil || !info.Mode().IsRegular() || !privatefs.Private(filepath.Join(o.Store.StateDir, "deployments", p.ID+".json")) {
		t.Fatalf("unsafe journal permissions %v", err)
	}
}

func TestRecipesRenderAndExportWithoutPrivateServerSecrets(t *testing.T) {
	for _, recipe := range Recipes() {
		for _, backend := range []string{"native", "compose"} {
			t.Run(recipe.ID+"/"+backend, func(t *testing.T) {
				o, _ := fixture(t)
				ctx := context.Background()
				p, err := Preview(ctx, request(recipe.ID, backend), o)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = Apply(ctx, p, p.Digest, o); err != nil {
					t.Fatal(err)
				}
				j, _ := loadJournal(o, p.ID)
				private, err := base64.RawURLEncoding.DecodeString(j.Credentials.PrivateKey)
				if err != nil {
					t.Fatal(err)
				}
				key, err := ecdh.X25519().NewPrivateKey(private)
				if err != nil {
					t.Fatal(err)
				}
				if base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) != j.Credentials.PublicKey {
					t.Fatal("REALITY keypair mismatch")
				}
				if raw, ok := j.Files["config.json"]; ok {
					var config map[string]any
					if json.Unmarshal([]byte(raw), &config) != nil {
						t.Fatal("invalid JSON core config")
					}
				}
				for _, name := range []string{"config.yaml", "compose.yaml"} {
					if raw, ok := j.Files[name]; ok {
						var doc map[string]any
						if yaml.Unmarshal([]byte(raw), &doc) != nil {
							t.Fatal("invalid YAML config")
						}
					}
				}
				if backend == "compose" && !strings.Contains(j.Files["compose.yaml"], "io.lazyclash.owner") {
					t.Fatal("missing compose ownership label")
				}
				for _, format := range []string{"uri", "yaml", "starter", "client-bundle"} {
					raw, err := Export(ctx, p.ID, format, o)
					if err != nil {
						t.Fatalf("%s export: %v", format, err)
					}
					for _, private := range []string{j.Credentials.PrivateKey, j.Token} {
						if strings.Contains(string(raw), private) {
							t.Fatalf("%s exported server secret", format)
						}
					}
				}
				png, err := Export(ctx, p.ID, "qr", o)
				if err != nil || len(png) < 8 || string(png[:8]) != "\x89PNG\r\n\x1a\n" {
					t.Fatalf("invalid QR PNG: %v", err)
				}
				uri, _ := Export(ctx, p.ID, "uri", o)
				defs, diag, err := configwork.ParseImport(uri)
				if err != nil || len(defs) != 1 || len(diag) != 0 {
					t.Fatalf("URI cannot reimport: %v %v", err, diag)
				}
				for _, action := range []string{"stop", "start", "restart", "remove"} {
					plan, err := PreviewAction(ctx, p.ID, action, o)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = ApplyAction(ctx, plan, "invalid", o); err == nil {
						t.Fatal("stale action accepted")
					}
					if _, err = ApplyAction(ctx, plan, plan.Digest, o); err != nil {
						t.Fatal(err)
					}
				}
				if _, err = ClientNode(ctx, p.ID, o); err == nil {
					t.Fatal("removed service exported active node")
				}
			})
		}
	}
}

func TestDraftValidationAndJournalTampering(t *testing.T) {
	for _, r := range []Request{{ID: "Bad_ID"}, {PublicHost: "https://example.com"}, {Domain: "example.com;true"}, {RealityTarget: "example.com;touch /tmp/no:443"}, {Email: "x@y\n"}, {Version: "latest;bad"}, {PublicPort: 65536}} {
		if ValidateDraft(r) == nil {
			t.Fatalf("invalid draft accepted: %+v", r)
		}
	}
	if err := ValidateDraft(Request{}); err != nil {
		t.Fatal(err)
	}
	o, _ := fixture(t)
	ctx := context.Background()
	p, err := Preview(ctx, request("vless-reality", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(ctx, p, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	path, _ := journalPath(o, p.ID)
	raw, _ := os.ReadFile(path)
	var j journal
	_ = json.Unmarshal(raw, &j)
	j.Files["config.json"] = "{}"
	raw, _ = json.Marshal(j)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Resume(ctx, p.ID, o); err == nil {
		t.Fatal("tampered journal accepted")
	}
}

func TestHelperOwnershipAndTracking(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	defs := helper[:strings.Index(helper, "phase='preflight'")]
	script := defs + `\n` // added below as real Python lines
	script = strings.TrimSuffix(script, `\n`) + `
import tempfile
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory);ident='test';r={'backend':'native'};phase='test';req={'token':'token'}
    manifest={'token':'token','file_hashes':{}}
    private_write(root/'config.json','{}');record(root/'config.json');check_files()
    private_write(root/'config.json','changed')
    try:check_files();raise AssertionError('drift accepted')
    except Failure:pass
    private_write(root/'config.json','{}')
    manifest['token']='different'
    try:check_files();raise AssertionError('wrong owner accepted')
    except Failure:pass
print('ok')
`
	out, err := exec.Command(python, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("helper ownership check: %v %s", err, out)
	}
}

func TestChangedPublicEndpointKeepsManagementAndOldClientExport(t *testing.T) {
	o, _ := fixture(t)
	ctx := context.Background()
	p, err := Preview(ctx, request("vless-reality", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(ctx, p, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	if err = o.Store.Update(func(i *serverstate.Inventory) error {
		h, _ := i.Host("test-host")
		h.PublicHost = "203.0.113.19"
		return i.UpsertHost(h)
	}); err != nil {
		t.Fatal(err)
	}
	status, err := GetStatus(ctx, p.ID, o)
	if err != nil || !status.ClientUpdateRequired || status.SSH != "reachable" {
		t.Fatalf("changed endpoint status: %+v %v", status, err)
	}
	node, err := ClientNode(ctx, p.ID, o)
	if err != nil || !strings.Contains(string(node), "203.0.113.10") {
		t.Fatalf("client export was silently rebound: %s %v", node, err)
	}
	if _, err = PreviewAction(ctx, p.ID, "restart", o); err == nil {
		t.Fatal("restart used a stale verification endpoint")
	}
	for _, action := range []string{"stop", "remove"} {
		plan, err := PreviewAction(ctx, p.ID, action, o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ApplyAction(ctx, plan, plan.Digest, o); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdministratorBackupIncludesIssuedTLSOnlyOnExplicitExport(t *testing.T) {
	o, _ := fixture(t)
	base := o.Execute
	o.Execute = func(ctx context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
		out, err := base(ctx, host, r)
		if r.Op == "backup" {
			out.CertificateFiles = map[string]string{"fullchain.pem": "fixture-issued-certificate", "privkey.pem": "fixture-issued-tls-private-key"}
		}
		return out, err
	}
	ctx := context.Background()
	p, err := Preview(ctx, request("hysteria2", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(ctx, p, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	admin, err := Export(ctx, p.ID, "admin-bundle", o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(admin), "fixture-issued-tls-private-key") {
		t.Fatal("admin backup omitted issued TLS key")
	}
	client, err := Export(ctx, p.ID, "client-bundle", o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(client), "fixture-issued-tls-private-key") {
		t.Fatal("client bundle exposed the server TLS key")
	}
}
