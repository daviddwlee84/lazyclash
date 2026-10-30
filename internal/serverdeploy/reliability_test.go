package serverdeploy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"go.yaml.in/yaml/v3"
)

func TestSalamanderCredentialsSurviveInterruptedDeployment(t *testing.T) {
	for _, backend := range []string{"native", "compose"} {
		t.Run(backend, func(t *testing.T) {
			o, _ := fixture(t)
			r := request("hysteria2", backend)
			r.Obfs = "salamander"
			ctx := context.Background()
			p, err := Preview(ctx, r, o)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(p)
			if strings.Contains(string(raw), "obfs_password") {
				t.Fatal("preview exposed credential")
			}
			base := o.Execute
			o.Execute = func(ctx context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
				if r.Op == "deploy" {
					return RemoteResponse{}, errors.New("interrupted")
				}
				return base(ctx, host, r)
			}
			if _, err = Apply(ctx, p, p.Digest, o); err == nil {
				t.Fatal("expected interruption")
			}
			j, err := loadJournal(o, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if j.Credentials.ObfsPassword == "" || j.Credentials.ObfsPassword == j.Credentials.Password {
				t.Fatal("missing independent secret")
			}
			var cfg map[string]any
			if yaml.Unmarshal([]byte(j.Files["config.yaml"]), &cfg) != nil {
				t.Fatal("invalid configuration")
			}
			obfs := cfg["obfs"].(map[string]any)
			if obfs["type"] != "salamander" || obfs["salamander"].(map[string]any)["password"] != j.Credentials.ObfsPassword {
				t.Fatal("server/client secret mismatch")
			}
			o.Execute = base
			o.Probe = func(context.Context, []byte) (string, error) { return "", errors.New("UDP blocked") }
			result, err := Resume(ctx, p.ID, o)
			if err != nil || result.Status != "installed-unverified" {
				t.Fatal(result, err)
			}
			o.Probe = func(context.Context, []byte) (string, error) { return "198.51.100.20", nil }
			result, err = Resume(ctx, p.ID, o)
			after, _ := loadJournal(o, p.ID)
			if err != nil || result.Status != "ready" || after.Credentials != j.Credentials {
				t.Fatal("resume rotated secrets", result, err)
			}
			for _, format := range []string{"yaml", "uri", "starter", "client-bundle", "qr"} {
				data, err := Export(ctx, p.ID, format, o)
				if err != nil || len(data) == 0 {
					t.Fatal(format, err)
				}
				if format == "uri" {
					defs, diag, err := configwork.ParseImport(data)
					if err != nil || len(diag) != 0 || len(defs) != 1 || defs[0].Map()["obfs-password"] != j.Credentials.ObfsPassword {
						t.Fatal("lost obfuscation during round trip", err)
					}
				}
			}
			plain := r
			plain.Obfs = "none"
			plain.ID = "other-server"
			plain.Domain = "other.example.com"
			plain.ListenPort = 8443
			pp, err := Preview(ctx, plain, o)
			if err != nil {
				t.Fatal(err)
			}
			if pp.Request.Obfs != "" || pp.Digest == p.Digest {
				t.Fatal("incorrect normalized mode or digest")
			}
		})
	}
}

func TestObfuscationValidationPrecedesRemoteInspection(t *testing.T) {
	for _, r := range []Request{{Recipe: "vless-reality", Obfs: "salamander"}, {Recipe: "hysteria2", Obfs: "gecko"}, {Obfs: "salamander"}} {
		o, calls := fixture(t)
		r.ID = "test-server"
		r.HostID = "test-host"
		if ValidateDraft(r) == nil {
			t.Fatal("invalid draft accepted", r)
		}
		if _, err := Preview(context.Background(), r, o); err == nil || len(*calls) != 0 {
			t.Fatal("invalid request inspected host", err)
		}
	}
}

func TestLegacyJournalPreservesDigestsAndExports(t *testing.T) {
	o, _ := fixture(t)
	raw, err := os.ReadFile("testdata/legacy-reality.json")
	if err != nil {
		t.Fatal(err)
	}
	path, err := journalPath(o, "test-server")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := loadJournal(o, "test-server")
	if err != nil {
		t.Fatal("legacy digest changed", err)
	}
	for _, format := range []string{"yaml", "uri", "qr", "starter", "client-bundle", "admin-bundle"} {
		if _, err = Export(context.Background(), j.Plan.ID, format, o); err != nil {
			t.Fatal(format, err)
		}
	}
	before, _ := ClientNode(context.Background(), j.Plan.ID, o)
	p, err := Preview(context.Background(), j.Plan.Request, o)
	if err != nil || p.Digest != j.Plan.Digest || p.Request.RealityMLKEM {
		t.Fatal("legacy preview rewritten", err)
	}
	if _, err = Resume(context.Background(), j.Plan.ID, o); err != nil {
		t.Fatal(err)
	}
	after, _ := ClientNode(context.Background(), j.Plan.ID, o)
	if string(before) != string(after) || strings.Contains(string(after), "support-x25519") {
		t.Fatal("legacy exports changed")
	}
	for _, action := range []string{"stop", "start", "restart", "remove"} {
		p, err := PreviewAction(context.Background(), j.Plan.ID, action, o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ApplyAction(context.Background(), p, p.Digest, o); err != nil {
			t.Fatal(action, err)
		}
	}
}

func TestRealityExportsRemainIndependentOfLossyURI(t *testing.T) {
	o, _ := fixture(t)
	ctx := context.Background()
	p, err := Preview(ctx, request("vless-reality", "native"), o)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Request.RealityMLKEM {
		t.Fatal("new preview lacks compatibility profile")
	}
	if _, err = Apply(ctx, p, p.Digest, o); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"yaml", "starter", "admin-bundle", "client-bundle"} {
		raw, err := Export(ctx, p.ID, format, o)
		if err != nil {
			t.Fatal(format, err)
		}
		if format == "client-bundle" {
			var bundle map[string]any
			if json.Unmarshal(raw, &bundle) != nil || bundle["uri"] != nil || bundle["warnings"] == nil || !strings.Contains(bundle["mihomo"].(string), "support-x25519mlkem768: true") {
				t.Fatal("incomplete client bundle")
			}
		}
	}
	for _, format := range []string{"uri", "qr"} {
		if _, err = Export(ctx, p.ID, format, o); err == nil {
			t.Fatal("lossy export succeeded")
		}
	}
}
