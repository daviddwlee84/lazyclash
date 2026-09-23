package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupFixture(t *testing.T) (Request, Options, *[]string) {
	t.Helper()
	calls := []string{}
	artifact := []byte("verified fixture archive")
	req := Request{ID: "fixture", Name: "Fixture", Backend: "native", InputKind: "links", Input: []byte("vless://123e4567-e89b-12d3-a456-426614174000@example.test:443?security=tls#test"), Preset: "simple", ServiceScope: "user"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"version":"v1.19.31","meta":true}`)
		case "/configs":
			io.WriteString(w, `{"mode":"rule"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	opts := Options{StateDir: filepath.Join(t.TempDir(), "state"), NetworkPlan: func(_ context.Context, _ string, n NetworkOptions) (NetworkOptions, []string, []string, error) {
		return n, nil, nil, nil
	}, ResolveArtifact: func(_ context.Context, r Request, h HostFacts) (Artifact, error) {
		return Artifact{Kind: "gzip", Version: r.Version, Platform: h.OS + "/" + h.Arch, SHA256: hashBytes(artifact), Size: int64(len(artifact))}, nil
	}, FetchArtifact: func(context.Context, Artifact) ([]byte, error) { return artifact, nil }, Probe: func(context.Context, config.Target) error { return nil }, Open: func(_ context.Context, _ config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		c, e := core.New(core.Options{Endpoint: server.URL, ReadOnly: readOnly})
		return c, nil, e
	}}
	opts.Execute = func(_ context.Context, _ string, priv bool, data []byte) ([]byte, error) {
		var r hostRequest
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, err
		}
		calls = append(calls, r.Op)
		switch r.Op {
		case "facts":
			return json.Marshal(hostResponse{Facts: HostFacts{OS: "linux", Arch: "amd64", Home: "/home/fixture", Systemd: true, Sandbox: true}})
		case "install":
			if priv {
				t.Error("user installation escalated")
			}
			return json.Marshal(hostResponse{Status: "running_unverified", Digest: "host-digest"})
		default:
			return nil, errors.New("unexpected host operation")
		}
	}
	return req, opts, &calls
}
func TestPreviewAndReadOnlyNeverCreateStateOrInstall(t *testing.T) {
	req, opts, calls := setupFixture(t)
	plan, err := Preview(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Blockers) > 0 || plan.Digest == "" {
		t.Fatal(plan.Blockers)
	}
	if _, err = os.Stat(opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview created state", err)
	}
	opts.ReadOnly = true
	if _, err = Apply(context.Background(), req, plan.Digest, opts); err == nil {
		t.Fatal("read-only installed")
	}
	if strings.Join(*calls, ",") != "facts" {
		t.Fatal(*calls)
	}
}
func TestInstallRegistersAfterAuthenticationAndPrivateState(t *testing.T) {
	req, opts, calls := setupFixture(t)
	registered := false
	opts.Register = func(target config.Target) error {
		registered = true
		if target.ManagedCoreID != req.ID || target.ProbeProxy == "" || target.ConfigSource == nil {
			t.Fatal(target)
		}
		return nil
	}
	plan, err := Preview(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := Apply(context.Background(), req, plan.Digest, opts)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "running_verified" || !registered {
		t.Fatal(receipt)
	}
	if strings.Join(*calls, ",") != "facts,facts,install" {
		t.Fatal(*calls)
	}
	saved, err := GetInstance(req.ID, opts)
	if err != nil || saved.OwnerToken == "" {
		t.Fatal(saved, err)
	}
	data, _ := json.Marshal(saved)
	if strings.Contains(string(data), saved.OwnerToken) {
		t.Fatal("public owner token")
	}
	info, _ := os.Stat(saved.Target.SecretFile)
	if !info.Mode().IsRegular() || !privatefs.Private(saved.Target.SecretFile) {
		t.Fatal(info.Mode())
	}
}
func TestChecksumFailureDoesNotMutateHost(t *testing.T) {
	req, opts, calls := setupFixture(t)
	opts.FetchArtifact = func(context.Context, Artifact) ([]byte, error) { return []byte("wrong"), nil }
	plan, err := Preview(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(context.Background(), req, plan.Digest, opts); err == nil {
		t.Fatal("bad archive installed")
	}
	for _, op := range *calls {
		if op != "facts" {
			t.Fatal(*calls)
		}
	}
}
func TestUnknownInstallationResultIsNotRetried(t *testing.T) {
	req, opts, calls := setupFixture(t)
	original := opts.Execute
	opts.Execute = func(ctx context.Context, host string, priv bool, data []byte) ([]byte, error) {
		var r hostRequest
		json.Unmarshal(data, &r)
		if r.Op == "install" {
			*calls = append(*calls, "install")
			return nil, errors.New("lost transport")
		}
		return original(ctx, host, priv, data)
	}
	plan, _ := Preview(context.Background(), req, opts)
	receipt, err := Apply(context.Background(), req, plan.Digest, opts)
	if err == nil || receipt.Status != "unknown_host_result" || receipt.ID == "" {
		t.Fatal(receipt, err)
	}
	if strings.Join(*calls, ",") != "facts,facts,install" {
		t.Fatal(*calls)
	}
	if _, err = GetInstance(req.ID, opts); err != nil {
		t.Fatal("lost recovery record", err)
	}
}
func TestUnacknowledgedGuardCannotRegister(t *testing.T) {
	req, opts, _ := setupFixture(t)
	registered := false
	opts.Register = func(config.Target) error { registered = true; return nil }
	original := opts.Execute
	opts.Execute = func(ctx context.Context, host string, priv bool, data []byte) ([]byte, error) {
		var r hostRequest
		json.Unmarshal(data, &r)
		if r.Op == "install" {
			return json.Marshal(hostResponse{Status: "running_unverified", Digest: "host-digest", AckToken: strings.Repeat("a", 48), GuardRef: "private", Deadline: 123})
		}
		if r.Op == "ack" {
			return json.Marshal(hostResponse{Status: "ack_pending"})
		}
		return original(ctx, host, priv, data)
	}
	plan, _ := Preview(context.Background(), req, opts)
	receipt, err := Apply(context.Background(), req, plan.Digest, opts)
	if err == nil || registered || !receipt.NeedsACK {
		t.Fatal(receipt, err, registered)
	}
}
