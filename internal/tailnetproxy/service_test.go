package tailnetproxy

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"go.yaml.in/yaml/v3"
)

func fixture(t *testing.T) (Service, Request, *RemoteResponse, *[]string) {
	t.Helper()
	base := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(base, "servers.toml"), StateDir: filepath.Join(base, "state")}
	if err := store.Update(func(i *serverstate.Inventory) error {
		return i.UpsertTailnetNode(serverstate.TailnetNode{ID: "rpi", PeerID: "peer-rpi", SSHHost: "rpi", Hostname: "rpi", IPs: []string{"100.72.151.78"}, OS: "linux"})
	}); err != nil {
		t.Fatal(err)
	}
	observed := &RemoteResponse{OK: true, PeerID: "peer-rpi", IPs: []string{"100.72.151.78"}, Running: true, ListenerSafe: true, ListenerActive: true}
	ops := []string{}
	s := Service{Options: Options{Store: store, Now: func() time.Time { return time.Unix(1234, 0) }, Probe: func(_ context.Context, b []byte) (string, error) {
		if !strings.Contains(string(b), "password: secret") {
			t.Fatal("probe lost credentials")
		}
		return "203.0.113.9", nil
	}}}
	s.Options.Execute = func(_ context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
		if host != "rpi" {
			t.Fatal("wrong host")
		}
		ops = append(ops, r.Op)
		if r.Op == "start" || r.Op == "stop" || r.Op == "remove" {
			if r.Expected != observed.Mapping {
				return *observed, errors.New("changed mapping")
			}
			if r.Op == "start" {
				observed.Mapping = `{"TCP":{"TCPForward":"127.0.0.1:7897"},"Web":{},"Funnel":{},"Foreground":{}}`
				observed.Owned = true
			} else {
				observed.Mapping = ""
				if r.Op == "remove" {
					observed.Owned = false
				}
			}
		}
		return *observed, nil
	}
	return s, Request{ID: "share", NodeID: "rpi", Egress: "existing", Upstream: "http://user:secret@127.0.0.1:7897"}, observed, &ops
}
func TestExistingProxyPreviewApplyExportsAndScopedLifecycle(t *testing.T) {
	s, r, _, ops := fixture(t)
	ctx := context.Background()
	p, err := s.Preview(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := s.Options.Store.StateRoot()
	if _, e := os.Stat(root); !os.IsNotExist(e) {
		t.Fatal("preview wrote private state")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "user:") {
		t.Fatal("credentials in plan", string(b))
	}
	result, err := s.Apply(ctx, r, p.Digest)
	if err != nil || result.Status != "running_verified" {
		t.Fatal(result, err)
	}
	path, _ := s.path(r.ID)
	info, _ := os.Stat(path)
	if !info.Mode().IsRegular() || !privatefs.Private(path) {
		t.Fatal("state permissions")
	}
	inv, err := os.ReadFile(s.Options.Store.Path)
	if err != nil || strings.Contains(string(inv), "secret") {
		t.Fatal("inventory credential leak", err)
	}
	for _, format := range []string{"yaml", "starter", "client-bundle"} {
		data, e := s.Export(r.ID, format)
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(string(data), "Tailnet") || strings.Contains(string(data), "token") || strings.Contains(string(data), "\"ssh_host\"") {
			t.Fatalf("invalid %s export: %s", format, data)
		}
	}
	node, err := s.ClientNode(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	definitions, issues, err := configwork.ParseImport(node)
	if err != nil || len(issues) > 0 || len(definitions) != 1 {
		t.Fatal("node cannot reimport", issues, err)
	}
	for _, action := range []string{"stop", "start", "remove"} {
		plan, e := s.PreviewAction(ctx, r.ID, action)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Action(ctx, r.ID, action, plan.Digest); e != nil {
			t.Fatal(action, e)
		}
	}
	if _, err = s.ClientNode(r.ID); err == nil {
		t.Fatal("removed share exported")
	}
	for _, op := range *ops {
		if strings.Contains(op, "reset") || strings.Contains(op, "down") {
			t.Fatal(op)
		}
	}
}
func TestChangedMappingAddressAndPeerFailBeforeMutation(t *testing.T) {
	for _, condition := range []string{"mapping", "address", "peer"} {
		t.Run(condition, func(t *testing.T) {
			s, r, state, ops := fixture(t)
			ctx := context.Background()
			p, err := s.Preview(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "mapping":
				state.Mapping = `{"TCP":{"TCPForward":"127.0.0.1:9999"}}`
			case "address":
				state.IPs = nil
			case "peer":
				state.PeerID = "other"
			}
			if _, err = s.Apply(ctx, r, p.Digest); err == nil {
				t.Fatal("changed host accepted")
			}
			for _, op := range *ops {
				if op != "inspect" {
					t.Fatal("mutated changed host", op)
				}
			}
		})
	}
}
func TestConfigureMergesPrivateUpstreamAndStopPreservesChangedMapping(t *testing.T) {
	s, r, state, _ := fixture(t)
	ctx := context.Background()
	p, _ := s.Preview(ctx, r)
	if _, err := s.Apply(ctx, r, p.Digest); err != nil {
		t.Fatal(err)
	}
	p, err := s.Preview(ctx, Request{ID: r.ID, Name: "Updated"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.Upstream != r.Upstream || p.Request.Port != DefaultPort {
		t.Fatal("lost saved configuration")
	}
	if _, err = s.Apply(ctx, Request{ID: r.ID, Name: "Updated"}, p.Digest); err != nil {
		t.Fatal(err)
	}
	p, err = s.PreviewAction(ctx, r.ID, "stop")
	if err != nil {
		t.Fatal(err)
	}
	state.Mapping = `{"TCP":{"TCPForward":"127.0.0.1:9999"},"Web":{},"Funnel":{}}`
	if _, err = s.Action(ctx, r.ID, "stop", p.Digest); err == nil {
		t.Fatal("external mapping stopped")
	}
	if !strings.Contains(state.Mapping, "9999") {
		t.Fatal("external mapping overwritten")
	}
}
func TestReadOnlyAndFailedVerification(t *testing.T) {
	s, r, _, ops := fixture(t)
	ctx := context.Background()
	p, _ := s.Preview(ctx, r)
	s.Options.ReadOnly = true
	if _, err := s.Apply(ctx, r, p.Digest); err == nil {
		t.Fatal("read-only mutation")
	}
	if len(*ops) != 1 {
		t.Fatal(*ops)
	}
	s.Options.ReadOnly = false
	s.Options.Probe = func(context.Context, []byte) (string, error) { return "", errors.New("network unavailable") }
	result, err := s.Apply(ctx, r, p.Digest)
	if err == nil || result.Status != "running_unverified" {
		t.Fatal(result, err)
	}
	status, err := s.Status(ctx, r.ID)
	if err != nil || !status.VerifiedAt.IsZero() {
		t.Fatal(status, err)
	}
}
func TestGatewayNormalizationAuthProfileCyclesAndUDP(t *testing.T) {
	n := serverstate.TailnetNode{Hostname: "rpi", IPs: []string{"100.72.151.78"}}
	for _, r := range []Request{
		{ID: "bad", Mode: "serve", UDP: true},
		{ID: "bad", Egress: "upstream", Upstream: "socks5://127.0.0.1:17898"},
		{ID: "bad", Egress: "upstream", Upstream: "http://rpi:7898"},
		{ID: "bad", Egress: "upstream", Upstream: "http://100.72.151.78:7898"},
		{ID: "bad", Egress: "existing", Upstream: "http://127.0.0.1:7897"},
		{ID: "bad", Egress: "existing", Upstream: "http://user:pass@0.0.0.0:7897"},
		{ID: "bad", Mode: "direct", UDP: true, Egress: "upstream", Upstream: "http://127.0.0.1:7897"},
	} {
		if _, e := normalize(r, n); e == nil {
			t.Fatalf("unsafe request accepted: %+v", r)
		}
	}
	r, e := normalize(Request{ID: "gateway", Mode: "direct", UDP: true}, n)
	if e != nil {
		t.Fatal(e)
	}
	j := journal{Request: r, CoreID: "gateway", ListenIP: n.IPs[0], Username: "gateway", Password: "private"}
	core, e := gatewayRequest(j)
	if e != nil {
		t.Fatal(e)
	}
	var profile map[string]any
	if yaml.Unmarshal(core.Input, &profile) != nil {
		t.Fatal("invalid profile")
	}
	if core.ProxyListen != n.IPs[0] || !core.ProxyUDP || !core.ProxyGateway || core.Network.TUN || core.Network.SystemProxy {
		t.Fatal(core)
	}
	if values, ok := profile["skip-auth-prefixes"].([]any); !ok || len(values) != 0 {
		t.Fatal("loopback authentication bypass")
	}
}
func TestFailedCoreDownloadCanResumeWithSameCredentials(t *testing.T) {
	s, _, _, _ := fixture(t)
	s.Options.Probe = nil
	artifact := []byte("fixture")
	s.Options.Core = managedcore.Options{NetworkPlan: func(_ context.Context, _ string, n managedcore.NetworkOptions) (managedcore.NetworkOptions, []string, []string, error) {
		return n, nil, nil, nil
	}, ResolveArtifact: func(_ context.Context, r managedcore.Request, _ managedcore.HostFacts) (managedcore.Artifact, error) {
		return managedcore.Artifact{Kind: "gzip", Version: r.Version, SHA256: hash(artifact)}, nil
	}, FetchArtifact: func(context.Context, managedcore.Artifact) ([]byte, error) { return nil, errors.New("download failed") }, Execute: func(_ context.Context, _ string, _ bool, data []byte) ([]byte, error) {
		var r map[string]any
		json.Unmarshal(data, &r)
		if r["op"] != "facts" {
			t.Fatal("unexpected mutation", r["op"])
		}
		return []byte(`{"facts":{"os":"linux","arch":"arm64","home":"/home/fixture","systemd":true,"sandbox":true}}`), nil
	}}
	r := Request{ID: "gateway", NodeID: "rpi"}
	ctx := context.Background()
	p, err := s.Preview(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Apply(ctx, r, p.Digest); err == nil {
		t.Fatal("failed download succeeded")
	}
	j, err := s.load(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err = s.Preview(ctx, Request{ID: r.ID})
	if err != nil {
		t.Fatal("partial draft cannot resume", err)
	}
	if p.Request.Egress != "direct" {
		t.Fatal(p)
	}
	after, _ := s.load(r.ID)
	if after.Password != j.Password || after.Token != j.Token {
		t.Fatal("recovery rotated credentials")
	}
}

func TestInterruptedRemoveAfterCoreRemovalCanFinish(t *testing.T) {
	s, r, _, _ := fixture(t)
	ctx := context.Background()
	p, _ := s.Preview(ctx, r)
	if _, err := s.Apply(ctx, r, p.Digest); err != nil {
		t.Fatal(err)
	}
	j, _ := s.load(r.ID)
	j.Request.Egress = "direct"
	j.Request.Upstream = ""
	j.CoreID = coreID(j.Request.ID)
	if err := s.save(j); err != nil {
		t.Fatal(err)
	}
	opts, _ := s.coreOptions()
	dir := filepath.Join(opts.StateDir, "instances", j.CoreID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"id": j.CoreID, "owner_token": "private-owner", "removed": true})
	if err := os.WriteFile(filepath.Join(dir, "instance.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	original := s.Options.Execute
	failOnce := true
	s.Options.Execute = func(ctx context.Context, host string, r RemoteRequest) (RemoteResponse, error) {
		if r.Op == "remove" && failOnce {
			failOnce = false
			return RemoteResponse{}, errors.New("lost cleanup response")
		}
		return original(ctx, host, r)
	}
	p, err := s.PreviewAction(ctx, r.ID, "remove")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Action(ctx, r.ID, "remove", p.Digest); err == nil {
		t.Fatal("lost cleanup response ignored")
	}
	p, err = s.PreviewAction(ctx, r.ID, "remove")
	if err != nil {
		t.Fatal("cannot resume after core removal", err)
	}
	if _, err = s.Action(ctx, r.ID, "remove", p.Digest); err != nil {
		t.Fatal("cannot finish cleanup", err)
	}
	inv, _ := s.Options.Store.Load()
	if len(inv.TailnetProxies) != 0 {
		t.Fatal("registration retained")
	}
}

func TestRemovedJournalReconcilesInventoryWithoutContactingHost(t *testing.T) {
	s, r, _, _ := fixture(t)
	ctx := context.Background()
	p, _ := s.Preview(ctx, r)
	if _, err := s.Apply(ctx, r, p.Digest); err != nil {
		t.Fatal(err)
	}
	j, _ := s.load(r.ID)
	j.Phase = "removed"
	if err := s.save(j); err != nil {
		t.Fatal(err)
	}
	s.Options.Execute = func(context.Context, string, RemoteRequest) (RemoteResponse, error) {
		t.Fatal("contacted host for retired local cleanup")
		return RemoteResponse{}, nil
	}
	p, err := s.PreviewAction(ctx, r.ID, "remove")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Action(ctx, r.ID, "remove", p.Digest); err != nil {
		t.Fatal(err)
	}
	inv, _ := s.Options.Store.Load()
	if len(inv.TailnetProxies) != 0 {
		t.Fatal("registration retained")
	}
}
