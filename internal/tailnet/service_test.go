package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type fakeHosts struct {
	remote, local     snapshot
	calls             []map[string]any
	mutate            func(map[string]any)
	remoteIP, localIP string
	ackCount          int
	selected          response
}

func (f *fakeHosts) execute(_ context.Context, host string, priv bool, input []byte) ([]byte, error) {
	var r map[string]any
	if err := json.Unmarshal(input, &r); err != nil {
		return nil, err
	}
	r["host"] = host
	r["privileged"] = priv
	f.calls = append(f.calls, r)
	switch r["op"] {
	case "inspect":
		if host == "rpi" {
			return json.Marshal(f.remote)
		}
		return json.Marshal(f.local)
	case "probe":
		ip := f.localIP
		if host == "rpi" {
			ip = f.remoteIP
		}
		return json.Marshal(response{IP: ip})
	case "apply":
		if f.mutate != nil {
			f.mutate(r)
		}
		return json.Marshal(response{Status: "verification_pending", Guard: "/fixture/guard", AckToken: strings.Repeat("a", 48)})
	case "ack":
		f.ackCount++
		return json.Marshal(response{Status: "acknowledged"})
	case "selection_status":
		return json.Marshal(f.selected)
	default:
		return nil, errors.New("unexpected operation")
	}
}
func fixtureService(t *testing.T) (Service, *fakeHosts) {
	t.Helper()
	p := Peer{ID: "peer-rpi", Hostname: "rpi", OS: "linux", IPs: []string{"100.72.151.78"}, Online: true}
	f := &fakeHosts{local: snapshot{Self: Peer{ID: "self", IPs: []string{"100.100.1.1"}}, Peers: []Peer{p}, Prefs: prefs{AllowLAN: true}, Core: map[string]any{}, Forwarding: map[string]string{}}, remote: snapshot{Self: p, OS: "linux", Prefs: prefs{}, Forwarding: map[string]string{"ipv4": "0", "ipv6": "0"}, Core: map[string]any{}}, remoteIP: "203.0.113.77", localIP: "203.0.113.77"}
	root := t.TempDir()
	s := Service{Store: serverstate.Store{Path: filepath.Join(root, "servers.toml"), StateDir: filepath.Join(root, "private")}, Options: Options{Execute: f.execute, Now: func() time.Time { return time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC) }, FreshManagement: func(context.Context, string) error { return nil }, NetworkCheck: func(context.Context, string, bool, string) ([]string, error) { return nil, nil }}}
	return s, f
}
func TestSetupPreviewReadOnlyAndIdentity(t *testing.T) {
	s, f := fixtureService(t)
	plan, err := s.Preview(context.Background(), Request{Action: "setup", ID: "rpi", SSHHost: "rpi"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.NeedsPrivilege || len(plan.Blockers) != 0 || plan.Peer.ID != "peer-rpi" {
		t.Fatalf("bad preview: %+v", plan)
	}
	if _, err := os.Stat(s.Store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview wrote inventory")
	}
	for _, r := range f.calls {
		if r["op"] != "inspect" {
			t.Fatalf("preview called %v", r)
		}
	}
	f.remote.Self.ID = "different-peer"
	if _, err = s.Preview(context.Background(), plan.Request); err == nil {
		t.Fatal("accepted SSH identity mismatch")
	}
}
func TestSetupApplyApprovalPendingAndPrivateState(t *testing.T) {
	s, f := fixtureService(t)
	plan, err := s.Preview(context.Background(), Request{Action: "setup", ID: "rpi", SSHHost: "rpi"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Apply(context.Background(), plan, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "approval_pending" || f.ackCount != 1 {
		t.Fatalf("unexpected result: %+v ack=%d", result, f.ackCount)
	}
	inv, err := s.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	n, err := inv.TailnetNode("rpi")
	if err != nil || !n.ExitManaged {
		t.Fatalf("missing registration: %+v %v", n, err)
	}
	r, err := s.readReceipt("rpi")
	if err != nil || len(r.OwnerToken) != 64 {
		t.Fatalf("bad private receipt: %v", err)
	}
	p, _ := s.receiptPath("rpi")
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatal("receipt not private")
	}
	data, _ := os.ReadFile(s.Store.Path)
	if strings.Contains(string(data), r.OwnerToken) {
		t.Fatal("inventory leaked owner secret")
	}
}
func TestApplyRejectsChangedForwarding(t *testing.T) {
	s, f := fixtureService(t)
	p, err := s.Preview(context.Background(), Request{Action: "setup", ID: "rpi", SSHHost: "rpi"})
	if err != nil {
		t.Fatal(err)
	}
	f.remote.Forwarding["ipv4"] = "1"
	if _, err = s.Apply(context.Background(), p, p.Digest); err == nil {
		t.Fatal("accepted stale preview")
	}
	for _, r := range f.calls {
		if r["op"] == "apply" {
			t.Fatal("mutated with stale digest")
		}
	}
}
func TestRegisterDoesNotAdvertise(t *testing.T) {
	s, f := fixtureService(t)
	p, err := s.Preview(context.Background(), Request{Action: "register", ID: "rpi", SSHHost: "rpi"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Apply(context.Background(), p, p.Digest)
	if err != nil || result.Status != "registered" {
		t.Fatalf("%+v %v", result, err)
	}
	for _, r := range f.calls {
		if r["op"] != "inspect" {
			t.Fatalf("registration changed host: %v", r)
		}
	}
	inv, _ := s.Store.Load()
	n, _ := inv.TailnetNode("rpi")
	if n.ExitManaged {
		t.Fatal("registration adopted exit ownership")
	}
}
func TestUseRequiresApprovedPeerAndVerifiesActualEgress(t *testing.T) {
	s, f := fixtureService(t)
	if _, err := s.Register(context.Background(), "rpi", "rpi"); err != nil {
		t.Fatal(err)
	}
	p, err := s.Preview(context.Background(), Request{Action: "use", ID: "rpi"})
	if err != nil || len(p.Blockers) == 0 {
		t.Fatalf("unapproved exit accepted: %v %+v", err, p)
	}
	f.local.Peers[0].ExitAvailable = true
	f.local.Core = map[string]any{"enabled": true, "device": "utun0", "identity": "core1", "config_hash": "hash"}
	p, err = s.Preview(context.Background(), Request{Action: "use", ID: "rpi", Controller: "unix:///tmp/controller.sock", ControllerSecret: "private-token", ProbeProxy: "http://127.0.0.1:7897"})
	if err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(p)
	if strings.Contains(string(public), "private-token") {
		t.Fatal("preview leaked controller secret")
	}
	result, err := s.Apply(context.Background(), p, p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Selected || !result.TUNPaused || result.DirectIP != f.remoteIP || result.ProxyIP != f.remoteIP {
		t.Fatalf("bad selection result: %+v", result)
	}
	f.localIP = "1.1.1.1"
	if _, err = s.Apply(context.Background(), p, p.Digest); err == nil {
		t.Fatal("accepted different exit IP")
	}
	if f.ackCount != 1 {
		t.Fatal("acknowledged failed egress")
	}
}
func TestUnknownVPNBlocksSelection(t *testing.T) {
	s, f := fixtureService(t)
	f.local.Peers[0].ExitAvailable = true
	if _, err := s.Register(context.Background(), "rpi", "rpi"); err != nil {
		t.Fatal(err)
	}
	s.Options.NetworkCheck = func(context.Context, string, bool, string) ([]string, error) { return []string{"unknown VPN"}, nil }
	p, err := s.Preview(context.Background(), Request{Action: "use", ID: "rpi"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Apply(context.Background(), p, p.Digest); err == nil {
		t.Fatal("unknown VPN did not block")
	}
}
func TestReadOnlyRejectsMutations(t *testing.T) {
	s, _ := fixtureService(t)
	s.Options.ReadOnly = true
	if _, err := s.Register(context.Background(), "rpi", "rpi"); err == nil {
		t.Fatal("read-only register")
	}
	if _, err := s.Apply(context.Background(), Plan{}, ""); err == nil {
		t.Fatal("read-only apply")
	}
}

func TestProbeProxyRejectsCredentialsAndRemoteEndpoints(t *testing.T) {
	s, _ := fixtureService(t)
	for _, endpoint := range []string{"http://u:p@127.0.0.1:7897", "http://100.72.151.78:7897", "http://127.0.0.1:7897/path", "file:///tmp/example", "http://127.0.0.1:7897?token=secret"} {
		if _, err := s.resolved(context.Background(), Request{ProbeProxy: endpoint}); err == nil {
			t.Errorf("accepted unsafe probe %q", endpoint)
		}
	}
	for _, endpoint := range []string{"http://127.0.0.1:7897", "socks5h://[::1]:7897"} {
		if _, err := s.resolved(context.Background(), Request{ProbeProxy: endpoint}); err != nil {
			t.Error(err)
		}
	}
}
func TestOfflinePeerIsNotReportedAsAcknowledged(t *testing.T) {
	s, f := fixtureService(t)
	if _, err := s.Register(context.Background(), "rpi", "rpi"); err != nil {
		t.Fatal(err)
	}
	f.local.Peers[0].Online = false
	f.local.Peers[0].Selected = true
	f.selected = response{NodeID: "rpi", Status: "acknowledged", TUNPaused: true}
	result, err := s.Status(context.Background(), "rpi")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "offline" || !result.Selected {
		t.Fatalf("offline acknowledged state masked: %+v", result)
	}
}
