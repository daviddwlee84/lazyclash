package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/tailnet"
	"github.com/daviddwlee84/lazyclash/internal/tailnetproxy"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
)

func tailnetCLIFixture(t *testing.T) (Dependencies, *[]string) {
	t.Helper()
	isolated(t)
	dir := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}
	err := store.Update(func(inv *serverstate.Inventory) error {
		if e := inv.UpsertTailnetNode(serverstate.TailnetNode{ID: "pi", PeerID: "peer1", SSHHost: "fixture-pi", Hostname: "pi", OS: "linux", IPs: []string{"100.72.1.1"}, ExitStatus: "registered"}); e != nil {
			return e
		}
		return inv.UpsertTailnetProxy(serverstate.TailnetProxy{ID: "gateway", NodeID: "pi", PeerID: "peer1", SSHHost: "fixture-pi", Name: "Gateway", Mode: "serve", Backend: "native", Egress: "direct", Port: 7898, LocalPort: 17898, Status: "ready"})
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	deps := Dependencies{ServerStore: store, Terminal: func(io.Reader, io.Writer) bool { return false }, Discover: func(context.Context, string) ([]config.Target, error) { return nil, nil }}
	deps.Tailnet = tailnet.Options{Execute: func(_ context.Context, host string, privileged bool, b []byte) ([]byte, error) {
		var req map[string]any
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}
		op, _ := req["op"].(string)
		calls = append(calls, host+":"+op)
		if op != "inspect" {
			return nil, errors.New("unexpected mutation " + op)
		}
		peer := tailnet.Peer{ID: "peer1", Hostname: "pi", OS: "linux", IPs: []string{"100.72.1.1"}, Online: true, ExitAvailable: true}
		self := tailnet.Peer{ID: "local", Hostname: "mac", OS: "macos", Online: true}
		if host != "" {
			self = peer
		}
		return json.Marshal(map[string]any{"self": self, "peers": []tailnet.Peer{peer}, "prefs": map[string]any{"advertise": false, "allow_lan": false, "exit_node": ""}, "os": "linux", "forwarding": map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}})
	}}
	return deps, &calls
}

func TestTailnetOfflineInventoryCompletionAndSkill(t *testing.T) {
	deps, calls := tailnetCLIFixture(t)
	for _, args := range [][]string{{"tailnet", "list", "--json"}, {"__complete", "tailnet", "exit", "use", ""}, {"__complete", "tailnet", "proxy", "export", ""}, {"skill", "print", "tailnet"}} {
		out, _, err := run(t, deps, args...)
		if err != nil {
			t.Fatal(args, err, out)
		}
		if args[0] == "tailnet" && !json.Valid([]byte(out)) {
			t.Fatal(out)
		}
		if args[0] == "__complete" && !strings.Contains(out, map[string]string{"exit": "pi", "proxy": "gateway"}[args[2]]) {
			t.Fatal("missing offline completion", out)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("offline operation contacted peer", *calls)
	}
}

func TestTailnetRegistrationPreviewIsReadOnlyAndJSON(t *testing.T) {
	deps, calls := tailnetCLIFixture(t)
	before, err := os.ReadFile(deps.ServerStore.Path)
	if err != nil {
		t.Fatal(err)
	}
	out, diagnostic, err := run(t, deps, "tailnet", "add", "second", "--ssh", "fixture-pi", "--json")
	var plan tailnet.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil || len(plan.Digest) != 64 {
		t.Fatal(err, out, diagnostic)
	}
	if plan.Request.Action != "register" || plan.NeedsPrivilege {
		t.Fatal("registration changes exit settings", out)
	}
	after, _ := os.ReadFile(deps.ServerStore.Path)
	if string(before) != string(after) {
		t.Fatal("preview changed inventory")
	}
	for _, call := range *calls {
		if !strings.HasSuffix(call, ":inspect") {
			t.Fatal("preview mutation", call)
		}
	}
}

func TestTailnetInvalidAndMachineRequestsDoNotPromptOrApply(t *testing.T) {
	deps, calls := tailnetCLIFixture(t)
	cases := [][]string{
		{"tailnet", "exit", "setup", "bad/id", "--ssh", "fixture-pi", "--interactive"},
		{"tailnet", "exit", "setup", "pi", "--yes"},
		{"tailnet", "exit", "release", "pi"},
		{"tailnet", "exit", "use", "pi", "--interactive", "--json"},
		{"tailnet", "proxy", "deploy", "--mode", "wrong", "--interactive"},
		{"tailnet", "proxy", "deploy", "demo", "--node", "pi", "--udp"},
		{"tailnet", "proxy", "deploy", "demo", "--node", "pi", "--yes"},
		{"tailnet", "proxy", "export", "gateway", "--format", "uri"},
		{"tailnet", "exit", "disable", "pi", "--yes", "--expect", strings.Repeat("a", 64), "--read-only"},
	}
	for _, args := range cases {
		out, _, err := run(t, deps, args...)
		if err == nil || ExitCode(err) != 2 {
			t.Fatal(args, err, out)
		}
	}
	if len(*calls) != 0 {
		t.Fatal("invalid CLI performed I/O", *calls)
	}
}

func TestTailnetNativeAuthorizationPreservesHelperOutput(t *testing.T) {
	deps, _ := tailnetCLIFixture(t)
	deps.Terminal = func(io.Reader, io.Writer) bool { return true }
	var seen bool
	deps.RunEditor = func(child *exec.Cmd) error {
		if child.Stdout == nil {
			t.Fatal("helper result collector lost")
		}
		seen = true
		return nil
	}
	opts := &options{deps: deps}
	cmd := &cobra.Command{}
	service, err := opts.tailnetService(cmd)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("unused")
	var collected strings.Builder
	child.Stdout = &collected
	if err = service.Options.Foreground(child); err != nil || !seen || child.Stdout != &collected {
		t.Fatal(err, "helper output replaced")
	}
	opts.json = true
	service, err = opts.tailnetService(cmd)
	if err != nil {
		t.Fatal(err)
	}
	err = service.Options.Foreground(child)
	if describeError(err).Code != "authorization-required" {
		t.Fatal(err)
	}
}

func TestTailnetInventoryWorkbenchAndReceiptNamespace(t *testing.T) {
	deps, calls := tailnetCLIFixture(t)
	o := &options{deps: deps}
	result, err := o.runServerWorkbench(context.Background(), tui.WorkRequest{Kind: "servers-list"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 || result.Rows[0].ID != "tailnet:pi" || result.Rows[1].ID != "tailnet-proxy:gateway" {
		t.Fatal(result)
	}
	if len(*calls) != 0 {
		t.Fatal("inventory waited on network")
	}
	target := config.Target{ID: "client", Controller: "http://127.0.0.1:9090"}
	old, _ := serverConnectionPath(deps.ServerStore, "same", target)
	same, _ := clientConnectionPath(deps.ServerStore, "server", "same", target)
	other, _ := clientConnectionPath(deps.ServerStore, "tailnet-proxy", "same", target)
	if old != same || old == other {
		t.Fatal("receipt paths broke compatibility or collided")
	}
}

func TestTailnetProxyReviewedLifecycleAndPrivateExport(t *testing.T) {
	deps, _ := tailnetCLIFixture(t)
	if err := deps.ServerStore.Update(func(inv *serverstate.Inventory) error { return inv.RemoveTailnetProxy("gateway") }); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	mapping := ""
	deps.TailnetProxy.Execute = func(_ context.Context, host string, req tailnetproxy.RemoteRequest) (tailnetproxy.RemoteResponse, error) {
		if host != "fixture-pi" {
			t.Fatal(host)
		}
		calls = append(calls, req.Op)
		if req.Op == "start" {
			mapping = `{"TCP":{"TCPForward":"127.0.0.1:17899"}}`
		}
		if req.Op == "stop" || req.Op == "remove" {
			mapping = ""
		}
		return tailnetproxy.RemoteResponse{OK: true, PeerID: "peer1", IPs: []string{"100.72.1.1"}, Running: true, Owned: true, ListenerSafe: true, ListenerActive: true, Mapping: mapping}, nil
	}
	deps.TailnetProxy.Probe = func(context.Context, []byte) (string, error) { return "203.0.113.55", nil }
	args := []string{"tailnet", "proxy", "deploy", "shared", "--node", "pi", "--egress", "existing", "--upstream", "socks5://user:fixture-secret@127.0.0.1:17899", "--json"}
	out, _, err := run(t, deps, args...)
	var plan tailnetproxy.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil || len(plan.Digest) != 64 || strings.Contains(out, "fixture-secret") {
		t.Fatal(err, out)
	}
	for _, call := range calls {
		if call != "inspect" {
			t.Fatal("preview applied change", call)
		}
	}
	out, _, err = run(t, deps, append(args, "--yes", "--expect", plan.Digest)...)
	if err != nil || !json.Valid([]byte(out)) {
		t.Fatal(err, out)
	}
	out, _, err = run(t, deps, "tailnet", "proxy", "export", "shared", "--format", "client-bundle", "--json")
	if err != nil || !json.Valid([]byte(out)) || !strings.Contains(out, "fixture-secret") {
		t.Fatal(err, out)
	}
	for _, action := range []string{"stop", "start", "remove"} {
		out, _, err = run(t, deps, "tailnet", "proxy", action, "shared", "--json")
		if err != nil || json.Unmarshal([]byte(out), &plan) != nil {
			t.Fatal(action, err, out)
		}
		out, _, err = run(t, deps, "tailnet", "proxy", action, "shared", "--yes", "--expect", plan.Digest, "--json")
		if err != nil || !json.Valid([]byte(out)) {
			t.Fatal(action, err, out)
		}
	}
}
