package networkcheck

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

func TestTailnetProposalUsesActualRoutesAndScopedDNS(t *testing.T) {
	r := Analyze(Report{Tailscale: Tailscale{Running: true, Suffix: "sample.ts.net"}, Interfaces: []Interface{{Name: "tailscale0", Kind: "tun"}}, Routes: []Route{{Destination: "100.90.1.2/32", Interface: "tailscale0"}, {Destination: "10.42.0.0/16", Interface: "tailscale0"}, {Destination: "0.0.0.0/0", Interface: "en0"}}, Resolvers: []Resolver{{Interface: "tailscale0", Domains: []string{"~corp.example"}, Servers: []string{"10.42.0.53"}}}, ManagementAddress: "192.0.2.4"})
	for _, want := range []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "10.42.0.0/16", "192.0.2.4/32"} {
		if !contains(r.ExcludedRoutes, want) {
			t.Fatalf("missing %s in %v", want, r.ExcludedRoutes)
		}
	}
	if contains(r.ExcludedRoutes, "0.0.0.0/0") || contains(r.ExcludedRoutes, "100.90.1.2/32") {
		t.Fatalf("default/covered routes leaked: %v", r.ExcludedRoutes)
	}
	if strings.Join(r.DNSPolicies["+.corp.example"], ",") != "10.42.0.53" || !contains(r.FakeIPFilter, "+.sample.ts.net") {
		t.Fatalf("split DNS lost: %#v", r)
	}
	p, e := PlanTUN(r, nil, false)
	if e != nil || p.Blocked || p.Settings["strict-route"] != false {
		t.Fatalf("plan: %#v %v", p, e)
	}
}
func TestVPNConflictAndOwnerIdentity(t *testing.T) {
	r := Report{Interfaces: []Interface{{Name: "utun2", Kind: "tunnel"}}, Routes: []Route{{Destination: "0.0.0.0/1", Interface: "utun2"}, {Destination: "128.0.0.0/1", Interface: "utun2"}}}
	p, _ := PlanTUN(r, nil, false)
	if !p.Blocked {
		t.Fatal("split default tunnel was missed")
	}
	r = WithCoreTUNDevice(r, true, "utun2")
	p, _ = PlanTUN(r, nil, true)
	if p.Blocked {
		t.Fatalf("own TUN cannot be configured: %#v", p)
	}
	r.Tailscale.ExitNode = true
	p, _ = PlanTUN(r, nil, true)
	if !p.Blocked {
		t.Fatal("own TUN override hid exit node")
	}
	r = Report{Interfaces: []Interface{{Name: "utun3", Kind: "tunnel"}}, Routes: []Route{{Destination: "::/0", Interface: "utun3", Scoped: true}}}
	p, _ = PlanTUN(r, nil, false)
	if p.Blocked {
		t.Fatal("interface-scoped route mistaken for global default")
	}
}
func TestProcessPresenceDoesNotClaimTUNAndUnknownIsVisible(t *testing.T) {
	r := Analyze(Report{Processes: []string{"SafeConnect", "mihomo"}, Capabilities: []Capability{{Name: "policy-routing", Available: false}}})
	if r.ExistingTUN || len(r.Conflicts) != 2 {
		t.Fatalf("bad evidence %#v", r)
	}
	for _, f := range r.Conflicts {
		if f.Level == "conflict" {
			t.Fatal("process-only evidence blocked setup")
		}
	}
	if _, err := PlanTUN(r, []string{"0.0.0.0/0"}, false); err == nil {
		t.Fatal("excluded all traffic")
	}
}
func TestHelperProtocolAndAuthentication(t *testing.T) {
	_, err := InspectWithOptions(context.Background(), "fixture", InspectOptions{Execute: func(context.Context, string, string, []byte, int) ([]byte, error) {
		return nil, &connection.AuthRequiredError{Host: "fixture"}
	}})
	if !connection.IsAuthRequired(err) {
		t.Fatal(err)
	}
	_, err = InspectWithOptions(context.Background(), "", InspectOptions{Execute: func(context.Context, string, string, []byte, int) ([]byte, error) {
		return []byte(`{"protocol":7}`), nil
	}})
	if err == nil {
		t.Fatal("accepted wrong protocol")
	}
}
func TestSystemProxyPlanGuardsAndRedacts(t *testing.T) {
	s := SystemProxySnapshot{Protocol: 1, OS: "Darwin", Backend: "macos-networksetup", SelectionExplicit: true, Services: []SystemProxyState{{Service: "Wi-Fi", PACEnabled: true, PACURL: "https://example.test/pac?token=private", Exceptions: []string{"*.corp.example"}}}}
	p, err := PlanSystemProxyWithSOCKS(s, "http://127.0.0.1:7890", "socks5://127.0.0.1:7890", []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Changes[0].After.HTTP.Enabled || p.Changes[0].After.PACEnabled || !contains(p.Changes[0].After.Exceptions, "*.corp.example") {
		t.Fatal(p)
	}
	data, _ := json.Marshal(p.Redacted())
	if strings.Contains(string(data), "token") || !strings.Contains(p.Changes[0].Before.PACURL, "token") {
		t.Fatal("redaction mutated source or leaked PAC")
	}
	s.SelectionExplicit = false
	if _, err = PlanSystemProxy(s, "http://127.0.0.1:7890", nil); err == nil {
		t.Fatal("implicit all-service apply")
	}
	s.SelectionExplicit = true
	s.Services[0].HTTP.Authenticated = true
	if _, err = PlanSystemProxy(s, "http://127.0.0.1:7890", nil); err == nil {
		t.Fatal("unrecoverable auth proxy accepted")
	}
}
func TestPythonSystemProxyConflictAndPartialResult(t *testing.T) {
	// The fixed adapter runs against in-memory readers/writers only. No host
	// proxy, DNS, route, service or production configuration is touched.
	fixture := `\nimport copy\nbase={"service":"Wi-Fi","http":{"enabled":False,"host":"","port":0,"authenticated":False},"https":{"enabled":False,"host":"","port":0,"authenticated":False},"socks":{"enabled":False,"host":"","port":0,"authenticated":False},"pac_enabled":False,"pac_url":"","discovery":False,"exceptions":[],"mode":"manual"}\nafter=copy.deepcopy(base)\nafter["http"].update({"enabled":True,"host":"127.0.0.1","port":7890})\nstate=copy.deepcopy(base)\nwrites=[]\ndef read(service): return copy.deepcopy(state)\ndef write(value):\n    state.clear();state.update(copy.deepcopy(value));writes.append(True)\nns["mac_state"]=read\nns["write_mac"]=write\nns["platform"].system=lambda:"Darwin"\nplan={"backend":"macos-networksetup","os":"Darwin","changes":[{"service":"Wi-Fi","before":base,"after":after}]}\nassert ns["apply_plan"](plan)["status"]=="applied"\nstate["http"]["port"]=9999\nassert ns["apply_plan"](plan,True)["status"]=="conflict"\nassert len(writes)==1\nstate.clear();state.update(copy.deepcopy(after))\nassert ns["apply_plan"](plan,True)["status"]=="restored"\ndef partial(value):\n    state["http"]=copy.deepcopy(value["http"]);raise RuntimeError("private raw failure")\nns["write_mac"]=partial\nresult=ns["apply_plan"](plan)\nassert result["status"]=="partial"\nassert "private raw failure" not in json.dumps(result)\nprint("ok")\n`
	encoded, _ := json.Marshal(SystemProxyScript)
	script := "import json,tempfile,pathlib,os\nns={'__name__':'lazyclash_system_proxy'}\nexec(json.loads(" + strconvQuote(string(encoded)) + "),ns)\nfixture_dir=tempfile.TemporaryDirectory()\nns['_proxy_lock_path']=lambda backend:(pathlib.Path(fixture_dir.name)/'proxy.lock',os.getuid())\n" + strings.ReplaceAll(fixture, `\n`, "\n")
	data, err := connection.ExecutePython(context.Background(), "", script, []byte("{}"), 4096)
	if errors.Is(err, connection.ErrPythonUnavailable) {
		t.Skip("Python3 unavailable")
	}
	if err != nil || strings.TrimSpace(string(data)) != "ok" {
		t.Fatalf("fixture failed %s %v", data, err)
	}
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func strconvQuote(value string) string { data, _ := json.Marshal(value); return string(data) }
