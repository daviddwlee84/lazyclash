package topology

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

const fixture = `secret: NEVER_CONTROLLER
defaults: &base {server: example.test, port: 443, type: vless, uuid: NEVER_UUID}
proxies:
  - {<<: *base, name: "台北 🙂", dialer-proxy: Hop}
  - {<<: *base, name: "東京"}
proxy-groups:
  - {name: FINAL, type: select, proxies: [PROXY]}
  - {name: PROXY, type: select, proxies: [Auto, DIRECT]}
  - {name: Auto, type: url-test, proxies: ["台北 🙂", 東京], use: [remote, local], filter: "台北|東京"}
  - {name: Hop, type: select, proxies: [DIRECT]}
  - {name: Dynamic, type: select, include-all: true, exclude-filter: experimental}
proxy-providers:
  remote: {type: http, url: "https://example.test/NEVER_TOKEN"}
  local: {type: inline, payload: [{name: private, type: trojan, password: NEVER_PASSWORD}]}
rule-providers:
  ads: {type: http, behavior: domain, url: "https://example.test/NEVER_RULE_TOKEN"}
rules:
  - RULE-SET,ads,REJECT
  - AND,((DOMAIN,example.com),(NETWORK,TCP)),PROXY
  - DOMAIN-SUFFIX,example.net,PROXY
  - MATCH,FINAL
`

func parsed(t *testing.T, raw string) Graph {
	t.Helper()
	g, err := Parse([]byte(raw), Source{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func edgeExists(g Graph, from, to, kind, origin string) bool {
	for _, e := range g.Edges {
		if g.node(e.From).Name == from && g.node(e.To).Name == to && e.Kind == kind && e.Origin == origin {
			return true
		}
	}
	return false
}

func TestYAMLTopologyRelationshipsAndPrivacy(t *testing.T) {
	g := parsed(t, fixture)
	for _, e := range [][3]string{{"FINAL", "PROXY", "member"}, {"PROXY", "Auto", "member"}, {"Auto", "台北 🙂", "member"}, {"Auto", "remote", "use"}, {"local", "private", "payload"}, {"台北 🙂", "Hop", "dialer"}, {"rules #4 MATCH → FINAL", "FINAL", "route"}} {
		if !edgeExists(g, e[0], e[1], e[2], "config") {
			t.Fatalf("missing edge %v", e)
		}
	}
	if len(g.Rules) != 4 || g.Rules[1].Index != 1 || g.Rules[1].Target != "PROXY" || !g.Rules[1].Resolved {
		t.Fatalf("rule order/parser: %+v", g.Rules)
	}
	if g.node(ID("builtin", "FINAL")) != nil {
		t.Fatal("FINAL group treated as a builtin")
	}
	raw, _ := json.Marshal(g)
	for _, output := range []string{string(raw), g.Relations(), Mermaid(g), g.Summary()} {
		if strings.Contains(output, "NEVER_") {
			t.Fatal("credential material reached topology output")
		}
	}
	again := parsed(t, fixture)
	if !reflect.DeepEqual(g, again) {
		t.Fatal("non-deterministic graph")
	}
	focus, err := g.Focus("台北 🙂")
	if err != nil || focus.node(ID("group", "FINAL")) == nil || focus.node(ID("group", "Hop")) == nil || focus.node(ID("proxy", "東京")) != nil {
		t.Fatalf("focus pulled siblings or lost ancestors: %+v %v", focus.Nodes, err)
	}
}

func TestUnknownMissingAndCyclicGraphRemainInspectable(t *testing.T) {
	g := parsed(t, "proxy-groups:\n- {name: A, type: select, proxies: [B, missing]}\n- {name: B, type: select, proxies: [A]}\nrules:\n- FUTURE,example.test,A\n- MATCH,A\n")
	if len(g.Diagnostics) < 3 || g.Rules[0].Resolved {
		t.Fatalf("missing diagnostics: %+v", g)
	}
	if _, err := ASCII(g, 80); err == nil {
		t.Fatal("cycle entered terminal layout")
	}
	if !strings.Contains(Mermaid(g), ID("group", "A")) || !strings.Contains(g.Relations(), "missing") {
		t.Fatal("cycle data was lost")
	}
	for _, raw := range []string{"proxies: []\nproxies: []", "password: SECRET\n---\nproxies: []", "[not, a, mapping]", "a: &loop [*loop]"} {
		if _, err := Parse([]byte(raw), Source{}); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("unsafe invalid input: %v", err)
		}
	}
}

func TestRuntimeOverlayPreservesProvenanceAndChanges(t *testing.T) {
	g := parsed(t, fixture)
	before := append([]Edge(nil), g.Edges...)
	g.Overlay(map[string]core.Proxy{"PROXY": {Type: "Selector", All: []string{"Auto", "DIRECT"}, Now: "Auto"}, "Auto": {Type: "URLTest", All: []string{"東京", "new-runtime"}, Now: "東京"}, "東京": {Type: "Vless"}, "new-runtime": {Type: "Trojan"}}, time.Unix(10, 0))
	if !reflect.DeepEqual(g.Edges[:len(before)], before) {
		t.Fatal("overlay rewrote configured edges")
	}
	if !edgeExists(g, "Auto", "台北 🙂", "member", "config") || !edgeExists(g, "Auto", "new-runtime", "member", "runtime") {
		t.Fatal("provenance lost")
	}
	selected := 0
	for _, e := range g.Edges {
		if e.Selected {
			selected++
			if e.Origin != "runtime" {
				t.Fatal("config claimed current selection")
			}
		}
	}
	if selected != 2 || !strings.Contains(strings.Join(g.Diagnostics, "\n"), "absent from runtime") {
		t.Fatal("current selections/difference missing")
	}
}

func TestRenderSharedMermaidSubset(t *testing.T) {
	g := parsed(t, "proxies:\n- {name: '台北 [private] & \"quoted\" --- --> 節點', type: vless}\nproxy-groups:\n- {name: PROXY, type: select, proxies: ['台北 [private] & \"quoted\" --- --> 節點']}\nrules:\n- MATCH,PROXY\n")
	out, err := ASCII(g, 100)
	if err != nil || !strings.Contains(out, "PROXY") || !strings.Contains(out, "台北") {
		t.Fatalf("render: %v\n%s", err, out)
	}
	if strings.Index(out, "rules") > strings.Index(out, "PROXY") || strings.Index(out, "PROXY") > strings.Index(out, "台北") {
		t.Fatalf("configuration file order reversed the routing diagram:\n%s", out)
	}
	if strings.Contains(Mermaid(g), "& \"quoted\"") {
		t.Fatal("raw Mermaid syntax in label")
	}
	large := g
	for i := 0; i < 121; i++ {
		large.Nodes = append(large.Nodes, Node{ID: ID("large", string(rune(i))), Name: "node"})
	}
	if _, err := ASCII(large, 80); err == nil {
		t.Fatal("unbounded layout")
	}
}

func TestReadSourcesUseOnlyReadOperation(t *testing.T) {
	for _, tc := range []struct {
		source    *config.ConfigSource
		path      string
		generated bool
	}{
		{&config.ConfigSource{Kind: "native", ConfigID: "main"}, "/host/config.yaml", false},
		{&config.ConfigSource{Kind: "docker", HostPath: "/host/config.yaml", CorePath: "/container/config.yaml"}, "/host/config.yaml", false},
		{&config.ConfigSource{Kind: "verge", DataDir: "/verge"}, "/verge/clash-verge.yaml", true},
	} {
		target := config.Target{ID: "saved", SSHHost: "remote", ConfigSource: tc.source, Configs: []config.CoreConfig{{ID: "main", Path: "/host/config.yaml"}}}
		opts := configwork.Options{Host: func(_ context.Context, got config.Target, r configwork.HostRequest) (configwork.HostResponse, error) {
			if r.Op != "read" || r.Path != tc.path || got.SSHHost != "remote" {
				t.Fatalf("wrong source operation: %+v", r)
			}
			return configwork.HostResponse{File: configwork.HostFile{Data: []byte(fixture)}}, nil
		}, Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("offline read opened API")
			return nil, nil, nil
		}}
		g, err := Read(context.Background(), target, "", false, opts)
		if err != nil || g.Source.Generated != tc.generated {
			t.Fatalf("%+v %v", g.Source, err)
		}
	}
	if _, err := SourceFor(config.Target{SourceConfig: "/credential-only"}, ""); !errors.Is(err, ErrNoSource) {
		t.Fatal("credential path silently became a source")
	}
}

func TestForwardProviderDialerAndRuleDetails(t *testing.T) {
	g := parsed(t, `proxy-providers:
  a: {type: inline, override: {dialer-proxy: later}, payload: []}
  b: {type: inline, payload: [{name: later, type: direct}]}
proxy-groups:
  - {name: FINAL, type: select, proxies: [later]}
rules:
  - SUB-RULE,(NETWORK,TCP),child
  - MATCH,FINAL
sub-rules:
  child: ["DOMAIN,example.test,FINAL"]
`)
	if strings.Contains(strings.Join(g.Diagnostics, "\n"), "Missing") {
		t.Fatal(g.Diagnostics)
	}
	if !edgeExists(g, "a", "later", "dialer-override", "config") || !edgeExists(g, "rules → child", "child", "route", "config") {
		t.Fatal("forward references lost")
	}
	if !strings.Contains(g.Detail(ID("rules", "rules #2 MATCH → FINAL")), "MATCH,FINAL") {
		t.Fatal("fallback rule detail missing")
	}
	for _, raw := range []string{"rules: [42, 'MATCH,DIRECT']", "proxy-groups: [{name: A, type: select, proxies: [42]}]"} {
		if _, err := Parse([]byte(raw), Source{}); err == nil {
			t.Fatal("invalid entries silently changed rule/member positions")
		}
	}
	if _, err := Parse([]byte("proxies: null\nproxy-providers: null\nrules: []"), Source{}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeKindChangesDoNotMisattachEdges(t *testing.T) {
	g := parsed(t, "proxies: [{name: changed, type: direct}]\nproxy-groups: [{name: root, type: select, proxies: [changed]}]")
	g.Overlay(map[string]core.Proxy{"root": {Type: "Selector", All: []string{"changed"}}, "changed": {Type: "Selector", All: []string{"DIRECT"}}, "DIRECT": {Type: "Direct"}}, time.Now())
	var configTo, runtimeTo string
	for _, e := range g.Edges {
		if e.From == ID("group", "root") {
			if e.Origin == "config" {
				configTo = e.To
			} else {
				runtimeTo = e.To
			}
		}
	}
	if configTo != ID("proxy", "changed") || runtimeTo != ID("group", "changed") {
		t.Fatal("runtime edge resolved through config kind")
	}
}

func TestCyclesRespectObservationOriginAndProviderDependencies(t *testing.T) {
	g := parsed(t, "proxy-groups: [{name: A, type: select, use: [p]}]\nproxy-providers: {p: {type: inline, payload: [], override: {dialer-proxy: A}}}")
	if !strings.Contains(strings.Join(g.Diagnostics, "\n"), "Cyclic dependency [config]") {
		t.Fatal("provider dialer cycle missed")
	}
	g = parsed(t, "proxy-groups: [{name: A, type: select, proxies: [B]}, {name: B, type: select, proxies: [DIRECT]}]")
	g.Overlay(map[string]core.Proxy{"A": {Type: "Selector", All: []string{"DIRECT"}}, "B": {Type: "Selector", All: []string{"A"}}, "DIRECT": {Type: "Direct"}}, time.Now())
	g.cycles("runtime")
	if strings.Contains(strings.Join(g.Diagnostics, "\n"), "Cyclic dependency") {
		t.Fatal("different snapshots were treated as one cyclic configuration")
	}
}

func TestLiveAPIOnlyUsesGETWithoutProviderRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("mutating request: %s", r.Method)
		}
		switch r.URL.Path {
		case "/version":
			io.WriteString(w, `{"version":"fixture","meta":true}`)
		case "/proxies":
			io.WriteString(w, `{"proxies":{"PROXY":{"type":"Selector","all":["leaf"],"now":"leaf"},"leaf":{"type":"Vless"}}}`)
		case "/providers/proxies":
			io.WriteString(w, `{"providers":{"remote":{"type":"Proxy","proxies":[{"name":"leaf","type":"Vless","password":"NEVER_RUNTIME"}]}}}`)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	g, err := Read(context.Background(), config.Target{ID: "api", Controller: server.URL}, "", true, configwork.Options{})
	if err != nil || g.Source.Kind != "runtime-only" || g.ObservedAt.IsZero() || !edgeExists(g, "remote", "leaf", "payload", "runtime") {
		t.Fatalf("%+v %v", g, err)
	}
	raw, _ := json.Marshal(g)
	if strings.Contains(string(raw), "NEVER_RUNTIME") {
		t.Fatal("runtime credential leaked")
	}
}
