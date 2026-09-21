package managedcore

import (
	"context"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestPrivateGatewayListenerHasDedicatedAuthenticationAndNoImplicitUDP(t *testing.T) {
	for _, backend := range []string{"native", "docker"} {
		for _, direct := range []bool{false, true} {
			r := Request{ID: "gateway", Backend: backend, ProxyGateway: true, InputKind: "yaml", Preset: "preserve", MixedPort: 17898, ControllerPort: 19098, Input: []byte("proxy-groups: []\nrules: ['MATCH,DIRECT']\nauthentication: [user:password]\nskip-auth-prefixes: [127.0.0.0/8]\n")}
			if direct {
				r.ProxyListen = "100.72.151.78"
				r.ProxyUDP = true
			}
			body, _, _, _, err := buildProfile(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			yaml.Unmarshal(body, &m)
			if m["mixed-port"] != 0 {
				t.Fatal("default listener not disabled", m)
			}
			list := m["listeners"].([]any)
			if len(list) != 1 {
				t.Fatal(list)
			}
			listener := list[0].(map[string]any)
			expected := "127.0.0.1"
			if direct {
				expected = r.ProxyListen
			}
			if backend == "docker" {
				expected = "0.0.0.0"
			}
			if listener["listen"] != expected || listener["udp"] != direct || listener["port"] != r.MixedPort {
				t.Fatal(listener)
			}
			users := listener["users"].([]any)
			if len(users) != 1 || users[0].(map[string]any)["password"] != "password" {
				t.Fatal("missing listener auth")
			}
			if len(m["skip-auth-prefixes"].([]any)) != 0 {
				t.Fatal("loopback auth bypass retained")
			}
			controller := "127.0.0.1:19098"
			if backend == "docker" {
				controller = "0.0.0.0:19098"
			}
			if m["external-controller"] != controller {
				t.Fatal("controller exposure changed")
			}
		}
	}
}
func TestPrivateGatewayRejectsEmptyAuthAndArbitraryAddress(t *testing.T) {
	r := Request{ID: "gateway", ProxyGateway: true, InputKind: "yaml", Preset: "preserve", MixedPort: 17898, ControllerPort: 19098, Input: []byte("proxy-groups: []\nrules: ['MATCH,DIRECT']\n")}
	if _, _, _, _, err := buildProfile(context.Background(), r); err == nil {
		t.Fatal("unauthenticated gateway accepted")
	}
	for _, ip := range []string{"0.0.0.0", "::", "192.168.1.1", "100.1.1.1", "example.com"} {
		r.ProxyListen = ip
		if _, err := normalize(r); err == nil {
			t.Fatal("invalid gateway address accepted", ip)
		}
	}
	r.ProxyListen = "100.72.151.78"
	r.Network.TUN = true
	r.ServiceScope = "system"
	if _, err := normalize(r); err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Fatal("gateway accepted host routing", err)
	}
}
func TestDockerGatewayPublishesOnlyExplicitTailnetDataAddress(t *testing.T) {
	runHostFixture(t, `r={'id':'gateway','owner_token':'owner','image':'test@sha256:'+'1'*64,'platform':'linux/arm64','ports':[19098,7898],'network':{},'proxy_listen':'100.72.151.78','proxy_udp':True}
s=json.loads(compose_data(pathlib.Path('/owned/gateway'),r))['services']['mihomo']
assert s['ports']==['127.0.0.1:19098:19098','100.72.151.78:7898:7898','100.72.151.78:7898:7898/udp']
r['proxy_listen']='fd7a:115c:a1e0::1';r['proxy_udp']=False
s=json.loads(compose_data(pathlib.Path('/owned/gateway'),r))['services']['mihomo']
assert s['ports']==['127.0.0.1:19098:19098','[fd7a:115c:a1e0::1]:7898:7898']
print('ok')`)
}
