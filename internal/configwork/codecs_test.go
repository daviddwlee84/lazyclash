package configwork

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestShareCodecsRoundTrip(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "東京 🙂", "add": "example.test", "port": "443", "id": "11111111-1111-1111-1111-111111111111", "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "edge.test", "path": "/ws?hello=world", "tls": "tls", "sni": "cert.test"})
	for _, link := range []string{
		"ss://YWVzLTEyOC1nY206cEBzczo%2FIw@[2001:db8::1]:443#台北",
		"ss://2022-blake3-aes-128-gcm:p%2Bss%3D@example.test:443#2022",
		"ss://YWVzLTEyOC1nY206cGFzcw@example.test:443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dedge.test%3Btls#plugin",
		"vless://11111111-1111-1111-1111-111111111111@[2001:db8::2]:443?encryption=none&security=reality&sni=cert.test&fp=chrome&pbk=PUBLIC&sid=abc&flow=xtls-rprx-vision#REALITY",
		"trojan://p%40ss%3A%3F%23@example.test:443?security=tls&sni=cert.test&type=ws&host=edge.test&path=%2Fa%3Fb%3Dc#東京",
		"hy2://user%3Apa%40ss@[2001:db8::3]:443/?sni=cert.test&insecure=0&obfs=salamander&obfs-password=hi%26there#HY2",
		"vmess://" + base64.StdEncoding.EncodeToString(vm),
	} {
		t.Run(strings.Split(link, ":")[0], func(t *testing.T) {
			n, e := ParseURI(link)
			if e != nil {
				t.Fatal(e)
			}
			d, e := definition(n, "proxy", "test")
			if e != nil {
				t.Fatal(e)
			}
			out, e := EncodeURI(d)
			if e != nil {
				t.Fatal(e)
			}
			again, e := ParseURI(out)
			if e != nil {
				t.Fatal(e)
			}
			if semantic(n) != semantic(again) {
				a, _ := encode(n)
				b, _ := encode(again)
				t.Fatalf("round trip changed node\n%s\n%s", a, b)
			}
		})
	}
}

func TestRemarksCompatibilityAndCanonicalExport(t *testing.T) {
	legacy := "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-128-gcm:private@example.test:443")) + "?remarks=台北"
	if n, err := ParseURI(legacy); err != nil || scalar(n, "name") != "台北" {
		t.Fatalf("legacy SS remarks: %v", err)
	}
	for _, scheme := range []string{"vless://UUID", "trojan://private", "hy2://private", "ss://YWVzLTEyOC1nY206cGFzcw"} {
		for _, suffix := range []string{"?remarks=%E5%8F%B0%E5%8C%97%20%2B%20A", "?remarks=ignored#台北%20%2B%20A"} {
			n, err := ParseURI(scheme + "@example.test:443" + suffix)
			if err != nil || scalar(n, "name") != "台北 + A" {
				t.Fatalf("%s: %v", scheme, err)
			}
			d, _ := definition(n, "proxy", "test")
			uri, err := EncodeURI(d)
			if err != nil || strings.Contains(uri, "remarks=") {
				t.Fatalf("canonical export: %v", err)
			}
		}
	}
	for _, suffix := range []string{"?remarks=a&remarks=b", "?remarks=a&unknown=NEVER_SECRET", "?remarks=%zz"} {
		_, err := ParseURI("vless://UUID@example.test:443" + suffix)
		if err == nil || strings.Contains(err.Error(), "NEVER_SECRET") {
			t.Fatal("invalid/unknown query accepted or leaked")
		}
	}
}
func TestImportDiagnosticsAndUnknownFields(t *testing.T) {
	valid := "trojan://password@example.test:443#test"
	defs, diags, e := ParseImport([]byte(valid + "\n" + valid + "?not-a-query"))
	if e != nil || len(defs) != 2 || len(diags) != 0 {
		t.Fatalf("%d %v %v", len(defs), diags, e)
	}
	defs, diags, e = ParseImport([]byte(valid + "\nvless://ID@example.test:443?secretFuture=hidden"))
	if e != nil || len(defs) != 1 || len(diags) != 1 {
		t.Fatalf("%d %v %v", len(defs), diags, e)
	}
	b, _ := json.Marshal(diags)
	if strings.Contains(string(b), "hidden") || strings.Contains(string(b), "password") {
		t.Fatal("diagnostic leaked credentials")
	}
	for _, bad := range []string{"vless://ID@h:443?type=ws&type=tcp", "https://token:pass@subscription.example/path", "vmess://%%", "hy2://a@h:0", "trojan://p@h:443?future=1"} {
		if _, e = ParseURI(bad); e == nil {
			t.Fatal("accepted invalid URI")
		}
	}
	raw := []byte("# comment\nname: n\ntype: ss\nserver: h\nport: 443\ncipher: aes-128-gcm\npassword: secret\nx-future:\n  mode: later\n")
	defs, _, e = ParseImport(raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = EncodeURI(defs[0]); e == nil {
		t.Fatal("URI silently dropped future field")
	}
	out, e := Export(defs[0], "yaml")
	if e != nil || !strings.Contains(string(out), "# comment") || !strings.Contains(string(out), "x-future") {
		t.Fatal("raw YAML lost source")
	}
}
func TestGroupCycleAndUnknownRawNodes(t *testing.T) {
	n, e := decode([]byte("proxies:\n- {name: local, type: direct, udp: true}\nproxy-groups:\n- {name: a, type: select, proxies: [b]}\n- {name: b, type: select, proxies: [a]}\n"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = definitions(n, "proxies", "proxy", ""); e != nil {
		t.Fatal("generic raw node should remain editable", e)
	}
	if e = validateGraph(n); e == nil {
		t.Fatal("cycle accepted")
	}
}
func TestBase64SubscriptionAndStandaloneAnchors(t *testing.T) {
	links := "trojan://p@a.test:443#a\nhy2://p@b.test:443#b"
	defs, diags, e := ParseImport([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	if e != nil || len(defs) != 2 || len(diags) != 0 {
		t.Fatal("base64 node subscription", e, diags)
	}
	doc, e := decode([]byte("defaults: &base\n  server: example.test\n  port: 443\n  password: secret\n  cipher: aes-128-gcm\nproxies:\n- <<: *base\n  name: n\n  type: ss\n"))
	if e != nil {
		t.Fatal(e)
	}
	defs, e = definitions(doc, "proxies", "proxy", "")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := defs[0].Raw()
	if e != nil {
		t.Fatal(e)
	}
	imported, _, e := ParseImport(raw)
	if e != nil || len(imported) != 1 {
		t.Fatalf("orphan YAML alias in standalone export: %s %v", raw, e)
	}
	if imported[0].Map()["password"] != "secret" {
		t.Fatal("merged credential lost")
	}
}
