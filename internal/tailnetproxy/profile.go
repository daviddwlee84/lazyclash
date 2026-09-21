package tailnetproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"go.yaml.in/yaml/v3"
)

func upstreamURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "socks5") || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return nil, errors.New("upstream must be an explicit http:// or socks5:// host:port endpoint")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("upstream requires an explicit port in 1..65535")
	}
	if u.User != nil {
		password, ok := u.User.Password()
		if !ok || u.User.Username() == "" || password == "" || strings.ContainsAny(u.User.Username(), ":\r\n") || strings.ContainsAny(password, "\r\n") {
			return nil, errors.New("upstream authentication requires a nonempty username and password")
		}
	}
	return u, nil
}
func redactedUpstream(value string) string {
	u, err := upstreamURL(value)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}
func tailnetIP(values []string) (string, error) {
	for _, v := range values {
		a, err := netip.ParseAddr(v)
		if err == nil && netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
			return a.String(), nil
		}
	}
	for _, v := range values {
		a, err := netip.ParseAddr(v)
		if err == nil && netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(a) {
			return a.String(), nil
		}
	}
	return "", errors.New("registered peer has no usable Tailscale address")
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func normalize(r Request, node serverstate.TailnetNode) (Request, error) {
	if err := serverstate.ValidateID(r.ID); err != nil {
		return r, err
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if strings.IndexFunc(r.Name, unicode.IsControl) >= 0 {
		return r, errors.New("proxy name cannot contain control characters")
	}
	if r.Mode == "" {
		r.Mode = "serve"
	}
	if r.Mode != "serve" && r.Mode != "direct" {
		return r, errors.New("proxy mode must be serve or direct")
	}
	if r.Backend == "" {
		r.Backend = "native"
	}
	if r.Backend != "native" && r.Backend != "docker" {
		return r, errors.New("gateway backend must be native or docker")
	}
	if r.Egress == "" {
		r.Egress = "direct"
	}
	if r.Egress != "direct" && r.Egress != "upstream" && r.Egress != "existing" {
		return r, errors.New("egress must be direct, upstream or existing")
	}
	if r.Port == 0 {
		r.Port = DefaultPort
	}
	if r.LocalPort == 0 {
		r.LocalPort = DefaultLocalPort
	}
	if r.ControllerPort == 0 {
		r.ControllerPort = DefaultControllerPort
	}
	if r.Mode == "direct" {
		r.LocalPort = r.Port
	}
	for _, p := range []int{r.Port, r.LocalPort, r.ControllerPort} {
		if p < 1024 || p > 65535 {
			return r, errors.New("gateway ports must be in 1024..65535")
		}
	}
	if r.ControllerPort == r.LocalPort || r.ControllerPort == r.Port {
		return r, errors.New("controller and data-proxy ports must differ")
	}
	if r.Mode == "serve" && r.UDP {
		return r, errors.New("Tailscale Serve forwards TCP only; choose direct for SOCKS UDP")
	}
	if r.Egress == "direct" {
		if r.Upstream != "" {
			return r, errors.New("direct egress cannot have an upstream")
		}
		return r, nil
	}
	u, err := upstreamURL(r.Upstream)
	if err != nil {
		return r, err
	}
	port, _ := strconv.Atoi(u.Port())
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	loopback := host == "localhost"
	if ip, e := netip.ParseAddr(host); e == nil {
		loopback = ip.IsLoopback()
	}
	self := loopback || contains(node.IPs, host) || host == strings.ToLower(strings.TrimSuffix(node.Hostname, "."))
	if r.Egress == "existing" {
		if r.Mode != "serve" {
			return r, errors.New("existing proxies can only be shared through Serve; their listeners remain externally managed")
		}
		if host != "127.0.0.1" && host != "localhost" {
			return r, errors.New("existing proxy must listen on IPv4 loopback")
		}
		if u.User == nil {
			return r, errors.New("sharing an existing proxy requires its username and password")
		}
		if port == r.Port {
			return r, errors.New("Serve endpoint and existing loopback port must differ")
		}
		r.LocalPort = port
	} else if self && (port == r.Port || port == r.LocalPort || port == r.ControllerPort) {
		return r, errors.New("upstream points back to this gateway or its controller")
	}
	if r.Egress == "upstream" && r.Backend == "docker" && loopback {
		return r, errors.New("a Docker gateway needs an upstream address reachable from its container; host loopback is a different network namespace")
	}
	if r.UDP && r.Egress == "upstream" && u.Scheme != "socks5" {
		return r, errors.New("HTTP upstream does not provide SOCKS UDP forwarding")
	}
	return r, nil
}

func gatewayRequest(j journal) (managedcore.Request, error) {
	proxies := []any{}
	rules := []string{"MATCH,DIRECT"}
	if j.Request.Egress == "upstream" {
		u, err := upstreamURL(j.Request.Upstream)
		if err != nil {
			return managedcore.Request{}, err
		}
		port, _ := strconv.Atoi(u.Port())
		kind := u.Scheme
		p := map[string]any{"name": "TAILNET-UPSTREAM", "type": kind, "server": u.Hostname(), "port": port}
		if kind == "socks5" {
			p["udp"] = j.Request.UDP
		}
		if u.User != nil {
			p["username"] = u.User.Username()
			p["password"], _ = u.User.Password()
		}
		proxies = append(proxies, p)
		rules = []string{"MATCH,TAILNET-UPSTREAM"}
	}
	input, err := yaml.Marshal(map[string]any{"proxy-groups": []any{}, "proxies": proxies, "rules": rules, "authentication": []string{j.Username + ":" + j.Password}, "skip-auth-prefixes": []string{}, "dns": map[string]any{"enable": false}, "ipv6": true})
	if err != nil {
		return managedcore.Request{}, err
	}
	r := managedcore.Request{ID: j.CoreID, Name: j.Request.Name, SSHHost: j.SSHHost, Backend: j.Request.Backend, InputKind: "yaml", Input: input, Preset: "preserve", ControllerPort: j.Request.ControllerPort, MixedPort: j.Request.LocalPort, ServiceScope: "system", Boot: true, ProxyGateway: true}
	if j.Request.Mode == "direct" {
		r.ProxyListen = j.ListenIP
		r.ProxyUDP = j.Request.UDP
	}
	return r, nil
}
func clientMap(j journal) map[string]any {
	kind := "socks5"
	if j.Request.Egress == "existing" {
		if u, e := upstreamURL(j.Request.Upstream); e == nil {
			kind = u.Scheme
		}
	}
	p := map[string]any{"name": j.Request.Name, "type": kind, "server": j.ListenIP, "port": j.Request.Port, "username": j.Username, "password": j.Password}
	if kind == "socks5" {
		p["udp"] = j.Request.Mode == "direct" && j.Request.UDP
	}
	return p
}
func endpoint(j journal) string { return net.JoinHostPort(j.ListenIP, fmt.Sprint(j.Request.Port)) }
