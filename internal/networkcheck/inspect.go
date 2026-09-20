// Package networkcheck collects passive host evidence and proposes explicit
// routing/DNS exclusions. It never enables a VPN, edits routes or stops services.
package networkcheck

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

import "github.com/daviddwlee84/lazyclash/internal/connection"

//go:embed inspect.py
var inspectScript string

type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
}
type Interface struct {
	Name      string   `json:"name"`
	State     string   `json:"state"`
	Kind      string   `json:"kind"`
	Addresses []string `json:"addresses"`
}
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Table       string `json:"table,omitempty"`
	Scoped      bool   `json:"scoped,omitempty"`
}
type Resolver struct {
	Interface string   `json:"interface,omitempty"`
	Domains   []string `json:"domains"`
	Servers   []string `json:"servers"`
}
type Tailscale struct {
	Present  bool     `json:"present"`
	Running  bool     `json:"running"`
	ExitNode bool     `json:"exit_node"`
	Suffix   string   `json:"suffix,omitempty"`
	IPs      []string `json:"ips"`
}
type Finding struct {
	Code       string   `json:"code"`
	Level      string   `json:"level"`      // conflict, warning, information
	Confidence string   `json:"confidence"` // confirmed, probable, unknown
	Message    string   `json:"message"`
	Evidence   []string `json:"evidence,omitempty"`
}
type Report struct {
	Protocol          int                 `json:"protocol"`
	OS                string              `json:"os"`
	Arch              string              `json:"arch"`
	Scope             string              `json:"scope"`
	Capabilities      []Capability        `json:"capabilities"`
	Interfaces        []Interface         `json:"interfaces"`
	Routes            []Route             `json:"routes"`
	PolicyRules       []string            `json:"policy_rules"`
	Resolvers         []Resolver          `json:"resolvers"`
	Processes         []string            `json:"processes"`
	Tailscale         Tailscale           `json:"tailscale"`
	ManagementAddress string              `json:"management_address,omitempty"`
	ExistingTUN       bool                `json:"existing_tun"`
	CoreTUNKnown      bool                `json:"core_tun_known"`
	CoreTUNDevice     string              `json:"core_tun_device,omitempty"`
	Conflicts         []Finding           `json:"findings"`
	ExcludedRoutes    []string            `json:"excluded_routes"`
	DNSPolicies       map[string][]string `json:"dns_policies"`
	FakeIPFilter      []string            `json:"fake_ip_filter"`
}
type InspectOptions struct {
	Execute func(context.Context, string, string, []byte, int) ([]byte, error)
}

func Inspect(ctx context.Context, sshHost string) (Report, error) {
	return InspectWithOptions(ctx, sshHost, InspectOptions{})
}
func InspectWithOptions(ctx context.Context, sshHost string, opts InspectOptions) (Report, error) {
	if opts.Execute == nil {
		opts.Execute = connection.ExecutePython
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	data, err := opts.Execute(ctx, sshHost, inspectScript, []byte("{}"), 2<<20)
	if err != nil {
		return Report{}, err
	}
	var report Report
	if json.Unmarshal(data, &report) != nil || report.Protocol != 1 {
		return Report{}, errors.New("network inventory returned an unsupported response")
	}
	report.Scope = "local host"
	if sshHost != "" {
		report.Scope = "SSH host " + sshHost
	}
	return Analyze(report), nil
}

// WithCoreTUN adds a separately observed controller result. A process name or an
// utun interface alone cannot establish that Mihomo owns the active TUN.
func WithCoreTUN(report Report, enabled bool) Report {
	report.ExistingTUN, report.CoreTUNKnown = enabled, true
	return Analyze(report)
}
func WithCoreTUNDevice(report Report, enabled bool, device string) Report {
	report.CoreTUNDevice = device
	return WithCoreTUN(report, enabled)
}

func Analyze(report Report) Report {
	report.Conflicts = nil
	report.ExcludedRoutes = nil
	report.DNSPolicies = map[string][]string{}
	report.FakeIPFilter = nil
	add := func(code, level, confidence, message string, evidence ...string) {
		report.Conflicts = append(report.Conflicts, Finding{code, level, confidence, message, evidence})
	}
	excluded := map[string]bool{}
	addPrefix := func(raw string) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			if ip, e := netip.ParseAddr(raw); e == nil {
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				return
			}
		}
		if prefix.Bits() > 0 {
			excluded[prefix.Masked().String()] = true
		}
	}
	for _, p := range []string{"127.0.0.0/8", "::1/128"} {
		addPrefix(p)
	}
	if report.ManagementAddress != "" {
		addPrefix(report.ManagementAddress)
	}
	interfaces := map[string]Interface{}
	for _, iface := range report.Interfaces {
		interfaces[iface.Name] = iface
	}
	if report.Tailscale.Running {
		addPrefix("100.64.0.0/10")
		addPrefix("fd7a:115c:a1e0::/48")
		if suffix := domain(report.Tailscale.Suffix); suffix != "" {
			report.DNSPolicies["+."+suffix] = []string{"100.100.100.100"}
			report.FakeIPFilter = append(report.FakeIPFilter, "+."+suffix)
		}
		add("tailscale-split", "information", "confirmed", "Review tailnet and accepted subnet exclusions together with MagicDNS settings.")
	}
	if report.Tailscale.ExitNode {
		add("tailscale-exit-node", "conflict", "confirmed", "A Tailscale exit node owns default routing; choose one full-tunnel owner before enabling Mihomo TUN.")
	}
	defaultVPN := map[string][]string{}
	for _, route := range report.Routes {
		iface := interfaces[route.Interface]
		vpn := tunnelInterface(route.Interface, iface.Kind)
		prefix, err := netip.ParsePrefix(route.Destination)
		full := route.Destination == "default" || (err == nil && prefix.Bits() <= 1)
		if full && vpn && !route.Scoped {
			defaultVPN[route.Interface] = append(defaultVPN[route.Interface], route.Destination)
		}
		if err != nil || full {
			continue
		}
		// Exclude actual connected private routes and accepted routes through VPNs,
		// not arbitrary advertised peer prefixes or the whole default route.
		if (vpn && route.Interface != report.CoreTUNDevice && !strings.Contains(strings.ToLower(route.Interface), "mihomo")) || (!vpn && prefix.Addr().IsPrivate() && route.Gateway == "") {
			addPrefix(prefix.String())
		}
		if route.Table == "2022" && !report.CoreTUNKnown {
			add("possible-mihomo-table", "warning", "probable", "Routing table 2022 is present; inspect the existing TUN owner before setup.", route.Interface)
		}
	}
	for iface, routes := range defaultVPN {
		// One /1 is not evidence for both halves, but is still overlapping global
		// routing that must be resolved before installing another default route.
		add("vpn-default-route", "conflict", "confirmed", "An existing tunnel has default or broad /1 routes; choose its routing owner before enabling another TUN.", append([]string{iface}, routes...)...)
	}
	for _, resolver := range report.Resolvers {
		var servers []string
		for _, server := range resolver.Servers {
			ip, err := netip.ParseAddr(strings.Split(server, "%")[0])
			if err != nil {
				continue
			}
			servers = append(servers, server)
			if ip.IsPrivate() || isTailnetIP(ip) {
				addPrefix(ip.String())
			}
		}
		for _, suffix := range resolver.Domains {
			suffix = strings.TrimPrefix(suffix, "~")
			if suffix == "." {
				if tunnelInterface(resolver.Interface, interfaces[resolver.Interface].Kind) {
					add("vpn-default-dns", "warning", "confirmed", "A VPN resolver handles all DNS domains; inspect resolver precedence before enabling DNS interception.", resolver.Interface)
				}
				continue
			}
			if suffix = domain(suffix); suffix != "" && len(servers) > 0 {
				key := "+." + suffix
				report.DNSPolicies[key] = appendUnique(report.DNSPolicies[key], servers...)
				report.FakeIPFilter = appendUnique(report.FakeIPFilter, key)
			}
		}
	}
	if report.ExistingTUN {
		add("existing-core-tun", "conflict", "confirmed", "The observed core already owns TUN; configure that owner instead of starting a second TUN.")
	}
	for _, process := range report.Processes {
		name := strings.ToLower(process)
		if strings.Contains(name, "safeconnect") || strings.Contains(name, "openvpn") || strings.Contains(name, "openconnect") || strings.Contains(name, "vpnagent") || strings.Contains(name, "forti") || strings.Contains(name, "globalprotect") || strings.Contains(name, "charon") {
			add("vpn-client-present", "warning", "probable", "A VPN client is running; process presence alone does not prove interception or compatibility.", process)
		}
	}
	for _, capability := range report.Capabilities {
		if !capability.Available {
			add("inventory-unavailable", "warning", "unknown", "Some network evidence is unavailable; an empty result is not proof of no conflict.", capability.Name, capability.Detail)
		}
	}
	for p := range excluded {
		prefix, _ := netip.ParsePrefix(p)
		covered := false
		for other := range excluded {
			parent, _ := netip.ParsePrefix(other)
			if parent.Bits() < prefix.Bits() && parent.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			report.ExcludedRoutes = append(report.ExcludedRoutes, p)
		}
	}
	sort.Strings(report.ExcludedRoutes)
	sort.Strings(report.FakeIPFilter)
	sort.SliceStable(report.Conflicts, func(i, j int) bool {
		a, b := report.Conflicts[i], report.Conflicts[j]
		return a.Code+strings.Join(a.Evidence, ",") < b.Code+strings.Join(b.Evidence, ",")
	})
	return report
}

type TUNPlan struct {
	Settings     map[string]any      `json:"settings"`
	DNSPolicies  map[string][]string `json:"dns_policies"`
	FakeIPFilter []string            `json:"fake_ip_filter"`
	DirectRules  []string            `json:"direct_rules"`
	Findings     []Finding           `json:"findings"`
	Blocked      bool                `json:"blocked"`
}

func PlanTUN(report Report, extraExclusions []string, currentOwner bool) (TUNPlan, error) {
	report = Analyze(report)
	exclusions := append([]string(nil), report.ExcludedRoutes...)
	for _, raw := range extraExclusions {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Bits() == 0 {
			return TUNPlan{}, errors.New("TUN exclusions must be explicit non-default CIDRs")
		}
		exclusions = appendUnique(exclusions, p.Masked().String())
	}
	sort.Strings(exclusions)
	plan := TUNPlan{Settings: map[string]any{"enable": true, "auto-route": true, "auto-redirect": false, "strict-route": false, "route-exclude-address": exclusions}, DNSPolicies: report.DNSPolicies, FakeIPFilter: report.FakeIPFilter, Findings: report.Conflicts}
	for _, finding := range plan.Findings {
		ownRoute := currentOwner && finding.Code == "vpn-default-route" && report.CoreTUNDevice != "" && len(finding.Evidence) > 0 && finding.Evidence[0] == report.CoreTUNDevice
		if finding.Level == "conflict" && !(currentOwner && finding.Code == "existing-core-tun") && !ownRoute {
			plan.Blocked = true
		}
	}
	for _, raw := range exclusions {
		p, _ := netip.ParsePrefix(raw)
		kind := "IP-CIDR"
		if p.Addr().Is6() {
			kind = "IP-CIDR6"
		}
		plan.DirectRules = append(plan.DirectRules, kind+","+raw+",DIRECT,no-resolve")
	}
	return plan, nil
}
func Format(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Network inventory · %s · %s/%s\n", report.Scope, report.OS, report.Arch)
	fmt.Fprintf(&b, "%d interfaces · %d routes · %d scoped resolvers\n", len(report.Interfaces), len(report.Routes), len(report.Resolvers))
	b.WriteString("Application env → OS routing → VPN / TUN → destination\n                    └ scoped DNS → resolver\n\n")
	for _, finding := range report.Conflicts {
		fmt.Fprintf(&b, "[%s · %s] %s\n", finding.Level, finding.Confidence, finding.Message)
		if len(finding.Evidence) > 0 {
			fmt.Fprintf(&b, "  %s\n", strings.Join(finding.Evidence, ", "))
		}
	}
	fmt.Fprintf(&b, "\nProposed route exclusions: %s\n", strings.Join(report.ExcludedRoutes, ", "))
	keys := make([]string, 0, len(report.DNSPolicies))
	for k := range report.DNSPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "DNS %s → %s\n", k, strings.Join(report.DNSPolicies[k], ", "))
	}
	b.WriteString("Passive evidence only; no routes, DNS, VPN or system proxy settings were changed.\n")
	return b.String()
}
func tunnelInterface(name, kind string) bool {
	s := strings.ToLower(name + " " + kind)
	for _, part := range []string{"utun", "tun", "tap", "tailscale", "wireguard", "ppp", "ipsec", "vpn"} {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}
func isTailnetIP(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)
}
func appendUnique(dst []string, values ...string) []string {
	for _, v := range values {
		found := false
		for _, old := range dst {
			found = found || old == v
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}
func domain(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " /\\:*\t\r\n") {
		return ""
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" || len(part) > 63 {
			return ""
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return value
}
