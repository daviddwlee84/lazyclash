package doctor

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
)

func collectSystem(ctx context.Context, opts Options, updates chan<- func(*Report)) {
	if ctx.Err() != nil {
		return
	}
	snapshot, err := opts.ReadSystemProxy(ctx, "", nil)
	if err != nil || snapshot.Unavailable != "" {
		publish(updates, Check{ID: "system_proxy", Status: Unknown, Message: "System proxy metadata is unavailable or unsupported; this does not mean system proxy is disabled.", Suggestion: "Check Python 3 and the supported OS backend; macOS Network services and active GNOME sessions are supported."})
		return
	}
	result := SystemProxy{Available: true, Backend: safeText(snapshot.Backend), Services: []SystemService{}}
	for _, service := range snapshot.Services {
		result.Services = append(result.Services, SystemService{Name: safeText(service.Service), HTTP: listener(service.HTTP, "http"), HTTPS: listener(service.HTTPS, "http"), SOCKS: listener(service.SOCKS, "socks5h"), PACEnabled: service.PACEnabled, AutoDiscovery: service.Discovery})
	}
	updates <- func(r *Report) {
		r.SystemProxy = &result
		r.set(Check{ID: "system_proxy", Status: Pass, Message: "Read system proxy settings. Configured macOS Network services are not proof that every service is currently active; PAC URLs are withheld."})
	}
}

func listener(value networkcheck.ProxyListener, scheme string) string {
	if !value.Enabled {
		return ""
	}
	if value.Port < 1 || value.Port > 65535 || strings.ContainsAny(value.Host, "/@?#\\\r\n") {
		return "<set; unrecognized>"
	}
	return safeEndpoint(scheme + "://" + net.JoinHostPort(value.Host, strconv.Itoa(value.Port)))
}

func collectNetwork(ctx context.Context, opts Options, updates chan<- func(*Report)) {
	if ctx.Err() != nil {
		return
	}
	snapshot, err := opts.Inspect(ctx, "", networkcheck.InspectOptions{})
	if err != nil {
		publish(updates, Check{ID: "network", Status: Unknown, Message: "Passive interface/route/DNS inventory is unavailable.", Suggestion: "Check Python 3 and local host-tool availability; no helper was installed."})
		return
	}
	// Inspect's pre-TUN conflict analysis is intentionally not reused here. An
	// existing tunnel/default route is evidence, not a doctor failure.
	result := Network{OS: safeText(snapshot.OS), Capabilities: []networkcheck.Capability{}, Interfaces: []string{}, DefaultRoutes: []networkcheck.Route{}, DNSServers: []string{}}
	available := false
	missing := false
	for _, capability := range snapshot.Capabilities {
		result.Capabilities = append(result.Capabilities, networkcheck.Capability{Name: safeText(capability.Name), Available: capability.Available})
		available = available || capability.Available
		missing = missing || !capability.Available
	}
	for _, iface := range snapshot.Interfaces {
		result.Interfaces = append(result.Interfaces, safeText(iface.Name))
	}
	for _, route := range snapshot.Routes {
		if route.Destination != "default" && route.Destination != "0.0.0.0/0" && route.Destination != "::/0" {
			continue
		}
		result.DefaultRoutes = append(result.DefaultRoutes, networkcheck.Route{Destination: route.Destination, Gateway: safeText(route.Gateway), Interface: safeText(route.Interface), Scoped: route.Scoped})
	}
	seen := map[string]bool{}
	for _, resolver := range snapshot.Resolvers {
		for _, server := range resolver.Servers {
			// Retain numeric DNS evidence, not search domains, URLs or tokens.
			ip, _, _ := strings.Cut(server, "%")
			if net.ParseIP(ip) != nil && !seen[server] {
				result.DNSServers = append(result.DNSServers, safeText(server))
				seen[server] = true
			}
		}
	}
	check := Check{ID: "network", Status: Pass, Message: "Collected passive interface, default-route and DNS evidence; no DNS query or outbound probe was sent."}
	if !available {
		check.Status = Unknown
		check.Message = "Host inventory has no available capabilities; unsupported is not disabled."
	} else if missing {
		check.Status = Warn
		check.Message = "Collected partial host evidence; some optional host tools are unavailable."
	}
	updates <- func(r *Report) { r.Network = &result; r.set(check) }
}

func compare(r *Report) {
	check := Check{ID: "consistency", Status: Unknown, Message: "Runtime listener evidence is unavailable; endpoint consistency could not be compared."}
	if !r.Selection.Local || r.Runtime == nil || !r.Runtime.IdentityVerified {
		r.set(check)
		return
	}
	for _, current := range r.Checks {
		if current.ID == "runtime" && current.Status != Pass {
			r.set(check)
			return
		}
	}
	if r.Runtime.MixedPort == 0 && r.Runtime.HTTPPort == 0 && r.Runtime.SOCKSPort == 0 {
		check.Status, check.Message = Skip, "No runtime HTTP/SOCKS listeners to compare. TUN-only operation is valid; egress remains untested."
		r.set(check)
		return
	}
	want := runtimeEndpoint(config.Target{Controller: r.Selection.Controller}, *r.Runtime)
	mismatch := false
	compared := 0
	consider := func(value, expected string) {
		if value == "" {
			return
		}
		u, err := url.Parse(value)
		if err != nil || !proxyenv.IsLocalTarget(config.Target{Controller: value}) {
			return
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
			return
		}
		compared++
		if !sameListener(value, expected) {
			mismatch = true
		}
	}
	for key, value := range r.Environment.Variables {
		expected := want.HTTP
		if strings.HasPrefix(value, "socks") {
			expected = want.SOCKS
		}
		if strings.EqualFold(key, "all_proxy") && expected == "" {
			expected = want.SOCKS
		}
		consider(value, expected)
	}
	if r.SystemProxy != nil {
		for _, service := range r.SystemProxy.Services {
			consider(service.HTTP, want.HTTP)
			consider(service.HTTPS, want.HTTP)
			consider(service.SOCKS, want.SOCKS)
		}
	}
	if r.DataEndpoint.Source != "core runtime ports" {
		expected := want.HTTP
		if strings.HasPrefix(r.DataEndpoint.HTTP, "socks") {
			expected = want.SOCKS
		}
		consider(r.DataEndpoint.HTTP, expected)
		consider(r.DataEndpoint.SOCKS, want.SOCKS)
	}
	check.Status = Pass
	check.Message = "Same-host proxy endpoints match the runtime listener ports; ownership and egress are not established."
	if compared == 0 {
		check.Status = Skip
		check.Message = "No comparable local proxy endpoints were observed; missing environment/system proxy settings alone are not a failure."
	}
	if mismatch {
		check.Status = Warn
		check.Message = "Some local proxy endpoints differ from this controller's runtime listeners; another proxy or inactive service may explain the difference."
		check.Suggestion = "Review process proxy variables and active OS network service settings before changing anything; doctor does not establish ownership."
	}
	r.set(check)
}

func sameListener(a, b string) bool {
	x, errX := url.Parse(a)
	y, errY := url.Parse(b)
	if errX != nil || errY != nil || x.Hostname() == "" || y.Hostname() == "" {
		return false
	}
	// localhost is intentionally family-neutral; do not resolve DNS to compare.
	xHost, yHost := strings.ToLower(x.Hostname()), strings.ToLower(y.Hostname())
	hostMatches := xHost == yHost || xHost == "localhost" || yHost == "localhost"
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "http" {
			return "80"
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "1080"
	}
	return hostMatches && port(x) == port(y)
}

// Format is a plain-text rendering of the same safe report used for JSON.
func Format(r Report) string {
	var b strings.Builder
	b.WriteString("Doctor — local, passive (no state changes)\n")
	if r.Selection.Controller != "" {
		b.WriteString("Controller: " + r.Selection.Controller + " (" + r.Selection.Source + ")\n")
	}
	if r.DataEndpoint.Source != "" {
		b.WriteString("Data endpoint: " + r.DataEndpoint.HTTP + " " + r.DataEndpoint.SOCKS + " (" + r.DataEndpoint.Source + "; untested)\n")
	}
	if r.Runtime != nil {
		tun := "unknown"
		if r.Runtime.TUNKnown {
			tun = strconv.FormatBool(r.Runtime.TUNEnabled)
		}
		b.WriteString("Runtime: mode=" + r.Runtime.Mode + " mixed=" + strconv.Itoa(r.Runtime.MixedPort) + " http=" + strconv.Itoa(r.Runtime.HTTPPort) + " socks=" + strconv.Itoa(r.Runtime.SOCKSPort) + " TUN=" + tun + " " + r.Runtime.TUNDevice + "\n")
	}
	keys := make([]string, 0, len(r.Environment.Variables))
	for key := range r.Environment.Variables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString("Environment: " + key + "=" + r.Environment.Variables[key] + "\n")
	}
	if r.SystemProxy != nil {
		for _, service := range r.SystemProxy.Services {
			b.WriteString("System proxy: " + service.Name + " http=" + service.HTTP + " https=" + service.HTTPS + " socks=" + service.SOCKS + " PAC=" + strconv.FormatBool(service.PACEnabled) + "\n")
		}
	}
	for _, check := range r.Checks {
		b.WriteString("[" + string(check.Status) + "] " + check.ID + ": " + check.Message + "\n")
	}
	if r.Summary.Canceled {
		b.WriteString("Canceled; partial results above.\n")
	} else if r.Summary.TimedOut {
		b.WriteString("Overall timeout reached; partial results above.\n")
	}
	for _, suggestion := range r.Suggestions {
		b.WriteString("Next: " + suggestion + "\n")
	}
	b.WriteString("Exit status: " + strconv.Itoa(r.Summary.ExitCode) + "\n")
	return b.String()
}
