package managedcore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"go.yaml.in/yaml/v3"
)

func buildProfile(ctx context.Context, request Request) ([]byte, map[string][]byte, string, []string, error) {
	if len(request.Input) == 0 || len(request.Input) > 8<<20 {
		return nil, nil, "", nil, errors.New("provide links, a node-subscription URL or a complete YAML (maximum 8 MiB)")
	}
	if request.Preset == "preserve" && request.InputKind != "yaml" {
		return nil, nil, "", nil, errors.New("preserve requires a complete YAML profile; choose cn-split or simple for nodes")
	}
	document := map[string]any{}
	resources := map[string][]byte{}
	warnings := []string{}
	if request.InputKind == "yaml" {
		warnings = append(warnings, "The imported DNS configuration is preserved; scoped VPN nameserver policies and fake-IP exceptions are merged explicitly.")
	} else {
		warnings = append(warnings, "Starter DNS uses host resolution with detected VPN suffix policies; regional routing rules do not prevent poisoned DNS and no broad DNS hijack is enabled.")
	}

	switch request.InputKind {
	case "links":
		definitions, issues, err := configwork.ParseImport(request.Input)
		if err != nil || len(issues) > 0 || len(definitions) == 0 {
			return nil, nil, "", nil, errors.New("one or more imported node definitions are invalid; use proxies import to inspect redacted diagnostics")
		}
		proxies := []any{}
		members := []any{}
		for _, definition := range definitions {
			if definition.Kind != "proxy" {
				return nil, nil, "", nil, errors.New("setup links must contain proxy nodes, not group definitions")
			}
			proxies = append(proxies, definition.Map())
			members = append(members, definition.Name)
		}
		document["proxies"] = proxies
		document["proxy-groups"] = []any{map[string]any{"name": "PROXY", "type": "select", "proxies": members}}
	case "subscription":
		endpoint := strings.TrimSpace(string(request.Input))
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, nil, "", nil, errors.New("node subscription must be an HTTPS URL without userinfo or fragment")
		}
		body, _, err := download(ctx, endpoint, nil, 8<<20)
		if err != nil {
			return nil, nil, "", nil, errors.New("node subscription could not be fetched; import a local node snapshot or choose an explicit reachable source")
		}
		var envelope map[string]any
		if yaml.Unmarshal(body, &envelope) == nil {
			for _, key := range []string{"proxy-groups", "rules", "rule-providers", "dns", "tun", "external-controller", "mixed-port"} {
				if _, full := envelope[key]; full {
					return nil, nil, "", nil, errors.New("subscription is a complete profile; download it to a private file and use --input-kind yaml")
				}
			}

		}
		if decoded, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body))); e == nil && bytes.Contains(decoded, []byte("://")) {
			body = decoded
		} else if decoded, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(body))); e == nil && bytes.Contains(decoded, []byte("://")) {
			body = decoded
		}
		definitions, issues, err := configwork.ParseImport(body)
		if err != nil || len(issues) > 0 || len(definitions) == 0 {
			return nil, nil, "", nil, errors.New("subscription did not contain supported node definitions; full-profile URLs are a separate import kind")
		}
		proxies := []any{}
		for _, definition := range definitions {
			proxies = append(proxies, definition.Map())
		}
		cached, _ := yaml.Marshal(map[string]any{"proxies": proxies})
		resources["providers/subscription.yaml"] = cached
		provider := map[string]any{"type": "file", "path": "./providers/subscription.yaml"}
		if _, yamlProvider := envelope["proxies"]; yamlProvider {
			provider["type"] = "http"
			provider["url"] = endpoint
			provider["interval"] = 86400
		} else {
			warnings = append(warnings, "Link/base64 subscription was converted to an offline node snapshot; explicitly reimport the subscription URL to fetch it again. Raw-link refresh is not delegated to the core.")
		}
		document["proxy-providers"] = map[string]any{"subscription": provider}
		recordResourceOrigin(ctx, "providers/subscription.yaml", "HTTPS node source "+u.Scheme+"://"+u.Host+" (private path/query omitted)")
		document["proxy-groups"] = []any{map[string]any{"name": "PROXY", "type": "select", "use": []any{"subscription"}}}
		if provider["type"] == "http" {
			warnings = append(warnings, "The initial node-provider snapshot is bundled; later subscription refresh uses the core's host networking and may fail independently.")
		}
	case "yaml":
		decoder := yaml.NewDecoder(bytes.NewReader(request.Input))
		if decoder.Decode(&document) != nil || document == nil {
			return nil, nil, "", nil, errors.New("complete profile is not a YAML mapping")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, nil, "", nil, errors.New("complete profile must contain one YAML document")
		}
		if _, ok := document["proxy-groups"]; !ok {
			return nil, nil, "", nil, errors.New("complete profile must declare proxy-groups")
		}
		if request.Preset != "preserve" {
			delete(document, "rules")
			delete(document, "rule-providers")
		}
		if values, ok := document["listeners"].([]any); ok && len(values) > 0 {
			return nil, nil, "", nil, errors.New("complete profile declares additional listeners; remove them before installing a loopback-owned client")
		}
		if err := profileResources(ctx, document, request.InputBaseDir, resources); err != nil {
			return nil, nil, "", nil, err
		}
	default:
		return nil, nil, "", nil, errors.New("input kind must be links, subscription or yaml")
	}
	version := ""
	if request.Preset != "preserve" {
		providers, rules, presetResources, revision, err := presetRules(request.Preset, request.Categories, request.PolicyRoles)
		if err != nil {
			return nil, nil, "", nil, err
		}
		known := map[string]bool{"DIRECT": true, "REJECT": true}
		groups, _ := document["proxy-groups"].([]any)
		for _, entry := range groups {
			group, _ := entry.(map[string]any)
			name, _ := group["name"].(string)
			known[name] = true
		}
		if !known["PROXY"] {
			return nil, nil, "", nil, errors.New("starter presets need an existing PROXY group; select preserve for an existing full profile")
		}
		for _, role := range request.PolicyRoles {
			if !known[role] {
				return nil, nil, "", nil, errors.New("a rule category refers to an unknown policy group")
			}
		}
		existing, _ := document["rule-providers"].(map[string]any)
		if existing == nil {
			existing = map[string]any{}
		}
		for name, provider := range providers {
			if _, ok := existing[name]; ok {
				return nil, nil, "", nil, errors.New("profile already defines a reserved lazyclash rule provider")
			}
			existing[name] = provider
		}
		document["rule-providers"], document["rules"] = existing, rules
		for path, data := range presetResources {
			resources[path] = data
		}
		version = revision
		if request.InputKind == "yaml" {
			warnings = append(warnings, "The selected starter preset replaces the imported profile's routing list; imported nodes/groups/DNS are retained. Choose preserve to retain its existing rules.")
		}
	}
	document["mixed-port"], document["port"], document["socks-port"], document["redir-port"], document["tproxy-port"] = request.MixedPort, 0, 0, 0, 0
	if mode, ok := document["mode"].(string); ok && mode != "rule" {
		warnings = append(warnings, "Managed setup selects rule mode; the imported mode is overridden explicitly.")
	}
	document["mode"] = "rule"
	document["allow-lan"] = request.Backend == "docker" && !request.Network.TUN
	document["bind-address"] = "127.0.0.1"
	controllerHost := "127.0.0.1"
	if request.Backend == "docker" && !request.Network.TUN {
		controllerHost = "0.0.0.0"
		document["bind-address"] = "*"
	}
	document["external-controller"] = fmt.Sprintf("%s:%d", controllerHost, request.ControllerPort)
	document["secret"] = "__LAZYCLASH_GENERATED_SECRET__"
	delete(document, "external-controller-tls")
	delete(document, "external-controller-unix")
	delete(document, "external-controller-pipe")
	delete(document, "external-ui-url")
	delete(document, "external-ui")
	if _, ok := document["log-level"]; !ok {
		document["log-level"] = "info"
	}
	if _, ok := document["profile"]; !ok {
		document["profile"] = map[string]any{"store-selected": true, "store-fake-ip": true}
	}
	tun, _ := document["tun"].(map[string]any)
	if tun == nil {
		tun = map[string]any{}
	}
	tun["enable"] = request.Network.TUN
	if request.Network.TUN {
		tun["auto-route"], tun["auto-redirect"], tun["strict-route"], tun["stack"] = true, false, false, "mixed"
		delete(tun, "device")
		exclusions := []any{}
		for _, prefix := range request.Network.ExcludedRoutes {
			if _, err := netip.ParsePrefix(prefix); err != nil {
				return nil, nil, "", nil, errors.New("network exclusion contains an invalid CIDR")
			}
			exclusions = append(exclusions, prefix)
		}
		tun["route-exclude-address"] = exclusions
		if request.InputKind == "yaml" {
			if _, configured := tun["dns-hijack"]; configured {
				warnings = append(warnings, "Imported TUN DNS hijack is preserved. Review its interaction with detected VPN split DNS; regional routing rules do not establish DNS correctness.")
			}
		} else {
			delete(tun, "dns-hijack")
		}

	}
	document["tun"] = tun
	if len(request.Network.DNSPolicies) > 0 || len(request.Network.FakeIPFilter) > 0 {
		dns, _ := document["dns"].(map[string]any)
		if dns == nil {
			dns = map[string]any{"enable": true, "enhanced-mode": "redir-host", "nameserver": []any{"system"}}
		}
		policies, _ := dns["nameserver-policy"].(map[string]any)
		if policies == nil {
			policies = map[string]any{}
		}
		for suffix, resolvers := range request.Network.DNSPolicies {
			policies[suffix] = resolvers
		}
		dns["nameserver-policy"] = policies
		filters, _ := dns["fake-ip-filter"].([]any)
		filters = mergeGeneratedStrings(filters, request.Network.FakeIPFilter, false)
		if len(filters) > 0 {
			dns["fake-ip-filter"] = filters
		}
		document["dns"] = dns
	}
	rules, _ := document["rules"].([]any)
	bypass := []string{}
	for _, prefix := range request.Network.ExcludedRoutes {
		p, _ := netip.ParsePrefix(prefix)
		kind := "IP-CIDR"
		if p.Addr().Is6() {
			kind = "IP-CIDR6"
		}
		bypass = append(bypass, kind+","+prefix+",DIRECT,no-resolve")
	}
	for _, suffix := range request.Network.FakeIPFilter {
		domain := strings.TrimPrefix(suffix, "+.")
		if !strings.ContainsAny(domain, "*,\r\n") && domain != "" {
			bypass = append(bypass, "DOMAIN-SUFFIX,"+domain+",DIRECT")
		}
	}
	document["rules"] = mergeGeneratedStrings(rules, bypass, true)
	data, err := yaml.Marshal(document)
	if err != nil {
		return nil, nil, "", nil, errors.New("cannot render managed profile")
	}
	return data, resources, version, warnings, nil
}

// Only exact generated entries are deduplicated. Other imported entries retain
// their relative order, including rules for the same destination with different
// policies or flags. Bypass rules stay first; existing DNS filter order is kept.
func mergeGeneratedStrings(existing []any, generated []string, prepend bool) []any {
	managed := make(map[string]bool, len(generated))
	for _, value := range generated {
		managed[value] = true
	}
	seen := make(map[string]bool, len(generated))
	result := make([]any, 0, len(existing)+len(generated))
	appendGenerated := func() {
		for _, value := range generated {
			if !seen[value] {
				result = append(result, value)
				seen[value] = true
			}
		}
	}
	if prepend {
		appendGenerated()
	}
	for _, entry := range existing {
		if value, ok := entry.(string); ok && managed[value] {
			if seen[value] {
				continue
			}
			seen[value] = true
		}
		result = append(result, entry)
	}
	if !prepend {
		appendGenerated()
	}
	return result
}

func profileResources(ctx context.Context, document map[string]any, base string, resources map[string][]byte) error {
	for _, field := range []string{"proxy-providers", "rule-providers"} {
		providers, _ := document[field].(map[string]any)
		keys := make([]string, 0, len(providers))
		for name := range providers {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			provider, _ := providers[name].(map[string]any)
			kind, _ := provider["type"].(string)
			if kind == "inline" {
				continue
			}
			path, _ := provider["path"].(string)
			endpoint, _ := provider["url"].(string)
			var data []byte
			sourceOrigin := ""
			var err error
			if cached, ok := snapshotResource(ctx, path); ok {
				data = cached
				sourceOrigin = "current owned resource " + path
			}
			if data == nil && path != "" && base != "" {
				source := path
				if !filepath.IsAbs(source) {
					source = filepath.Join(base, source)
				}
				info, e := os.Stat(source)
				if e == nil && info.Mode().IsRegular() && info.Size() <= 8<<20 {
					data, err = os.ReadFile(source)
					sourceOrigin = "local file " + source
				}
			}
			if data == nil && kind == "http" {
				u, e := url.Parse(endpoint)
				if e != nil || u.Scheme != "https" || u.User != nil {
					return errors.New("profile providers require HTTPS URLs or a readable cached local file")
				}
				data, _, err = download(ctx, endpoint, nil, 8<<20)
				sourceOrigin = "HTTPS provider " + u.Scheme + "://" + u.Host + " (private path/query omitted)"
			}
			if err != nil || data == nil {
				return errors.New("profile provider resource is unavailable; supply its local cache or reachable HTTPS source")
			}
			relative := "providers/" + hashBytes([]byte(field + ":" + name))[:16] + ".yaml"
			provider["path"] = "./" + relative
			resources[relative] = data
			recordResourceOrigin(ctx, relative, sourceOrigin)
		}
	}
	// Explicitly relocate referenced certificate resources into private storage.
	var walk func(any) error
	walk = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				fileKey := key == "certificate" || key == "certificate-path" || key == "private-key-path" || key == "ca" || (key == "private-key" && v["certificate"] != nil)
				if text, ok := item.(string); ok && fileKey && text != "" && !strings.Contains(text, "-----BEGIN") {
					path := text
					data, cached := snapshotResource(ctx, text)
					if !cached {
						if !filepath.IsAbs(path) {
							path = filepath.Join(base, path)
						}
						if base == "" && !filepath.IsAbs(text) {
							return errors.New("relative certificate file requires an input file directory")
						}
						info, e := os.Stat(path)
						if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
							return errors.New("certificate/key resource is not a bounded readable file")
						}
						data, e = os.ReadFile(path)
						if e != nil {
							return errors.New("certificate/key resource could not be read")
						}
					}
					name := "certificates/" + hashBytes([]byte(path))[:16] + ".pem"
					resources[name] = data
					recordResourceOrigin(ctx, name, "local certificate/key "+path)
					v[key] = "./" + name
				} else if e := walk(item); e != nil {
					return e
				}
			}
		case []any:
			for _, item := range v {
				if e := walk(item); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if err := walk(document); err != nil {
		return err
	}
	required := map[string]bool{}
	var geodata func(any)
	geodata = func(value any) {
		switch values := value.(type) {
		case string:
			upper := strings.ToUpper(values)
			if strings.Contains(upper, "GEOSITE,") || strings.Contains(upper, "GEOSITE:") {
				required["GeoSite.dat"] = true
			}
			if strings.Contains(upper, "GEOIP,") || strings.Contains(upper, "GEOIP:") {
				name := "Country.mmdb"
				if document["geodata-mode"] == true {
					name = "GeoIP.dat"
				}
				required[name] = true
			}
		case map[string]any:
			for key, item := range values {
				geodata(key)
				if key == "geoip" && item == true {
					name := "Country.mmdb"
					if document["geodata-mode"] == true {
						name = "GeoIP.dat"
					}
					required[name] = true
				}
				geodata(item)
			}
		case []any:
			for _, item := range values {
				geodata(item)
			}
		}
	}
	geodata(document)

	for name := range required {
		path := filepath.Join(base, name)
		data, cached := snapshotResource(ctx, name)
		if !cached {
			info, e := os.Stat(path)
			if base == "" || e != nil || !info.Mode().IsRegular() || info.Size() > 24<<20 {
				return errors.New("full profile requires local geodata beside its YAML; use offline cn-split to replace those rules")
			}
			data, e = os.ReadFile(path)
			if e != nil {
				return errors.New("profile geodata could not be read")
			}
		}
		resources[name] = data
		recordResourceOrigin(ctx, name, "owned/local geodata "+path)
	}

	return nil
}

func toStrings(value any) []string {
	var result []string
	if values, ok := value.([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok {
				result = append(result, text)
			}
		}
	}
	return result
}

func injectControllerSecret(profile []byte, secret string) ([]byte, error) {
	var document map[string]any
	if err := yaml.Unmarshal(profile, &document); err != nil || document == nil {
		return nil, errors.New("invalid generated controller profile")
	}
	document["secret"] = secret
	return yaml.Marshal(document)
}

type profileOriginsKey struct{}

func recordResourceOrigin(ctx context.Context, name, origin string) {
	if origins, ok := ctx.Value(profileOriginsKey{}).(map[string]string); ok {
		origins[name] = origin
	}
}

type profileSnapshotKey struct{}
type profileSnapshot struct {
	Home  string
	Files map[string][]byte
}

func snapshotResource(ctx context.Context, path string) ([]byte, bool) {
	snapshot, ok := ctx.Value(profileSnapshotKey{}).(profileSnapshot)
	if !ok {
		return nil, false
	}
	if filepath.IsAbs(path) {
		relative, e := filepath.Rel(snapshot.Home, path)
		if e != nil {
			return nil, false
		}
		path = relative
	}
	path = filepath.ToSlash(filepath.Clean(path))
	data, ok := snapshot.Files[path]
	return data, ok
}
