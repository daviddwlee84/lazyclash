package topology

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

const MaxDocument = 8 << 20

func Parse(raw []byte, source Source) (Graph, error) {
	g := Graph{Source: source, Nodes: []Node{}, Edges: []Edge{}, Rules: []Rule{}}
	if len(raw) == 0 || len(raw) > MaxDocument {
		return g, errors.New("configuration must contain 1 byte to 8 MiB")
	}
	var root map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if decoder.Decode(&root) != nil || root == nil {
		return g, errors.New("invalid YAML mapping or duplicate keys")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return g, errors.New("only one YAML document is supported")
	}
	if err := validateShape(root); err != nil {
		return g, err
	}
	g.Source.SHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	if g.Source.Kind == "" {
		g.Source.Kind = "yaml"
	}
	proxies := entries(root["proxies"])
	groups := entries(root["proxy-groups"])
	providers := mapping(root["proxy-providers"])
	seen := map[string]bool{}
	add := func(v map[string]any, kind string) {
		name := text(v["name"])
		if name == "" || seen[name] || builtin(name) {
			g.warn("Invalid or duplicate %s name %q", kind, name)
			return
		}
		seen[name] = true
		g.addNode(kind, name, text(v["type"]), "config")
	}
	for _, p := range proxies {
		add(p, "proxy")
	}
	for _, p := range groups {
		add(p, "group")
	}
	for _, name := range sortedKeys(providers) {
		p := mapping(providers[name])
		id := g.addNode("provider", name, text(p["type"]), "config")
		for i, proxy := range entries(p["payload"]) {
			add(proxy, "proxy")
			g.edge(id, g.outbound(text(proxy["name"]), "config"), "payload", "config", i)
			proxies = append(proxies, proxy)
		}
		if text(p["type"]) != "inline" {
			g.warn("Provider %q: external contents are unresolved offline", name)
		}
	}
	// Resolve overrides after all inline payloads have been registered, so a
	// reference to a later provider's node is not mistaken for a missing node.
	for _, name := range sortedKeys(providers) {
		if via := text(mapping(mapping(providers[name])["override"])["dialer-proxy"]); via != "" {
			g.edge(ID("provider", name), g.outbound(via, "config"), "dialer-override", "config", 0)
		}
	}
	ruleProviders := mapping(root["rule-providers"])
	for _, name := range sortedKeys(ruleProviders) {
		p := mapping(ruleProviders[name])
		g.addNode("rule-provider", name, text(p["behavior"]), "config")
	}
	for _, p := range proxies {
		if via := text(p["dialer-proxy"]); via != "" {
			g.edge(g.outbound(text(p["name"]), "config"), g.outbound(via, "config"), "dialer", "config", 0)
		}
	}
	for _, p := range groups {
		id := ID("group", text(p["name"]))
		if g.node(id) == nil {
			continue
		}
		kind := "member"
		if text(p["type"]) == "relay" {
			kind = "relay-member"
		}
		for i, name := range stringsList(p["proxies"]) {
			g.edge(id, g.outbound(name, "config"), kind, "config", i)
		}
		for i, name := range stringsList(p["use"]) {
			pid := ID("provider", name)
			if g.node(pid) == nil {
				pid = g.addNode("missing-provider", name, "", "config")
				g.warn("Missing provider reference %q", name)
			}
			g.edge(id, pid, "use", "config", i)
		}
		decl := map[string]string{}
		for _, k := range []string{"include-all", "include-all-proxies", "include-all-providers", "filter", "exclude-filter", "exclude-type", "default-selected", "empty-fallback"} {
			if v, ok := p[k]; ok {
				switch v.(type) {
				case string, bool:
					decl[k] = fmt.Sprint(v)
				}
			}
		}
		g.node(id).Declarations = decl
		for _, k := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
			if decl[k] == "true" {
				dynamic := g.addNode("dynamic", text(p["name"])+": "+k, "unresolved selection", "config")
				g.edge(id, dynamic, "declaration", "config", 0)
			}
		}
	}
	subRules := mapping(root["sub-rules"])
	for _, name := range sortedKeys(subRules) {
		g.addNode("sub-rule", name, "", "config")
	}
	g.parseRules("rules", stringsList(root["rules"]))
	for _, name := range sortedKeys(subRules) {
		g.parseRules(name, stringsList(subRules[name]))
	}
	g.cycles("config")
	return g, nil
}

func (g *Graph) parseRules(scope string, rules []string) {
	counts := map[string]int{}
	for index, expression := range rules {
		rule := Rule{Index: index, Scope: scope, Expression: core.Sanitize(expression)}
		parts, ok := splitRule(expression)
		if len(parts) > 0 {
			rule.Type = parts[0]
		}
		if len(parts) > 0 && parts[len(parts)-1] == "no-resolve" {
			parts = parts[:len(parts)-1]
		}
		expected := 3
		if rule.Type == "MATCH" {
			expected = 2
		}
		if !ok || len(parts) != expected || !knownRule(rule.Type) {
			g.warn("Unresolved rule syntax at %s #%d", scope, index+1)
			g.Rules = append(g.Rules, rule)
			continue
		}
		rule.Target = parts[len(parts)-1]
		to := ""
		if rule.Type == "SUB-RULE" {
			to = ID("sub-rule", rule.Target)
			if g.node(to) == nil {
				to = g.addNode("missing-sub-rule", rule.Target, "", "config")
				g.warn("Missing sub-rule %q", rule.Target)
			}
		} else {
			to = g.outbound(rule.Target, "config")
		}
		rule.Resolved = !strings.HasPrefix(g.node(to).Kind, "missing")
		name := scope + " → " + rule.Target
		if expected == 2 {
			name = scope + " #" + strconv.Itoa(index+1) + " " + rule.Type + " → " + rule.Target
		}
		id := g.addNode("rules", name, "rule summary", "config")
		if counts[id] == 0 {
			g.edge(id, to, "route", "config", index)
			if scope != "rules" {
				g.edge(ID("sub-rule", scope), id, "rules", "config", index)
			}
		}
		counts[id]++
		if rule.Type == "RULE-SET" {
			rule.Provider = parts[1]
			pid := ID("rule-provider", rule.Provider)
			if g.node(pid) == nil {
				pid = g.addNode("missing-rule-provider", rule.Provider, "", "config")
				g.warn("Missing rule provider %q", rule.Provider)
				rule.Resolved = false
			}
			g.edge(id, pid, "rule-set", "config", index)
		}
		g.Rules = append(g.Rules, rule)
	}
	for id, count := range counts {
		g.node(id).Declarations = map[string]string{"rule-count": strconv.Itoa(count)}
	}
}

func validateShape(root map[string]any) error {
	sequence := func(value any, mappings bool) error {
		if value == nil {
			return nil
		}
		items, ok := value.([]any)
		if !ok {
			return errors.New("expected a sequence")
		}
		for _, item := range items {
			if mappings {
				if mapping(item) == nil {
					return errors.New("expected mapping entries")
				}
			} else if _, ok := item.(string); !ok {
				return errors.New("expected string entries")
			}
		}
		return nil
	}
	for _, key := range []string{"proxies", "proxy-groups", "rules"} {
		if value, exists := root[key]; exists {
			if err := sequence(value, key != "rules"); err != nil {
				return fmt.Errorf("invalid %s: %w", key, err)
			}
		}
	}
	for _, group := range entries(root["proxy-groups"]) {
		for _, key := range []string{"proxies", "use"} {
			if value, exists := group[key]; exists {
				if err := sequence(value, false); err != nil {
					return fmt.Errorf("invalid group %s: %w", key, err)
				}
			}
		}
	}
	for _, key := range []string{"proxy-providers", "rule-providers", "sub-rules"} {
		if value, exists := root[key]; exists {
			if value == nil {
				continue
			}
			m := mapping(value)
			if m == nil {
				return fmt.Errorf("%s must be a mapping", key)
			}
			for _, name := range sortedKeys(m) {
				if key == "sub-rules" {
					if err := sequence(m[name], false); err != nil {
						return fmt.Errorf("invalid sub-rules: %w", err)
					}
					continue
				}
				p := mapping(m[name])
				if p == nil {
					return fmt.Errorf("%s entries must be mappings", key)
				}
				if payload, exists := p["payload"]; exists && key == "proxy-providers" {
					if err := sequence(payload, true); err != nil {
						return fmt.Errorf("invalid provider payload: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func knownRule(kind string) bool {
	switch kind {
	case "MATCH", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", "GEOIP", "IP-CIDR", "IP-CIDR6", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-NAME", "PROCESS-NAME-REGEX", "UID", "NETWORK", "DSCP", "RULE-SET", "AND", "OR", "NOT", "SUB-RULE":
		return true
	}
	return false
}

// Logical-rule payloads contain commas inside parentheses.
func splitRule(raw string) ([]string, bool) {
	var parts []string
	depth, start := 0, 0
	for i, r := range raw {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(raw[start:i]))
				start = i + 1
			}
		}
	}
	return append(parts, strings.TrimSpace(raw[start:])), depth == 0
}

func mapping(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any) string            { s, _ := v.(string); return s }
func entries(v any) []map[string]any {
	var result []map[string]any
	items, _ := v.([]any)
	for _, item := range items {
		if m := mapping(item); m != nil {
			result = append(result, m)
		}
	}
	return result
}
func stringsList(v any) []string {
	var result []string
	items, _ := v.([]any)
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}
