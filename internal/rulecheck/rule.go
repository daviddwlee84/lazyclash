// Package rulecheck performs bounded, read-only analysis of ordered rules.
// It does not resolve DNS, expand providers, or execute a core's match engine.
package rulecheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// Rule keeps source options separate from the destination selector. Runtime
// adapters should preserve Disabled and must not infer missing source options.
type Rule struct {
	Index     int      `json:"index"`
	Type      string   `json:"type"`
	Payload   string   `json:"payload,omitempty"`
	Policy    string   `json:"policy,omitempty"`
	Options   []string `json:"options,omitempty"`
	SourceIP  bool     `json:"source_ip,omitempty"`
	NoResolve bool     `json:"no_resolve,omitempty"`
	Opaque    bool     `json:"opaque,omitempty"`
	Invalid   string   `json:"invalid,omitempty"`
	Disabled  bool     `json:"disabled,omitempty"`
	Raw       string   `json:"raw,omitempty"`
}

// Parse accepts one raw scalar or one YAML string item. It only accepts the
// common quick-apply rule types, with optional no-resolve on destination CIDRs.
func Parse(raw string) (Rule, error) {
	value, err := scalar(raw)
	if err != nil {
		return Rule{}, err
	}
	r := parse(value, -1, false)
	if r.Invalid != "" {
		return Rule{}, errors.New(r.Invalid)
	}
	if r.Opaque {
		return Rule{}, fmt.Errorf("quick apply does not support rule type %q", r.Type)
	}
	if r.Type == "MATCH" || r.SourceIP {
		return Rule{}, errors.New("quick apply supports DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR and IP-CIDR6")
	}
	return r, nil
}

// ParseExisting reads a string already extracted from a rules sequence. Unknown
// kinds are opaque, not invalid: the installed core may support newer syntax.
func ParseExisting(raw string, index int) Rule { return parse(raw, index, true) }

func scalar(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return "", errors.New("supply one rule of at most 64 KiB")
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewBufferString(raw))
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 {
		return "", errors.New("supply one raw rule or one YAML string item")
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return "", errors.New("supply only one rule in one YAML document")
	}
	n := doc.Content[0]
	if n.Kind == yaml.SequenceNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", errors.New("supply one raw rule or one YAML string item")
	}
	return strings.TrimSpace(n.Value), nil
}

func parse(raw string, index int, existing bool) Rule {
	r := Rule{Index: index, Raw: raw}
	fail := func(message string) Rule { r.Invalid = message; return r }
	if strings.TrimSpace(raw) == "" || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return fail("rule must be nonempty and contain no control characters")
	}
	parts, balanced := split(raw)
	if len(parts) == 0 {
		return fail("rule is empty")
	}
	r.Type = strings.ToUpper(parts[0])
	if r.Type == "" {
		return fail("rule type must be nonempty")
	}
	common := r.Type == "DOMAIN" || r.Type == "DOMAIN-SUFFIX" || r.Type == "DOMAIN-KEYWORD" || r.Type == "IP-CIDR" || r.Type == "IP-CIDR6" || r.Type == "MATCH"
	if existing && r.Type == "SRC-IP-CIDR" {
		common, r.SourceIP, r.NoResolve = true, true, true
	}
	if !common {
		r.Opaque = true
		// Preserve familiar outer fields for policy counts and reference checks;
		// nested expressions and unknown syntax remain deliberately unvalidated.
		if balanced && len(parts) >= 3 {
			r.Payload, r.Policy = parts[1], parts[2]
			r.Options = append([]string(nil), parts[3:]...)
		}
		return r
	}
	if !balanced {
		return fail("rule contains unbalanced parentheses")
	}
	if r.Type == "MATCH" {
		if len(parts) != 2 {
			return fail("MATCH requires exactly one policy")
		}
		r.Policy = parts[1]
	} else {
		if len(parts) < 3 {
			return fail("rule requires type, payload and policy")
		}
		r.Payload, r.Policy = parts[1], parts[2]
		r.Options = append([]string(nil), parts[3:]...)
	}
	if r.Policy == "" || len(r.Policy) > 4096 {
		return fail("rule policy must be nonempty and at most 4096 bytes")
	}
	if r.Type == "MATCH" {
		return r
	}
	seen := map[string]bool{}
	for _, option := range r.Options {
		if option == "" || seen[option] {
			return fail("rule contains an empty or repeated modifier")
		}
		seen[option] = true
		ip := r.Type == "IP-CIDR" || r.Type == "IP-CIDR6" || r.Type == "SRC-IP-CIDR"
		switch {
		case option == "no-resolve" && ip:
			r.NoResolve = true
		case option == "src" && ip && existing:
			r.SourceIP = true
		case existing:
			// Future modifiers can change the matching semantics. Keep the rule
			// opaque rather than discarding them or asserting a false conflict.
			r.Opaque = true
		default:
			return fail("only optional no-resolve on IP-CIDR/IP-CIDR6 is supported")
		}
	}
	switch r.Type {
	case "DOMAIN", "DOMAIN-SUFFIX":
		if r.Payload == "" {
			return fail("domain rule requires a nonempty payload")
		}
		value, err := domain(r.Payload)
		if existing {
			// Mihomo's constructors lowercase the literal; they do not apply
			// DNS-label validation or strip a trailing dot. Strict new-input
			// normalization must not change the identity of an existing rule.
			r.Payload = strings.ToLower(r.Payload)
			if err != nil || value != r.Payload {
				r.Opaque = true
			}
		} else if err != nil {
			return fail(err.Error())
		} else {
			r.Payload = value
		}
	case "DOMAIN-KEYWORD":
		if r.Payload == "" {
			return fail("DOMAIN-KEYWORD requires a nonempty literal keyword")
		}
		r.Payload = strings.ToLower(r.Payload)
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR":
		prefix, err := netip.ParsePrefix(r.Payload)
		if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return fail("IP rule requires an IPv4/IPv6 CIDR without a zone or mapped address family")
		}
		r.Payload = prefix.Masked().String()
		r.Type = "IP-CIDR6"
		if prefix.Addr().Is4() {
			r.Type = "IP-CIDR"
		}
	}
	// Canonical option order, including equivalent SRC-IP-CIDR declarations.
	if !r.Opaque {
		r.Options = nil
		if r.NoResolve {
			r.Options = append(r.Options, "no-resolve")
		}
		if r.SourceIP {
			r.Options = append(r.Options, "src")
		}
	}
	return r
}

func domain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return "", errors.New("domain rule requires an ASCII DNS hostname, not an IP address or URL")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("domain rule contains an invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("domain rule requires ASCII DNS labels (use punycode for international names)")
			}
		}
	}
	return value, nil
}

func split(raw string) ([]string, bool) {
	var parts []string
	depth, start := 0, 0
	for i, char := range raw {
		switch char {
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

func (r Rule) String() string {
	if r.Opaque || r.Invalid != "" {
		return strings.TrimSpace(r.Raw)
	}
	parts := []string{r.Type, r.Payload, r.Policy}
	if r.Type == "MATCH" {
		parts = []string{r.Type, r.Policy}
	}
	return strings.Join(append(parts, r.Options...), ",")
}

// SelectorKey excludes policy and DNS-resolution behavior, but source and
// destination IPs are different selectors. Opaque/invalid rules have no key.
func (r Rule) SelectorKey() string {
	if r.Opaque || r.Invalid != "" || r.Type == "" {
		return ""
	}
	return fmt.Sprintf("%s\x00%s\x00%t", r.Type, r.Payload, r.SourceIP)
}

// Equal means the persistent rule is identical after safe canonicalization.
func (r Rule) Equal(other Rule) bool {
	key := r.SelectorKey()
	return key != "" && key == other.SelectorKey() && r.Policy == other.Policy && r.NoResolve == other.NoResolve && slices.Equal(r.Options, other.Options)
}
