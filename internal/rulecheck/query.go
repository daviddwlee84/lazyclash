package rulecheck

import (
	"errors"
	"strings"
	"unicode"
)

type FindMatch struct {
	Entry       Entry    `json:"entry"`
	Kind        string   `json:"kind"`
	Differences []string `json:"differences,omitempty"`
}

type FindReport struct {
	Found       bool        `json:"found"`
	Matches     []FindMatch `json:"matches"`
	Limitations []string    `json:"limitations"`
}

// ParseQuery preserves an existing rule's literal semantics. Unlike Parse, it
// never strips a trailing domain dot and accepts opaque existing rule kinds.
func ParseQuery(raw string) (Rule, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return Rule{}, errors.New("supply one rule of at most 64 KiB")
	}
	value := strings.TrimSpace(raw)
	head, _, comma := strings.Cut(value, ",")
	if comma && queryTypeToken(strings.TrimSpace(head)) {
		// A raw TYPE,... expression is not YAML. In particular, ': ' and
		// ' # ' can be literal regex text, not a mapping or comment marker.
		if strings.IndexFunc(raw, unicode.IsControl) >= 0 {
			return Rule{}, errors.New("raw query must be one line without control characters")
		}
		return parseQueryValue(value)
	}
	value, err := scalar(raw)
	if err != nil {
		return Rule{}, err
	}
	return parseQueryValue(value)
}

// parseQueryValue operates on an already-extracted scalar. Source readers must
// not decode it as YAML again: literal '#', ':' and quotes belong to the rule.
func parseQueryValue(value string) (Rule, error) {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return Rule{}, errors.New("query must contain no control characters")
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	kind := strings.ToUpper(parts[0])
	if kind == "" {
		return Rule{}, errors.New("query rule type must be nonempty")
	}
	if !queryTypeToken(kind) {
		return Rule{}, errors.New("query rule type contains invalid characters")
	}
	if commonQueryKind(kind) {
		rule := ParseExisting(value, -1)
		if rule.Invalid != "" {
			return Rule{}, errors.New(rule.Invalid)
		}
		return rule, nil
	}
	if len(parts) < 3 || parts[len(parts)-1] == "" || strings.Join(parts[1:len(parts)-1], ",") == "" {
		return Rule{}, errors.New("query requires one rule with a type, payload and policy (MATCH uses only a policy)")
	}
	rule := Rule{Index: -1, Type: kind, Raw: value, Opaque: true}
	canonicalKind := reportedKind(kind)
	if commaPayloadKind(canonicalKind) {
		// Mihomo ParseRulePayload defines these kinds without params: target
		// is the final field, and the whole middle is the payload. Parentheses
		// and commas inside regexes must not truncate either exposed field.
		if logicalKind(canonicalKind) {
			if _, balanced := split(value); !balanced {
				return Rule{}, errors.New("logical query contains unbalanced parentheses")
			}
		}
		rule.Payload = strings.Join(parts[1:len(parts)-1], ",")
		rule.Policy = parts[len(parts)-1]
		return rule, nil
	}
	if flatQueryKind(canonicalKind) {
		if parts[1] == "" || parts[2] == "" {
			return Rule{}, errors.New("query requires a nonempty payload and policy")
		}
		rule.Payload, rule.Policy = parts[1], parts[2]
		rule.Options = append([]string(nil), parts[3:]...)
		return rule, nil
	}
	// New core kinds can introduce their own delimiter/parameter grammar.
	// Preserve the full expression, without manufacturing a selector/policy.
	rule.LiteralOnly = true
	return rule, nil
}

func queryTypeToken(kind string) bool {
	if kind == "" || !(kind[0] >= 'A' && kind[0] <= 'Z' || kind[0] >= 'a' && kind[0] <= 'z') {
		return false
	}
	for _, c := range kind {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func logicalKind(kind string) bool {
	return kind == "AND" || kind == "OR" || kind == "NOT" || kind == "SUB-RULE"
}

func commonQueryKind(kind string) bool {
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "MATCH":
		return true
	}
	return false
}

func commaPayloadKind(kind string) bool {
	return logicalKind(kind) || kind == "DOMAIN-REGEX" || kind == "PROCESS-NAME-REGEX" || kind == "PROCESS-PATH-REGEX"
}

func flatQueryKind(kind string) bool {
	switch kind {
	case "DOMAIN-WILDCARD", "GEOSITE", "GEOIP", "SRC-GEOIP", "IP-ASN", "SRC-IP-ASN", "IP-SUFFIX", "SRC-IP-SUFFIX", "SRC-PORT", "DST-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD", "REMATCH-NAME", "UID", "NETWORK", "DSCP", "RULE-SET":
		return true
	}
	return false
}

// FindEntries returns every full match and same-selector alternative. Found
// means the requested declaration is present; disabled is reported separately
// on each entry and does not make an existing declaration absent.
func FindEntries(entries []Entry, query Rule, reported bool) FindReport {
	report := FindReport{Matches: []FindMatch{}, Limitations: comparisonLimits(reported)}
	if query.Opaque && !reported {
		report.Limitations = append(report.Limitations, "The query has opaque semantics; source matching is literal and does not infer selector alternatives.")
	}
	if query.LiteralOnly {
		report.Limitations = append(report.Limitations, "The query's outer grammar is unknown; only the full serialized expression is compared, without inferring payload, policy or selector alternatives.")
	}
	for _, entry := range entries {
		if entry.Section == "delete" {
			continue
		}
		rule := entry.Rule
		key, wanted := selectorKey(rule, reported), selectorKey(query, reported)
		if key == "" || wanted == "" {
			if strings.TrimSpace(rule.Raw) != "" && literalExpressionKey(rule, reported) == literalExpressionKey(query, reported) {
				report.Found = true
				kind := "literal"
				if reported {
					kind = "reported_literal"
				}
				report.Matches = append(report.Matches, FindMatch{Entry: *copyEntry(entry), Kind: kind})
			}
			continue
		}
		if key != wanted {
			continue
		}
		// Enabled state is evidence about use, not part of the requested rule
		// text. Only policy/options distinguish alternatives for this query.
		requested := query
		requested.Disabled = rule.Disabled
		fields := differences(rule, requested, reported)
		kind := "same_selector"
		if len(fields) == 0 {
			report.Found = true
			kind = "exact"
			if reported {
				kind = "reported"
			}
		}
		report.Matches = append(report.Matches, FindMatch{Entry: *copyEntry(entry), Kind: kind, Differences: fields})
	}
	return report
}
