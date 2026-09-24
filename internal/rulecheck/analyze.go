package rulecheck

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type Finding struct {
	Severity     string `json:"severity"`
	Code         string `json:"code"`
	Index        int    `json:"index"`
	RelatedIndex *int   `json:"related_index,omitempty"`
	Rule         string `json:"rule,omitempty"`
	RelatedRule  string `json:"related_rule,omitempty"`
	Message      string `json:"message"`
}

type Stats struct {
	Total    int            `json:"total"`
	Analyzed int            `json:"analyzed"`
	Opaque   int            `json:"opaque"`
	Invalid  int            `json:"invalid"`
	Disabled int            `json:"disabled"`
	ByType   map[string]int `json:"by_type"`
	ByPolicy map[string]int `json:"by_policy"`
}

type Report struct {
	Findings    []Finding `json:"findings"`
	Stats       Stats     `json:"stats"`
	Limitations []string  `json:"limitations"`
}

func (r Report) HasErrors() bool   { return r.hasSeverity("error") }
func (r Report) HasWarnings() bool { return r.hasSeverity("warning") }
func (r Report) hasSeverity(severity string) bool {
	for _, f := range r.Findings {
		if f.Severity == severity {
			return true
		}
	}
	return false
}

// Analyze interprets slice order as matching order, retaining each caller's
// Index for source/runtime attribution. A nil policies map means unavailable;
// a non-nil map is the complete set of known policy names.
func Analyze(rules []Rule, policies map[string]bool) Report {
	report := Report{Findings: []Finding{}, Stats: Stats{Total: len(rules), ByType: map[string]int{}, ByPolicy: map[string]int{}}, Limitations: []string{}}
	add := func(severity, code string, rule Rule, related *Rule, message string) {
		f := Finding{Severity: severity, Code: code, Index: rule.Index, Rule: rule.String(), Message: message}
		if related != nil {
			index := related.Index
			f.RelatedIndex = &index
			f.RelatedRule = related.String()
		}
		report.Findings = append(report.Findings, f)
	}
	opaqueKinds := map[string]bool{}
	selectors := map[string][]Rule{}
	active := make([]Rule, 0, len(rules))
	var fallback *Rule
	for _, rule := range rules {
		report.Stats.ByType[rule.Type]++
		if rule.Policy != "" {
			report.Stats.ByPolicy[rule.Policy]++
		}
		if rule.Disabled {
			report.Stats.Disabled++
		}
		if rule.Invalid != "" {
			report.Stats.Invalid++
			add("error", "invalid_syntax", rule, nil, rule.Invalid)
			continue
		}
		if rule.Opaque {
			report.Stats.Opaque++
			opaqueKinds[rule.Type] = true
		} else {
			report.Stats.Analyzed++
		}
		// A SUB-RULE target is a subrule name, not an outbound policy. Other
		// opaque grammars are not sufficiently parsed to assert missing names.
		if !rule.Opaque && policies != nil && !policies[rule.Policy] {
			add("error", "policy_missing", rule, nil, fmt.Sprintf("Policy %q does not exist on this target.", rule.Policy))
		}
		if rule.Disabled {
			continue
		}
		if fallback != nil {
			add("warning", "unreachable", rule, fallback, "An earlier MATCH makes this rule unreachable in ordinary first-match routing.")
		}
		if rule.Opaque {
			continue
		}
		key := rule.SelectorKey()
		previous := selectors[key]
		var conflict, duplicate, modifiers *Rule
		for i := range previous {
			p := &previous[i]
			switch {
			case p.Policy != rule.Policy && conflict == nil:
				conflict = p
			case p.Equal(rule) && duplicate == nil:
				duplicate = p
			case p.Policy == rule.Policy && !p.Equal(rule) && modifiers == nil:
				modifiers = p
			}
		}
		if conflict != nil {
			add("warning", "selector_conflict", rule, conflict, fmt.Sprintf("The same selector is declared with policies %q and %q; earlier matching rules take precedence.", conflict.Policy, rule.Policy))
		}
		if duplicate != nil {
			add("info", "duplicate", rule, duplicate, "An identical rule is already present earlier in this list.")
		}
		if modifiers != nil {
			add("warning", "overlap", rule, modifiers, "The same selector and policy use different DNS-resolution modifiers; these are not identical rules.")
		}
		// Keep one representative per action/options combination. Exact checks
		// still cover the whole list without quadratic duplicate comparisons.
		if duplicate == nil {
			selectors[key] = append(previous, rule)
		}
		if rule.Type == "MATCH" && rule.Policy != "PASS" && fallback == nil {
			copy := rule
			fallback = &copy
		}
		active = append(active, rule)
	}
	// Large provider-style rule lists must not turn health checks into an
	// unbounded quadratic operation. The exact-selector pass above is complete.
	const maxComparisons = 250000
	const maxOverlapFindings = 1000
	comparisons, overlapFindings := 0, 0
	limited := false
outer:
	for i, later := range active {
		for j := 0; j < i; j++ {
			earlier := active[j]
			if earlier.Type == "MATCH" || later.Type == "MATCH" || earlier.SelectorKey() == later.SelectorKey() {
				continue
			}
			if comparisons == maxComparisons || overlapFindings == maxOverlapFindings {
				limited = true
				break outer
			}
			comparisons++
			overlap, covered := relation(earlier, later)
			if !overlap {
				continue
			}
			overlapFindings++
			code, message := overlapDescription(earlier, later, covered)
			add("warning", code, later, &earlier, message)
		}
	}
	if limited {
		report.Limitations = append(report.Limitations, "Overlap analysis reached its size limit; exact selector and syntax checks still cover the complete list.")
	}
	if len(opaqueKinds) > 0 {
		kinds := make([]string, 0, len(opaqueKinds))
		for kind := range opaqueKinds {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		report.Limitations = append(report.Limitations, "Matching semantics or modifiers are not analyzed for: "+strings.Join(kinds, ", ")+". Provider contents, geodata and logical expressions are not expanded.")
	}
	report.Limitations = append(report.Limitations, "Only confirmed domain, keyword and CIDR relations are reported; absent findings do not prove disjointness. Static order does not prove application traffic, DNS state or UDP fallback behavior.")
	return report
}

func overlapDescription(earlier, later Rule, covered bool) (code, message string) {
	code, message = "overlap", "These selectors have a confirmed overlap; earlier matching rules take precedence."
	if earlier.Policy == "PASS" {
		message = "These selectors have a confirmed overlap; the earlier PASS action continues to later rules."
	} else if covered {
		code, message = "shadowed", "An earlier selector covers this selector; this rule may be shadowed in first-match routing."
	}
	if earlier.Policy == later.Policy {
		message += " Both select the same policy."
	} else {
		message += fmt.Sprintf(" Policies differ: %q then %q.", earlier.Policy, later.Policy)
	}
	return code, message
}

// relation only returns true for a provable intersection/containment. An
// unproven keyword relation is not evidence that the sets are disjoint.
func relation(earlier, later Rule) (overlap, covered bool) {
	if earlier.SourceIP != later.SourceIP {
		return false, false
	}
	if ipRule(earlier) && ipRule(later) {
		a, ea := netip.ParsePrefix(earlier.Payload)
		b, eb := netip.ParsePrefix(later.Payload)
		if ea != nil || eb != nil || a.Addr().BitLen() != b.Addr().BitLen() {
			return false, false
		}
		overlap = a.Contains(b.Addr()) || b.Contains(a.Addr())
		covered = a.Bits() <= b.Bits() && a.Contains(b.Addr())
		// A no-resolve rule can be bypassed before a destination IP is known.
		if earlier.NoResolve && !later.NoResolve && !earlier.SourceIP {
			covered = false
		}
		return overlap, covered
	}
	if !domainRule(earlier) || !domainRule(later) {
		return false, false
	}
	if earlier.Type == "DOMAIN" {
		return matchesDomain(later, earlier.Payload), later.Type == "DOMAIN" && later.Payload == earlier.Payload
	}
	if earlier.Type == "DOMAIN-SUFFIX" {
		switch later.Type {
		case "DOMAIN":
			v := hasSuffix(later.Payload, earlier.Payload)
			return v, v
		case "DOMAIN-SUFFIX":
			covered := hasSuffix(later.Payload, earlier.Payload)
			return covered || hasSuffix(earlier.Payload, later.Payload), covered
		case "DOMAIN-KEYWORD":
			return strings.Contains(earlier.Payload, later.Payload), false
		}
	}
	if earlier.Type == "DOMAIN-KEYWORD" {
		covered := strings.Contains(later.Payload, earlier.Payload)
		if later.Type == "DOMAIN-KEYWORD" {
			return covered || strings.Contains(earlier.Payload, later.Payload), covered
		}
		return covered, covered
	}
	return false, false
}

func ipRule(r Rule) bool { return r.Type == "IP-CIDR" || r.Type == "IP-CIDR6" }
func domainRule(r Rule) bool {
	return r.Type == "DOMAIN" || r.Type == "DOMAIN-SUFFIX" || r.Type == "DOMAIN-KEYWORD"
}
func hasSuffix(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}
func matchesDomain(rule Rule, domain string) bool {
	switch rule.Type {
	case "DOMAIN":
		return rule.Payload == domain
	case "DOMAIN-SUFFIX":
		return hasSuffix(domain, rule.Payload)
	case "DOMAIN-KEYWORD":
		return strings.Contains(domain, rule.Payload)
	}
	return false
}
