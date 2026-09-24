package rulecheck

import (
	"fmt"
	"strings"
	"testing"
)

func parsed(lines ...string) []Rule {
	rules := make([]Rule, len(lines))
	for i, line := range lines {
		rules[i] = ParseExisting(line, i)
	}
	return rules
}

func finding(report Report, code string, index int) *Finding {
	for i := range report.Findings {
		f := &report.Findings[i]
		if f.Code == code && f.Index == index {
			return f
		}
	}
	return nil
}

func TestDuplicatesDoNotHideSelectorConflict(t *testing.T) {
	r := Analyze(parsed("DOMAIN,EXAMPLE.COM,DIRECT", "DOMAIN,example.com,DIRECT", "DOMAIN,example.com,PROXY"), map[string]bool{"DIRECT": true, "PROXY": true})
	if r.HasErrors() || !r.HasWarnings() || finding(r, "duplicate", 1) == nil || finding(r, "selector_conflict", 2) == nil {
		t.Fatalf("duplicate masked contradictory selector: %+v", r)
	}
	if got := finding(r, "selector_conflict", 2); got.RelatedIndex == nil || *got.RelatedIndex != 0 || got.Severity != "warning" || got.Rule != "DOMAIN,example.com,PROXY" || got.RelatedRule != "DOMAIN,example.com,DIRECT" {
		t.Fatalf("conflict lacks earlier evidence: %+v", got)
	}
}

func TestModifierAndAddressFamilyIdentity(t *testing.T) {
	r := Analyze(parsed(
		"IP-CIDR,2001:db8::1/64,DIRECT",
		"IP-CIDR6,2001:db8::/64,DIRECT,no-resolve",
		"IP-CIDR,2001:db8::/64,PROXY,no-resolve",
		"SRC-IP-CIDR,2001:db8::/64,OTHER",
	), nil)
	if finding(r, "overlap", 1) == nil || finding(r, "selector_conflict", 2) == nil || finding(r, "selector_conflict", 3) != nil || finding(r, "duplicate", 1) != nil {
		t.Fatalf("flags/family/source identity incorrect: %+v", r)
	}
}

func TestConfirmedOverlapAndOrderedShadow(t *testing.T) {
	for _, tc := range []struct {
		name, earlier, later, want string
	}{
		{"suffix covers exact", "DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN,api.example.com,PROXY", "shadowed"},
		{"suffix covers suffix", "DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN-SUFFIX,api.example.com,PROXY", "shadowed"},
		{"exact overlaps suffix", "DOMAIN,api.example.com,DIRECT", "DOMAIN-SUFFIX,example.com,PROXY", "overlap"},
		{"suffix boundary", "DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN,evil-example.com,PROXY", ""},
		{"suffix unrelated", "DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN,example.com.evil,PROXY", ""},
		{"keyword covers exact", "DOMAIN-KEYWORD,github,DIRECT", "DOMAIN,api.github.com,PROXY", "shadowed"},
		{"keyword covers suffix", "DOMAIN-KEYWORD,github,DIRECT", "DOMAIN-SUFFIX,github.com,PROXY", "shadowed"},
		{"keyword covers keyword", "DOMAIN-KEYWORD,git,DIRECT", "DOMAIN-KEYWORD,github,PROXY", "shadowed"},
		{"keyword contained", "DOMAIN-KEYWORD,github,DIRECT", "DOMAIN-KEYWORD,git,PROXY", "overlap"},
		{"keyword unproven", "DOMAIN-KEYWORD,api,DIRECT", "DOMAIN-SUFFIX,example.com,PROXY", ""},
		{"CIDR covers", "IP-CIDR,192.0.2.0/24,DIRECT", "IP-CIDR,192.0.2.7/32,PROXY", "shadowed"},
		{"CIDR partial", "IP-CIDR,192.0.2.7/32,DIRECT", "IP-CIDR,192.0.2.0/24,PROXY", "overlap"},
		{"CIDR disjoint", "IP-CIDR,192.0.2.0/25,DIRECT", "IP-CIDR,192.0.2.128/25,PROXY", ""},
		{"CIDR address families", "IP-CIDR,192.0.2.0/24,DIRECT", "IP-CIDR6,2001:db8::/32,PROXY", ""},
		{"noresolve not full shadow", "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", "IP-CIDR,192.0.2.7/32,PROXY", "overlap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(parsed(tc.earlier, tc.later), nil)
			if r.HasErrors() {
				t.Fatalf("overlap became hard error: %+v", r)
			}
			if tc.want == "" {
				if r.HasWarnings() {
					t.Fatalf("invented overlap: %+v", r)
				}
			} else if got := finding(r, tc.want, 1); got == nil || got.RelatedIndex == nil || *got.RelatedIndex != 0 || got.Severity != "warning" {
				t.Fatalf("missing confirmed relation %q: %+v", tc.want, r)
			}
		})
	}
}

func TestDisabledRuleDoesNotShadowOrConflict(t *testing.T) {
	rules := parsed("DOMAIN-SUFFIX,example.com,PROXY", "DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN,api.example.com,DIRECT")
	rules[0].Disabled = true
	r := Analyze(rules, nil)
	if r.HasErrors() || finding(r, "selector_conflict", 1) != nil {
		t.Fatalf("disabled rule conflicts: %+v", r)
	}
	for _, f := range r.Findings {
		if f.RelatedIndex != nil && *f.RelatedIndex == 0 {
			t.Fatalf("disabled rule shadows: %+v", f)
		}
	}
	if r.Stats.Disabled != 1 || finding(r, "shadowed", 2) == nil {
		t.Fatalf("active rule/count lost: %+v", r)
	}
}

func TestPASSIsNonterminalButRetainsSelectorConflict(t *testing.T) {
	r := Analyze(parsed("MATCH,PASS", "DOMAIN-SUFFIX,example.com,PASS", "DOMAIN,api.example.com,DIRECT"), nil)
	if r.HasErrors() || finding(r, "unreachable", 1) != nil || finding(r, "unreachable", 2) != nil || finding(r, "shadowed", 2) != nil {
		t.Fatalf("PASS incorrectly terminates rule evaluation: %+v", r)
	}
	if f := finding(r, "overlap", 2); f == nil || !strings.Contains(f.Message, "PASS action continues") {
		t.Fatalf("PASS overlap lacks action semantics: %+v", r)
	}
	conflict := Analyze(parsed("DOMAIN,example.com,PASS", "DOMAIN,example.com,DIRECT"), nil)
	if finding(conflict, "selector_conflict", 1) == nil {
		t.Fatal("PASS unexpectedly bypassed the user's exact-selector policy conflict rule")
	}
}

func TestFallbackOpaqueCoverageAndPolicyChecks(t *testing.T) {
	r := Analyze(parsed("RULE-SET,remote,PROXY", "DOMAIN,example.com,MISSING", "MATCH,DIRECT", "GEOSITE,cn,DIRECT", "DOMAIN,invalid"), map[string]bool{"DIRECT": true, "PROXY": true})
	if !r.HasErrors() || !r.HasWarnings() || finding(r, "policy_missing", 1) == nil || finding(r, "unreachable", 3) == nil || finding(r, "invalid_syntax", 4) == nil {
		t.Fatalf("health findings incomplete: %+v", r)
	}
	if r.Stats.Total != 5 || r.Stats.Analyzed != 2 || r.Stats.Opaque != 2 || r.Stats.Invalid != 1 || r.Stats.ByType["MATCH"] != 1 || r.Stats.ByPolicy["DIRECT"] != 2 {
		t.Fatalf("coverage counts misleading: %+v", r.Stats)
	}
	if !strings.Contains(strings.Join(r.Limitations, " "), "GEOSITE, RULE-SET") {
		t.Fatalf("opaque matcher scope hidden: %+v", r.Limitations)
	}
	if r := Analyze(parsed("DOMAIN,example.com,DIRECT", "MATCH,PROXY"), nil); r.HasWarnings() || r.HasErrors() {
		t.Fatalf("normal final fallback was flagged as overlap: %+v", r)
	}
}

func TestCandidateIndexAndCompleteConflictCheckAfterOverlapLimit(t *testing.T) {
	rules := make([]Rule, 0, 800)
	candidate, err := Parse("DOMAIN,existing.example,DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	rules = append(rules, candidate)
	for i := 0; i < 750; i++ {
		rules = append(rules, ParseExisting(fmt.Sprintf("DOMAIN,h%d.example,DIRECT", i), i))
	}
	rules = append(rules, ParseExisting("DOMAIN,existing.example,PROXY", 900))
	r := Analyze(rules, nil)
	f := finding(r, "selector_conflict", 900)
	if f == nil || f.RelatedIndex == nil || *f.RelatedIndex != -1 {
		t.Fatalf("bounded overlap lost full conflict scan or candidate index: %+v", f)
	}
	if !strings.Contains(strings.Join(r.Limitations, " "), "size limit") {
		t.Fatal("bounded overlap did not report incomplete analysis")
	}
}
