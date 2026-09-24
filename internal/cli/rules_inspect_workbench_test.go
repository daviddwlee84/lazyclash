package cli

import (
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
)

func inspectionEntry(section, raw string, index int) rulecheck.Entry {
	return rulecheck.Entry{Section: section, Rule: rulecheck.ParseExisting(raw, index)}
}

func TestRuleDiffWorkbenchKeepsScopesAvailabilityAndChanges(t *testing.T) {
	left := inspectionEntry("rules", "DOMAIN,example.com,DIRECT", 0)
	right := inspectionEntry("rules", "DOMAIN,example.com,PROXY", 2)
	report := rulework.RuleDiffReport{Status: "partial", Scope: "both", Baseline: rulework.RuleTargetInfo{TargetID: "base", ObservedAt: "base-time"}, Targets: []rulework.TargetRuleDiff{{
		Target:  rulework.RuleTargetInfo{TargetID: "other", ObservedAt: "target-time", SourceBinding: "config_source"},
		Runtime: &rulework.RuleLayerDiff{Status: "available", LeftShape: "complete", RightShape: "complete", Result: &rulecheck.DiffReport{Changes: []rulecheck.RuleChange{{Kind: "changed", Left: &left, Right: &right, Fields: []string{"policy", "order"}}}, Limitations: []string{"Runtime options are not exposed"}}},
		Source:  &rulework.RuleLayerDiff{Status: "unavailable", Message: "source unbound"},
	}}}
	result := ruleDiffWorkbench(report)
	if result.Apply != nil || len(result.Rows) != 2 || result.Rows[0].ID != "other:runtime" || result.Rows[1].ID != "other:source" || !strings.Contains(result.Summary, "Incomplete") {
		t.Fatalf("unsafe or incomplete result: %+v", result)
	}
	for _, text := range []string{"base-time", "target-time", "DOMAIN,example.com,DIRECT", "DOMAIN,example.com,PROXY", "policy, order", "Runtime options are not exposed"} {
		if !strings.Contains(result.Rows[0].Detail, text) {
			t.Fatalf("comparison omitted %q", text)
		}
	}
	if !strings.Contains(result.Rows[1].Detail, "source unbound") || strings.Contains(result.Rows[1].Label, "equal") {
		t.Fatal("missing source became equality")
	}
}

func TestRuleFindWorkbenchShowsDisabledMatchesAndAlternatives(t *testing.T) {
	entry := inspectionEntry("prepend", "DOMAIN,example.com,DIRECT", 3)
	entry.Rule.Disabled = true
	other := inspectionEntry("append", "DOMAIN,example.com,PROXY", 1)
	report := rulework.RuleFindReport{Status: "completed", Scope: "source", Complete: true, Query: "DOMAIN,example.com,DIRECT", Targets: []rulework.TargetRuleFind{{Target: rulework.RuleTargetInfo{TargetID: "test"}, Source: &rulework.RuleLayerFind{Status: "available", Shape: "verge-companion", Result: &rulecheck.FindReport{Found: true, Matches: []rulecheck.FindMatch{{Entry: entry, Kind: "exact"}, {Entry: other, Kind: "selector", Differences: []string{"policy"}}}, Limitations: []string{"Source composition is incomplete"}}}}}}
	result := ruleFindWorkbench(report)
	if result.Apply != nil || len(result.Rows) != 1 || !strings.Contains(result.Rows[0].Label, "found") {
		t.Fatal("find result lost matching declaration")
	}
	for _, text := range []string{"prepend #4 [disabled]", "append #2", "Different: policy", "Source composition is incomplete"} {
		if !strings.Contains(result.Rows[0].Detail, text) {
			t.Fatalf("find omitted %q", text)
		}
	}
}

func TestRuleLookupWorkbenchDoesNotInventWinnerAfterUnknown(t *testing.T) {
	opaque := inspectionEntry("rules", "RULE-SET,remote,PROXY", 0)
	later := inspectionEntry("rules", "DOMAIN,example.com,DIRECT", 1)
	report := rulework.RuleLookupReport{Status: "completed", Scope: "runtime", Complete: true, Input: rulecheck.LookupInput{Kind: "domain", Value: "example.com"}, Targets: []rulework.TargetRuleLookup{{Target: rulework.RuleTargetInfo{TargetID: "test", Mode: "rule"}, Runtime: &rulework.RuleLayerLookup{Status: "available", Result: &rulecheck.LookupReport{Status: "unknown", Steps: []rulecheck.LookupStep{{Entry: opaque, Outcome: "unknown", Reason: "provider content unknown"}, {Entry: later, Outcome: "match", Reason: "selector matches"}}, Limitations: []string{"Earlier unknown rule may win"}}}}}}
	result := ruleLookupWorkbench(report)
	if result.Apply != nil || len(result.Rows) != 1 || !strings.Contains(result.Rows[0].Label, "unknown") || strings.Contains(result.Rows[0].Detail, "First static candidate:") {
		t.Fatal("lookup invented a conclusive candidate")
	}
	for _, text := range []string{"provider content unknown", "Earlier unknown rule may win", "DOMAIN,example.com,DIRECT"} {
		if !strings.Contains(result.Rows[0].Detail, text) {
			t.Fatalf("lookup omitted %q", text)
		}
	}
	if !strings.Contains(result.Summary, "No traffic or DNS requests") {
		t.Fatal("lookup did not state static evidence")
	}
}

func TestRuleHealthWorkbenchShowsStructuredDrift(t *testing.T) {
	left := inspectionEntry("rules", "DOMAIN,example.com,DIRECT", 0)
	right := inspectionEntry("rules", "DOMAIN,example.com,PROXY", 1)
	report := rulework.HealthReport{Status: "completed", Targets: []rulework.TargetHealth{{TargetID: "test", Snapshot: &rulework.RulesSnapshot{SourceBinding: "config_source", Source: &rulework.RulesView{Status: "available"}, Runtime: &rulework.RulesView{Status: "available"}}, Drift: &rulecheck.DiffReport{Changes: []rulecheck.RuleChange{{Kind: "changed", Left: &left, Right: &right, Fields: []string{"policy"}}}}}}}
	result := ruleHealthResult(report)
	for _, text := range []string{"Source binding: config_source", "Source snapshot: available", "runtime (+) drift", "DOMAIN,example.com,PROXY"} {
		if len(result.Rows) != 1 || !strings.Contains(result.Rows[0].Detail, text) {
			t.Fatalf("healthcheck omitted %q", text)
		}
	}
}
