package rulecheck

import (
	"fmt"
	"sort"
	"strings"
)

// AnalyzeFocused checks only relations involving requested. A negative
// existingPosition models prepending it; otherwise that slice position must
// identify an active identical occurrence whose current position is retained.
// Unlike whole-list health analysis, a different policy for the requested
// selector is an error. Every existing rule is checked in linear time, even
// after the bounded warning output fills. Stats describe the requested rule.
func AnalyzeFocused(rules []Rule, requested Rule, existingPosition int, policies map[string]bool) Report {
	focus := requested
	focus.Index = -1
	if existingPosition >= 0 {
		if existingPosition >= len(rules) || rules[existingPosition].Disabled || !rules[existingPosition].Equal(requested) {
			return Report{Findings: []Finding{{Severity: "error", Code: "invalid_focus_position", Index: -1, Rule: requested.String(), Message: "The retained rule occurrence does not match the requested rule."}}}
		}
		focus = rules[existingPosition]
	}
	report := Analyze([]Rule{focus}, policies)
	if focus.Invalid != "" || focus.Opaque || focus.Disabled {
		return report
	}
	const maxRelatedFindings = 1000
	emitted, limited := 0, false
	add := func(severity, code string, later, earlier Rule, message string) {
		if severity != "error" {
			if emitted == maxRelatedFindings {
				limited = true
				return
			}
			emitted++
		}
		related := earlier.Index
		report.Findings = append(report.Findings, Finding{Severity: severity, Code: code, Index: later.Index, RelatedIndex: &related, Rule: later.String(), RelatedRule: earlier.String(), Message: message})
	}
	opaqueKinds := map[string]bool{}
	for position, old := range rules {
		if position == existingPosition || old.Disabled || old.Invalid != "" {
			continue
		}
		if old.Opaque {
			opaqueKinds[old.Type] = true
			continue
		}
		earlier, later := focus, old
		if existingPosition >= 0 && position < existingPosition {
			earlier, later = old, focus
		}
		if old.SelectorKey() == focus.SelectorKey() {
			switch {
			case old.Policy != focus.Policy:
				add("error", "selector_conflict", later, earlier, fmt.Sprintf("The requested policy %q differs from existing policy %q for the same selector; resolve this conflict before applying.", focus.Policy, old.Policy))
			case old.Equal(focus):
				add("info", "duplicate", later, earlier, "An identical rule is already present in this list.")
			default:
				add("warning", "overlap", later, earlier, "The same selector and policy use different DNS-resolution modifiers; these are not identical rules.")
			}
			continue
		}
		if earlier.Type == "MATCH" {
			if earlier.Policy != "PASS" {
				add("warning", "unreachable", later, earlier, "An earlier MATCH makes this rule unreachable in ordinary first-match routing.")
			}
			continue
		}
		if later.Type == "MATCH" {
			continue
		}
		overlap, covered := relation(earlier, later)
		if !overlap {
			continue
		}
		code, message := overlapDescription(earlier, later, covered)
		add("warning", code, later, earlier, message)
	}
	if limited {
		report.Limitations = append(report.Limitations, "Related warning output reached its size limit; every requested-selector conflict was still checked and reported.")
	}
	if len(opaqueKinds) > 0 {
		kinds := make([]string, 0, len(opaqueKinds))
		for kind := range opaqueKinds {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		report.Limitations = append(report.Limitations, "Relations to opaque rules are unknown for: "+strings.Join(kinds, ", ")+". Provider contents, geodata and logical expressions are not expanded.")
	}
	return report
}
