package rulework

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"go.yaml.in/yaml/v3"
)

// Healthcheck observes source and runtime separately. It never refreshes
// providers, evaluates scripts, reloads owners or generates test traffic.
func Healthcheck(ctx context.Context, targets []config.Target, all bool, opts Options) (HealthReport, error) {
	report := HealthReport{Status: "completed", Targets: []TargetHealth{}}
	items, err := quickTargets(targets, all)
	if err != nil {
		return report, err
	}
	usable, hasErrors := 0, false
	for _, t := range items {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		h := healthTarget(ctx, t, opts)
		report.Targets = append(report.Targets, h)
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if h.Runtime != nil || h.Source != nil {
			usable++
		}
		if h.Status == "errors" {
			hasErrors = true
		}
		if h.Status == "skipped_unavailable" || h.Status == "partial" {
			report.Status = "completed_with_skips"
		}
	}
	if hasErrors {
		report.Status = "errors"
		return report, errors.New("rule healthcheck found errors; inspect findings")
	}
	if usable == 0 {
		report.Status = "unavailable"
		return report, errors.New("no selected target could be inspected")
	}
	return report, nil
}

func healthTarget(ctx context.Context, t config.Target, opts Options) TargetHealth {
	snapshot, _ := ReadRulesSnapshot(ctx, t, "both", opts)
	h := TargetHealth{TargetID: t.ID, Status: "checked", ObservedAt: snapshot.ObservedAt, Owner: snapshot.Owner, Mode: snapshot.Mode, Providers: snapshot.Providers, Snapshot: &snapshot, Findings: []rulecheck.Finding{}}
	h.Limitations = append(h.Limitations, snapshot.Limitations...)
	if snapshot.Source != nil {
		h.Limitations = append(h.Limitations, snapshot.Source.Limitations...)
		if snapshot.Source.Status == "available" {
			rules := activeSnapshotRules(snapshot.Source.Entries)
			report := rulecheck.Analyze(rules, snapshot.Policies)
			if snapshot.source != nil {
				report.Findings = append(report.Findings, sourceReferenceFindings(*snapshot.source, rules, snapshot.Policies)...)
			}
			h.Source = &report
			for _, warning := range snapshot.Owner.Warnings {
				h.Findings = append(h.Findings, finding("warning", "owner_context", warning))
			}
		} else if snapshot.Source.Status == "error" {
			h.Findings = append(h.Findings, finding("error", "source_unavailable", snapshot.Source.Message))
		} else if snapshot.SourceBinding != "" {
			h.Status = "partial"
			h.Findings = append(h.Findings, finding("warning", "source_unavailable", snapshot.Source.Message))
		}
	}
	if snapshot.Runtime != nil {
		h.Limitations = append(h.Limitations, snapshot.Runtime.Limitations...)
		if snapshot.Runtime.Status == "available" {
			report := rulecheck.Analyze(activeSnapshotRules(snapshot.Runtime.Entries), snapshot.Policies)
			h.Runtime = &report
		} else {
			h.Message = snapshot.Runtime.Message
			h.Status = "partial"
			if snapshot.Runtime.Status == "error" {
				h.Findings = append(h.Findings, finding("error", "invalid_runtime", snapshot.Runtime.Message))
			}
		}
	}
	if snapshot.Source != nil && snapshot.Runtime != nil && snapshot.Source.Status == "available" && snapshot.Runtime.Status == "available" {
		drift := snapshotDrift(snapshot)
		h.Drift = &drift
		h.Limitations = append(h.Limitations, drift.Limitations...)
		for _, change := range drift.Changes {
			index := -1
			if change.Left != nil {
				index = change.Left.Rule.Index
			}
			message := "Source/runtime rule difference: " + change.Kind
			if change.Kind == "removed" {
				message = "Declared in the inspected source but not present in runtime"
			}
			if change.Kind == "added" {
				message = "Present in runtime but not declared in the inspected source"
			}
			if change.Left != nil {
				message += ": " + change.Left.Rule.String()
			} else if change.Right != nil {
				message += ": " + change.Right.Rule.String()
			}
			if len(change.Fields) > 0 {
				message += " (" + strings.Join(change.Fields, ", ") + ")"
			}
			f := rulecheck.Finding{Severity: "warning", Code: "source_runtime_drift", Index: index, Message: message}
			if change.Left != nil {
				f.Rule = change.Left.Rule.String()
			}
			if change.Right != nil {
				if change.Left == nil {
					f.Rule = change.Right.Rule.String()
					f.Index = change.Right.Rule.Index
				} else {
					related := change.Right.Rule.Index
					f.RelatedIndex = &related
					f.RelatedRule = change.Right.Rule.String()
				}
			}
			h.Findings = append(h.Findings, f)
		}
	}
	if h.Mode != "" && h.Mode != "rule" {
		h.Findings = append(h.Findings, finding("warning", "runtime_mode", "Runtime mode is "+h.Mode+"; routing rules may not determine traffic."))
	}
	return finalizeHealth(h)
}

func activeSnapshotRules(entries []rulecheck.Entry) []rulecheck.Rule {
	rules := []rulecheck.Rule{}
	for _, entry := range entries {
		if entry.Section == "delete" {
			continue
		}
		rule := entry.Rule
		rule.Index = len(rules)
		rules = append(rules, rule)
	}
	return rules
}

func snapshotDrift(snapshot RulesSnapshot) rulecheck.DiffReport {
	project := func(entries []rulecheck.Entry) []rulecheck.Entry {
		out := []rulecheck.Entry{}
		for _, entry := range entries {
			if entry.Section == "delete" {
				continue
			}
			entry.Section = "rules"
			out = append(out, entry)
		}
		return out
	}
	left, right := project(snapshot.Source.Entries), project(snapshot.Runtime.Entries)
	if snapshot.Source.Shape != "verge-companion" {
		return rulecheck.CompareEntries(left, right, true)
	}
	// A companion owns declarations inserted around an otherwise unknown base.
	// Match only those declarations, preserving multiplicity and ignoring normal
	// runtime baseline additions and source/runtime absolute index differences.
	selected := []rulecheck.Entry{}
	used := make([]bool, len(right))
	for _, want := range left {
		match := -1
		for j, actual := range right {
			if !used[j] && sameSnapshotSelector(want.Rule, actual.Rule) && want.Rule.Policy == actual.Rule.Policy && want.Rule.Disabled == actual.Rule.Disabled {
				match = j
				break
			}
		}
		if match < 0 {
			for j, actual := range right {
				if !used[j] && sameSnapshotSelector(want.Rule, actual.Rule) {
					match = j
					break
				}
			}
		}
		if match >= 0 {
			used[match] = true
			selected = append(selected, right[match])
		}
	}
	report := rulecheck.CompareEntries(left, selected, true)
	// Presence checks cannot establish the complete native ordering of a Verge
	// profile; absolute baseline offsets must not be reported as moved rules.
	filtered := report.Changes[:0]
	for _, change := range report.Changes {
		if change.Kind != "moved" {
			filtered = append(filtered, change)
		}
	}
	report.Changes = filtered
	report.Equal = len(report.Changes) == 0
	report.Limitations = append(report.Limitations, "Verge drift checks only declared active companion entries; runtime baseline additions, delete directives and complete profile/Merge/Script ordering are not compared.")
	return report
}

func sameSnapshotSelector(a, b rulecheck.Rule) bool {
	// Keep the same known aliases and literal-only boundary as exact queries.
	// Empty opaque selector fields are never evidence that two rules match.
	report := rulecheck.FindEntries([]rulecheck.Entry{{Section: "rules", Rule: b}}, a, true)
	return len(report.Matches) > 0
}

// These references have a known flat grammar even though the provider/geodata
// matching contents remain opaque. Verge companion files do not own providers.
func sourceReferenceFindings(source Source, rules []rulecheck.Rule, policies map[string]bool) []rulecheck.Finding {
	var out []rulecheck.Finding
	providers := map[string]bool{}
	if source.Kind != "verge" {
		doc, err := decodeYAML(source.file.Data)
		if err != nil {
			return out
		}
		if n := mappingValue(doc.Content[0], "rule-providers"); n != nil && n.Tag != "!!null" {
			if n.Kind != yaml.MappingNode {
				return []rulecheck.Finding{finding("error", "invalid_providers", "rule-providers must be a YAML mapping")}
			}
			for i := 0; i+1 < len(n.Content); i += 2 {
				providers[n.Content[i].Value] = true
			}
		}
	}
	for _, r := range rules {
		if r.Invalid != "" || r.Disabled {
			continue
		}
		if r.Type == "RULE-SET" && r.Payload != "" && source.Kind != "verge" && !providers[r.Payload] {
			out = append(out, rulecheck.Finding{Severity: "error", Code: "provider_missing", Index: r.Index, Rule: r.String(), Message: "Rule provider is not declared in this source: " + r.Payload})
		}
		if r.Opaque && (r.Type == "RULE-SET" || r.Type == "GEOSITE" || r.Type == "GEOIP") && r.Policy != "" && policies != nil && !policies[r.Policy] {
			out = append(out, rulecheck.Finding{Severity: "error", Code: "policy_missing", Index: r.Index, Rule: r.String(), Message: "Rule policy is unavailable on this target: " + r.Policy})
		}
	}
	return out
}

func finalizeHealth(h TargetHealth) TargetHealth {
	for _, f := range h.Findings {
		if f.Severity == "error" {
			h.Status = "errors"
		}
	}
	if h.Source != nil && h.Source.HasErrors() || h.Runtime != nil && h.Runtime.HasErrors() {
		h.Status = "errors"
	}
	if h.Source == nil && h.Runtime == nil && h.Status != "errors" {
		h.Status = "skipped_unavailable"
	}
	return h
}

// Summary functions are shared by CLI and embedded TUI workbench adapters.
func FormatQuickPlan(p QuickPlan) string {
	text := fmt.Sprintf("Rule: %s\nStatus: %s\nDigest: %s\n", p.Rule, p.Status, p.Digest)
	for _, t := range p.Targets {
		text += fmt.Sprintf("\n%s: %s\n", t.TargetID, t.Status)
		if t.ReasonCode != "" {
			text += "Reason: " + t.ReasonCode + "\n"
		}
		if t.Owner != nil {
			text += "Source: " + t.Owner.File + " (" + t.Owner.Kind + ")\n"
		}
		if t.Diff != "" {
			text += t.Diff + "\n"
		}
		if t.Message != "" {
			text += t.Message + "\n"
		}
		for _, command := range t.NextCommands {
			text += "Next: " + command + "\n"
		}
		for _, f := range t.Findings {
			where := ""
			if f.Index >= 0 {
				where = fmt.Sprintf(" rule #%d", f.Index+1)
			} else if f.Rule != "" {
				where = " proposed rule"
			}
			text += fmt.Sprintf("  %s [%s]%s: %s\n", f.Severity, f.Code, where, f.Message)
			if f.Rule != "" {
				text += "    " + f.Rule + "\n"
			}
			if f.RelatedRule != "" {
				label := "Proposed rule"
				if f.RelatedIndex != nil && *f.RelatedIndex >= 0 {
					label = fmt.Sprintf("Related rule #%d", *f.RelatedIndex+1)
				}
				text += fmt.Sprintf("    %s: %s\n", label, f.RelatedRule)
			}
		}
		for _, l := range t.Limitations {
			text += "  Analysis limit: " + l + "\n"
		}
	}
	return text
}
