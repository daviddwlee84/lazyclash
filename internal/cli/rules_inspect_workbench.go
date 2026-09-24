package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
)

func (o *options) runRuleInspectWorkbench(ctx context.Context, req tui.WorkRequest) (tui.WorkResult, error) {
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	opts := o.ruleOptions(cmd)
	opts.ReadOnly = true
	switch req.Kind {
	case "rule-diff":
		report, err := rulework.DiffRules(ctx, req.Target, req.Targets, req.Scope, opts)
		return ruleDiffWorkbench(report), err
	case "rule-find":
		report, err := rulework.FindRules(ctx, req.Targets, req.Query, req.Scope, opts)
		return ruleFindWorkbench(report), err
	case "rule-lookup":
		report, err := rulework.LookupRules(ctx, req.Targets, req.Query, req.Scope, opts)
		return ruleLookupWorkbench(report), err
	}
	return tui.WorkResult{}, usage("unknown rule inspection")
}

func ruleInspectSummary(scope string, complete bool) string {
	text := "Read-only · scope: " + scope + "\nRuntime and persistent source are separate observations."
	if !complete {
		text += "\nIncomplete: inspect unavailable/error rows and coverage before drawing conclusions."
	}
	return text + "\ne Edit query / selection · Tab list/detail"
}

func ruleTargetEvidence(target rulework.RuleTargetInfo) []string {
	lines := []string{"Target: " + target.TargetID, "Observed: " + target.ObservedAt}
	if target.Version != "" {
		lines = append(lines, "Core version: "+target.Version)
	}
	if target.Mode != "" {
		lines = append(lines, "Runtime mode: "+target.Mode)
	}
	if target.SourceBinding != "" {
		lines = append(lines, "Source binding: "+target.SourceBinding)
	}
	if target.Owner != nil {
		lines = append(lines, "Owner: "+target.Owner.Kind, "File: "+target.Owner.File)
	}
	return append(lines, ruleCoverageLines(target.Limitations)...)
}

func ruleCoverageLines(limitations []string) []string {
	lines := make([]string, 0, len(limitations))
	for _, limitation := range limitations {
		lines = append(lines, "Coverage: "+limitation)
	}
	return lines
}

func ruleEntryText(entry rulecheck.Entry) string {
	mark := ""
	if entry.Rule.Disabled {
		mark = " [disabled]"
	}
	if entry.Section == "delete" {
		mark += " [owner directive]"
	}
	return fmt.Sprintf("%s #%d%s · %s", entry.Section, entry.Rule.Index+1, mark, entry.Rule.String())
}

func ruleDiffLines(report rulecheck.DiffReport) []string {
	lines := []string{}
	if report.Equal {
		lines = append(lines, "No differences in the compared rule fields and order.")
	}
	for _, change := range report.Changes {
		heading := change.Kind
		if len(change.Fields) > 0 {
			heading += " · " + strings.Join(change.Fields, ", ")
		}
		lines = append(lines, heading)
		if change.Left != nil {
			lines = append(lines, "  - "+ruleEntryText(*change.Left))
		}
		if change.Right != nil {
			lines = append(lines, "  + "+ruleEntryText(*change.Right))
		}
	}
	return append(lines, ruleCoverageLines(report.Limitations)...)
}

func ruleDiffWorkbench(report rulework.RuleDiffReport) tui.WorkResult {
	result := tui.WorkResult{Title: "Rule comparison · " + report.Status, Summary: "Baseline: " + report.Baseline.TargetID + "\n" + ruleInspectSummary(report.Scope, report.Complete)}
	for _, target := range report.Targets {
		for _, lane := range []struct {
			name  string
			layer *rulework.RuleLayerDiff
		}{{"runtime", target.Runtime}, {"source", target.Source}} {
			if lane.layer == nil {
				continue
			}
			layer := lane.layer
			label := target.Target.TargetID + " · " + lane.name + " · " + layer.Status
			if layer.Result != nil {
				if layer.Result.Equal {
					label += " · equal compared rules"
				} else {
					label += fmt.Sprintf(" · %d changes", len(layer.Result.Changes))
				}
			}
			detail := []string{label, layer.Message, "Baseline evidence:"}
			detail = append(detail, ruleTargetEvidence(report.Baseline)...)
			detail = append(detail, "\nCompared target evidence:")
			detail = append(detail, ruleTargetEvidence(target.Target)...)
			if layer.LeftShape != "" || layer.RightShape != "" {
				detail = append(detail, "Rule shape: "+layer.LeftShape+" → "+layer.RightShape)
			}
			if layer.Result != nil {
				detail = append(detail, "\nBaseline (-) → compared target (+):")
				detail = append(detail, ruleDiffLines(*layer.Result)...)
			}
			detail = append(detail, ruleCoverageLines(layer.Limitations)...)
			result.Rows = append(result.Rows, tui.WorkRow{ID: target.Target.TargetID + ":" + lane.name, Label: label, Detail: strings.Join(detail, "\n")})
		}
	}
	return result
}

func ruleFindWorkbench(report rulework.RuleFindReport) tui.WorkResult {
	result := tui.WorkResult{Title: "Find rule · " + report.Status, Summary: "Query: " + report.Query + "\n" + ruleInspectSummary(report.Scope, report.Complete)}
	for _, target := range report.Targets {
		for _, lane := range []struct {
			name  string
			layer *rulework.RuleLayerFind
		}{{"runtime", target.Runtime}, {"source", target.Source}} {
			if lane.layer == nil {
				continue
			}
			layer := lane.layer
			label := target.Target.TargetID + " · " + lane.name + " · " + layer.Status
			if layer.Result != nil {
				if layer.Result.Found {
					label += " · found"
				} else {
					label += " · no exact match"
				}
				label += fmt.Sprintf(" (%d matching/related entries)", len(layer.Result.Matches))
			}
			detail := []string{label, layer.Message, "Rule shape: " + layer.Shape}
			detail = append(detail, ruleTargetEvidence(target.Target)...)
			if layer.Result != nil {
				for _, match := range layer.Result.Matches {
					detail = append(detail, "\n"+match.Kind+" · "+ruleEntryText(match.Entry))
					if len(match.Differences) > 0 {
						detail = append(detail, "Different: "+strings.Join(match.Differences, ", "))
					}
				}
				detail = append(detail, ruleCoverageLines(layer.Result.Limitations)...)
			}
			detail = append(detail, ruleCoverageLines(layer.Limitations)...)
			result.Rows = append(result.Rows, tui.WorkRow{ID: target.Target.TargetID + ":" + lane.name, Label: label, Detail: strings.Join(detail, "\n")})
		}
	}
	return result
}

func ruleLookupWorkbench(report rulework.RuleLookupReport) tui.WorkResult {
	result := tui.WorkResult{Title: "Static rule lookup · " + report.Status, Summary: report.Input.Kind + ": " + report.Input.Value + "\nNo traffic or DNS requests are sent; this is not an observed connection.\n" + ruleInspectSummary(report.Scope, report.Complete)}
	for _, target := range report.Targets {
		for _, lane := range []struct {
			name  string
			layer *rulework.RuleLayerLookup
		}{{"runtime", target.Runtime}, {"source", target.Source}} {
			if lane.layer == nil {
				continue
			}
			layer := lane.layer
			label := target.Target.TargetID + " · " + lane.name + " · " + layer.Status
			if layer.Result != nil {
				label += " · " + layer.Result.Status
			}
			detail := []string{label, layer.Message, "Rule shape: " + layer.Shape}
			detail = append(detail, ruleTargetEvidence(target.Target)...)
			if layer.Result != nil {
				if layer.Result.Winner != nil {
					detail = append(detail, "\nFirst static candidate: "+ruleEntryText(*layer.Result.Winner))
				}
				for _, step := range layer.Result.Steps {
					detail = append(detail, "\n"+step.Outcome+" · "+ruleEntryText(step.Entry), step.Reason)
				}
				detail = append(detail, ruleCoverageLines(layer.Result.Limitations)...)
			}
			detail = append(detail, ruleCoverageLines(layer.Limitations)...)
			result.Rows = append(result.Rows, tui.WorkRow{ID: target.Target.TargetID + ":" + lane.name, Label: label, Detail: strings.Join(detail, "\n")})
		}
	}
	return result
}
