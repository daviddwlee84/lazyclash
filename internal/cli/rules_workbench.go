package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
)

func (o *options) runQuickRuleWorkbench(ctx context.Context, req tui.WorkRequest) (tui.WorkResult, error) {
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	opts := o.ruleOptions(cmd)
	if len(req.Targets) == 0 && !req.All {
		req.Targets = []config.Target{req.Target}
	}
	switch req.Kind {
	case "quick-rule-preview":
		plan, err := rulework.PreviewRules(ctx, req.Targets, req.Rule, req.All, opts)
		o.ruleGuidanceContext(cmd, &plan)
		result := quickRulePreviewResult(req, plan)
		if err != nil {
			result.Apply = nil
		}
		return result, err
	case "quick-rule-apply":
		receipt, err := rulework.ApplyRules(ctx, req.Targets, req.Rule, req.All, req.Digest, opts)
		return quickRuleApplyResult(receipt), err
	case "rule-healthcheck":
		report, err := rulework.Healthcheck(ctx, req.Targets, req.All, opts)
		return ruleHealthResult(report), err
	}
	return tui.WorkResult{}, usage("unknown quick rule operation")
}

func quickRulePreviewResult(req tui.WorkRequest, plan rulework.QuickPlan) tui.WorkResult {
	result := tui.WorkResult{Title: "Review routing rule · " + plan.Status}
	lines := []string{plan.Rule, "All targets are inspected before any write. Conflicts block the entire batch."}
	for _, target := range plan.Targets {
		label := target.TargetID + " · " + target.Status
		lines = append(lines, label)
		detail := []string{label, target.Message}
		if target.ReasonCode != "" {
			detail = append(detail, "Reason: "+target.ReasonCode)
		}
		if len(target.NextCommands) > 0 {
			detail = append(detail, "Suggested commands:")
			detail = append(detail, target.NextCommands...)
		}
		if target.Owner != nil {
			detail = append(detail, "Owner: "+target.Owner.Kind, "File: "+target.Owner.File)
			detail = append(detail, target.Owner.Warnings...)
		}
		detail = append(detail, ruleFindingLines(target.Findings)...)
		for _, limitation := range target.Limitations {
			detail = append(detail, "Coverage: "+limitation)
		}
		if target.Diff != "" {
			detail = append(detail, "\nProposed source change:\n"+target.Diff)
		}
		result.Rows = append(result.Rows, tui.WorkRow{ID: target.TargetID, Label: label, Detail: strings.Join(detail, "\n")})
	}
	if plan.Status == "ready" && plan.HasChanges() {
		req.Kind, req.Rule, req.Digest = "quick-rule-apply", plan.Rule, plan.Digest
		result.Apply = &req
		lines = append(lines, "a Review confirmation · e Edit rule", "Writes run in order; a later failure may leave earlier targets applied.")
	} else if plan.Status == "no_changes" {
		lines = append(lines, "The selected targets already have the rule; no write is needed.")
	} else {
		lines = append(lines, "No targets will be changed. Inspect each target's findings; e edits the draft.")
	}
	result.Summary = strings.Join(lines, "\n")
	return result
}

func quickRuleApplyResult(receipt rulework.QuickResult) tui.WorkResult {
	result := tui.WorkResult{Title: "Routing rule result · " + receipt.Status, Summary: receipt.Rule}
	for _, target := range receipt.Results {
		label := target.TargetID + " · " + target.Status
		detail := []string{label, target.Message, fmt.Sprintf("Runtime verified: %t", target.RuntimeVerified)}
		detail = append(detail, ruleFindingLines(target.Findings)...)
		if target.Receipt != nil {
			detail = append(detail, "Receipt: "+target.Receipt.ID, "File: "+target.Receipt.File, target.Receipt.Message)
		}
		result.Rows = append(result.Rows, tui.WorkRow{ID: target.TargetID, Label: label, Detail: strings.Join(detail, "\n")})
		result.Summary += "\n" + label
	}
	return result
}

func ruleHealthResult(report rulework.HealthReport) tui.WorkResult {
	result := tui.WorkResult{Title: "Rules healthcheck · " + report.Status, Summary: "Read-only inspection. Coverage limitations are shown per target; no routing rules were changed."}
	for _, target := range report.Targets {
		label := target.TargetID + " · " + target.Status
		detail := []string{label, target.Message, "Observed: " + target.ObservedAt, "Routing mode: " + target.Mode, fmt.Sprintf("Rule providers: %d", target.Providers)}
		if target.Owner != nil {
			detail = append(detail, "Owner: "+target.Owner.Kind, "File: "+target.Owner.File)
		}
		if target.Snapshot != nil {
			if target.Snapshot.SourceBinding != "" {
				detail = append(detail, "Source binding: "+target.Snapshot.SourceBinding)
			}
			for _, lane := range []struct {
				name string
				view *rulework.RulesView
			}{{"Runtime", target.Snapshot.Runtime}, {"Source", target.Snapshot.Source}} {
				if lane.view != nil {
					detail = append(detail, lane.name+" snapshot: "+lane.view.Status+" · "+lane.view.Message)
				}
			}
		}
		detail = append(detail, ruleFindingLines(target.Findings)...)
		for _, source := range []struct {
			label  string
			report *rulecheck.Report
		}{{"Persistent source", target.Source}, {"Runtime", target.Runtime}} {
			if source.report == nil {
				continue
			}
			stats := source.report.Stats
			detail = append(detail, fmt.Sprintf("\n%s: %d rules, %d analyzed, %d opaque, %d invalid, %d disabled", source.label, stats.Total, stats.Analyzed, stats.Opaque, stats.Invalid, stats.Disabled))
			detail = append(detail, "By type: "+ruleCounts(stats.ByType), "By policy: "+ruleCounts(stats.ByPolicy))
			detail = append(detail, ruleFindingLines(source.report.Findings)...)
			for _, limitation := range source.report.Limitations {
				detail = append(detail, "Coverage: "+limitation)
			}
		}
		for _, limitation := range target.Limitations {
			detail = append(detail, "Coverage: "+limitation)
		}
		if target.Drift != nil {
			detail = append(detail, "\nPersistent source (-) → runtime (+) drift:")
			detail = append(detail, ruleDiffLines(*target.Drift)...)
		}
		result.Rows = append(result.Rows, tui.WorkRow{ID: target.TargetID, Label: label, Detail: strings.Join(detail, "\n")})
	}
	return result
}

func ruleFindingLines(findings []rulecheck.Finding) []string {
	var lines []string
	for _, finding := range findings {
		where := ""
		if finding.Index >= 0 {
			where = fmt.Sprintf(" rule #%d", finding.Index+1)
		}
		if finding.RelatedIndex != nil {
			if *finding.RelatedIndex < 0 {
				where += " / proposed rule"
			} else {
				where += fmt.Sprintf(" / #%d", *finding.RelatedIndex+1)
			}
		}
		lines = append(lines, fmt.Sprintf("[%s] %s%s: %s", finding.Severity, finding.Code, where, finding.Message))
		if finding.Rule != "" {
			lines = append(lines, "  Rule: "+finding.Rule)
		}
		if finding.RelatedRule != "" {
			lines = append(lines, "  Related: "+finding.RelatedRule)
		}
	}
	return lines
}

func ruleCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s: %d", key, counts[key]))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, ", ")
}
