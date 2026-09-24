package cli

import (
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/spf13/cobra"
)

func (o *options) writeQuickRulePlan(cmd *cobra.Command, plan rulework.QuickPlan) error {
	headers := map[string]string{}
	for _, target := range plan.Targets {
		headers[target.TargetID] = target.Status
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), o.commandStyle(cmd.OutOrStdout()).quickRuleOutput(rulework.FormatQuickPlan(plan), plan.Status, headers))
	return err
}

func (o *options) writeQuickRuleResult(cmd *cobra.Command, result rulework.QuickResult) error {
	headers := map[string]string{}
	for _, target := range result.Results {
		headers[target.TargetID] = target.Status
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), o.commandStyle(cmd.OutOrStdout()).quickRuleOutput(rulework.FormatQuickResult(result), result.Status, headers))
	return err
}

// Preserve the canonical human report byte-for-byte when ANSI is stripped.
// Styling stays a CLI presentation concern; the domain's compact formatting is
// shared unchanged with TUI adapters and retains every finding and receipt.
func (s cliStyle) quickRuleOutput(raw, status string, targets map[string]string) string {
	plain := core.Sanitize(raw)
	if !s.enabled {
		return plain
	}
	headers := map[string]string{}
	for id, targetStatus := range targets {
		headers[core.Sanitize(id+": "+targetStatus)] = s.paint(toneAccent, id) + ": " + s.paint(statusTone(targetStatus), targetStatus)
	}
	lines := strings.Split(plain, "\n")
	for i, line := range lines {
		if header, ok := headers[line]; ok {
			lines[i] = header
			continue
		}
		switch {
		case strings.HasPrefix(line, "Rule: "):
			lines[i] = s.paint(toneAccent, "Rule: ") + s.paint(toneStrong, strings.TrimPrefix(line, "Rule: "))
		case line == "Status: "+core.Sanitize(status):
			lines[i] = s.paint(toneAccent, "Status: ") + s.paint(statusTone(status), status)
		case strings.HasPrefix(line, "Digest: "), strings.HasPrefix(line, "Source: "), strings.HasPrefix(line, "Receipt: "), strings.HasPrefix(line, "File: "):
			lines[i] = s.paint(toneMuted, line)
		case strings.HasPrefix(line, "Next: "):
			lines[i] = s.paint(toneAccent, "Next: ") + strings.TrimPrefix(line, "Next: ")
		case line == "Operation checks:":
			lines[i] = s.paint(toneAccent, line)
		case strings.HasPrefix(line, "Existing health "), strings.HasPrefix(line, "  Analysis limit: "), strings.HasPrefix(line, "  Existing health limit: "):
			lines[i] = s.paint(toneWarning, line)
		case strings.HasPrefix(line, "  error ["), strings.Contains(line, " distinct error ["):
			lines[i] = s.paint(toneError, line)
		case strings.HasPrefix(line, "  warning ["), strings.Contains(line, " distinct warning ["):
			lines[i] = s.paint(toneWarning, line)
		case strings.HasPrefix(line, "  info ["), strings.Contains(line, " distinct info ["):
			lines[i] = s.paint(toneMuted, line)
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"), strings.HasPrefix(line, "@@"):
			lines[i] = s.paint(toneAccent, line)
		case strings.HasPrefix(line, "+"):
			lines[i] = s.paint(toneSuccess, line)
		case strings.HasPrefix(line, "-"):
			lines[i] = s.paint(toneError, line)
		case line == "Runtime verified: true":
			lines[i] = s.paint(toneMuted, "Runtime verified: ") + s.paint(toneSuccess, "true")
		case line == "Runtime verified: false":
			lines[i] = s.paint(toneMuted, "Runtime verified: ") + s.paint(toneWarning, "false")
		}
	}
	return strings.Join(lines, "\n")
}
