package cli

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

// The PTY helper renders the exact production human writers and JSON path with
// fixed reports. It never loads settings, discovers hosts, or opens a core.
func TestRulesApplyColorPTYHelper(t *testing.T) {
	if os.Getenv("LAZYCLASH_RULES_COLOR_PTY_HELPER") != "1" {
		return
	}
	args := []string{}
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	o := &options{}
	cmd := &cobra.Command{Use: "rules-color-fixture", SilenceErrors: true, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateColorMode(o.color); err != nil {
			return err
		}
		scenario := os.Getenv("LAZYCLASH_RULES_COLOR_SCENARIO")
		if scenario == "ready" || scenario == "blocked" || scenario == "sanitized" {
			status := scenario
			if scenario == "sanitized" {
				status = "ready"
			}
			plan := rulesColorPlanFixture(status)
			if scenario == "sanitized" {
				plan.Targets[0].Message = "Remote\x1b]52;c;PRIVATE_CLIPBOARD\a\x1b[31m diagnostic\x1b[0m"
			}
			if o.json {
				return o.output(cmd, plan)
			}
			return o.writeQuickRulePlan(cmd, plan)
		}
		status := map[string]string{"completed": "applied_verified", "pending": "persisted_pending_owner_reload", "unknown": "write_result_unknown", "skipped": "skipped_existing", "unavailable": "skipped_unavailable"}[scenario]
		if status == "" {
			return fmt.Errorf("unknown fixture scenario %q", scenario)
		}
		result := rulesColorResultFixture(status)
		if o.json {
			return o.output(cmd, result)
		}
		return o.writeQuickRuleResult(cmd, result)
	}}
	o.registerColorFlag(cmd)
	cmd.Flags().BoolVar(&o.json, "json", false, "JSON fixture output")
	cmd.SetArgs(args)
	cmd.SetIn(os.Stdin)
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(ExitCode(err))
	}
	os.Exit(0)
}
