package cli

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
)

func TestRuleAddRawMisusePointsToApplyBeforePolicyOrNetwork(t *testing.T) {
	isolated(t)
	deps := Dependencies{
		Terminal: func(io.Reader, io.Writer) bool { t.Fatal("raw misuse checked terminal"); return false },
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("raw misuse reached controller")
			return nil, nil, nil
		},
		Discover: func(context.Context, string) ([]config.Target, error) {
			t.Fatal("raw misuse discovered targets")
			return nil, nil
		},
	}
	for _, args := range [][]string{
		{"rules", "add-domain", quickCLIRule},
		{"rules", "add-domain", "--", "- " + quickCLIRule},
		{"rules", "add-domain", quickCLIRule, "--via", "DIRECT"},
		{"rules", "add-ip", "IP-CIDR,203.0.113.0/24,DIRECT"},
	} {
		code, out, errOut := runProcess(t, deps, append([]string{"--json"}, args...)...)
		failure := decodeFailure(t, errOut)
		if code != 2 || out != "" || failure.Code != "usage" || !strings.Contains(failure.Message, "rules apply --dry-run --") || strings.Contains(failure.Message, "--via must") {
			t.Fatal("misleading raw-rule error", args, code, out, failure)
		}
	}
}

func TestUnboundQuickRuleGuidanceHasOneDiagnosticAndNoRead(t *testing.T) {
	settings := isolated(t)
	cfg := config.Config{DefaultTarget: "a", Targets: []config.Target{{ID: "a", Controller: "http://127.0.0.1:1"}}}
	saveRuleInspectionSettings(t, settings, cfg)
	before, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("unbound preview reached runtime")
		return nil, nil, nil
	}}
	for _, reuse := range []bool{false, true} {
		if reuse {
			cfg = loadRuleInspectionSettings(t, settings)
			cfg.Targets[0].ConfigSource = &config.ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: "/fixture/verge", ProfileUID: "chosen"}
			saveRuleInspectionSettings(t, settings, cfg)
			before, _ = os.ReadFile(settings)
		}
		code, out, errOut := runProcess(t, deps, "rules", "apply", quickCLIRule, "--json")
		plan := decodeRuleInspectionJSON[rulework.QuickPlan](t, out)
		failure := decodeFailure(t, errOut)
		if code == 0 || plan.Status != "blocked" || len(plan.Targets) != 1 || plan.Targets[0].ReasonCode != "unbound_rule_source" || len(plan.Targets[0].NextCommands) != 1 {
			t.Fatal("missing actionable unbound result", code, plan, failure)
		}
		want := "--help"
		if reuse {
			want = "--from-config-source"
		}
		if !strings.Contains(plan.Targets[0].NextCommands[0], want) || strings.Contains(failure.Message, plan.Targets[0].Message) || len(plan.Targets[0].Findings) != 0 {
			t.Fatal("unbound source was mislabeled conflict or duplicated diagnostic", plan, failure)
		}
		code, human, diagnostic := runProcess(t, deps, "rules", "apply", quickCLIRule)
		if code == 0 || strings.Count(human, plan.Targets[0].Message) != 1 || strings.Count(diagnostic, "lazyclash:") != 1 || strings.Contains(diagnostic, plan.Targets[0].Message) {
			t.Fatal("human preflight duplicated or lost the actionable target reason", code, human, diagnostic)
		}
		if after, err := os.ReadFile(settings); err != nil || string(after) != string(before) {
			t.Fatal("unbound guidance changed settings")
		}
	}
}

func TestRuleGuidanceRetainsSelectedSettingsFile(t *testing.T) {
	settings := isolated(t)
	saveRuleInspectionSettings(t, settings, config.Config{DefaultTarget: "a", Targets: []config.Target{{ID: "a", Controller: "http://127.0.0.1:1"}}})
	code, out, _ := runProcess(t, Dependencies{}, "--config", settings, "rules", "apply", quickCLIRule, "--json")
	plan := decodeRuleInspectionJSON[rulework.QuickPlan](t, out)
	if code == 0 || len(plan.Targets) != 1 || len(plan.Targets[0].NextCommands) != 1 || !strings.Contains(plan.Targets[0].NextCommands[0], "--config '") || !strings.Contains(plan.Targets[0].NextCommands[0], settings) {
		t.Fatal(code, plan)
	}
}
