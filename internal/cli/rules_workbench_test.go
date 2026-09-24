package cli

import (
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/tui"
)

func TestQuickWorkbenchPreviewPreservesBlockedFindingsAndGuardsApply(t *testing.T) {
	proposed := -1
	plan := rulework.QuickPlan{Status: "blocked", Rule: "DOMAIN,example.com,DIRECT", Targets: []rulework.QuickTargetPlan{
		{TargetID: "ready", Status: "ready", Diff: "+ DOMAIN,example.com,DIRECT"},
		{TargetID: "bad", Status: "blocked", Findings: []rulecheck.Finding{{Index: 4, RelatedIndex: &proposed, Severity: "error", Code: "conflict", Rule: "DOMAIN,example.com,PROXY", RelatedRule: "DOMAIN,example.com,DIRECT", Message: "different action"}}, Limitations: []string{"provider members opaque"}},
	}}
	result := quickRulePreviewResult(tui.WorkRequest{}, plan)
	if result.Apply != nil || len(result.Rows) != 2 || !strings.Contains(result.Rows[1].Detail, "rule #5 / proposed rule: different action") || !strings.Contains(result.Rows[1].Detail, "provider members opaque") || !strings.Contains(result.Rows[0].Detail, plan.Targets[0].Diff) {
		t.Fatalf("unsafe/incomplete preview: %+v", result)
	}
	if !strings.Contains(result.Rows[1].Detail, "Rule: DOMAIN,example.com,PROXY") || !strings.Contains(result.Rows[1].Detail, "Related: DOMAIN,example.com,DIRECT") {
		t.Fatal("conflict omitted concrete expressions")
	}
	plan.Status, plan.Digest, plan.Targets = "ready", "approved", plan.Targets[:1]
	result = quickRulePreviewResult(tui.WorkRequest{All: true}, plan)
	if result.Apply == nil || result.Apply.Kind != "quick-rule-apply" || result.Apply.Digest != "approved" || !result.Apply.All {
		t.Fatal("preview omitted reviewed request")
	}
}

func TestQuickWorkbenchPartialResultsAndHealthCoverage(t *testing.T) {
	result := quickRuleApplyResult(rulework.QuickResult{Status: "partial", Results: []rulework.QuickTargetResult{
		{TargetID: "saved", Status: "persisted_pending_owner_reload", Receipt: &rulework.Receipt{ID: "receipt-1", Message: "Reactivate profile"}},
		{TargetID: "failed", Status: "failed", Message: "reload failed"},
	}})
	if len(result.Rows) != 2 || !strings.Contains(result.Rows[0].Detail, "receipt-1") || !strings.Contains(result.Rows[0].Detail, "Runtime verified: false") || !strings.Contains(result.Rows[1].Detail, "reload failed") {
		t.Fatal("partial result lost outcome evidence")
	}
	health := ruleHealthResult(rulework.HealthReport{Status: "warning", Targets: []rulework.TargetHealth{{TargetID: "test", Status: "warning", Runtime: &rulecheck.Report{Stats: rulecheck.Stats{Total: 3, Opaque: 1, ByType: map[string]int{"MATCH": 1, "DOMAIN": 2}, ByPolicy: map[string]int{"PROXY": 1, "DIRECT": 2}}, Findings: []rulecheck.Finding{{Severity: "warning", Code: "unreachable", Message: "shadowed"}}, Limitations: []string{"GEOIP membership unavailable"}}}}})
	if health.Apply != nil || len(health.Rows) != 1 || !strings.Contains(health.Rows[0].Detail, "1 opaque") || !strings.Contains(health.Rows[0].Detail, "shadowed") || !strings.Contains(health.Rows[0].Detail, "GEOIP membership unavailable") {
		t.Fatal("healthcheck omitted coverage")
	}
	if !strings.Contains(health.Rows[0].Detail, "By type: DOMAIN: 2, MATCH: 1") || !strings.Contains(health.Rows[0].Detail, "By policy: DIRECT: 2, PROXY: 1") {
		t.Fatal("healthcheck omitted sorted type/policy counts")
	}
}
