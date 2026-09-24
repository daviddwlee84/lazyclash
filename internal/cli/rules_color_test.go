package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
)

func rulesColorPlanFixture(status string) rulework.QuickPlan {
	findings := []rulecheck.Finding{{Severity: "warning", Code: "runtime_policy_drift", Index: 2, Message: "Runtime differs from the persistent source.", Rule: "DOMAIN,existing.test,DIRECT"}}
	if status == "blocked" {
		findings = append(findings, rulecheck.Finding{Severity: "error", Code: "selector_conflict", Index: 0, Message: "The requested selector already has a different policy.", Rule: "DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,Proxy", RelatedRule: quickCLIRule})
	}
	return rulework.QuickPlan{Rule: quickCLIRule, Status: status, Digest: strings.Repeat("a", 64), Targets: []rulework.QuickTargetPlan{{
		TargetID: "office", Status: status, Owner: &rulework.Source{Kind: "file", File: "/fixture/config.yaml"},
		Diff: "+ [0] " + quickCLIRule + "\nAll existing rules retain their order.", Findings: findings,
		ExistingHealth: &rulework.QuickExistingHealth{Source: &rulecheck.Report{Findings: []rulecheck.Finding{{Severity: "warning", Code: "selector_conflict", Index: 3, Message: "Unrelated existing conflict.", Rule: "DOMAIN,unrelated.test,DIRECT", RelatedRule: "DOMAIN,unrelated.test,Proxy"}}}},
		NextCommands:   []string{"lazyclash --target office rules healthcheck"}, Limitations: []string{"Provider contents are outside static analysis."},
	}}}
}

func rulesColorResultFixture(status string) rulework.QuickResult {
	resultStatus := "completed"
	if status == "write_result_unknown" {
		resultStatus = "stopped"
	}
	if status == "skipped_unavailable" {
		resultStatus = "completed_with_skips"
	}
	target := rulework.QuickTargetResult{TargetID: "office", Status: status, RuntimeVerified: status == "applied_verified", Message: "Rule saved; inspect verification state.", Receipt: &rulework.Receipt{ID: "receipt-fixture", File: "/fixture/config.yaml", Status: status}}
	if status == "skipped_existing" || status == "skipped_unavailable" {
		target.Receipt = nil
		target.Message = "No target write was attempted."
	}
	return rulework.QuickResult{Rule: quickCLIRule, Status: resultStatus, Digest: strings.Repeat("b", 64), Results: []rulework.QuickTargetResult{target}}
}

func TestCLIColorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, mode, term         string
		json, tty, noColor, want bool
	}{
		{name: "auto terminal", mode: "auto", term: "xterm-256color", tty: true, want: true},
		{name: "auto pipe", mode: "auto", term: "xterm-256color"},
		{name: "NO_COLOR", mode: "auto", tty: true, noColor: true},
		{name: "dumb", mode: "auto", term: "dumb", tty: true},
		{name: "never", mode: "never", tty: true},
		{name: "always pipe", mode: "always", want: true},
		{name: "always overrides environment", mode: "always", term: "dumb", noColor: true, want: true},
		{name: "JSON overrides always", mode: "always", json: true, tty: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := colorEnabled(tc.mode, tc.json, tc.tty, tc.noColor, tc.term); got != tc.want {
				t.Fatalf("enabled=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestQuickRuleColorPreservesReportAndHighlightsSemantics(t *testing.T) {
	style := cliStyle{enabled: true}
	for _, status := range []string{"ready", "blocked"} {
		plan := rulesColorPlanFixture(status)
		plain := rulework.FormatQuickPlan(plan)
		colored := style.quickRuleOutput(plain, plan.Status, map[string]string{"office": status})
		if ansi.Strip(colored) != plain {
			t.Fatalf("color changed report content:\n%s", colored)
		}
		for _, expected := range []string{style.paint(toneAccent, "office"), style.paint(statusTone(status), status), style.paint(toneSuccess, "+ [0] "+quickCLIRule), style.paint(toneMuted, "Digest: "+plan.Digest)} {
			if !strings.Contains(colored, expected) {
				t.Fatalf("missing semantic style %q in %q", expected, colored)
			}
		}
		if !strings.Contains(colored, style.paint(toneWarning, "  warning [runtime_policy_drift] rule #3: Runtime differs from the persistent source.")) {
			t.Fatal("warning not highlighted")
		}
		if status == "blocked" && !strings.Contains(colored, style.paint(toneError, "  error [selector_conflict] rule #1: The requested selector already has a different policy.")) {
			t.Fatal("blocking error not highlighted")
		}
		if got := (cliStyle{}).quickRuleOutput(plain, status, nil); got != plain {
			t.Fatal("plain output changed")
		}
	}
}

func TestQuickRuleResultColorsKeepReceiptAndUnknownState(t *testing.T) {
	style := cliStyle{enabled: true}
	for _, tc := range []struct {
		status string
		tone   cliTone
	}{{"applied_verified", toneSuccess}, {"persisted_pending_owner_reload", toneWarning}, {"write_result_unknown", toneWarning}, {"skipped_existing", toneMuted}, {"skipped_unavailable", toneWarning}} {
		result := rulesColorResultFixture(tc.status)
		plain := rulework.FormatQuickResult(result)
		colored := style.quickRuleOutput(plain, result.Status, map[string]string{"office": tc.status})
		if ansi.Strip(colored) != plain || !strings.Contains(colored, style.paint(tc.tone, tc.status)) {
			t.Fatalf("bad result style for %s: %q", tc.status, colored)
		}
		if result.Results[0].Receipt != nil && (!strings.Contains(colored, "receipt-fixture") || !strings.Contains(colored, "/fixture/config.yaml")) {
			t.Fatal("receipt hidden")
		}
	}
}

func TestQuickRuleColorsSanitizeUntrustedTextBeforeAddingSGR(t *testing.T) {
	plan := rulesColorPlanFixture("blocked")
	plan.Targets[0].Message = "Remote\x1b]52;c;PRIVATE_CLIPBOARD\a\x1b[32m warning\x1b[0m"
	plan.Targets[0].Owner.File = "/fixture/\t\x1b]8;;https://hostile.test\x1b\\config.yaml\x1b]8;;\x1b\\"
	before, _ := json.Marshal(plan)
	plain := rulework.FormatQuickPlan(plan)
	colored := (cliStyle{enabled: true}).quickRuleOutput(plain, plan.Status, map[string]string{"office": "blocked"})
	if ansi.Strip(colored) != core.Sanitize(plain) || strings.Contains(colored, "PRIVATE_CLIPBOARD") || strings.Contains(colored, "hostile.test") || strings.Contains(colored, "\x1b]") {
		t.Fatalf("untrusted terminal escape survived: %q", colored)
	}
	after, _ := json.Marshal(plan)
	if string(before) != string(after) {
		t.Fatal("styling mutated report data")
	}
}

func TestQuickRuleCLIColorAndJSONRemainSeparate(t *testing.T) {
	_, source := quickCLIFixture(t, "prepend: []\n")
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	for _, mode := range []string{"auto", "never", "always"} {
		out, _, err := run(t, Dependencies{}, "--color", mode, "rules", "apply", quickCLIRule, "--dry-run")
		if err != nil || strings.Contains(out, "\x1b[") != (mode == "always") || !strings.Contains(ansi.Strip(out), "Status: ready") {
			t.Fatalf("%s: %q %v", mode, out, err)
		}
	}
	out, _, err := run(t, Dependencies{}, "rules", "apply", quickCLIRule, "--color", "always", "--json", "--dry-run")
	var plan rulework.QuickPlan
	if err != nil || strings.Contains(out, "\x1b") || json.Unmarshal([]byte(out), &plan) != nil || plan.Status != "ready" {
		t.Fatalf("JSON changed: %q %v", out, err)
	}
	if after, err := os.ReadFile(source); err != nil || string(after) != string(before) {
		t.Fatal("styled preview changed source", err)
	}
}

func TestCLIColorFlagValidationCompletionAndBusinessIntent(t *testing.T) {
	isolated(t)
	code, out, errOut := runProcess(t, Dependencies{}, "--color", "rainbow", "status")
	if code != 2 || out != "" || !strings.Contains(errOut, "--color must be") {
		t.Fatalf("invalid color not rejected before target resolution: %d %q %q", code, out, errOut)
	}
	out, _, err := run(t, Dependencies{}, "__complete", "rules", "apply", "--color", "a")
	if err != nil || !strings.Contains(out, "auto\n") || !strings.Contains(out, "always\n") || !strings.Contains(out, ":4") {
		t.Fatalf("missing offline color completion %q %v", out, err)
	}
	cmd := NewCommand()
	add, _, err := cmd.Find([]string{"targets", "add"})
	if err != nil {
		t.Fatal(err)
	}
	if err = add.ParseFlags([]string{"--color", "never"}); err != nil {
		t.Fatal(err)
	}
	if businessChanged(add) {
		t.Fatal("global color changed target business intent")
	}
	// The setup wizard loads settings before displaying its first screen. A
	// missing explicit fixture path proves --color retains bare wizard intent
	// without starting a terminal reader or contacting any managed host.
	_, _, err = run(t, Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }}, "--color", "never", "--config", filepath.Join(t.TempDir(), "missing.toml"), "setup")
	if err == nil || !strings.Contains(err.Error(), "read configuration") {
		t.Fatalf("global color bypassed bare setup wizard: %v", err)
	}
}
