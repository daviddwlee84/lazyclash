package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
)

func reviewFixture(t *testing.T) *ruleReview {
	t.Helper()
	at := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	a := ruleobserve.New("desktop", at)
	a.Add(ruleobserve.Event{At: at, Kind: ruleobserve.KindDialError, Host: "z-fallback.example", Rule: "Match", Policy: "Final", ErrorKind: "timeout"})
	a.Add(ruleobserve.Event{At: at, Kind: ruleobserve.KindDialError, Host: "a-covered.example", Rule: "Domain", Policy: "DIRECT", ErrorKind: "refused"})
	a.Add(ruleobserve.Event{At: at, Kind: ruleobserve.KindDialSuccess, Host: "healthy.example", Rule: "Match", Policy: "Final"})
	a.Add(ruleobserve.Event{At: at, Kind: ruleobserve.KindDialError, Host: "203.0.113.8", Rule: "IPCIDR", Policy: "DIRECT", ErrorKind: "timeout"})
	a.Add(ruleobserve.Event{At: at, Kind: ruleobserve.KindOtherWarning})
	m := newRuleReview(context.Background(), RuleReviewOptions{Snapshot: a.Snapshot(at), Policies: func(context.Context) ([]string, error) { return []string{"Proxy", "DIRECT", "Proxy"}, nil }}, true)
	t.Cleanup(m.close)
	return m
}

func reviewKey(m *ruleReview, k string) tea.Cmd { _, cmd := m.Update(key(k)); return cmd }
func reviewRun(m *ruleReview, cmd tea.Cmd) {
	if cmd != nil {
		m.Update(cmd())
	}
}
func reviewInput(m *ruleReview, action, value string) {
	reviewKey(m, action)
	m.Update(tea.PasteMsg{Content: value})
	reviewKey(m, "enter")
}
func readyReviewPlan() rulework.QuickPlan {
	return rulework.QuickPlan{Status: "ready", Digest: strings.Repeat("a", 64), Targets: []rulework.QuickTargetPlan{{TargetID: "desktop", Status: "ready", Diff: "+ DOMAIN,z-fallback.example,Proxy"}}}
}

func TestRuleReviewPoliciesLoadWithoutBlockingNavigationOrTextOwnership(t *testing.T) {
	m := reviewFixture(t)
	load := m.Init()
	if !m.policyLoading || m.pending {
		t.Fatal("policy discovery blocked navigation")
	}
	reviewKey(m, "j")
	if m.index != 1 {
		t.Fatal("loading policies stole navigation")
	}
	reviewKey(m, "/")
	reviewKey(m, "q")
	reviewKey(m, "j")
	m.Update(tea.PasteMsg{Content: "\nk/y"})
	if m.closed || m.inputMode != "filter" || !strings.Contains(m.input.Value(), "qj") || m.filter != m.input.Value() || m.help || m.phase != "list" {
		t.Fatalf("text escaped input: value=%q filter=%q closed=%t", m.input.Value(), m.filter, m.closed)
	}
	// Arriving policies must not replace the focused input or its draft.
	before := m.input.Value()
	reviewRun(m, load)
	if m.policyLoading || m.input.Value() != before || len(m.policies) != 2 {
		t.Fatal("policy completion lost input or retained duplicates")
	}
	reviewKey(m, "esc")
	if m.filter != "" || m.inputMode != "" || m.closed {
		t.Fatal("Esc did not clear local filter")
	}
	reviewInput(m, "/", "covered")
	if m.inputMode != "" || len(m.rows()) != 1 || m.rows()[0].Host != "a-covered.example" {
		t.Fatal("accepted filter did not select matching row")
	}
	// Bracketed paste outside an edit is never interpreted as navigation/apply.
	m.Update(tea.PasteMsg{Content: "q\ny\na"})
	if m.closed || m.phase != "list" || m.pending {
		t.Fatal("paste invoked action")
	}
}

func TestRuleReviewSelectionPolicyValidationSuffixAndIgnore(t *testing.T) {
	m := reviewFixture(t)
	reviewRun(m, m.Init())
	if g, _ := m.selected(); g.Host != "z-fallback.example" {
		t.Fatal("fallback failure not prioritized")
	}
	reviewKey(m, " ")
	k := "domain:z-fallback.example"
	if !m.drafts[k].checked || m.drafts[k].policy != "" || m.drafts[k].suffix {
		t.Fatal("mark guessed a policy or suffix")
	}
	reviewInput(m, "p", "Unknown")
	if m.inputMode != "policy" || m.drafts[k].policy != "" || !strings.Contains(m.notice, "existing policy") {
		t.Fatal("unavailable policy accepted")
	}
	m.input.SetValue("Proxy")
	reviewKey(m, "enter")
	if m.inputMode != "" || m.drafts[k].policy != "Proxy" {
		t.Fatal("known policy not assigned")
	}
	if !strings.Contains(m.detail(m.rows()[0]), "DOMAIN,z-fallback.example,Proxy") {
		t.Fatal("exact hostname not default")
	}
	reviewKey(m, "s")
	if !m.drafts[k].suffix || !strings.Contains(m.detail(m.rows()[0]), "DOMAIN-SUFFIX,z-fallback.example,Proxy") {
		t.Fatal("explicit suffix not reflected")
	}
	reviewKey(m, "i")
	if !m.drafts[k].ignored || m.drafts[k].checked {
		t.Fatal("ignore retained selected candidate")
	}
	reviewKey(m, "u")
	if m.drafts[k].ignored || m.drafts[k].checked {
		t.Fatal("unignore silently selected candidate")
	}
	reviewInput(m, "/", "203.0.113.8")
	reviewKey(m, "s")
	if m.drafts["ip:203.0.113.8"].suffix || !strings.Contains(m.notice, "hostname") {
		t.Fatal("IP suffix accepted")
	}
	reviewInput(m, "p", "DIRECT")
	if !strings.Contains(m.detail(m.rows()[0]), "IP-CIDR,203.0.113.8/32,DIRECT,no-resolve") {
		t.Fatal("IP widened or resolved")
	}
	reviewInput(m, "e", "https://not-a-host.example/path")
	if m.inputMode != "host" || m.drafts["ip:203.0.113.8"].host != "203.0.113.8" {
		t.Fatal("invalid edited host accepted")
	}
}

func TestRuleReviewPreviewCancelAndExplicitReadyApply(t *testing.T) {
	m := reviewFixture(t)
	reviewRun(m, m.Init())
	previews, applies := 0, 0
	m.opts.Preview = func(_ context.Context, rules []string) (rulework.QuickPlan, error) {
		previews++
		if len(rules) != 1 || rules[0] != "DOMAIN,z-fallback.example,Proxy" {
			t.Fatalf("wrong batch: %v", rules)
		}
		return readyReviewPlan(), nil
	}
	m.opts.Apply = func(_ context.Context, rules []string, digest string) (rulework.QuickResult, error) {
		applies++
		if digest != strings.Repeat("a", 64) || rules[0] != "DOMAIN,z-fallback.example,Proxy" {
			t.Fatal("apply lost reviewed candidate")
		}
		return rulework.QuickResult{Status: "completed"}, nil
	}
	reviewKey(m, " ")
	if cmd := reviewKey(m, "a"); cmd != nil || previews != 0 {
		t.Fatal("missing policy reached preview")
	}
	reviewInput(m, "p", "Proxy")
	late := reviewKey(m, "a")
	if !m.pending || applies != 0 {
		t.Fatal("preview missing or wrote rules")
	}
	reviewKey(m, "esc")
	reviewRun(m, late)
	if m.pending || m.phase != "list" || m.previewValid || applies != 0 || !m.drafts["domain:z-fallback.example"].checked {
		t.Fatal("canceled preview reopened or lost draft")
	}
	reviewRun(m, reviewKey(m, "a"))
	if !m.canApply() || applies != 0 || m.phase != "preview" {
		t.Fatal("ready preview missing or auto-applied")
	}
	reviewKey(m, "enter")
	if m.phase != "list" || applies != 0 || m.canApply() {
		t.Fatal("Enter applied or kept stale readiness")
	}
	reviewRun(m, reviewKey(m, "a"))
	apply := reviewKey(m, "y")
	if duplicate := reviewKey(m, "y"); duplicate != nil {
		t.Fatal("duplicate apply accepted")
	}
	reviewRun(m, apply)
	if applies != 1 || m.phase != "result" || m.result.Status != "completed" {
		t.Fatal("explicit apply failed")
	}
}

func TestRuleReviewFailedPreviewReadOnlyAndStaleMessagesCannotApply(t *testing.T) {
	for _, scenario := range []string{"error", "blocked", "empty-digest", "no-changes", "read-only", "binding"} {
		t.Run(scenario, func(t *testing.T) {
			m := reviewFixture(t)
			reviewRun(m, m.Init())
			m.opts.Apply = func(context.Context, []string, string) (rulework.QuickResult, error) {
				t.Fatal("unsafe apply")
				return rulework.QuickResult{}, nil
			}
			m.opts.Preview = func(context.Context, []string) (rulework.QuickPlan, error) {
				p := readyReviewPlan()
				switch scenario {
				case "error":
					return p, errors.New("preview failed")
				case "blocked":
					p.Status = "blocked"
				case "empty-digest":
					p.Digest = ""
				case "no-changes":
					p.Targets = nil
				}
				return p, nil
			}
			reviewKey(m, " ")
			reviewInput(m, "p", "Proxy")
			if scenario == "read-only" {
				m.opts.ReadOnly = true
			}
			if scenario == "binding" {
				m.opts.BlockedReason = "Target changed"
			}
			reviewRun(m, reviewKey(m, "a"))
			if m.canApply() || strings.Contains(m.View().Content, "y Apply") || reviewKey(m, "y") != nil {
				t.Fatal("unready action enabled")
			}
		})
	}
	m := reviewFixture(t)
	load := m.Init()
	foreign := reviewFixture(t)
	m.Update(ruleReviewMsg{owner: foreign, kind: "policies", serial: m.policySerial, policies: []string{"Injected"}})
	if len(m.policies) != 0 || !m.policyLoading {
		t.Fatal("foreign policy result accepted")
	}
	m.close()
	reviewRun(m, load)
	if len(m.policies) != 0 {
		t.Fatal("closed view accepted late policies")
	}
}

func TestRuleReviewApplyCancellationPreservesOutcome(t *testing.T) {
	m := reviewFixture(t)
	reviewRun(m, m.Init())
	m.opts.Preview = func(context.Context, []string) (rulework.QuickPlan, error) { return readyReviewPlan(), nil }
	m.opts.Apply = func(ctx context.Context, _ []string, _ string) (rulework.QuickResult, error) {
		<-ctx.Done()
		return rulework.QuickResult{Status: "unknown", Results: []rulework.QuickTargetResult{{TargetID: "desktop", Status: "unknown", Message: "Verify receipt before retrying"}}}, ctx.Err()
	}
	reviewKey(m, " ")
	reviewInput(m, "p", "Proxy")
	reviewRun(m, reviewKey(m, "a"))
	pending := reviewKey(m, "y")
	reviewKey(m, "esc")
	if !m.pending || m.closed {
		t.Fatal("canceled write outcome hidden")
	}
	reviewRun(m, pending)
	if m.phase != "result" || m.result.Status != "unknown" || !strings.Contains(m.body, "Verify receipt") {
		t.Fatal("unknown write outcome lost")
	}
}

func TestRuleReviewScopesUnknownRowsAndResponsiveResize(t *testing.T) {
	m := reviewFixture(t)
	if len(m.rows()) != 4 {
		t.Fatal("anomaly scope includes healthy-only flow")
	}
	reviewKey(m, "v")
	if len(m.rows()) != 2 {
		t.Fatal("MATCH scope omitted observed success or included other rule")
	}
	reviewKey(m, "v")
	if len(m.rows()) != 5 {
		t.Fatal("all scope incomplete")
	}
	reviewInput(m, "/", "other")
	reviewKey(m, " ")
	if m.drafts["other"].checked || !strings.Contains(m.detail(m.rows()[0]), "inspection only") {
		t.Fatal("unparsed warning became rule candidate")
	}
	for _, size := range [][2]int{{0, 0}, {1, 1}, {40, 12}, {80, 24}, {160, 40}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		for _, focus := range []int{0, 1} {
			m.focus = focus
			lines := strings.Split(m.View().Content, "\n")
			if len(lines) > max(1, size[1]) {
				t.Fatalf("height overflow %v", size)
			}
			for _, line := range lines {
				if ansi.StringWidth(line) > max(1, size[0]) {
					t.Fatalf("width overflow %v: %q", size, line)
				}
			}
		}
	}
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	reviewKey(m, "?")
	reviewKey(m, "j")
	if !m.help || m.offset != 1 {
		t.Fatal("help cannot scroll")
	}
	reviewKey(m, "esc")
	if m.help || m.closed {
		t.Fatal("help Esc escaped review")
	}
}
