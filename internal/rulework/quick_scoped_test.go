package rulework

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
)

func TestQuickUnrelatedConflictsRemainSeparateHealthAndApply(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n- DOMAIN-SUFFIX,nicovideo.jp,DIRECT\n- DOMAIN-SUFFIX,nicovideo.jp,PROXY\n- MATCH,DIRECT\n")
	f.mu.Lock()
	f.rules = []map[string]any{
		{"type": "DomainSuffix", "payload": "nicovideo.jp", "proxy": "DIRECT"},
		{"type": "DomainSuffix", "payload": "nicovideo.jp", "proxy": "PROXY"},
		{"type": "Match", "payload": "", "proxy": "DIRECT"},
	}
	f.mu.Unlock()
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err != nil || p.Status != "ready" || len(p.Targets) != 1 {
		t.Fatal(p, err)
	}
	target := p.Targets[0]
	if quickFindings(target.Findings, "selector_conflict") || target.ExistingHealth == nil || target.ExistingHealth.Source == nil || target.ExistingHealth.Runtime == nil {
		t.Fatal("whole-list health leaked into operation findings", target)
	}
	for _, report := range []*rulecheck.Report{target.ExistingHealth.Source, target.ExistingHealth.Runtime} {
		if report.HasErrors() || !quickFindings(report.Findings, "selector_conflict") {
			t.Fatal("existing conflict missing or still a health error", report)
		}
	}
	human := FormatQuickPlan(p)
	if strings.Count(human, "selector_conflict") != 1 || !strings.Contains(human, "source + runtime") || strings.Contains(human, "nicovideo.jp") || !strings.Contains(human, "rules healthcheck") {
		t.Fatal("existing health repeated full unrelated rules or lost guidance", human)
	}
	if strings.Count(human, "Only confirmed domain") != 1 || strings.Count(human, "Applying the registered YAML") != 1 {
		t.Fatal("repeated limitations or owner warning", human)
	}
	encoded, _ := json.Marshal(p)
	if !strings.Contains(string(encoded), "existing_health") || !strings.Contains(string(encoded), "nicovideo.jp") {
		t.Fatal("JSON lost independent full reports", string(encoded))
	}
	result, err := ApplyRules(context.Background(), []config.Target{f.target}, quickSuffix, false, p.Digest, f.opts)
	if err != nil || result.Status != "completed" || result.Results[0].Status != "applied_verified" || result.Results[0].ExistingHealth == nil {
		t.Fatal(result, err)
	}
	after, err := os.ReadFile(f.target.Configs[0].Path)
	if err != nil || !strings.Contains(string(after), "nicovideo.jp,DIRECT\n") || strings.Index(string(after), "nicovideo.jp,DIRECT") > strings.Index(string(after), "nicovideo.jp,PROXY") {
		t.Fatal("existing order changed", string(after), err)
	}
}

func TestQuickExactExistingConflictStillBlocksBatch(t *testing.T) {
	a, b := newFixture(t, false), newFixture(t, false)
	a.target.ID, b.target.ID = "a", "b"
	quickSource(t, b, "rules:\n- "+quickSuffix+"\n- DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,PROXY\n- MATCH,DIRECT\n")
	p, err := PreviewRules(context.Background(), []config.Target{a.target, b.target}, quickSuffix, true, a.opts)
	if err == nil || p.Status != "blocked" || p.Targets[1].Status != "blocked" || !quickFindings(p.Targets[1].Findings, "selector_conflict") {
		t.Fatal("exact occurrence masked requested selector conflict", p, err)
	}
	if !strings.Contains(p.Targets[1].Message, "Requested policy conflicts") {
		t.Fatal("operation conflict was presented as an invalid existing config", p.Targets[1].Message)
	}
	if _, err := ApplyRules(context.Background(), []config.Target{a.target, b.target}, quickSuffix, true, p.Digest, a.opts); err == nil {
		t.Fatal("conflicting exact skip bypassed batch preflight")
	}
	quickAssertUnchanged(t, a, b)
}

func TestQuickExactExistingIgnoresUnrelatedHealthWithoutWriting(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n- DOMAIN-SUFFIX,unrelated.example,DIRECT\n- DOMAIN-SUFFIX,unrelated.example,PROXY\n- "+quickSuffix+"\n- MATCH,DIRECT\n")
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err != nil || p.Status != "no_changes" || p.Targets[0].Status != "skipped_existing" {
		t.Fatal(p, err)
	}
	r, err := ApplyRules(context.Background(), []config.Target{f.target}, quickSuffix, false, p.Digest, f.opts)
	if err != nil || r.Results[0].Receipt != nil || r.Results[0].ExistingHealth == nil {
		t.Fatal(r, err)
	}
	quickAssertUnchanged(t, f)
	if _, err := os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("skip created receipt state", err)
	}
}

func TestQuickRuntimeConflictDependsOnPersistentOwner(t *testing.T) {
	for _, owner := range []string{"mihomo", "docker", "verge"} {
		for _, exists := range []bool{false, true} {
			verge := owner == "verge"
			f := newFixture(t, verge)
			if exists {
				if verge {
					f.source = []byte("prepend:\n- " + quickSuffix + "\nappend: []\ndelete: []\n")
					if err := os.WriteFile(filepath.Join(f.target.RuleSource.DataDir, "profiles", "owned.yaml"), f.source, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					quickSource(t, f, "rules:\n- "+quickSuffix+"\n- MATCH,DIRECT\n")
				}
			}
			if owner == "docker" {
				f.target.RuleSource = &config.RuleSource{Kind: "docker", Container: "fixture", HostPath: f.target.Configs[0].Path, CorePath: "/core/config.yaml", Binary: "/mihomo", Home: "/core"}
				f.opts.Docker = func(context.Context, config.Target, DockerRequest) (DockerInfo, error) {
					return DockerInfo{ContainerID: "fixture-container", Image: "fixture-image", SourceSHA256: sha(f.source)}, nil
				}
			}
			f.mu.Lock()
			f.rules = []map[string]any{{"type": "DomainSuffix", "payload": "api.enterprise.githubcopilot.com", "proxy": "PROXY"}}
			f.mu.Unlock()
			p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
			if verge {
				if err == nil || p.Status != "blocked" || !quickFindings(p.Targets[0].Findings, "selector_conflict") {
					t.Fatal("retained Verge runtime conflict did not block", exists, p, err)
				}
			} else if err != nil || p.Status == "blocked" || !quickFindings(p.Targets[0].Findings, "runtime_policy_drift") {
				t.Fatal("replaceable native/Docker runtime conflict blocked", owner, exists, p, err)
			} else {
				for _, f := range p.Targets[0].Findings {
					if f.Code == "runtime_policy_drift" && strings.Contains(f.Message, "resolve this conflict before applying") {
						t.Fatal("runtime drift warning still described a blocker", f)
					}
				}
			}
		}
	}
}

func TestQuickSourceIntegrityStillBlocksAndRuntimeHealthDoesNot(t *testing.T) {
	for _, input := range []struct{ rule, code string }{
		{"DOMAIN,broken", "invalid_syntax"},
		{"DOMAIN,unrelated.example,MISSING", "policy_missing"},
		{"RULE-SET,missing,DIRECT", "provider_missing"},
	} {
		for _, exists := range []bool{false, true} {
			f := newFixture(t, false)
			source := "rules:\n- " + input.rule + "\n"
			if exists {
				source += "- " + quickSuffix + "\n"
			}
			quickSource(t, f, source+"- MATCH,DIRECT\n")
			p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
			if err == nil || p.Status != "blocked" || !quickFindings(p.Targets[0].Findings, input.code) {
				t.Fatal("source integrity error bypassed", input, exists, p, err)
			}
			quickAssertUnchanged(t, f)
		}
	}
	f := newFixture(t, false)
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "Domain", "payload": "unrelated.example", "proxy": "MISSING"}}
	f.mu.Unlock()
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err != nil || p.Status != "ready" || quickFindings(p.Targets[0].Findings, "policy_missing") || !p.Targets[0].ExistingHealth.Runtime.HasErrors() {
		t.Fatal("unrelated runtime health became candidate validation", p, err)
	}
}

func TestQuickReportedNoResolveIsNotAnOptionDifferenceOrPersistentSkip(t *testing.T) {
	f := newFixture(t, false)
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "IPCIDR", "payload": "192.0.2.0/24", "proxy": "DIRECT"}}
	f.mu.Unlock()
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, "IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", false, f.opts)
	if err != nil || p.Status != "ready" || quickFindings(p.Targets[0].Findings, "overlap") || !p.Targets[0].RuntimeVerified {
		t.Fatal("runtime presence skipped persistence or fabricated absent option", p, err)
	}
}

func TestFormatQuickResultKeepsHealthCompactAndReceiptVisible(t *testing.T) {
	rules := []rulecheck.Rule{rulecheck.ParseExisting("DOMAIN,unrelated.example,DIRECT", 0), rulecheck.ParseExisting("DOMAIN,unrelated.example,PROXY", 1)}
	health := rulecheck.Analyze(rules, nil)
	result := QuickResult{Rule: quickSuffix, Status: "completed", Digest: "reviewed", Results: []QuickTargetResult{{
		TargetID: "server", Status: "applied_verified", Message: "Rule saved and verified.", RuntimeVerified: true,
		Findings:       []rulecheck.Finding{{Severity: "warning", Code: "overlap", Index: -1, Rule: quickSuffix, Message: "A broader selector overlaps this rule."}},
		ExistingHealth: &QuickExistingHealth{Source: &health, Runtime: &health},
		Receipt:        &Receipt{ID: "receipt-id", File: "/owner/config.yaml", Message: "Rule saved and verified."},
	}}}
	text := FormatQuickResult(result)
	for _, want := range []string{quickSuffix, "Status: completed", "server: applied_verified", "source + runtime", "Receipt: receipt-id", "File: /owner/config.yaml", "Runtime verified: true"} {
		if !strings.Contains(text, want) {
			t.Fatal("result lost useful detail", want, text)
		}
	}
	if strings.Contains(text, "unrelated.example") || strings.Count(text, "selector_conflict") != 1 || strings.Count(text, "Rule saved and verified.") != 1 {
		t.Fatal("result repeated whole-list health or receipt message", text)
	}
}
