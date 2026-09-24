package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

const quickCLIRule = "DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT"

func quickCLIFixture(t *testing.T, initial string) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX host fixture; Windows adapter is covered separately")
	}
	settings := isolated(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	server := testcore.NewServer()
	t.Cleanup(server.Close)
	home := filepath.Join(t.TempDir(), "verge")
	if err := os.MkdirAll(filepath.Join(home, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "profiles.yaml"), []byte("current: chosen\nitems:\n- uid: chosen\n  type: remote\n  option: {rules: owned}\n- uid: owned\n  type: rules\n  file: rules.yaml\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "profiles", "rules.yaml")
	if err := os.WriteFile(source, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = []config.Target{{ID: "a", Controller: server.URL, RuleSource: &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: home, ProfileUID: "chosen"}}}
	cfg.DefaultTarget = "a"
	if err = config.Save(settings, cfg); err != nil {
		t.Fatal(err)
	}
	return settings, source
}

func TestQuickRuleCLIPreviewYesSkipAndGuard(t *testing.T) {
	_, source := quickCLIFixture(t, "prepend: []\nappend: []\ndelete: []\n")
	before, _ := os.ReadFile(source)
	base := []string{"rules", "apply", "--json", "--", "- " + quickCLIRule}
	out, _, err := run(t, Dependencies{}, base...)
	var p rulework.QuickPlan
	if err != nil || json.Unmarshal([]byte(out), &p) != nil || p.Status != "ready" {
		t.Fatal(out, err)
	}
	if got, _ := os.ReadFile(source); !bytes.Equal(before, got) {
		t.Fatal("noninteractive preview wrote source")
	}
	out, _, err = run(t, Dependencies{}, "rules", "apply", quickCLIRule, "--yes", "--expect", strings.Repeat("0", 64), "--json")
	if err == nil || ExitCode(err) != 2 {
		t.Fatal("stale digest accepted", out, err)
	}
	out, _, err = run(t, Dependencies{}, "rules", "apply", quickCLIRule, "--yes", "--json")
	var result rulework.QuickResult
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || result.Results[0].Status != "persisted_pending_owner_reload" {
		t.Fatal(out, err)
	}
	if result.Results[0].Receipt == nil {
		t.Fatal("missing receipt")
	}
	out, _, err = run(t, Dependencies{}, "rules", "apply", quickCLIRule, "--yes", "--json")
	result = rulework.QuickResult{}
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || result.Results[0].Status != "skipped_existing" || result.Results[0].Receipt != nil {
		t.Fatal(out, err)
	}
}

func TestQuickRuleCLIAllSkipsAndBlockingErrors(t *testing.T) {
	settings, source := quickCLIFixture(t, "prepend: []\n")
	cfg, err := config.Load(settings, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = append(cfg.Targets, config.Target{ID: "unbound", Controller: "http://127.0.0.1:1"})
	if err = config.Save(settings, cfg); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, Dependencies{}, "rules", "apply", quickCLIRule, "--all", "--yes", "--json")
	var result rulework.QuickResult
	if err != nil || json.Unmarshal([]byte(out), &result) != nil || result.Status != "completed_with_skips" || result.Results[1].Status != "skipped_unavailable" {
		t.Fatal(out, err)
	}
	conflict := "prepend:\n  - DOMAIN-SUFFIX,api.enterprise.githubcopilot.com," + testcore.Selector + "\n"
	if err = os.WriteFile(source, []byte(conflict), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, err = run(t, Dependencies{}, "rules", "apply", quickCLIRule, "--all", "--yes", "--json")
	if err == nil || !strings.Contains(out, "selector_conflict") {
		t.Fatal("--yes bypassed conflict", out, err)
	}
	if got, _ := os.ReadFile(source); string(got) != conflict {
		t.Fatal("blocked command wrote source")
	}
	for _, args := range [][]string{{"--target", "a", "rules", "apply", quickCLIRule, "--all"}, {"rules", "apply", quickCLIRule, "--all", "--secret-env", "SECRET"}} {
		if _, _, err = run(t, Dependencies{}, args...); err == nil || ExitCode(err) != 2 {
			t.Fatal(args, err)
		}
	}
}

func TestQuickRuleCLIHealthAndSourceReuse(t *testing.T) {
	settings, _ := quickCLIFixture(t, "prepend: []\n")
	cfg, err := config.Load(settings, true)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Targets[0].RuleSource
	cfg.Targets[0].ConfigSource = &config.ConfigSource{Kind: s.Kind, Version: s.Version, DataDir: s.DataDir, ProfileUID: s.ProfileUID}
	cfg.Targets[0].RuleSource = nil
	if err = config.Save(settings, cfg); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, Dependencies{}, "rules", "healthcheck", "--json")
	var report rulework.HealthReport
	if err != nil || json.Unmarshal([]byte(out), &report) != nil || report.Targets[0].Runtime == nil || report.Targets[0].Source == nil || report.Targets[0].Snapshot == nil || report.Targets[0].Snapshot.SourceBinding != "config_source" {
		t.Fatal(out, err)
	}
	unchanged, e := config.Load(settings, true)
	if e != nil || unchanged.Targets[0].RuleSource != nil {
		t.Fatal("read-only inspection created a rule binding", e)
	}
	if _, _, err = run(t, Dependencies{}, "rules", "source", "set", "--from-config-source", "--kind", "verge"); err == nil {
		t.Fatal("mixed source flags accepted")
	}
	if _, _, err = run(t, Dependencies{}, "rules", "source", "set", "--from-config-source", "--read-only"); err == nil {
		t.Fatal("read-only binding accepted")
	}
	if _, _, err = run(t, Dependencies{}, "rules", "source", "set", "--from-config-source"); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(settings, true)
	if err != nil || cfg.Targets[0].RuleSource == nil || cfg.Targets[0].ConfigSource == nil {
		t.Fatal(cfg, err)
	}
}

func TestQuickRuleCLIInvalidInputAndFlagsNeverPrompt(t *testing.T) {
	isolated(t)
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { t.Fatal("invalid invocation inspected terminal"); return true }}
	for _, args := range [][]string{
		{"rules", "apply", "DOMAIN-SUFFIX,,DIRECT"},
		{"rules", "apply", "RULE-SET,custom,DIRECT"},
		{"rules", "apply", quickCLIRule, "--force"},
		{"rules", "apply", quickCLIRule, "--yes", "--dry-run"},
		{"rules", "apply", quickCLIRule, "--expect", "bad"},
	} {
		if _, _, err := run(t, deps, args...); err == nil || ExitCode(err) != 2 {
			t.Fatal(args, err)
		}
	}
}

func TestQuickRuleCompletionIsOffline(t *testing.T) {
	isolated(t)
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"__complete", "rules", "apply", "DOMAIN-S"}, "DOMAIN-SUFFIX,"},
		{[]string{"__complete", "rules", "source", "set", "--kind", "d"}, "docker"},
	} {
		out, _, err := run(t, Dependencies{}, test.args...)
		if err != nil || !strings.Contains(out, test.want) {
			t.Fatal(test.args, out, err)
		}
	}
}

func TestQuickRuleCLIConfirmationIsDefaultNegative(t *testing.T) {
	for _, answer := range []string{"", "\n", "n\n", "no\n", "\x1b\n", "yes!\n"} {
		accepted, err := confirmQuickRule(context.Background(), strings.NewReader(answer), io.Discard)
		if err != nil || accepted {
			t.Fatal(answer, accepted, err)
		}
	}
	for _, answer := range []string{"y\n", "YES\n"} {
		accepted, err := confirmQuickRule(context.Background(), strings.NewReader(answer), io.Discard)
		if err != nil || !accepted {
			t.Fatal(answer, accepted, err)
		}
	}
	_, source := quickCLIFixture(t, "prepend: []\n")
	before, _ := os.ReadFile(source)
	cmd := New(Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }})
	cmd.SetArgs([]string{"rules", "apply", quickCLIRule})
	cmd.SetIn(strings.NewReader("\n"))
	var out, diag bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&diag)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diag.String(), "[y/N]") || !strings.Contains(out.String(), "Canceled") {
		t.Fatal(out.String(), diag.String())
	}
	if got, _ := os.ReadFile(source); !bytes.Equal(before, got) {
		t.Fatal("Enter applied source")
	}
}
