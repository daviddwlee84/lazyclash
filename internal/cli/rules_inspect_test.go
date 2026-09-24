package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func decodeRuleInspectionJSON[T any](t *testing.T, raw string) T {
	t.Helper()
	var result T
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("invalid command JSON: %v\n%s", err, raw)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("stdout has extra content: %q", raw)
	}
	return result
}

func loadRuleInspectionSettings(t *testing.T, path string) config.Config {
	t.Helper()
	cfg, err := config.Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func saveRuleInspectionSettings(t *testing.T, path string, cfg config.Config) {
	t.Helper()
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
}

func inspectCLIReadOnlyDeps(t *testing.T, opens map[string]int) Dependencies {
	t.Helper()
	return Dependencies{
		Terminal: func(io.Reader, io.Writer) bool { t.Fatal("read-only inspection attempted a prompt"); return false },
		Open: func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
			if !readOnly {
				t.Fatal("inspection opened a writable client")
			}
			opens[target.ID]++
			if strings.HasPrefix(target.ID, "offline") {
				return nil, nil, &core.Error{Kind: core.KindUnreachable, Operation: "fixture offline"}
			}
			client, err := core.New(core.Options{Endpoint: target.Controller, ReadOnly: true})
			return client, nil, err
		},
	}
}

func TestRuleInspectCLIDiffPairAndBaselineAll(t *testing.T) {
	settings, sourceA := quickCLIFixture(t, "prepend:\n  - DOMAIN,example.com,DIRECT\nappend: []\ndelete: []\n")
	cfg := loadRuleInspectionSettings(t, settings)
	handler := testcore.NewHandler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg.Targets[0].Controller = server.URL
	second := cfg.Targets[0]
	second.ID = "b"
	owner := *second.RuleSource
	owner.DataDir = t.TempDir()
	second.RuleSource = &owner
	if err := os.MkdirAll(filepath.Join(owner.DataDir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(cfg.Targets[0].RuleSource.DataDir, "profiles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(owner.DataDir, "profiles.yaml"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	sourceB := filepath.Join(owner.DataDir, "profiles", "rules.yaml")
	if err = os.WriteFile(sourceB, []byte("prepend:\n  - DOMAIN,example.com,"+testcore.Selector+"\nappend: []\ndelete: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Targets = append(cfg.Targets, second, config.Target{ID: "offline", Controller: "http://127.0.0.1:1"})
	saveRuleInspectionSettings(t, settings, cfg)
	beforeSettings, _ := os.ReadFile(settings)
	beforeA, _ := os.ReadFile(sourceA)
	beforeB, _ := os.ReadFile(sourceB)
	opens := map[string]int{}
	deps := inspectCLIReadOnlyDeps(t, opens)
	out, diagnostics, err := run(t, deps, "rules", "diff", "a", "b", "--read-only", "--json")
	if err != nil || diagnostics != "" {
		t.Fatal(out, diagnostics, err)
	}
	pair := decodeRuleInspectionJSON[rulework.RuleDiffReport](t, out)
	if !pair.Complete || pair.Scope != "both" || pair.Baseline.TargetID != "a" || len(pair.Targets) != 1 || pair.Targets[0].Target.TargetID != "b" || pair.Targets[0].Runtime.Status != "equal" || pair.Targets[0].Source.Status != "different" || opens["a"] != 1 || opens["b"] != 1 {
		t.Fatalf("wrong A/B comparison: %+v opens=%v", pair, opens)
	}
	opens = map[string]int{}
	deps = inspectCLIReadOnlyDeps(t, opens)
	out, _, err = run(t, deps, "rules", "diff", "a", "--all", "--json")
	if err != nil {
		t.Fatal(out, err)
	}
	all := decodeRuleInspectionJSON[rulework.RuleDiffReport](t, out)
	if all.Complete || all.Status != "incomplete" || len(all.Targets) != 2 || all.Targets[1].Target.TargetID != "offline" || all.Targets[1].Runtime.Status != "unavailable" || opens["a"] != 1 || opens["b"] != 1 || opens["offline"] != 1 {
		t.Fatalf("wrong baseline/all results: %+v opens=%v", all, opens)
	}
	for _, request := range handler.Requests() {
		if request.Method != http.MethodGet || strings.Contains(request.Path, "healthcheck") || request.Path == "/dns/query" {
			t.Fatalf("inspection issued an active operation: %+v", request)
		}
	}
	for path, before := range map[string][]byte{settings: beforeSettings, sourceA: beforeA, sourceB: beforeB} {
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
			t.Fatalf("inspection changed fixture %s: %v", path, err)
		}
	}
}

func TestRuleInspectCLIFindFallbackVariantsAbsentAndUnknown(t *testing.T) {
	query := "DOMAIN-SUFFIX,example.test,DIRECT"
	settings, source := quickCLIFixture(t, "prepend:\n  - "+query+"\nappend:\n  - DOMAIN-SUFFIX,example.test,"+testcore.Selector+"\ndelete: []\n")
	cfg := loadRuleInspectionSettings(t, settings)
	owner := cfg.Targets[0].RuleSource
	cfg.Targets[0].ConfigSource = &config.ConfigSource{Kind: owner.Kind, Version: owner.Version, DataDir: owner.DataDir, ProfileUID: owner.ProfileUID}
	cfg.Targets[0].RuleSource = nil
	cfg.Targets = append(cfg.Targets, config.Target{ID: "unbound", Controller: cfg.Targets[0].Controller})
	saveRuleInspectionSettings(t, settings, cfg)
	beforeSettings, _ := os.ReadFile(settings)
	beforeSource, _ := os.ReadFile(source)
	opens := map[string]int{}
	deps := inspectCLIReadOnlyDeps(t, opens)
	out, diagnostics, err := run(t, deps, "rules", "find", query, "--all", "--json", "--read-only")
	if err != nil || diagnostics != "" {
		t.Fatal(out, diagnostics, err)
	}
	report := decodeRuleInspectionJSON[rulework.RuleFindReport](t, out)
	if report.Complete || len(report.Targets) != 2 || report.Targets[0].Target.SourceBinding != "config_source" || report.Targets[0].Source.Result == nil || !report.Targets[0].Source.Result.Found || len(report.Targets[0].Source.Result.Matches) != 2 {
		t.Fatalf("missing source fallback/exact/variant: %+v", report)
	}
	matches := report.Targets[0].Source.Result.Matches
	if matches[0].Kind != "exact" || matches[1].Kind != "same_selector" || len(matches[1].Differences) == 0 || report.Targets[0].Runtime.Result.Found || report.Targets[1].Source.Status != "unavailable" || report.Targets[1].Source.Result != nil {
		t.Fatalf("conflated source, runtime or unknown presence: %+v", report)
	}
	out, _, err = run(t, deps, "rules", "find", "DOMAIN,absent.example,DIRECT", "--all", "--json")
	if err != nil {
		t.Fatal(err)
	}
	absent := decodeRuleInspectionJSON[rulework.RuleFindReport](t, out)
	if absent.Targets[0].Source.Result.Found || len(absent.Targets[0].Source.Result.Matches) != 0 || absent.Targets[1].Source.Result != nil {
		t.Fatal("known absence and unavailable evidence were merged")
	}
	opens = map[string]int{}
	out, _, err = run(t, inspectCLIReadOnlyDeps(t, opens), "rules", "find", query, "--scope", "source", "--json")
	if err != nil || len(opens) != 0 {
		t.Fatal("source-only find contacted a controller", out, opens, err)
	}
	sourceOnly := decodeRuleInspectionJSON[rulework.RuleFindReport](t, out)
	if sourceOnly.Targets[0].Runtime != nil || !sourceOnly.Targets[0].Source.Result.Found {
		t.Fatal("source-only scope was ignored")
	}
	if human, diagnostics, err := run(t, deps, "rules", "find", query, "--scope", "source"); err != nil || diagnostics != "" || !strings.Contains(human, "found=true") {
		t.Fatal("human read-only find did not return data without prompting", human, diagnostics, err)
	}
	for path, before := range map[string][]byte{settings: beforeSettings, source: beforeSource} {
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
			t.Fatal("read-only source fallback wrote source or binding", path, err)
		}
	}
}

func TestRuleInspectCLILookupEarlierUnknownAndUnavailableExit(t *testing.T) {
	settings, _ := quickCLIFixture(t, "prepend:\n  - MATCH,DIRECT\n")
	deps := inspectCLIReadOnlyDeps(t, map[string]int{})
	out, diagnostics, err := run(t, deps, "rules", "lookup", "unlisted.example", "--read-only", "--json")
	if err != nil || diagnostics != "" {
		t.Fatal(out, diagnostics, err)
	}
	report := decodeRuleInspectionJSON[rulework.RuleLookupReport](t, out)
	if len(report.Targets) != 1 || report.Targets[0].Runtime.Result.Status != "unknown" || report.Targets[0].Runtime.Result.Winner != nil || report.Targets[0].Source.Result.Winner != nil {
		t.Fatal("lookup invented a winner past unknown/composed rules", report)
	}
	unknown := false
	for _, step := range report.Targets[0].Runtime.Result.Steps {
		unknown = unknown || step.Outcome == "unknown"
	}
	if !unknown {
		t.Fatal("runtime trace lost opaque provider evidence")
	}
	cfg := loadRuleInspectionSettings(t, settings)
	cfg.Targets = append(cfg.Targets, config.Target{ID: "offline", Controller: "http://127.0.0.1:1"})
	saveRuleInspectionSettings(t, settings, cfg)
	code, out, errOut := runProcess(t, deps, "rules", "lookup", "203.0.113.10", "--all", "--scope", "runtime", "--json")
	partial := decodeRuleInspectionJSON[rulework.RuleLookupReport](t, out)
	if code != 0 || errOut != "" || partial.Status != "incomplete" || len(partial.Targets) != 2 || partial.Targets[1].Runtime.Status != "unavailable" {
		t.Fatal("usable partial lookup failed or hid offline target", code, partial, errOut)
	}
	cfg = loadRuleInspectionSettings(t, settings)
	cfg.Targets = []config.Target{{ID: "offline-a", Controller: "http://127.0.0.1:1"}, {ID: "offline-b", Controller: "http://127.0.0.1:2"}}
	cfg.DefaultTarget = "offline-a"
	saveRuleInspectionSettings(t, settings, cfg)
	for _, args := range [][]string{{"rules", "lookup", "example.com", "--all", "--scope", "runtime", "--json"}, {"rules", "find", quickCLIRule, "--all", "--scope", "runtime", "--json"}, {"rules", "diff", "offline-a", "--all", "--scope", "runtime", "--json"}} {
		code, out, errOut = runProcess(t, deps, args...)
		result := decodeRuleInspectionJSON[map[string]any](t, out)
		if code == 0 || result["status"] != "unavailable" || result["complete"] != false {
			t.Fatal("all-unavailable request reported success", args, code, result, errOut)
		}
		decodeFailure(t, errOut)
	}
}

func TestRuleInspectCLIValidationAndCompletionStayOffline(t *testing.T) {
	settings := isolated(t)
	cfg := config.Config{DefaultTarget: "a", Targets: []config.Target{{ID: "a", Controller: "http://127.0.0.1:1", SecretEnv: "MUST_NOT_RESOLVE_FOR_COMPLETION"}, {ID: "b", Controller: "http://127.0.0.1:2"}}}
	saveRuleInspectionSettings(t, settings, cfg)
	deps := Dependencies{
		Terminal: func(io.Reader, io.Writer) bool { t.Fatal("validation/completion prompted"); return true },
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("validation/completion connected")
			return nil, nil, nil
		},
		Discover: func(context.Context, string) ([]config.Target, error) {
			t.Fatal("validation/completion discovered")
			return nil, nil
		},
	}
	for _, args := range [][]string{
		{"rules", "diff", "a", "b", "--scope", "typo"},
		{"rules", "diff", "a", "a"},
		{"rules", "diff", "a"},
		{"rules", "diff", "a", "b", "--all"},
		{"rules", "find", quickCLIRule, "--scope", "typo"},
		{"rules", "find", "DOMAIN,missing"},
		{"rules", "lookup", "https://example.com"},
		{"rules", "lookup", "example.com", "--scope", "typo"},
		{"--target", "a", "rules", "find", quickCLIRule, "--all"},
		{"--target", "a", "rules", "diff", "a", "b"},
	} {
		if _, _, err := run(t, deps, args...); err == nil || ExitCode(err) != 2 {
			t.Fatal("invalid invocation was accepted", args, err)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"rules", "diff", ""}, "a"},
		{[]string{"rules", "diff", "a", ""}, "b"},
		{[]string{"rules", "diff", "a", "b", "--scope", "r"}, "runtime"},
		{[]string{"rules", "find", "--scope", "s"}, "source"},
		{[]string{"rules", "lookup", "--scope", "b"}, "both"},
		{[]string{"rules", "find", "--target", ""}, "a"},
	} {
		out, _, err := run(t, deps, append([]string{"__complete"}, tc.args...)...)
		if err != nil || !strings.Contains(out, tc.want) || !strings.Contains(out, ":4") {
			t.Fatal("offline completion missing", tc.args, out, err)
		}
	}
}
