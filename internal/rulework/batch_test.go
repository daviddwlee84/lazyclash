package rulework

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
)

var batchRules = []string{"DOMAIN,one.example,PROXY", "DOMAIN,two.example,DIRECT", "IP-CIDR,192.0.2.7/32,DIRECT,no-resolve"}

func TestRuleBatchOrderedSingleWriteReceiptReloadAndRestore(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	validations, writes := 0, 0
	validate := f.opts.Validate
	f.opts.Validate = func(ctx context.Context, target config.Target, data []byte, version string) error {
		validations++
		return validate(ctx, target, data, version)
	}
	f.opts.Host = func(ctx context.Context, target config.Target, request HostRequest) (HostFile, error) {
		if request.Op == "write" {
			writes++
		}
		return hostCall(ctx, target.SSHHost, request)
	}
	raw := append(append([]string{}, batchRules...), "DOMAIN,ONE.EXAMPLE,PROXY")
	p, err := PreviewRuleBatch(ctx, []config.Target{f.target}, raw, false, f.opts)
	if err != nil || !reflect.DeepEqual(p.Rules, batchRules) || p.Rule != "" || validations != 1 {
		t.Fatal(p, validations, err)
	}
	if writes != 0 || f.writes != 0 || !strings.Contains(p.Targets[0].Diff, "+ [2] "+batchRules[2]) {
		t.Fatal("preview changed source or lost ordered additions", p, writes, f.writes)
	}
	validations = 0
	r, err := ApplyRuleBatch(ctx, []config.Target{f.target}, raw, false, p.Digest, f.opts)
	if err != nil || r.Status != "completed" || r.Results[0].Status != "applied_verified" {
		t.Fatal(r, err)
	}
	if validations != 1 || writes != 1 || f.writes != 1 {
		t.Fatal("batch did not validate/write/reload exactly once", validations, writes, f.writes)
	}
	receipt := r.Results[0].Receipt
	if receipt == nil || !reflect.DeepEqual(receipt.Rules, batchRules) || !reflect.DeepEqual(receipt.AddedRules, batchRules) || receipt.Rule != "" {
		t.Fatal("incomplete batch receipt", receipt)
	}
	entries, err := os.ReadDir(f.opts.StateDir)
	if err != nil || len(entries) != 1 {
		t.Fatal("batch created more than one receipt", entries, err)
	}
	got, err := sourceRuleList(Source{file: readBatchFile(t, receipt.File)})
	if err != nil || !reflect.DeepEqual(quickExpressions(got), append(append([]string{}, batchRules...), "MATCH,DIRECT")) {
		t.Fatal(got, err)
	}
	if _, err := Verify(ctx, f.target, receipt.ID, f.opts); err != nil {
		t.Fatal(err)
	}
	p, err = PreviewRuleBatch(ctx, []config.Target{f.target}, batchRules, false, f.opts)
	if err != nil || p.Status != "no_changes" || p.Targets[0].Status != "skipped_existing" || !p.Targets[0].RuntimeVerified {
		t.Fatal(p, err)
	}
	if result, err := ApplyRuleBatch(ctx, []config.Target{f.target}, batchRules, false, p.Digest, f.opts); err != nil || result.Results[0].Receipt != nil || writes != 1 || f.writes != 1 {
		t.Fatal("all-existing batch wrote or reloaded", result, err)
	}
	if restored, err := Restore(ctx, f.target, receipt.ID, f.opts); err != nil || restored.Status != "restored_verified" {
		t.Fatal(restored, err)
	}
	before, _ := os.ReadFile(receipt.File)
	if string(before) != string(f.source) {
		t.Fatal("batch restore did not retain original source bytes")
	}
}

func readBatchFile(t *testing.T, path string) hostFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return hostFile{Data: data}
}

func TestRuleBatchMixedExistingAndVerifyEveryRule(t *testing.T) {
	for _, failure := range []string{"later_missing", "reordered", "disabled", "retained_missing"} {
		t.Run(failure, func(t *testing.T) {
			f := newFixture(t, false)
			quickSource(t, f, "rules:\n- DOMAIN,retained.example,PROXY\n- MATCH,DIRECT\n")
			rules := []string{"DOMAIN,retained.example,PROXY", batchRules[0], batchRules[1]}
			p, err := PreviewRuleBatch(context.Background(), []config.Target{f.target}, rules, false, f.opts)
			if err != nil || p.Targets[0].Rules[0].Status != "skipped_existing" {
				t.Fatal(p, err)
			}
			r, err := ApplyRuleBatch(context.Background(), []config.Target{f.target}, rules, false, p.Digest, f.opts)
			if err != nil || !r.Results[0].RuntimeVerified || len(r.Results[0].Receipt.AddedRules) != 2 {
				t.Fatal(r, err)
			}
			f.mu.Lock()
			switch failure {
			case "later_missing":
				f.rules = append(f.rules[:1], f.rules[2:]...)
			case "reordered":
				f.rules[0], f.rules[1] = f.rules[1], f.rules[0]
			case "disabled":
				f.rules[1]["extra"] = map[string]any{"disabled": true}
			case "retained_missing":
				f.rules = append(f.rules[:2], f.rules[3:]...)
			}
			f.mu.Unlock()
			verified, err := Verify(context.Background(), f.target, r.Results[0].Receipt.ID, f.opts)
			if err != nil || verified.RuntimeVerified || verified.Status != "persisted_not_verified" {
				t.Fatal("partial runtime incorrectly verified whole batch", verified, err)
			}
		})
	}
}

func TestRuleBatchRejectsInvalidAndInternalConflictBeforeIO(t *testing.T) {
	opts := Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("invalid batch opened controller")
		return nil, nil, nil
	}, Host: func(context.Context, config.Target, HostRequest) (HostFile, error) {
		t.Fatal("invalid batch read source")
		return HostFile{}, nil
	}}
	for _, raw := range [][]string{nil, {batchRules[0], "DOMAIN,invalid..example,DIRECT"}, {batchRules[0], "DOMAIN,ONE.EXAMPLE,DIRECT"}, make([]string, MaxRuleBatchSize+1)} {
		p, err := PreviewRuleBatch(context.Background(), []config.Target{{ID: "target"}}, raw, false, opts)
		if err == nil || p.Status != "blocked" {
			t.Fatal("invalid batch accepted", p, err)
		}
	}
}

func TestRuleBatchAllPreflightBlocksBeforeAnyWrite(t *testing.T) {
	a, b := newFixture(t, false), newFixture(t, false)
	a.target.ID, b.target.ID = "a", "b"
	quickSource(t, b, "rules:\n- DOMAIN,two.example,PROXY\n- MATCH,DIRECT\n")
	opts := a.opts
	p, err := PreviewRuleBatch(context.Background(), []config.Target{b.target, a.target}, batchRules, true, opts)
	if err == nil || p.Targets[0].Status != "ready" || p.Targets[1].Status != "blocked" || !quickFindings(p.Targets[1].Findings, "selector_conflict") {
		t.Fatal(p, err)
	}
	if _, err = ApplyRuleBatch(context.Background(), []config.Target{a.target, b.target}, batchRules, true, p.Digest, opts); err == nil {
		t.Fatal("batch conflict bypassed")
	}
	quickAssertUnchanged(t, a, b)
}

func TestRuleBatchGuardsSourceRuntimeAndOrder(t *testing.T) {
	for _, change := range []string{"source", "runtime", "order"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t, false)
			raw := append([]string{}, batchRules...)
			p, err := PreviewRuleBatch(context.Background(), []config.Target{f.target}, raw, false, f.opts)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "source":
				quickSource(t, f, "rules:\n- DOMAIN,intervening.example,PROXY\n- MATCH,DIRECT\n")
			case "runtime":
				f.mu.Lock()
				f.rules[0]["proxy"] = "PROXY"
				f.mu.Unlock()
			case "order":
				raw[0], raw[1] = raw[1], raw[0]
			}
			if _, err = ApplyRuleBatch(context.Background(), []config.Target{f.target}, raw, false, p.Digest, f.opts); err == nil {
				t.Fatal("stale batch was applied")
			}
			quickAssertUnchanged(t, f)
		})
	}
}

func TestRuleBatchVergePendingAndRuntimeConflict(t *testing.T) {
	f := newFixture(t, true)
	p, err := PreviewRuleBatch(context.Background(), []config.Target{f.target}, batchRules, false, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ApplyRuleBatch(context.Background(), []config.Target{f.target}, batchRules, false, p.Digest, f.opts)
	if err != nil || r.Results[0].Status != "persisted_pending_owner_reload" || f.writes != 0 {
		t.Fatal(r, err)
	}
	data := readBatchFile(t, filepath.Join(f.target.RuleSource.DataDir, "profiles", "owned.yaml"))
	got, err := sourceRuleList(Source{Kind: "verge", file: data})
	if err != nil || !reflect.DeepEqual(quickExpressions(got), batchRules) {
		t.Fatal(got, err)
	}
	f.mu.Lock()
	f.rules = append(f.rules, map[string]any{"type": "Domain", "payload": "two.example", "proxy": "PROXY"})
	f.mu.Unlock()
	p, err = PreviewRuleBatch(context.Background(), []config.Target{f.target}, batchRules, false, f.opts)
	if err == nil || p.Targets[0].Status != "blocked" {
		t.Fatal("retained Verge runtime conflict accepted", p, err)
	}
}

func TestRuleBatchSingleJSONAndReceiptCompatibility(t *testing.T) {
	f := newFixture(t, false)
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, batchRules[0], false, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ApplyRules(context.Background(), []config.Target{f.target}, batchRules[0], false, p.Digest, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range []any{p, r, r.Results[0].Receipt} {
		data, _ := json.Marshal(object)
		if strings.Contains(string(data), `"added_rules"`) || strings.Contains(string(data), `"rules":`) || !strings.Contains(string(data), `"rule":"`+batchRules[0]+`"`) {
			t.Fatal("single-rule public shape changed", string(data))
		}
	}
}

func TestRuleBatchAllSkipsAndStopsAfterLaterFailure(t *testing.T) {
	a, b := newFixture(t, false), newFixture(t, false)
	a.target.ID, b.target.ID = "a", "b"
	b.reject = true
	targets := []config.Target{b.target, {ID: "unbound", Controller: "http://127.0.0.1:1"}, a.target}
	p, err := PreviewRuleBatch(context.Background(), targets, batchRules, true, a.opts)
	if err != nil || p.Targets[2].Status != "skipped_unavailable" {
		t.Fatal(p, err)
	}
	r, err := ApplyRuleBatch(context.Background(), targets, batchRules, true, p.Digest, a.opts)
	if err == nil || r.Status != "stopped" || r.Results[0].Status != "applied_verified" || r.Results[1].Status != "runtime_result_unknown" || r.Results[0].Receipt == nil || r.Results[1].Receipt == nil {
		t.Fatal("partial results lost", r, err)
	}
	if a.writes != 1 || b.writes != 1 {
		t.Fatal("batch retried uncertain reload", a.writes, b.writes)
	}
}

func TestRuleBatchAnalyzesRequestedOrdering(t *testing.T) {
	f := newFixture(t, false)
	rules := []string{"DOMAIN-SUFFIX,example,PROXY", "DOMAIN,api.example,DIRECT"}
	p, err := PreviewRuleBatch(context.Background(), []config.Target{f.target}, rules, false, f.opts)
	if err != nil || !quickFindings(p.Targets[0].Findings, "shadowed") {
		t.Fatal("broad first rule did not report batch shadowing", p, err)
	}
	reverse, err := PreviewRuleBatch(context.Background(), []config.Target{f.target}, []string{rules[1], rules[0]}, false, f.opts)
	if err != nil || reverse.Digest == p.Digest || quickFindings(reverse.Targets[0].Findings, "shadowed") {
		t.Fatal("batch order did not affect overlap analysis", reverse, err)
	}
}

func TestRuleBatchBlocksPendingDiscoveryAcrossTargetAliasesAndBeforeWrite(t *testing.T) {
	for _, when := range []string{"preflight", "before_write"} {
		t.Run(when, func(t *testing.T) {
			f := newFixture(t, false)
			plan, err := discoveryguard.Preview(context.Background(), f.target)
			if err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat("b", 32)
			data, err := json.Marshal(map[string]any{"version": 1, "settings_path": "/other/settings.toml", "plan": plan, "status": discoveryguard.Status{ID: id, TargetID: f.target.ID, Phase: "active", Deadline: time.Now().Add(time.Minute), UpdatedAt: time.Now()}})
			if err != nil {
				t.Fatal(err)
			}
			installGuard := func() {
				dir := filepath.Join(os.Getenv("XDG_STATE_HOME"), "lazyclash", "discovery-guards")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			alias := f.target
			alias.ID = "another-name-for-the-same-controller"
			if when == "preflight" {
				installGuard()
				p, err := PreviewRuleBatch(context.Background(), []config.Target{alias}, batchRules, false, f.opts)
				if err == nil || p.Targets[0].ReasonCode != "discovery_restore_pending" {
					t.Fatal("target alias bypassed active discovery", p, err)
				}
			} else {
				p, err := PreviewRuleBatch(context.Background(), []config.Target{f.target}, batchRules, false, f.opts)
				if err != nil {
					t.Fatal(err)
				}
				f.opts.Host = func(ctx context.Context, target config.Target, request HostRequest) (HostFile, error) {
					if request.Op == "check" {
						installGuard()
					}
					return hostCall(ctx, target.SSHHost, request)
				}
				if _, err = ApplyRuleBatch(context.Background(), []config.Target{f.target}, batchRules, false, p.Digest, f.opts); err == nil {
					t.Fatal("discovery activated during apply was ignored")
				}
			}
			quickAssertUnchanged(t, f)
		})
	}
}
