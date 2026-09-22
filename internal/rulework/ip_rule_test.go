package rulework

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeIPRulePrefix(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"134.185.90.66", "134.185.90.66/32"},
		{"134.185.90.66/32", "134.185.90.66/32"},
		{"192.0.2.17/28", "192.0.2.16/28"},
		{"2001:0DB8:0:0::1", "2001:db8::1/128"},
		{"2001:db8::abcd/120", "2001:db8::ab00/120"},
	} {
		got, err := NormalizeIPPrefix(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%q normalized as %q: %v", tc.input, got, err)
		}
	}
	for _, input := range []string{"", "example.com", "https://192.0.2.1", "192.0.2.1:22", "192.0.2.1/128", "2001:db8::/129", "fe80::1%en1", "fe80::1%en1/128", "::ffff:192.0.2.1", "::ffff:192.0.2.1/128", "192.0.2.1/32/32", "192.0.2.1\n", "192.0.2.1,PROXY"} {
		if prefix, err := NormalizeIPPrefix(input); err == nil {
			t.Fatalf("invalid/mixed input %q became %q", input, prefix)
		}
	}
}

func TestIPRulesPreviewApplyVerifyRestore(t *testing.T) {
	for _, tc := range []struct{ input, prefix, kind string }{
		{"134.185.90.66", "134.185.90.66/32", "IP-CIDR"},
		{"2001:0DB8::1", "2001:db8::1/128", "IP-CIDR6"},
		{"192.0.2.19/28", "192.0.2.16/28", "IP-CIDR"},
	} {
		t.Run(tc.kind+tc.prefix, func(t *testing.T) {
			f := newFixture(t, false)
			ctx := context.Background()
			plan, err := PreviewIP(ctx, f.target, tc.input, "DIRECT", f.opts)
			wantRule := tc.kind + "," + tc.prefix + ",DIRECT,no-resolve"
			if err != nil || plan.Domain != "" || plan.Prefix != tc.prefix || plan.Rule != wantRule || !strings.Contains(plan.Diff, "+ [0] "+wantRule) {
				t.Fatalf("bad IP preview: %+v %v", plan, err)
			}
			canonical, err := PreviewIP(ctx, f.target, tc.prefix, "DIRECT", f.opts)
			if err != nil || canonical.Digest != plan.Digest {
				t.Fatal("equivalent canonical input changed the preview digest")
			}
			encoded, _ := json.Marshal(plan)
			if strings.Contains(string(encoded), `"domain"`) || strings.Contains(string(encoded), "do-not-expose-this") {
				t.Fatal("IP preview mislabeled its prefix or exposed a secret")
			}
			if _, err := os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
				t.Fatal("preview wrote receipt state")
			}
			receipt, err := ApplyIP(ctx, f.target, tc.input, "DIRECT", plan.Digest, f.opts)
			if err != nil || receipt.Prefix != tc.prefix || receipt.Domain != "" || receipt.Status != "applied_verified" || !receipt.RuntimeVerified {
				t.Fatalf("IP apply did not verify: %+v %v", receipt, err)
			}
			source, _ := os.ReadFile(receipt.File)
			if !strings.Contains(string(source), wantRule) || !strings.Contains(string(source), "# keep this comment") {
				t.Fatal("IP rule or unrelated source content lost")
			}
			again, err := PreviewIP(ctx, f.target, tc.prefix, "DIRECT", f.opts)
			if err != nil || !again.NoChange {
				t.Fatal("IP rule was not idempotent", err)
			}
			restored, err := Restore(ctx, f.target, receipt.ID, f.opts)
			if err != nil || restored.Status != "restored_verified" {
				t.Fatal("IP restore did not verify", restored, err)
			}
			source, _ = os.ReadFile(receipt.File)
			if string(source) != string(f.source) {
				t.Fatal("restore did not preserve exact original bytes")
			}
		})
	}
}

func TestIPRuleReplacesOnlySameCanonicalPrefix(t *testing.T) {
	before := []byte("rules:\n  - DOMAIN,example.com,PROXY\n  - IP-CIDR,134.185.90.66/32,PROXY # keep comment\n  - IP-CIDR,134.185.90.66/24,PROXY,no-resolve\n  - IP-CIDR,134.185.90.66/32,OTHER\n  - IP-CIDR6,2001:0DB8::1/128,PROXY\n  - MATCH,PROXY\n")
	rule := "IP-CIDR,134.185.90.66/32,DIRECT,no-resolve"
	after, noChange, err := addRule(before, "mihomo", rule)
	if err != nil || noChange || strings.Count(string(after), "134.185.90.66/32") != 1 {
		t.Fatalf("same-prefix duplicates remain: %s %v", after, err)
	}
	for _, unchanged := range []string{"DOMAIN,example.com,PROXY", "IP-CIDR,134.185.90.66/24,PROXY,no-resolve", "IP-CIDR6,2001:0DB8::1/128,PROXY", "MATCH,PROXY", "keep comment"} {
		if !strings.Contains(string(after), unchanged) {
			t.Fatalf("removed an unrelated rule/comment: %s", unchanged)
		}
	}
	diff := ruleDiff(before, "mihomo", rule, "134.185.90.66/32", false)
	if !strings.Contains(diff, "- [1]") || !strings.Contains(diff, "- [3]") || strings.Contains(diff, "/24") || strings.Contains(diff, "example.com") {
		t.Fatal("IP preview did not isolate the reviewed changes", diff)
	}
}

func TestIPRuleRequiresExactFirstRuntimeTypePrefixAndPolicy(t *testing.T) {
	f := newFixture(t, true)
	ctx := context.Background()
	plan, err := PreviewIP(ctx, f.target, "134.185.90.66", "DIRECT", f.opts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ApplyIP(ctx, f.target, "134.185.90.66", "DIRECT", plan.Digest, f.opts)
	if err != nil || receipt.Status != "persisted_pending_owner_reload" || f.writes != 0 {
		t.Fatal("Verge IP rule unexpectedly reloaded runtime", receipt, err)
	}
	for _, tc := range []struct {
		kind, prefix, policy string
		want                 bool
	}{
		{"Domain", "134.185.90.66/32", "DIRECT", false},
		{"SrcIPCIDR", "134.185.90.66/32", "DIRECT", false},
		{"IPCIDR", "134.185.90.0/24", "DIRECT", false},
		{"IPCIDR", "134.185.90.66/32", "PROXY", false},
		{"IPCIDR", "134.185.90.66/32", "DIRECT", true},
	} {
		f.mu.Lock()
		f.rules = []map[string]any{{"type": tc.kind, "payload": tc.prefix, "proxy": tc.policy}}
		f.mu.Unlock()
		got, err := Verify(ctx, f.target, receipt.ID, f.opts)
		if err != nil || got.RuntimeVerified != tc.want {
			t.Fatalf("incorrect runtime proof for %+v: %+v %v", tc, got, err)
		}
	}
}

func TestIPRuleDigestAndReadOnlyRefuseBeforeWrite(t *testing.T) {
	for _, scenario := range []string{"wrong-prefix", "wrong-type", "read-only", "stale-source"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			ctx := context.Background()
			plan, err := PreviewIP(ctx, f.target, "134.185.90.66", "DIRECT", f.opts)
			if err != nil {
				t.Fatal(err)
			}
			want := f.source
			switch scenario {
			case "wrong-prefix":
				_, err = ApplyIP(ctx, f.target, "134.185.90.67", "DIRECT", plan.Digest, f.opts)
			case "wrong-type":
				_, err = Apply(ctx, f.target, "example.com", "DIRECT", plan.Digest, f.opts)
			case "read-only":
				f.opts.ReadOnly = true
				_, err = ApplyIP(ctx, f.target, "134.185.90.66", "DIRECT", plan.Digest, f.opts)
			case "stale-source":
				want = append([]byte("# external edit\n"), f.source...)
				os.WriteFile(plan.Owner.File, want, 0640)
				_, err = ApplyIP(ctx, f.target, "134.185.90.66", "DIRECT", plan.Digest, f.opts)
			}
			if err == nil || f.writes != 0 {
				t.Fatal("unreviewed IP write accepted")
			}
			data, _ := os.ReadFile(plan.Owner.File)
			if string(data) != string(want) {
				t.Fatal("refusal changed source bytes")
			}
			if _, err := os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
				t.Fatal("refusal wrote receipt state")
			}
		})
	}
}

func TestVergeMergeEmptyTemplatesDoNotRelaxOtherSources(t *testing.T) {
	for _, tc := range []struct {
		source string
		valid  bool
	}{
		{"# Profile Enhancement Merge Template\n\n", true}, {"", true}, {"null\n", true}, {"~\n", true}, {"!!null null\n", true}, {"{}\n", true},
		{"!!null malformed\n", false}, {"null\n---\n{}\n", false}, {"null\n---\n", false}, {"\"null\"\n", false}, {"[]\n", false}, {"rules: []\nrules: []\n", false},
	} {
		t.Run(strings.ReplaceAll(tc.source, "\n", "_"), func(t *testing.T) {
			f := newFixture(t, true)
			home := f.target.RuleSource.DataDir
			manifest := filepath.Join(home, "profiles.yaml")
			data, _ := os.ReadFile(manifest)
			data = append(data, []byte("  - uid: Merge\n    type: merge\n    file: merge.yaml\n")...)
			os.WriteFile(manifest, data, 0600)
			mergePath := filepath.Join(home, "profiles", "merge.yaml")
			os.WriteFile(mergePath, []byte(tc.source), 0600)
			_, err := InspectSource(context.Background(), f.target)
			if (err == nil) != tc.valid {
				t.Fatalf("Merge validity mismatch: %v", err)
			}
			if tc.valid && tc.source != "{}\n" {
				if _, _, err := addRule([]byte(tc.source), "verge", "DOMAIN,example.com,DIRECT"); err == nil {
					t.Fatal("empty Merge exception leaked to Rules source")
				}
			}
			readBack, _ := os.ReadFile(mergePath)
			if string(readBack) != tc.source {
				t.Fatal("inspection rewrote Merge template")
			}
		})
	}
}

func TestIPVerificationRejectsDisabledFirstRuleAndMalformedNoOp(t *testing.T) {
	f := newFixture(t, true)
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "IPCIDR", "payload": "134.185.90.66/32", "proxy": "DIRECT", "extra": map[string]any{"disabled": true}}}
	f.mu.Unlock()
	verified, err := runtimeFirstRule(context.Background(), f.target, "", "134.185.90.66/32", "DIRECT", f.opts)
	if err != nil || verified {
		t.Fatal("disabled rule was presented as an effective repair", err)
	}
	_, _, err = addRule([]byte("prepend:\n  - IP-CIDR,134.185.90.66/32,DIRECT,no-resolve\n  - invalid: mapping\n"), "verge", "IP-CIDR,134.185.90.66/32,DIRECT,no-resolve")
	if err == nil {
		t.Fatal("an identical first rule bypassed the companion schema check")
	}
}
