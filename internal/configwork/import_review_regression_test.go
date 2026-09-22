package configwork

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreAdoptOnlyReceiptDoesNotReloadStartupSettings(t *testing.T) {
	for _, verge := range []bool{false, true} {
		f := newConfigFixture(t, verge)
		definition, err := ReadDefinition(context.Background(), f.target, "proxy", "node1", f.opts)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := definition.Raw()
		request := Request{Kind: "proxy", Action: "import", Input: raw, AdoptExisting: true, Groups: []string{"G1"}}
		plan, err := Preview(context.Background(), f.target, request, f.opts)
		if err != nil || len(plan.Changes) != 0 {
			t.Fatal(plan, err)
		}
		receipt, err := Apply(context.Background(), f.target, request, plan.Digest, f.opts)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(f.base)
		restored, err := Restore(context.Background(), f.target, receipt.ID, f.opts)
		after, _ := os.ReadFile(f.base)
		if err != nil || restored.Status != "restored_no_changes" || !restored.Restored || f.writes.Load() != 0 || string(before) != string(after) {
			t.Fatalf("adopt-only restore changed runtime/source: %+v %v writes=%d", restored, err, f.writes.Load())
		}
		verified, err := Verify(context.Background(), f.target, receipt.ID, f.opts)
		if err != nil || verified.Status != "restored_no_changes" || f.writes.Load() != 0 {
			t.Fatal(verified, err)
		}
	}
}
func TestVergeEmptyMergeRejectsMalformedExplicitNullTag(t *testing.T) {
	f := newConfigFixture(t, true)
	manifest := filepath.Join(f.target.ConfigSource.DataDir, "profiles.yaml")
	raw, _ := os.ReadFile(manifest)
	raw = []byte(strings.Replace(string(raw), "proxies: px, groups: gr", "proxies: px, groups: gr, merge: mg", 1) + "- {uid: mg, type: merge, file: merge.yaml}\n")
	os.WriteFile(manifest, raw, 0600)
	merge := filepath.Join(f.target.ConfigSource.DataDir, "profiles", "merge.yaml")
	for _, invalid := range []string{"!!null invalid-private-value\n", "!!null 123\n", "null\n---\n!!null invalid-private-value\n", "proxies: []\nproxies: []\n"} {
		os.WriteFile(merge, []byte(invalid), 0600)
		_, err := Inspect(context.Background(), f.target, f.opts)
		if err == nil {
			t.Fatalf("malformed merge accepted: %q", invalid)
		}
		if strings.Contains(err.Error(), "invalid-private-value") {
			t.Fatal("parser credential data leaked", err)
		}
	}
}
