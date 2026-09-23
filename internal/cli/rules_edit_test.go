package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func TestRuleCLIRequiresReviewedDigestAndUsesVergeCompanion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	isolated(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	server := testcore.NewServer()
	defer server.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "fixture", "--controller", server.URL); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "Verge Data")
	os.MkdirAll(filepath.Join(home, "profiles"), 0700)
	manifest := []byte("current: selected\nitems:\n  - uid: selected\n    type: remote\n    option: {rules: rule-file}\n  - uid: rule-file\n    type: rules\n    file: rules.yaml\n")
	os.WriteFile(filepath.Join(home, "profiles.yaml"), manifest, 0600)
	path := filepath.Join(home, "profiles", "rules.yaml")
	original := []byte("prepend: []\nappend: []\ndelete: []\n")
	os.WriteFile(path, original, 0600)
	args := []string{"rules", "source", "set", "--kind", "verge", "--data-dir", home, "--profile", "selected", "--owner-version", "2.5.2", "--json"}
	out, _, err := run(t, Dependencies{}, args...)
	if err != nil || !json.Valid([]byte(out)) {
		t.Fatalf("source bind: %s %v", out, err)
	}
	base := []string{"rules", "add-domain", "example.com", "--via", testcore.Selector, "--json"}
	out, _, err = run(t, Dependencies{}, base...)
	var plan rulework.Plan
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil || len(plan.Digest) != 64 {
		t.Fatalf("preview: %s %v", out, err)
	}
	if _, _, err = run(t, Dependencies{}, append(append([]string{}, base...), "--yes")...); err == nil || ExitCode(err) != 2 {
		t.Fatal("unreviewed mutation accepted", err)
	}
	apply := append(append([]string{}, base...), "--yes", "--expect", plan.Digest)
	if _, _, err = run(t, Dependencies{}, append(append([]string{}, apply...), "--read-only")...); err == nil {
		t.Fatal("read-only apply accepted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != string(original) {
		t.Fatal("refused commands changed file")
	}
	out, _, err = run(t, Dependencies{}, apply...)
	var receipt rulework.Receipt
	if err != nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Status != "persisted_pending_owner_reload" {
		t.Fatalf("apply: %s %v", out, err)
	}
	if !strings.Contains(out, "Reactivate Profiles") {
		t.Fatal("missing required owner action")
	}
	out, _, err = run(t, Dependencies{}, "rules", "restore", receipt.ID, "--yes", "--json")
	if err != nil || !strings.Contains(out, "restored_pending_owner_reload") {
		t.Fatalf("restore: %s %v", out, err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != string(original) {
		t.Fatal("restore did not retain original")
	}
	data, _ = os.ReadFile(filepath.Join(home, "profiles.yaml"))
	if string(data) != string(manifest) {
		t.Fatal("profile manifest changed")
	}
}

func TestTargetTransportEditRequiresRuleOwnerRebinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		keep bool
	}{
		{"controller", []string{"--controller", "http://other.invalid:9090"}, false},
		{"ssh", []string{"--ssh", "other-host"}, false},
		{"credentials", []string{"--secret-env", "NEW_SECRET"}, true},
		{"name", []string{"--name", "Renamed"}, true},
		{"same normalized controller", []string{"--controller", "127.0.0.1:9090"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := isolated(t)
			if _, _, err := run(t, Dependencies{}, "targets", "add", "fixture", "--controller", "http://127.0.0.1:9090"); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path, true)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Targets[0].RuleSource = &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: "/verge", ProfileUID: "selected"}
			if err = config.Save(path, cfg); err != nil {
				t.Fatal(err)
			}
			if _, _, err = run(t, Dependencies{}, append([]string{"targets", "edit", "fixture"}, tc.args...)...); err != nil {
				t.Fatal(err)
			}
			cfg, err = config.Load(path, true)
			if err != nil {
				t.Fatal(err)
			}
			if (cfg.Targets[0].RuleSource != nil) != tc.keep {
				t.Fatalf("binding retention wrong: %+v", cfg.Targets[0])
			}
		})
	}
}

func TestIPRuleCLIUsesPrefixAndReviewedVergeCompanion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	for _, tc := range []struct{ address, prefix, kind string }{{"134.185.90.66", "134.185.90.66/32", "IP-CIDR"}, {"2001:0DB8::1", "2001:db8::1/128", "IP-CIDR6"}} {
		t.Run(tc.kind, func(t *testing.T) {
			isolated(t)
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			server := testcore.NewServer()
			defer server.Close()
			if _, _, err := run(t, Dependencies{}, "targets", "add", "fixture", "--controller", server.URL); err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(t.TempDir(), "Verge Data")
			os.MkdirAll(filepath.Join(home, "profiles"), 0700)
			manifest := []byte("current: selected\nitems:\n  - uid: selected\n    type: remote\n    option: {rules: rule-file}\n  - uid: rule-file\n    type: rules\n    file: rules.yaml\n  - uid: Merge\n    type: merge\n    file: merge.yaml\n")
			os.WriteFile(filepath.Join(home, "profiles.yaml"), manifest, 0600)
			path := filepath.Join(home, "profiles", "rules.yaml")
			original := []byte("prepend: []\nappend: []\ndelete: []\n")
			os.WriteFile(path, original, 0600)
			os.WriteFile(filepath.Join(home, "profiles", "merge.yaml"), []byte("# Profile Enhancement Merge Template\n"), 0600)
			if _, _, err := run(t, Dependencies{}, "rules", "source", "set", "--kind", "verge", "--data-dir", home, "--profile", "selected", "--owner-version", "2.5.2"); err != nil {
				t.Fatal(err)
			}
			base := []string{"rules", "add-ip", tc.address, "--policy", "DIRECT", "--json"}
			out, _, err := run(t, Dependencies{}, base...)
			var plan rulework.Plan
			if err != nil || json.Unmarshal([]byte(out), &plan) != nil || plan.Domain != "" || plan.Prefix != tc.prefix || plan.Rule != tc.kind+","+tc.prefix+",DIRECT,no-resolve" {
				t.Fatalf("IP preview: %s %v", out, err)
			}
			if strings.Contains(out, `"domain"`) {
				t.Fatal("IP prefix labeled as a domain")
			}
			if _, _, err = run(t, Dependencies{}, append(append([]string{}, base...), "--yes")...); err == nil {
				t.Fatal("unreviewed IP apply accepted")
			}
			apply := append(append([]string{}, base...), "--yes", "--expect", plan.Digest)
			if _, _, err = run(t, Dependencies{}, append(append([]string{}, apply...), "--read-only")...); err == nil {
				t.Fatal("read-only IP apply accepted")
			}
			before, _ := os.ReadFile(path)
			if string(before) != string(original) {
				t.Fatal("preview/refused apply changed source")
			}
			out, _, err = run(t, Dependencies{}, apply...)
			var receipt rulework.Receipt
			if err != nil || json.Unmarshal([]byte(out), &receipt) != nil || receipt.Status != "persisted_pending_owner_reload" || receipt.Prefix != tc.prefix {
				t.Fatalf("IP apply: %s %v", out, err)
			}
			written, _ := os.ReadFile(path)
			if !strings.Contains(string(written), plan.Rule) {
				t.Fatal("IP rule not persisted")
			}
			if _, _, err = run(t, Dependencies{}, "rules", "restore", receipt.ID, "--yes"); err != nil {
				t.Fatal(err)
			}
			restored, _ := os.ReadFile(path)
			if string(restored) != string(original) {
				t.Fatal("IP restore lost original source")
			}
			currentManifest, _ := os.ReadFile(filepath.Join(home, "profiles.yaml"))
			if string(currentManifest) != string(manifest) {
				t.Fatal("IP workflow modified Verge manifest")
			}
		})
	}
}
