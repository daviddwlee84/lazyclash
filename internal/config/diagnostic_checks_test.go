package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiagnosticChecksValidateWithoutWritingDefaults(t *testing.T) {
	for _, endpoint := range []string{"https://example.com/generate_204", "http://localhost:8080/", "http://127.0.0.1:1/", "https://[2001:db8::1]:65535/check", "https://xn--bcher-kva.example/", "https://example.com./", "https://example.com/測試", "https://example.com/a%23b"} {
		check := DiagnosticCheck{ID: "a.0_check-1", Name: "測試", URL: endpoint, Via: "🚀 PROXY"}
		if err := ValidateTarget(Target{Controller: "http://localhost:9090", Checks: []DiagnosticCheck{check}}); err != nil {
			t.Fatalf("valid endpoint %q: %v", endpoint, err)
		}
		if check.ExpectedStatuses != nil {
			t.Fatal("validation mutated absent status defaults")
		}
	}
	checks := make([]DiagnosticCheck, 64)
	for i := range checks {
		checks[i] = DiagnosticCheck{ID: fmt.Sprintf("check-%d", i), URL: "https://example.com/", ExpectedStatuses: []int{100, 200, 399, 599}}
	}
	if err := ValidateDiagnosticChecks(checks); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDiagnosticChecks(append(checks, DiagnosticCheck{ID: "extra", URL: "https://example.com/"})); err == nil {
		t.Fatal("accepted more than 64 checks")
	}
}

func TestDiagnosticChecksRejectUnsafeOrAmbiguousConfiguration(t *testing.T) {
	for _, endpoint := range []string{
		"", "/relative", "ftp://example.com/", "https:example.com", "https:///path", "https://:443/",
		"https://user:PRIVATE@host/", "https://@host/", "https://host/?token=PRIVATE", "https://host/?", "https://host/#PRIVATE", "https://host/#",
		"https://host:0/", "https://host:65536/", "https://host:wat/", "https://host:/", "https://host:443x/",
		"https://host\n/", "https://host/%00", "https://host/%0A", "https://host/a\x7fb",
		"https://例子.example/", "https://bad_host/", "https://bad,host/", "https://-bad.host/", "https://bad..host/",
		"https://[not-ip]/", "https://[127.0.0.1]/", "https://::1/", "https://host/" + strings.Repeat("x", 8192),
	} {
		err := ValidateDiagnosticChecks([]DiagnosticCheck{{ID: "test", URL: endpoint}})
		if err == nil {
			t.Errorf("accepted invalid endpoint %q", endpoint)
		} else if strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("validation exposed credentials/query")
		}
	}
	for _, edit := range []func(*DiagnosticCheck){
		func(c *DiagnosticCheck) { c.ID = "" }, func(c *DiagnosticCheck) { c.ID = "-bad" }, func(c *DiagnosticCheck) { c.ID = strings.Repeat("x", 65) },
		func(c *DiagnosticCheck) { c.Name = strings.Repeat("x", 257) }, func(c *DiagnosticCheck) { c.Via = strings.Repeat("x", 257) },
		func(c *DiagnosticCheck) { c.Name = "bad\nname" }, func(c *DiagnosticCheck) { c.Via = "proxy\x1b[2J" },
		func(c *DiagnosticCheck) { c.ExpectedStatuses = []int{99} }, func(c *DiagnosticCheck) { c.ExpectedStatuses = []int{600} }, func(c *DiagnosticCheck) { c.ExpectedStatuses = []int{200, 200} },
	} {
		check := DiagnosticCheck{ID: "test", URL: "https://example.com/"}
		edit(&check)
		if err := ValidateDiagnosticChecks([]DiagnosticCheck{check}); err == nil {
			t.Fatalf("accepted invalid check: %+v", check)
		}
	}
	if err := ValidateDiagnosticChecks([]DiagnosticCheck{{ID: "same", URL: "https://example.com/"}, {ID: "same", URL: "https://example.net/"}}); err == nil {
		t.Fatal("accepted duplicate IDs")
	}
}

func TestDiagnosticChecksPreserveAddEditRemoveAndOtherTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	other := `[[targets]] # other target stays exact
id = "second"
controller = "http://localhost:9097"
[[targets.checks]] # second check stays exact
id = "web"
url = "https://second.example/"
expected_statuses = [ 204 ] # unrelated policy
future_second = "keep"
`
	original := `# config note
[[targets]]
id = "first"
controller = "http://localhost:9090"
future_target = "keep"
[[targets.configs]] # profile stays
id = "work"
path = "/srv/work.yaml"
future_config = "keep"
[[targets.checks]] # web stays
id = "web"
url = "https://old.example/" # endpoint explanation
via = "old group"
expected_statuses = [
  0xC8, # accepted success ] comment
  204, # no content
] # policy explanation
future_check = "keep"
[targets.checks.future]
note = "nested keep"
[[targets.checks]] # remove only this check
id = "remove"
url = "https://remove.example/"
` + other
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	want := cfg.Targets[0].Checks[0]
	want.URL, want.Name, want.Via = "https://new.example/check", "新的測試", ""
	want.ExpectedStatuses = []int{201, 204, 301}
	added := DiagnosticCheck{ID: "new", URL: "https://new.example/generate_204", ExpectedStatuses: []int{204}}
	cfg.Targets[0].Checks = []DiagnosticCheck{want, added}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, true)
	if err != nil || !reflect.DeepEqual(loaded.Targets[0].Checks, cfg.Targets[0].Checks) {
		t.Fatalf("checks were not saved: %+v, %v", loaded.Targets, err)
	}
	raw, _ := os.ReadFile(path)
	for _, fragment := range []string{"# config note", "# profile stays", "future_config = \"keep\"", "future_target = \"keep\"", "# web stays", "# endpoint explanation", "# accepted success ] comment", "# no content", "# policy explanation", "future_check = \"keep\"", "note = \"nested keep\"", other} {
		if !strings.Contains(string(raw), fragment) {
			t.Fatalf("lost settings/comment %q:\n%s", fragment, raw)
		}
	}
	if strings.Contains(string(raw), "remove.example") {
		t.Fatal("removed check remains")
	}
	loaded.Targets[0].Checks = nil
	if err := Save(path, loaded); err != nil {
		t.Fatal(err)
	}
	final, err := Load(path, true)
	if err != nil || len(final.Targets[0].Checks) != 0 || len(final.Targets[1].Checks) != 1 || len(final.Targets[0].Configs) != 1 {
		t.Fatalf("removal affected another owner: %+v, %v", final.Targets, err)
	}
	raw, _ = os.ReadFile(path)
	if !strings.Contains(string(raw), other) || !strings.Contains(string(raw), "future_target = \"keep\"") {
		t.Fatal("removal changed another target or root settings")
	}
}

func TestDiagnosticStatusEditsPreserveArrayComments(t *testing.T) {
	for _, original := range []string{"[200, 204]", "[200, 204,]", "[\n0xC8, # keep comment ]\n204, # keep second\n]", "[]", "[ # keep empty\n]"} {
		for _, next := range [][]int{nil, {}, {201}, {201, 204}, {201, 204, 301, 400}} {
			t.Run(fmt.Sprintf("%s-%v", original, next), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.toml")
				raw := "[[targets]]\nid='core'\ncontroller='http://localhost:9090'\n[[targets.checks]]\nid='web'\nurl='https://example.com/'\nexpected_statuses = " + original + " # trailing keep\nfuture=17\n"
				if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := Load(path, true)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Targets[0].Checks[0].ExpectedStatuses = next
				if err := Save(path, cfg); err != nil {
					t.Fatal(err)
				}
				loaded, err := Load(path, true)
				if err != nil || len(loaded.Targets[0].Checks[0].ExpectedStatuses) != len(next) {
					t.Fatalf("status array failed roundtrip: %+v, %v", loaded, err)
				}
				for i, status := range next {
					if loaded.Targets[0].Checks[0].ExpectedStatuses[i] != status {
						t.Fatal("wrong status saved")
					}
				}
				got, _ := os.ReadFile(path)
				for _, comment := range []string{"# trailing keep", "# keep comment ]", "# keep second", "# keep empty", "future=17"} {
					if strings.Contains(raw, comment) && !strings.Contains(string(got), comment) {
						t.Fatalf("lost comment %q:\n%s", comment, got)
					}
				}
			})
		}
	}
}

func TestDiagnosticChecksRetainInlineLayoutUntilEditedAndGuardConcurrentSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "[[targets]]\nid='core'\ncontroller='http://localhost:9090'\nchecks=[{id='web',url='https://example.com/'}] # inline note\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].Name = "updated target"
	if err := Save(path, cfg); err != nil {
		t.Fatal("unchanged checks should not block other target edits:", err)
	}
	cfg, _ = Load(path, true)
	before, _ := os.ReadFile(path)
	cfg.Targets[0].Checks[0].URL = "https://changed.example/"
	if err := Save(path, cfg); err == nil || !strings.Contains(err.Error(), "[[targets.checks]]") {
		t.Fatalf("inline check edit did not fail safely: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(before) {
		t.Fatal("unsupported layout changed")
	}
	if err := os.WriteFile(path, append(before, []byte("# another writer\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); !errors.Is(err, ErrConflict) {
		t.Fatalf("check edit bypassed concurrent-write guard: %v", err)
	}
}
