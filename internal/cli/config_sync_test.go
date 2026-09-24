package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
)

func TestConfigSelectionParsingIsExplicitAndCredentialFree(t *testing.T) {
	targets := []config.Target{{ID: "server"}, {ID: "laptop"}}
	cases := []struct {
		text         string
		multi, valid bool
	}{
		{`{"objects":[{"id":"proxy/node"}]}`, false, true},
		{`{"objects":[{"id":"proxy/node"}]}`, true, false},
		{`{"destinations":[{"target":"server","selection":{"objects":[{"id":"proxy/node","replace":true}]}}]}`, true, true},
		{`{"destinations":[{"target":"other","selection":{"objects":[]}}]}`, true, false},
		{`{"destinations":[{"target":"server","selection":{}},{"target":"server","selection":{}}]}`, true, false},
		{`{"objects":[],"objects":[{"id":"proxy/node"}]}`, false, false},
		{`{"objects":[{"id":"proxy/node","password":"secret"}]}`, false, false},
		{`{"objects":[]} {"objects":[]}`, false, false},
		{`null`, false, false},
	}
	for _, tc := range cases {
		file := filepath.Join(t.TempDir(), "selection.json")
		if err := os.WriteFile(file, []byte(tc.text), 0600); err != nil {
			t.Fatal(err)
		}
		selected := targets
		if !tc.multi {
			selected = targets[:1]
		}
		result, err := readConfigSelection(file, selected)
		if (err == nil) != tc.valid {
			t.Errorf("%s: %v", tc.text, err)
		}
		if tc.valid && result["laptop"].Objects != nil {
			t.Fatal("choices were propagated to an omitted destination")
		}
	}
}

func TestConfigSyncCLIRejectsAmbiguousInvocationBeforeIO(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{
		{"configs", "sync", "a", "b"},
		{"configs", "sync", "a", "b", "--yes", "--selection", "absent.json"},
		{"configs", "sync", "a", "b", "--interactive", "--json"},
		{"configs", "sync", "a", "b", "--selection", "absent.json", "--expect", "digest"},
		{"configs", "diff", "a", "b", "--format", "raw"},
		{"configs", "diff", "a", "b", "--target", "a"},
	} {
		_, _, err := run(t, Dependencies{}, args...)
		if err == nil || ExitCode(err) != 2 {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestConfigDiffCLIReportsMaskedProxyAndRuleDriftWithoutWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX local source fixture")
	}
	settings := isolated(t)
	dir := t.TempDir()
	cfg, err := config.Load(settings, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"a", "b"} {
		path := filepath.Join(dir, id+".yaml")
		secret := "source-private-password"
		rule := "DOMAIN,example.test,DIRECT"
		if i == 1 {
			secret, rule = "destination-private-password", "MATCH,DIRECT"
		}
		raw := "# comment-private-token\nproxies:\n- {name: node, type: ss, server: example.test, port: 443, cipher: aes-128-gcm, password: " + secret + "}\nproxy-groups: []\nrules: [\"" + rule + "\"]\n"
		if err = os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Targets = append(cfg.Targets, config.Target{ID: id, Controller: "http://127.0.0.1:1", Configs: []config.CoreConfig{{ID: "main", Path: path}}, ConfigSource: &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/not/executed", Home: dir}})
	}
	cfg.DefaultTarget = "a"
	if err = config.Save(settings, cfg); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"tree", "unified", "json"} {
		args := []string{"configs", "diff", "a", "b"}
		if format == "json" {
			args = append(args, "--json")
		} else {
			args = append(args, "--format", format)
		}
		out, _, err := run(t, Dependencies{}, args...)
		if err != nil {
			t.Fatal(out, err)
		}
		for _, secret := range []string{"source-private-password", "destination-private-password", "comment-private-token"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaked a credential or comment", format)
			}
		}
		if format == "json" {
			var report configwork.ConfigDiffReport
			if json.Unmarshal([]byte(out), &report) != nil || len(report.Targets) != 1 || report.Targets[0].Diff == nil || report.Targets[0].Diff.Equal {
				t.Fatal(out)
			}
		}
	}
}
