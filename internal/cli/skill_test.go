package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/selfupdate"
	"github.com/daviddwlee84/lazyclash/internal/skill"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
	"github.com/daviddwlee84/lazyclash/internal/tui"
)

func staticSkillDependencies(t *testing.T) Dependencies {
	t.Helper()
	return Dependencies{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("skill output opened a controller")
			return nil, nil, nil
		},
		Discover: func(context.Context, string) ([]config.Target, error) {
			t.Fatal("skill output discovered controllers")
			return nil, nil
		},
		Terminal: func(io.Reader, io.Writer) bool {
			t.Fatal("skill output checked terminal state")
			return false
		},
		RunTUI: func(context.Context, tui.Options, io.Reader, io.Writer) error {
			t.Fatal("skill output started a TUI")
			return nil
		},
	}
}

func TestSkillOutputIsStaticAndMatchesEmbeddedDocuments(t *testing.T) {
	settingsPath := isolated(t)
	corrupt := filepath.Join(t.TempDir(), "corrupt.toml")
	contents := []byte("[this is not valid TOML")
	if err := os.WriteFile(corrupt, contents, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAZYCLASH_CONFIG", corrupt)
	t.Setenv("LAZYCLASH_TARGET", "conflicting-target")
	t.Setenv("LAZYCLASH_CONTROLLER", "http://127.0.0.1:1")
	for _, test := range []struct {
		args  []string
		topic string
	}{
		{args: []string{"--skill"}},
		{args: []string{"--skill=true"}},
		{args: []string{"skill", "print"}},
		{args: []string{"skill", "print", "controllers"}, topic: "controllers"},
		{args: []string{"skill", "print", "runtime"}, topic: "runtime"},
		{args: []string{"skill", "print", "automation"}, topic: "automation"},
		{args: []string{"--config", "/does/not/exist", "--skill"}},
		{args: []string{"--target", "unused", "--controller", "http://127.0.0.1:1", "skill", "print"}},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			out, diagnostics, err := run(t, staticSkillDependencies(t), test.args...)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := skill.Read(test.topic)
			if out != want || diagnostics != "" {
				t.Fatalf("document output changed or gained diagnostics: stdout=%q stderr=%q", out, diagnostics)
			}
		})
	}
	if _, err := os.Stat(settingsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("skill output created settings: %v", err)
	}
	after, err := os.ReadFile(corrupt)
	if err != nil || !bytes.Equal(after, contents) {
		t.Fatalf("skill output modified corrupt settings: %q %v", after, err)
	}
}

func TestSkillRejectsInvalidArgumentsWithoutRuntimeAccess(t *testing.T) {
	isolated(t)
	for _, args := range [][]string{
		{"--skill", "--json"},
		{"skill", "print", "--json"},
		{"skill", "print", "automation", "--json"},
		{"skill", "print", "missing"},
		{"skill", "print", "../SKILL.md"},
		{"skill", "print", "runtime", "controllers"},
		{"skill", "print", "--unknown"},
		{"skill", "unknown"},
		{"--skill", "--unknown"},
		{"--skill", "extra"},
		{"--skill", "status"},
		{"status", "--skill"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, _, err := run(t, staticSkillDependencies(t), args...)
			if err == nil || ExitCode(err) != 2 || out != "" {
				t.Fatalf("expected usage error without document output: %q %v", out, err)
			}
		})
	}
}

func TestSkillFalsePreservesNormalRootBehavior(t *testing.T) {
	isolated(t)
	checkedTerminal := false
	deps := staticSkillDependencies(t)
	deps.Terminal = func(io.Reader, io.Writer) bool {
		checkedTerminal = true
		return false
	}
	out, _, err := run(t, deps, "--skill=false")
	if err != nil || !checkedTerminal || !strings.Contains(out, "Usage:") {
		t.Fatalf("--skill=false did not use the ordinary non-TTY root path: %q %v", out, err)
	}
}

func TestSkillPropagatesOutputFailure(t *testing.T) {
	isolated(t)
	failure := errors.New("document output closed")
	cmd := New(staticSkillDependencies(t))
	cmd.SetArgs([]string{"skill", "print", "runtime"})
	cmd.SetOut(brokenWriter{failure})
	cmd.SetErr(io.Discard)
	if err := cmd.ExecuteContext(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("wrong output error: %v", err)
	}
}

// The guide's sh blocks intentionally use simple arguments and individually
// quoted variable placeholders. Execute those actual examples against a fixture
// to catch command drift without invoking a shell or a real controller.
func skillExampleCommands(t *testing.T, topic string, variables map[string]string) [][]string {
	t.Helper()
	document, err := skill.Read(topic)
	if err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	inShell := false
	for _, line := range strings.Split(document, "\n") {
		if line == "```sh" {
			inShell = true
			continue
		}
		if line == "```" {
			inShell = false
			continue
		}
		if !inShell || !strings.HasPrefix(line, "lazyclash ") {
			continue
		}
		args := strings.Fields(line)[1:]
		for i, arg := range args {
			if strings.HasPrefix(arg, `"$`) && strings.HasSuffix(arg, `"`) {
				key := strings.TrimSuffix(strings.TrimPrefix(arg, `"$`), `"`)
				value, ok := variables[key]
				if !ok {
					t.Fatalf("unknown variable %q in embedded example", key)
				}
				args[i] = value
			}
		}
		commands = append(commands, args)
	}
	if len(commands) == 0 {
		t.Fatal("no executable examples in guide")
	}
	return commands
}

func TestSkillWorkflowExamplesAgainstFixture(t *testing.T) {
	isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "fixture", "--controller", server.URL); err != nil {
		t.Fatal(err)
	}
	variables := map[string]string{"TARGET": "fixture", "GROUP": testcore.Selector, "MEMBER": testcore.Tokyo}
	for _, topic := range []string{"", "runtime"} {
		for _, args := range skillExampleCommands(t, topic, variables) {
			out, _, err := run(t, Dependencies{}, args...)
			if err != nil || !json.Valid([]byte(out)) {
				t.Fatalf("example %v: %q %v", args, out, err)
			}
		}
	}
	out, _, err := run(t, Dependencies{}, "--target", "fixture", "proxies", "list", "--json")
	var proxies map[string]core.Proxy
	if err != nil || json.Unmarshal([]byte(out), &proxies) != nil || proxies[testcore.Selector].Now != testcore.Tokyo {
		t.Fatalf("guide's selection was not applied to the fixture: %s %v", out, err)
	}
}

func TestSkillAutomationExamplesAgainstFixtures(t *testing.T) {
	isolated(t)
	server := testcore.NewServer()
	defer server.Close()
	if _, _, err := run(t, Dependencies{}, "targets", "add", "fixture", "--controller", server.URL); err != nil {
		t.Fatal(err)
	}
	for _, args := range skillExampleCommands(t, "automation", map[string]string{"TARGET": "fixture"}) {
		deps := Dependencies{Upgrade: func(_ context.Context, request selfupdate.Request, _ io.Writer) (selfupdate.Result, error) {
			if request.Force {
				t.Fatal("guide silently overrides development protection")
			}
			result := upgradeFixture()
			if !request.Check {
				result.Status = "updated"
			}
			return result, nil
		}}
		out, diagnostics, err := run(t, deps, args...)
		if err != nil || diagnostics != "" {
			t.Fatalf("automation example %v: stderr=%q %v", args, diagnostics, err)
		}
		if args[0] == "upgrade" {
			var result selfupdate.Result
			if json.Unmarshal([]byte(out), &result) != nil || result.Installation.ResolvedPath != "/test/custom/lazyclash" {
				t.Fatalf("upgrade example produced invalid result: %s", out)
			}
			continue
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 5 {
			t.Fatalf("bounded log example produced %d lines, expected 5", len(lines))
		}
		for _, line := range lines {
			if !json.Valid([]byte(line)) {
				t.Fatalf("log example emitted invalid NDJSON: %q", line)
			}
		}
	}
}
