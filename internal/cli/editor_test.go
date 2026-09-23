package cli

import (
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEditorArgumentsDoNotEvaluateShell(t *testing.T) {
	got, err := editorArguments(`"/path with spaces/editor" --wait 'file name' "$(touch nope)" '$HOME'`)
	want := []string{"/path with spaces/editor", "--wait", "file name", "$(touch nope)", "$HOME"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"", "''", "editor 'oops", "editor \\"} {
		if _, err := editorArguments(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSettingsEditCreatesPrivateFileAndHonorsVisual(t *testing.T) {
	path := isolated(t)
	t.Setenv("VISUAL", `sh --flag 'quoted argument'`)
	t.Setenv("EDITOR", "missing-editor")
	called := false
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, RunEditor: func(cmd *exec.Cmd) error {
		called = true
		if !reflect.DeepEqual(cmd.Args[1:], []string{"--flag", "quoted argument", path}) {
			t.Fatalf("argv: %q", cmd.Args)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || !privatefs.Private(path) {
			t.Fatalf("private file: %v %v", info, err)
		}
		info, err = os.Stat(filepath.Dir(path))
		if err != nil || !info.IsDir() || !privatefs.Private(filepath.Dir(path)) {
			t.Fatalf("private directory: %v %v", info, err)
		}
		return os.WriteFile(path, []byte("# edited\n"), 0600)
	}}
	if _, _, err := run(t, deps, "settings", "edit"); err != nil || !called {
		t.Fatalf("edit: %v called=%v", err, called)
	}
}

func TestSettingsEditorRepairsInvalidFileAndKeepsInvalidEdits(t *testing.T) {
	path := isolated(t)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[[bad"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, Dependencies{}, "settings", "path")
	if err != nil || strings.TrimSpace(out) != path {
		t.Fatalf("path inaccessible: %s %v", out, err)
	}
	t.Setenv("VISUAL", "sh")
	deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }, RunEditor: func(cmd *exec.Cmd) error {
		return os.WriteFile(cmd.Args[len(cmd.Args)-1], []byte("# repaired\n"), 0600)
	}}
	if _, _, err := run(t, deps, "settings", "edit"); err != nil {
		t.Fatal(err)
	}
	deps.RunEditor = func(cmd *exec.Cmd) error { return os.WriteFile(path, []byte("[invalid"), 0600) }
	if _, _, err := run(t, deps, "settings", "edit"); err == nil || ExitCode(err) != 2 {
		t.Fatalf("invalid accepted: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "[invalid" {
		t.Fatalf("edits lost: %s", got)
	}
}

func TestSettingsEditorRejectsBeforeMutation(t *testing.T) {
	path := isolated(t)
	for _, json := range []bool{false, true} {
		deps := Dependencies{Terminal: func(io.Reader, io.Writer) bool { return json }, RunEditor: func(*exec.Cmd) error { t.Fatal("editor launched"); return nil }}
		args := []string{"settings", "edit"}
		if json {
			args = append(args, "--json")
		}
		if _, _, err := run(t, deps, args...); err == nil || ExitCode(err) != 2 {
			t.Fatalf("accepted %v", args)
		}
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("created directory: %v", err)
	}
}
