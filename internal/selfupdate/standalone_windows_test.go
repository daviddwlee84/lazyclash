//go:build windows

package selfupdate

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsStandaloneUpdatesRemainExternal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lazyclash.exe")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	install := Installation{Executable: path, ResolvedPath: path, Version: "v0.1.1", BuildKind: "release", Method: "go-install", IdentityValid: true}
	opts := runOptions{inspect: func() (Installation, error) { return install, nil }, latest: func(context.Context) (Release, error) {
		t.Fatal("unsupported standalone check consulted GitHub")
		return Release{}, nil
	}, lookPath: func(string) (string, error) { t.Fatal("unsupported install requested a compiler"); return "", nil }}
	for _, request := range []Request{{Check: true}, {Force: true}} {
		result, err := run(context.Background(), request, io.Discard, opts)
		if result.CanUpgrade || !strings.Contains(result.Reason, "Scoop") {
			t.Fatalf("wrong Windows policy: %+v %v", result, err)
		}
		if !request.Check && err == nil {
			t.Fatal("force bypassed standalone Windows protection")
		}
	}
	entries, _ := os.ReadDir(dir)
	data, _ := os.ReadFile(path)
	if len(entries) != 1 || string(data) != "existing" {
		t.Fatal("unsupported update changed the installation")
	}
}
