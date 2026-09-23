package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func TestManagedRPiRejectsGenericOwnerAndTemporaryTransport(t *testing.T) {
	deps, input, calls := managedCLIFixture(t)
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	target := config.Target{ID: "pi", Controller: "https://192.0.2.1:9090", CAFile: "/private/ca.pem", ManagedRPi: &config.ManagedRPi{ProjectDir: root, ConnectionFile: filepath.Join(root, "private", "connection.json")}}
	if err = config.Save(path, config.Config{DefaultTarget: "pi", Targets: []config.Target{target}}); err != nil {
		t.Fatal(err)
	}
	deps.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("owner bypass reached controller")
		return nil, nil, nil
	}
	for _, args := range [][]string{
		{"setup", "new-core", "--ssh", "root@192.0.2.1", "--input", input, "--json"},
		{"cores", "stop", "pi", "--json"},
		{"--controller", target.Controller, "status", "--json"},
		{"--controller", "http://192.0.2.1:9090", "status", "--json"},
		{"--target", "pi", "--ssh", "other-host", "status", "--json"},
	} {
		_, _, err := run(t, deps, args...)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "rpi") {
			t.Fatalf("owner bypass %v: %v", args, err)
		}
	}
	if *calls != 0 {
		t.Fatal("generic setup contacted owner host")
	}
	for _, group := range []string{"configs", "rules"} {
		_, _, err := run(t, deps, "--target", "pi", group, "restore", "invalid-receipt", "--yes", "--json")
		if err == nil || !strings.Contains(err.Error(), "receipt ID") {
			t.Fatalf("%s restore inspected live source before its receipt: %v", group, err)
		}
	}
}
