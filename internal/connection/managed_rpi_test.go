package connection

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestManagedOwnerValidatesBeforeResolvingCredentials(t *testing.T) {
	root := t.TempDir()
	target := config.Target{ID: "pi", Controller: "https://192.0.2.1:9090", CAFile: "/private/ca.pem", SecretEnv: "LAZYCLASH_MANAGED_RPI_MISSING_SECRET", ManagedRPi: &config.ManagedRPi{ProjectDir: root, ConnectionFile: filepath.Join(root, "private", "connection.json")}}
	_, _, err := Open(context.Background(), target, true)
	if err == nil || !strings.Contains(err.Error(), "managed RPi connection") {
		t.Fatalf("credentials or API reached before owner validation: %v", err)
	}
}
