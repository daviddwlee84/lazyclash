//go:build windows

package proxyenv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPersistentSessionsRefuseBeforeWriting(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "absent")
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Start(context.Background(), id, os.Getpid(), Plan{HTTP: "http://127.0.0.1:7890"}, SessionOptions{Directory: directory})
	if err == nil || !strings.Contains(err.Error(), "macOS or Linux") {
		t.Fatalf("unsupported session: %v", err)
	}
	if _, e := os.Stat(directory); !os.IsNotExist(e) {
		t.Fatalf("unsupported session created state: %v", e)
	}
}
