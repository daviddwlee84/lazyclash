//go:build unix

package vps

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunCLICancelsWrapperAndInheritedOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	// The shell waits for a child which also holds stdout. Killing just the
	// shell reproduces the real Homebrew az timeout that stranded its Python.
	_, err := runCLI(ctx, "sh", []string{"-c", "sleep 4 & wait"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("child retained command output after cancellation: %s", elapsed)
	}
}

func TestRunCLIRetainsSuccessfulOutput(t *testing.T) {
	data, err := runCLI(context.Background(), "sh", []string{"-c", "printf '{\"ok\":true}'"})
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("output=%q error=%v", data, err)
	}
}
