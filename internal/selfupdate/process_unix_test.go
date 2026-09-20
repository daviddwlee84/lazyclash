//go:build darwin || linux

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCancelStopsOwnedBuildChildren(t *testing.T) {
	directory := t.TempDir()
	fakeGo := filepath.Join(directory, "go")
	script := "#!/bin/sh\nsleep 60 &\nprintf '%s' \"$!\" > \"$GOBIN/child.pid\"\nwait\n"
	if err := os.WriteFile(fakeGo, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- buildRelease(ctx, fakeGo, directory, "v0.1.2") }()
	var pid int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		body, _ := os.ReadFile(filepath.Join(directory, "child.pid"))
		pid, _ = strconv.Atoi(string(body))
		if pid > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("build helper did not start its child")
	}
	defer unix.Kill(pid, unix.SIGKILL)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled build succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled build did not return")
	}
	for time.Now().Before(deadline) {
		if errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			return
		}
		if runtime.GOOS == "linux" {
			// Minimal container PID 1 may not reap orphaned zombies promptly.
			body, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
			_, state, _ := strings.Cut(string(body), ") ")
			if strings.HasPrefix(state, "Z ") {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Go child survived cancellation")
}
