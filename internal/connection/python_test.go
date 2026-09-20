package connection

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExecutePythonKeepsDataOnStdinAndBoundsResults(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	input := []byte(`{"value":"quotes'\" $() ; PRIVATE"}`)
	out, err := ExecutePython(context.Background(), "", `import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())`, input, 1024)
	if err != nil || string(out) != string(input) {
		t.Fatalf("stdin changed: %q %v", out, err)
	}
	_, err = ExecutePython(context.Background(), "", `print("PRIVATE"*1000)`, nil, 128)
	if err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("output limit leak: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err = ExecutePython(ctx, "", `import time;time.sleep(30)`, nil, 128)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := ExecutePython(context.Background(), "--bad", `print("bad")`, nil, 128); err == nil {
		t.Fatal("unsafe SSH host accepted")
	}
}
