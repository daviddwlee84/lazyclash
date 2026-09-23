package proxyenv

import (
	"context"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSessionLocalOwnershipNoCredentialsPersisted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	opts := SessionOptions{Directory: filepath.Join(t.TempDir(), "sessions")}
	id, _ := NewID()
	p := Plan{HTTP: "http://127.0.0.1:7890", All: "http://127.0.0.1:7890", PasswordEnv: "FIXTURE_SESSION_PASSWORD"}
	t.Setenv("FIXTURE_SESSION_PASSWORD", "PRIVATE_NEVER_PERSIST")
	s, err := Start(context.Background(), id, os.Getpid(), p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if s.State != "ready" {
		t.Fatal(s.State)
	}
	b, _ := os.ReadFile(filepath.Join(opts.Directory, id+".json"))
	if strings.Contains(string(b), "PRIVATE_NEVER_PERSIST") {
		t.Fatal("password persisted")
	}
	local, err := SessionPlan(context.Background(), id, opts)
	if err != nil || local.PasswordEnv != "FIXTURE_SESSION_PASSWORD" {
		t.Fatalf("credential ref lost: %+v %v", local, err)
	}
	removed, err := Cleanup(context.Background(), opts)
	if err != nil || len(removed) != 0 {
		t.Fatalf("live shell GC: %v %v", removed, err)
	}
	if err = Stop(context.Background(), id, opts); err != nil {
		t.Fatal(err)
	}
	if err = Stop(context.Background(), id, opts); err != nil {
		t.Fatal("stop not idempotent:", err)
	}
}

type sessionSSHFixture struct {
	listeners         map[string]net.Listener
	calls             [][]string
	deny, failForward bool
}

func (f *sessionSSHFixture) run(cmd *exec.Cmd) error {
	f.calls = append(f.calls, append([]string{}, cmd.Args...))
	var operation, socket string
	for i, arg := range cmd.Args {
		if arg == "-O" {
			operation = cmd.Args[i+1]
		}
		if arg == "-S" {
			socket = strings.ReplaceAll(cmd.Args[i+1], "%%", "%")
		}
		if strings.HasPrefix(arg, "ControlPath=") {
			socket = strings.ReplaceAll(strings.TrimPrefix(arg, "ControlPath="), "%%", "%")
		}
	}
	if operation == "" {
		if f.deny {
			io.WriteString(cmd.Stderr, "Permission denied (publickey,password). PRIVATE")
			return errors.New("fixture denied")
		}
		ln, err := net.Listen("unix", socket)
		if err != nil {
			return err
		}
		os.Chmod(socket, 0600)
		f.listeners[socket] = ln
		return nil
	}
	if !strings.Contains(strings.Join(cmd.Args, " "), "-F "+os.DevNull) {
		return errors.New("control read user config")
	}
	switch operation {
	case "check":
		if f.listeners[socket] == nil {
			return errors.New("no master")
		}
		fmt.Fprintf(cmd.Stderr, "Master running (pid=%d)\n", os.Getpid())
	case "forward":
		if f.failForward {
			return errors.New("fixture forward failed")
		}
	case "exit":
		if ln := f.listeners[socket]; ln != nil {
			ln.Close()
			delete(f.listeners, socket)
		}
	}
	return nil
}

func TestPersistentSSHPrivateOwnershipFailureAndGC(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	f := &sessionSSHFixture{listeners: map[string]net.Listener{}}
	t.Cleanup(func() {
		for _, ln := range f.listeners {
			ln.Close()
		}
	})
	opts := SessionOptions{Directory: filepath.Join(t.TempDir(), "sessions"), Run: f.run}
	p := Plan{HTTP: "http://127.0.0.1:7890", All: "socks5h://127.0.0.1:7891", SSHHost: "fixture"}
	one, _ := NewID()
	two, _ := NewID()
	a, err := Start(context.Background(), one, os.Getpid(), p, opts)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Start(context.Background(), two, os.Getpid(), p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if a.Socket == b.Socket || a.Local.HTTP == b.Local.HTTP || a.Local.SSHHost != "" {
		t.Fatal("sessions shared private state")
	}
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call, " "), "-M -N -f") {
			text := strings.Join(call, " ")
			for _, want := range []string{"ControlPersist=no", "ControlMaster=yes", "ClearAllForwardings=yes", "BatchMode=yes"} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %s", want)
				}
			}
		}
	}
	if err = Stop(context.Background(), one, opts); err != nil {
		t.Fatal(err)
	}
	if _, err = SessionPlan(context.Background(), two, opts); err != nil {
		t.Fatal("other session closed:", err)
	}
	b.ShellIdentity = "another process generation"
	if err = saveSession(opts.Directory, b); err != nil {
		t.Fatal(err)
	}
	removed, err := Cleanup(context.Background(), opts)
	if err != nil || len(removed) != 1 || removed[0] != two {
		t.Fatalf("orphan gc: %v %v", removed, err)
	}
	f.deny = true
	id, _ := NewID()
	_, err = Start(context.Background(), id, os.Getpid(), p, opts)
	if !connection.IsAuthRequired(err) {
		t.Fatalf("auth required: %v", err)
	}
	if _, err = os.Stat(filepath.Join(opts.Directory, id+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed auth left record")
	}
	f.deny = false
	f.failForward = true
	id, _ = NewID()
	_, err = Start(context.Background(), id, os.Getpid(), p, opts)
	if err == nil {
		t.Fatal("failed forward accepted")
	}
	if len(f.listeners) != 0 {
		t.Fatal("failed start leaked owned master")
	}
}

func TestSessionRefusesTLSHostnameRewriteAndUntrustedState(t *testing.T) {
	dir := t.TempDir()
	opts := SessionOptions{Directory: filepath.Join(dir, "sessions")}
	id, _ := NewID()
	_, err := Start(context.Background(), id, os.Getpid(), Plan{HTTP: "https://internal.invalid:443", All: "https://internal.invalid:443", SSHHost: "fixture"}, opts)
	if err == nil {
		t.Fatal("rewrote TLS identity")
	}
	if _, err = os.Stat(opts.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("validation wrote state")
	}
	os.Symlink(dir, opts.Directory)
	if _, err = Start(context.Background(), id, os.Getpid(), Plan{HTTP: "http://127.0.0.1:7890", All: "http://127.0.0.1:7890"}, opts); err == nil {
		t.Fatal("symlink registry accepted")
	}
}
