package proxyenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReverseRejectsUnsupportedSourcesBeforeSSHOrState(t *testing.T) {
	base := Plan{HTTP: "http://127.0.0.1:7890", All: "socks5h://127.0.0.1:7890"}
	for _, name := range []string{"ssh", "auth", "ca", "tls", "host", "port", "collision", "temporary-origin"} {
		t.Run(name, func(t *testing.T) {
			p, ro := base, ReverseOptions{Host: "fixture"}
			switch name {
			case "ssh":
				p.SSHHost = "source"
			case "auth":
				p.PasswordEnv = "PRIVATE_REFERENCE"
			case "ca":
				p.CAFile = "/not/read"
			case "tls":
				p.HTTP = "https://127.0.0.1:7890"
			case "host":
				ro.Host = "-oProxyCommand=bad"
			case "port":
				ro.HTTPPort = 65536
			case "collision":
				p.All = "socks5h://127.0.0.1:7891"
				ro.HTTPPort, ro.SocksPort = 12345, 12345
			case "temporary-origin":
				p.Origin, _ = TemporaryOrigin(p, "ssh-forward")
			}
			dir := filepath.Join(t.TempDir(), "state")
			_, err := PrepareReverse(context.Background(), p, ro, SessionOptions{Directory: dir, Run: func(*exec.Cmd) error { t.Fatal("invalid source invoked SSH"); return nil }})
			if err == nil {
				t.Fatal("unsupported source accepted")
			}
			if _, e := os.Stat(dir); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("invalid source created state", e)
			}
		})
	}
}

func TestReverseRejectsCopiedKnownSSHSourceBeforeConnecting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	opts := SessionOptions{Directory: filepath.Join(t.TempDir(), "sessions"), Run: func(*exec.Cmd) error { t.Fatal("copied source invoked SSH"); return nil }}
	dir, err := sessionDir(opts, true)
	if err != nil {
		t.Fatal(err)
	}
	p := Plan{HTTP: "http://127.0.0.1:7890", All: "socks5h://127.0.0.1:7890"}
	original := p
	original.SSHHost = "source-host"
	id, _ := NewID()
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	s := Session{ID: id, State: "ready", ShellPID: os.Getpid(), ShellIdentity: identity, Plan: original, Local: p}
	if err := saveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	_, err = PrepareReverse(context.Background(), p, ReverseOptions{Host: "destination"}, opts)
	if err == nil || !strings.Contains(err.Error(), "chained forwarding") {
		t.Fatal("copied known tunnel was not rejected before connecting", err)
	}
	if _, err := readSession(dir, id); err != nil {
		t.Fatal("source lease changed", err)
	}
}

func TestReverseListenerProofRejectsWildcardMissingAndChatter(t *testing.T) {
	for _, fixture := range []struct {
		name, raw string
		valid     bool
	}{
		{"linux-v4", "linux\nv4 0100007F:3039\n", true},
		{"linux-v6", "linux\nv6 00000000000000000000000001000000:3039\n", true},
		{"linux-wildcard", "linux\nv4 00000000:3039\n", false},
		{"linux-both", "linux\nv4 0100007F:3039\nv6 00000000000000000000000000000000:3039\n", false},
		{"darwin-v4", "darwin\np123\nf12\nn127.0.0.1:12345\n", true},
		{"darwin-v6", "darwin\np123\nn[::1]:12345\n", true},
		{"darwin-wildcard", "darwin\np123\nn*:12345\n", false},
		{"missing", "linux\n", false},
		{"other-port", "linux\nv4 0100007F:3038\n", false},
		{"startup-chatter", "Welcome!\nlinux\nv4 0100007F:3039\n", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if err := parseReverseListeners(fixture.raw, []int{12345}); (err == nil) != fixture.valid {
				t.Fatalf("valid=%v error=%v", fixture.valid, err)
			}
		})
	}
}

func TestReverseArgvQuotingStdinAndOrigin(t *testing.T) {
	p := Plan{HTTP: "http://127.0.0.1:12345", All: "socks5h://127.0.0.1:12346"}
	p.Origin, _ = TemporaryOrigin(p, "ssh-reverse")
	arg := "literal ' \" $HOME ; $(printf BAD)\nsecond line"
	command, err := reverseShellCommand(p, []string{"/bin/sh", "-c", `printf '%s\n%s\n%s\n' "$http_proxy" "$LAZYCLASH_PROXY_ORIGIN" "$1"; cat; exit 37`, "fixture", arg}, false)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = strings.NewReader("stdin\x00bytes\n")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 37 {
		t.Fatal(err)
	}
	if want := p.HTTP + "\n" + p.Origin + "\n" + arg + "\nstdin\x00bytes\n"; out.String() != want {
		t.Fatalf("argv/stdin changed: %q", out.String())
	}
	if _, err = reverseShellCommand(p, []string{"echo", "no"}, true); err == nil {
		t.Fatal("clean shell accepted with argv")
	}
	if _, err = reverseShellCommand(p, []string{"bad\x00arg"}, false); err == nil {
		t.Fatal("NUL argv accepted")
	}
}

func TestReverseChannelCannotReconnectOrReuseUserConfig(t *testing.T) {
	s := Session{Socket: "/private/control", Reverse: &ReverseSession{Host: "fixture"}}
	for _, tty := range []bool{true, false} {
		cmd := reverseCommand(context.Background(), s, "exec true", tty)
		args := strings.Join(cmd.Args, " ")
		for _, wanted := range []string{"-F " + os.DevNull, "ProxyCommand=false", "BatchMode=yes", "ControlMaster=no", "ControlPersist=no", "-S /private/control"} {
			if !strings.Contains(args, wanted) {
				t.Fatal("missing fail-closed channel option", wanted)
			}
		}
	}
}

func TestReversePreparingCrashLeaseCanBeReadAndCleaned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	opts := SessionOptions{Directory: filepath.Join(t.TempDir(), "sessions")}
	dir, err := sessionDir(opts, true)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewID()
	p := Plan{HTTP: "http://127.0.0.1:7890", All: "http://127.0.0.1:7890"}
	s := Session{ID: id, State: "preparing", Plan: p, Local: p, Reverse: &ReverseSession{Host: "fixture", OwnerPID: os.Getpid(), OwnerIdentity: "previous invocation generation"}}
	if err := saveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := readSession(dir, id)
	if err != nil || loaded.Reverse.Remote.Origin != "" {
		t.Fatalf("preparing record unreadable: %v", err)
	}
	removed, err := Cleanup(context.Background(), opts)
	if err != nil || len(removed) != 1 || removed[0] != id {
		t.Fatalf("preparing crash cleanup: %v %v", removed, err)
	}
}

func TestReversePrepareCancellationRetainsCleanupEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	for _, phase := range []string{"source", "forward", "proof", "cleanup"} {
		t.Run(phase, func(t *testing.T) {
			proxy := httptest.NewServer(nil)
			defer proxy.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fixture := &sessionSSHFixture{listeners: map[string]net.Listener{}}
			t.Cleanup(func() {
				for _, ln := range fixture.listeners {
					_ = ln.Close()
				}
			})
			exitAttempted := false
			opts := SessionOptions{Directory: filepath.Join(t.TempDir(), "sessions")}
			opts.Run = func(cmd *exec.Cmd) error {
				if phase == "source" {
					t.Fatal("canceled source invoked SSH")
				}
				operation := ""
				for i, arg := range cmd.Args {
					if arg == "-O" {
						operation = cmd.Args[i+1]
					}
				}
				if operation == "forward" {
					if phase == "forward" || phase == "cleanup" {
						cancel()
						return errors.New("fixture interrupted forward")
					}
					_, _ = fmt.Fprintln(cmd.Stdout, "12345")
					return nil
				}
				if strings.Contains(cmd.Args[len(cmd.Args)-1], "/proc/net/tcp") {
					cancel()
					return errors.New("fixture interrupted listener proof")
				}
				if operation == "exit" {
					exitAttempted = true
					if phase == "cleanup" {
						return errors.New("fixture cleanup unavailable")
					}
				}
				return fixture.run(cmd)
			}
			if phase == "source" {
				cancel()
			}
			s, err := PrepareReverse(ctx, Plan{HTTP: proxy.URL, All: proxy.URL}, ReverseOptions{Host: "fixture"}, opts)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost during %s: %v", phase, err)
			}
			if phase == "source" {
				if _, e := os.Stat(opts.Directory); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("canceled source created state", e)
				}
				return
			}
			if !exitAttempted {
				t.Fatal("canceled preparation did not clean its master")
			}
			if phase == "cleanup" {
				if !strings.Contains(err.Error(), "needs inspection") {
					t.Fatal("cleanup evidence was hidden", err)
				}
				if _, e := readSession(opts.Directory, s.ID); e != nil {
					t.Fatal("uncertain cleanup lost private lease", e)
				}
			} else {
				if _, e := readSession(opts.Directory, s.ID); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("successful cancellation cleanup retained lease", e)
				}
			}
		})
	}
}

func TestReverseRunRevalidatesRemoteCredentialsBeforeSSH(t *testing.T) {
	p := Plan{HTTP: "http://127.0.0.1:12345", All: "http://127.0.0.1:12345"}
	for _, field := range []string{"password", "username", "ca", "tls"} {
		t.Run(field, func(t *testing.T) {
			remote := p
			switch field {
			case "password":
				remote.PasswordEnv = "PRIVATE_REFERENCE"
			case "username":
				remote.Username = "private-user"
			case "ca":
				remote.CAFile = "/not/read"
			case "tls":
				remote.HTTP = "https://127.0.0.1:12345"
				remote.All = remote.HTTP
			}
			s := Session{State: "ready", Plan: p, Reverse: &ReverseSession{Host: "fixture", Remote: remote, OwnerPID: os.Getpid(), OwnerIdentity: "fixture"}}
			err := RunReverseSSH(context.Background(), s, []string{"true"}, false, SessionOptions{Run: func(*exec.Cmd) error { t.Fatal("unsupported remote plan invoked SSH"); return nil }})
			if err == nil || !strings.Contains(err.Error(), "invalid reverse session endpoints") {
				t.Fatal("remote plan was not rejected before control access", err)
			}
			if strings.Contains(err.Error(), "PRIVATE_REFERENCE") || strings.Contains(err.Error(), "private-user") {
				t.Fatal("remote plan error exposed credential reference")
			}
		})
	}
}
