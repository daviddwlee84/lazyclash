package connection

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type privateCopyFixture struct {
	t          *testing.T
	calls      [][]string
	version    string
	policy     string
	copyReply  muxReply
	beforeCopy func()
	local      string
}

func newPrivateCopyFixture(t *testing.T) *privateCopyFixture {
	t.Helper()
	f := &privateCopyFixture{t: t, version: "OpenSSH_10.3p1, LibreSSL 3.3.6\n", policy: "controlmaster auto\ncontrolpersist 600\ncontrolpath /tmp/fixture control % socket\n"}
	f.local = filepath.Join(t.TempDir(), "private material 配置.bin")
	if err := os.WriteFile(f.local, []byte("PRIVATE_BODY_MUST_NOT_ENTER_ARGV"), 0600); err != nil {
		t.Fatal(err)
	}
	clearMultiplexPolicies()
	old := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		f.calls = append(f.calls, append([]string{name}, args...))
		var reply muxReply
		switch {
		case name == "ssh" && len(args) == 1 && args[0] == "-V":
			reply.Err = f.version
		case name == "ssh" && len(args) > 0 && args[0] == "-G":
			reply.Out = f.policy
		case name == "scp":
			if f.beforeCopy != nil {
				f.beforeCopy()
			}
			reply = f.copyReply
		default:
			t.Fatalf("unexpected copy subprocess: %s %v", name, args)
		}
		raw, _ := json.Marshal(reply)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMuxReplyProcess")
		cmd.Env = append(os.Environ(), "LAZYCLASH_MUX_REPLY="+base64.StdEncoding.EncodeToString(raw), "GORACE=atexit_sleep_ms=0")
		return cmd
	}
	t.Cleanup(func() { commandContext = old; clearMultiplexPolicies() })
	return f
}

func (f *privateCopyFixture) transfers() [][]string {
	var result [][]string
	for _, args := range f.calls {
		if args[0] == "scp" {
			result = append(result, args)
		}
	}
	return result
}

func TestCopyPrivateFileUsesDefaultSFTPAndExistingSSHPolicy(t *testing.T) {
	f := newPrivateCopyFixture(t)
	remote := `C:\Users\User Name\私有\transfer-123\packet.bin`
	if err := CopyPrivateFile(context.Background(), "fixture-ssh", f.local, remote); err != nil {
		t.Fatal(err)
	}
	copies := f.transfers()
	if len(copies) != 1 {
		t.Fatal("transfer was retried or omitted", len(copies))
	}
	args := copies[0]
	for _, want := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "ClearAllForwardings=yes", "ControlMaster=no", "ControlPath=" + controlSocketArgument(func() string { p, _ := filepath.Abs("/tmp/fixture control % socket"); return p }()), "-q"} {
		found := false
		for _, arg := range args {
			found = found || arg == want
		}
		if !found {
			t.Fatal("SSH policy missing", want)
		}
	}
	if len(args) < 4 || args[len(args)-3] != "--" || args[len(args)-2] != f.local || args[len(args)-1] != "fixture-ssh:C:/Users/User Name/私有/transfer-123/packet.bin" {
		t.Fatal("paths were shell-quoted, split or rebound", args)
	}
	for _, arg := range args {
		if arg == "-O" || arg == "-T" || arg == "-r" || strings.Contains(arg, "PRIVATE_BODY") {
			t.Fatal("unsafe transfer option or private body in argv")
		}
	}
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call, " "), "PRIVATE_BODY") {
			t.Fatal("payload appeared in a subprocess command")
		}
	}
	if got, _ := os.ReadFile(f.local); string(got) != "PRIVATE_BODY_MUST_NOT_ENTER_ARGV" {
		t.Fatal("copy changed local source")
	}
}

func TestCopyPrivateFileRejectsUnsafePathsBeforeSubprocesses(t *testing.T) {
	for _, path := range []string{"", "relative.bin", "C:relative.bin", "/tmp/file", `\\server\share\file`, `\\?\C:\file`, `C:\private\..\other.bin`, `C:\private\.\file`, `C:\private\`, `C:\private\file.`, `C:\private\space \file`, `C:\private\file:stream`, "C:/private/line\nfile", "C:/private/line\tfile", `C:\private\$payload`, `C:\private\a;start`, `C:\private\[glob]`, `C:\private\wild*`, `C:\private\%TEMP%`, `C:\private\a'quote`} {
		t.Run(strings.ReplaceAll(path, "\\", "/"), func(t *testing.T) {
			f := newPrivateCopyFixture(t)
			if err := CopyPrivateFile(context.Background(), "fixture-ssh", f.local, path); err == nil || len(f.calls) != 0 {
				t.Fatal("unsafe path reached a subprocess", path, err)
			}
		})
	}
	for _, host := range []string{"", "-bad", "bad;host", "host/path", "host:2222"} {
		f := newPrivateCopyFixture(t)
		if err := CopyPrivateFile(context.Background(), host, f.local, `C:\private\file.bin`); err == nil || len(f.calls) != 0 {
			t.Fatal("unsafe host reached a subprocess", err)
		}
	}
}

func TestCopyPrivateFileRequiresBoundedPrivateRegularSource(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "empty", "public", "symlink", "oversize", "control-path"} {
		t.Run(kind, func(t *testing.T) {
			f := newPrivateCopyFixture(t)
			path := f.local
			switch kind {
			case "missing":
				path += ".missing"
			case "directory":
				path = t.TempDir()
			case "empty":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			case "public":
				if runtime.GOOS == "windows" {
					t.Skip("Windows ACL ownership is enforced by its staging helper")
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path += ".symlink"
				if err := os.Symlink(f.local, path); err != nil {
					t.Skip("symlinks unavailable")
				}
			case "oversize":
				if err := os.Truncate(path, privateCopyLimit+1); err != nil {
					t.Fatal(err)
				}
			case "control-path":
				path += "\nother"
			}
			if err := CopyPrivateFile(context.Background(), "fixture-ssh", path, `C:\private\file.bin`); err == nil || len(f.calls) != 0 {
				t.Fatal("invalid local source reached a subprocess", err)
			}
		})
	}
}

func TestCopyPrivateFileRequiresModernOpenSSHWithoutLegacyFallback(t *testing.T) {
	for _, version := range []string{"OpenSSH_8.9p1\n", "not OpenSSH PRIVATE_VERSION\n", "OpenSSH_7.9\n"} {
		f := newPrivateCopyFixture(t)
		f.version = version
		err := CopyPrivateFile(context.Background(), "fixture-ssh", f.local, `C:\private\file.bin`)
		if err == nil || strings.Contains(err.Error(), "PRIVATE_VERSION") || len(f.transfers()) != 0 || len(f.calls) != 1 {
			t.Fatal("unverified SFTP default used a transfer/fallback", err, f.calls)
		}
	}
	f := newPrivateCopyFixture(t)
	f.version = "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2\n"
	if err := CopyPrivateFile(context.Background(), "fixture-ssh", f.local, `C:\private\file.bin`); err != nil {
		t.Fatal("modern Windows OpenSSH not recognized", err)
	}
}

func TestCopyPrivateFileErrorsAreRedactedClassifiedAndNeverRetried(t *testing.T) {
	cases := []struct {
		name                   string
		reply                  muxReply
		auth, transport, limit bool
	}{
		{"auth", muxReply{Code: 255, Err: "PRIVATE_DETAIL: Permission denied (publickey)."}, true, false, false},
		{"host-key", muxReply{Code: 255, Err: "PRIVATE_DETAIL: Host key verification failed."}, true, false, false},
		{"route", muxReply{Code: 255, Err: "ssh: connect to host PRIVATE_DETAIL port 22: No route to host"}, false, true, false},
		{"remote-permission", muxReply{Code: 1, Err: "scp: dest open C:/PRIVATE_DETAIL: Permission denied"}, false, false, false},
		{"limit", muxReply{Code: 1, Err: strings.Repeat("PRIVATE_DETAIL", 2000)}, false, false, true},
		{"stdout-limit", muxReply{Out: strings.Repeat("PRIVATE_DETAIL", 2000)}, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPrivateCopyFixture(t)
			f.copyReply = tc.reply
			err := CopyPrivateFile(context.Background(), "fixture-ssh", f.local, `C:\private\file.bin`)
			if err == nil || strings.Contains(err.Error(), "PRIVATE_DETAIL") || len(f.transfers()) != 1 {
				t.Fatal("unsafe diagnostic or repeated transfer", err)
			}
			var transport *SSHTransportError
			if IsAuthRequired(err) != tc.auth || errors.As(err, &transport) != tc.transport || errors.Is(err, ErrHelperOutputLimit) != tc.limit {
				t.Fatal("copy failure classification lost", err)
			}
		})
	}
}

func TestCopyPrivateFileCancellationAndSourceChange(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		f := newPrivateCopyFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f.copyReply.Hold = true
		f.beforeCopy = func() { time.AfterFunc(75*time.Millisecond, cancel) }
		start := time.Now()
		err := CopyPrivateFile(ctx, "fixture-ssh", f.local, `C:\private\file.bin`)
		if !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second || len(f.transfers()) != 1 {
			t.Fatal("copy did not cancel cleanly", err, time.Since(start))
		}
	})
	t.Run("source-change", func(t *testing.T) {
		f := newPrivateCopyFixture(t)
		f.beforeCopy = func() {
			if err := os.WriteFile(f.local, []byte("changed-source"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := CopyPrivateFile(context.Background(), "fixture-ssh", f.local, `C:\private\file.bin`); err == nil || !strings.Contains(err.Error(), "source changed") {
			t.Fatal("changed local source was accepted", err)
		}
	})
}

func TestPrivateCopyBracketsIPv6Destination(t *testing.T) {
	f := newPrivateCopyFixture(t)
	if err := CopyPrivateFile(context.Background(), "user@2001:db8::1", f.local, `C:\private\file.bin`); err != nil {
		t.Fatal(err)
	}
	args := f.transfers()[0]
	if args[len(args)-1] != "user@[2001:db8::1]:C:/private/file.bin" {
		t.Fatal("IPv6 was mistaken for a host/path separator", args)
	}
}
