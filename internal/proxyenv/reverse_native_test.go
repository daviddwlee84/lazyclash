//go:build !windows

package proxyenv

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type reverseNativeFixture struct {
	opts                           SessionOptions
	host, clientConfig, userSocket string
}

func reverseNativeUnavailable(t *testing.T, message string) {
	t.Helper()
	if os.Getenv("LAZYCLASH_REQUIRE_SSH_ISOLATION") == "1" || os.Getenv("LAZYCLASH_REQUIRE_NATIVE_ISOLATION") == "1" {
		t.Fatal(message)
	}
	t.Skip(message)
}

func newReverseNativeFixture(t *testing.T, gateway, forwarding string) reverseNativeFixture {
	t.Helper()
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		sshd = "/usr/sbin/sshd"
		if _, err = os.Stat(sshd); err != nil {
			reverseNativeUnavailable(t, "isolated sshd unavailable")
		}
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		reverseNativeUnavailable(t, "ssh-keygen unavailable")
	}
	dir := t.TempDir()
	serverKey, clientKey := filepath.Join(dir, "host"), filepath.Join(dir, "client")
	for _, path := range []string{serverKey, clientKey} {
		if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("fixture keys: %v %s", err, out)
		}
	}
	identity, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	serverConfig := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s.pub\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nAllowTcpForwarding %s\nGatewayPorts %s\nPermitRootLogin yes\nPermitUserRC no\nSetEnv HOME=%s ZDOTDIR=%s SHELL=/bin/sh\nLogLevel ERROR\n", port, serverKey, filepath.Join(dir, "sshd.pid"), clientKey, forwarding, gateway, dir, dir)
	serverFile := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(serverFile, []byte(serverConfig), 0600); err != nil {
		t.Fatal(err)
	}
	var daemonLog bytes.Buffer
	daemon := exec.Command(sshd, "-D", "-e", "-f", serverFile)
	daemon.Stderr = &daemonLog
	if err := daemon.Start(); err != nil {
		reverseNativeUnavailable(t, "isolated sshd could not start")
	}
	done := make(chan error, 1)
	go func() { done <- daemon.Wait() }()
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case err := <-done:
			reverseNativeUnavailable(t, fmt.Sprintf("isolated sshd unavailable: %v %s", err, daemonLog.String()))
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		reverseNativeUnavailable(t, "isolated sshd not ready")
	}
	socketDir, err := os.MkdirTemp("", "lc-reverse-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	userSocket := filepath.Join(socketDir, "user")
	pub, _ := os.ReadFile(serverKey + ".pub")
	knownHosts := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, pub)), 0600); err != nil {
		t.Fatal(err)
	}
	host := "isolated-reverse-fixture"
	clientConfig := fmt.Sprintf("Host %s\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n StrictHostKeyChecking yes\n UserKnownHostsFile %s\n LogLevel ERROR\n ControlMaster auto\n ControlPersist 60\n ControlPath %s\n", host, port, identity.Username, clientKey, knownHosts, userSocket)
	clientFile := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(clientFile, []byte(clientConfig), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(cmd *exec.Cmd) error {
		for _, arg := range cmd.Args {
			if arg == "-F" {
				return cmd.Run()
			}
		}
		cmd.Args = append([]string{cmd.Args[0], "-F", clientFile}, cmd.Args[1:]...)
		return cmd.Run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userMaster := exec.CommandContext(ctx, "ssh", "-F", clientFile, "-M", "-N", "-f", "-o", "BatchMode=yes", "--", host)
	if out, err := userMaster.CombinedOutput(); err != nil {
		reverseNativeUnavailable(t, fmt.Sprintf("isolated sshd authentication unavailable: %v %s", err, out))
	}
	t.Cleanup(func() { _ = exec.Command("ssh", "-F", os.DevNull, "-S", userSocket, "-O", "exit", "--", host).Run() })
	return reverseNativeFixture{opts: SessionOptions{Directory: filepath.Join(dir, "sessions"), Run: run}, host: host, clientConfig: clientFile, userSocket: userSocket}
}

func TestNativeReverseSSHDataCommandOwnershipAndCleanup(t *testing.T) {
	f := newReverseNativeFixture(t, "no", "yes")
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := Plan{HTTP: proxy.URL, All: proxy.URL}
	s, err := PrepareReverse(ctx, p, ReverseOptions{Host: f.host}, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop(context.Background(), s.ID, f.opts) })
	if s.Socket == f.userSocket || s.Reverse.Remote.HTTP != s.Reverse.Remote.All {
		t.Fatal("mixed endpoint or private master not preserved")
	}
	if _, err := SessionPlan(ctx, s.ID, f.opts); err == nil {
		t.Fatal("reverse lease accepted as local shell plan")
	}
	if got, err := Test(ctx, s.Reverse.Remote, "http://fixture.invalid/"); err != nil || got.HTTPStatus != 204 {
		t.Fatalf("reverse HTTP: %+v %v", got, err)
	}
	var stdout, stderr bytes.Buffer
	execOpts := f.opts
	execOpts.In, execOpts.Out, execOpts.Err = strings.NewReader("stdin\x00bytes\n"), &stdout, &stderr
	arg := "space ' $HOME ; $(printf BAD)\nline"
	err = RunReverseSSH(ctx, s, []string{"/bin/sh", "-c", `printf '%s\n%s\n%s\n' "$http_proxy" "$LAZYCLASH_PROXY_ORIGIN" "$1"; cat; exit 37`, "fixture", arg}, false, execOpts)
	var exited *ExitError
	if !errors.As(err, &exited) || exited.Code != 37 {
		t.Fatalf("remote exit: %v %s", err, stderr.String())
	}
	if want := s.Reverse.Remote.HTTP + "\n" + s.Reverse.Remote.Origin + "\n" + arg + "\nstdin\x00bytes\n"; stdout.String() != want {
		t.Fatalf("remote argv/stdin changed: %q", stdout.String())
	}
	// A second split endpoint lease survives stopping the first invocation.
	other := reverseSOCKSFixture(t)
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixed := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	b, err := PrepareReverse(ctx, Plan{HTTP: proxy.URL, All: other}, ReverseOptions{Host: f.host, HTTPPort: fixed}, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop(context.Background(), b.ID, f.opts) })
	if b.Reverse.Remote.HTTP == b.Reverse.Remote.All {
		t.Fatal("split endpoints incorrectly merged")
	}
	remoteHTTP, _ := url.Parse(b.Reverse.Remote.HTTP)
	if remoteHTTP.Port() != strconv.Itoa(fixed) {
		t.Fatal("fixed remote port not honored")
	}
	if got, err := Test(ctx, Plan{HTTP: b.Reverse.Remote.All, All: b.Reverse.Remote.All}, "http://fixture.invalid/"); err != nil || got.HTTPStatus != 205 {
		t.Fatalf("split SOCKS path: %+v %v", got, err)
	}
	if err := Stop(ctx, s.ID, f.opts); err != nil {
		t.Fatal(err)
	}
	if _, err := Test(ctx, s.Reverse.Remote, "http://fixture.invalid/"); err == nil {
		t.Fatal("stopped reverse listener still open")
	}
	if _, err := Test(ctx, b.Reverse.Remote, "http://fixture.invalid/"); err != nil {
		t.Fatal("other reverse lease stopped", err)
	}
	check := exec.CommandContext(ctx, "ssh", "-F", os.DevNull, "-S", f.userSocket, "-O", "check", "--", f.host)
	if out, err := check.CombinedOutput(); err != nil || !strings.Contains(string(out), "Master running") {
		t.Fatal("user master stopped", err)
	}
	waitCtx, stopWait := context.WithCancel(ctx)
	stopWait()
	if err := WaitReverse(waitCtx, b, f.opts); !errors.Is(err, context.Canceled) {
		t.Fatal("share cancellation not preserved", err)
	}
	// A retained lease owned by a dead process generation is recoverable.
	b.Reverse.OwnerIdentity = "previous invocation generation"
	dir, _ := sessionDir(f.opts, false)
	if err := saveSession(dir, b); err != nil {
		t.Fatal(err)
	}
	removed, err := Cleanup(ctx, f.opts)
	if err != nil || len(removed) != 1 || removed[0] != b.ID {
		t.Fatalf("orphan cleanup: %v %v", removed, err)
	}
	// Lose the private socket immediately after the ownership check. The
	// execution channel must fail closed, without a new transport or replay.
	c, err := PrepareReverse(ctx, p, ReverseOptions{Host: f.host}, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop(context.Background(), c.ID, f.opts) })
	disappearing := f.opts
	var afterLoss bytes.Buffer
	disappearing.Out, disappearing.Err = &afterLoss, &afterLoss
	launched := 0
	disappearing.Run = func(cmd *exec.Cmd) error {
		if strings.Contains(cmd.Args[len(cmd.Args)-1], "MUST_NOT_EXECUTE") {
			launched++
			if err := Stop(ctx, c.ID, f.opts); err != nil {
				return err
			}
		}
		return f.opts.Run(cmd)
	}
	err = RunReverseSSH(ctx, c, []string{"printf", "MUST_NOT_EXECUTE"}, false, disappearing)
	if err == nil || launched != 1 || strings.Contains(afterLoss.String(), "MUST_NOT_EXECUTE") {
		t.Fatalf("lost master retried/executed command: %v %q", err, afterLoss.String())
	}
}

// An isolated SOCKS5 endpoint answers a HEAD request itself; it never dials
// the requested destination, including the intentionally non-resolving name.
func reverseSOCKSFixture(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var greeting [2]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil {
					return
				}
				if greeting[0] != 5 {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				var request [4]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil {
					return
				}
				count := int64(0)
				switch request[3] {
				case 1:
					count = 4
				case 4:
					count = 16
				case 3:
					var n [1]byte
					if _, err := io.ReadFull(conn, n[:]); err != nil {
						return
					}
					count = int64(n[0])
				default:
					return
				}
				if _, err := io.CopyN(io.Discard, conn, count+2); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
					return
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}()
		}
	}()
	return "socks5h://" + ln.Addr().String()
}

func TestNativeReverseSSHRejectsWildcardDeniedAndOccupiedPort(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer proxy.Close()
	for _, mode := range []string{"wildcard", "denied", "occupied"} {
		t.Run(mode, func(t *testing.T) {
			gateway, forwarding := "no", "yes"
			if mode == "wildcard" {
				gateway = "yes"
			}
			if mode == "denied" {
				forwarding = "no"
			}
			f := newReverseNativeFixture(t, gateway, forwarding)
			ro := ReverseOptions{Host: f.host}
			if mode == "occupied" {
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				ro.HTTPPort = ln.Addr().(*net.TCPAddr).Port
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s, err := PrepareReverse(ctx, Plan{HTTP: proxy.URL, All: proxy.URL}, ro, f.opts)
			if err == nil {
				_ = Stop(ctx, s.ID, f.opts)
				t.Fatal("unsafe/unavailable listener accepted")
			}
			if mode == "wildcard" && !strings.Contains(err.Error(), "loopback") {
				t.Fatal("wildcard did not reach bind proof", err)
			}
			remaining, e := Sessions(ctx, f.opts)
			if e != nil || len(remaining) != 0 {
				t.Fatalf("failed prepare retained live lease: %v %v", remaining, e)
			}
		})
	}
}
