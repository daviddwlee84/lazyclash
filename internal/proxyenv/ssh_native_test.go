//go:build !windows

package proxyenv

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Uses a disposable loopback sshd, disposable keys and configuration. It never
// authenticates to a configured host or reads/writes the user's SSH directory.
func TestNativeSSHPrivateSessions(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		if _, e := os.Stat("/usr/sbin/sshd"); e == nil {
			sshd = "/usr/sbin/sshd"
		} else {
			t.Skip("sshd unavailable")
		}
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	dir := t.TempDir()
	serverKey, clientKey := filepath.Join(dir, "host"), filepath.Join(dir, "client")
	for _, path := range []string{serverKey, clientKey} {
		if out, e := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-f", path).CombinedOutput(); e != nil {
			t.Fatalf("fixture key generation: %s %v", out, e)
		}
	}
	identity, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	serverConfig := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s.pub\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nAllowTcpForwarding yes\nPermitRootLogin yes\nLogLevel ERROR\n", port, serverKey, filepath.Join(dir, "sshd.pid"), clientKey)
	configFile := filepath.Join(dir, "sshd_config")
	os.WriteFile(configFile, []byte(serverConfig), 0600)
	var daemonLog bytes.Buffer
	daemon := exec.Command(sshd, "-D", "-e", "-f", configFile)
	daemon.Stderr = &daemonLog
	if err = daemon.Start(); err != nil {
		t.Skipf("isolated sshd unavailable: %v", err)
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
		conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case e := <-done:
			t.Skipf("isolated sshd capability unavailable: %v (%s)", e, daemonLog.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Skip("isolated sshd did not become ready")
	}
	socketDir, err := os.MkdirTemp("", "lc-ssh-")
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
	clientConfig := fmt.Sprintf("Host isolated-proxy-fixture\n HostName 127.0.0.1\n Port %d\n User %s\n IdentityFile %s\n IdentitiesOnly yes\n StrictHostKeyChecking yes\n UserKnownHostsFile %s\n LogLevel ERROR\n ControlMaster auto\n ControlPersist 60\n ControlPath %s\n", port, identity.Username, clientKey, knownHosts, userSocket)
	clientFile := filepath.Join(dir, "ssh_config")
	os.WriteFile(clientFile, []byte(clientConfig), 0600)
	run := func(cmd *exec.Cmd) error {
		hasConfig := false
		for _, arg := range cmd.Args {
			if arg == "-F" {
				hasConfig = true
			}
		}
		if !hasConfig {
			cmd.Args = append([]string{cmd.Args[0], "-F", clientFile}, cmd.Args[1:]...)
		}
		return cmd.Run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// A separately owned fixture master proves persistent sessions ignore its
	// ControlPath even though the host config offers it for automatic reuse.
	userMaster := exec.CommandContext(ctx, "ssh", "-F", clientFile, "-M", "-N", "-f", "-o", "BatchMode=yes", "--", "isolated-proxy-fixture")
	if out, e := userMaster.CombinedOutput(); e != nil {
		t.Skipf("isolated sshd cannot authenticate this test user: %v (%s)", e, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("ssh", "-F", os.DevNull, "-S", userSocket, "-O", "exit", "--", "isolated-proxy-fixture").Run()
	})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("unexpected proxy method %s", r.Method)
		}
		w.WriteHeader(204)
	}))
	defer proxy.Close()
	opts := SessionOptions{Directory: filepath.Join(dir, "sessions"), Run: run}
	p := Plan{HTTP: proxy.URL, All: proxy.URL, SSHHost: "isolated-proxy-fixture"}
	aid, _ := NewID()
	bid, _ := NewID()
	a, err := Start(ctx, aid, os.Getpid(), p, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop(context.Background(), aid, opts) })
	b, err := Start(ctx, bid, os.Getpid(), p, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Stop(context.Background(), bid, opts) })
	if a.Socket == userSocket || a.Socket == b.Socket {
		t.Fatal("private master reused another session")
	}
	for _, s := range []Session{a, b} {
		r, e := Test(ctx, s.Local, "http://fixture.invalid/health")
		if e != nil || r.HTTPStatus != 204 {
			t.Fatalf("real forwarded request: %+v %v", r, e)
		}
	}
	if err = Stop(ctx, aid, opts); err != nil {
		t.Fatal(err)
	}
	if _, err = Test(ctx, b.Local, "http://fixture.invalid/health"); err != nil {
		t.Fatal("second shell tunnel stopped:", err)
	}
	check := exec.CommandContext(ctx, "ssh", "-F", os.DevNull, "-S", userSocket, "-O", "check", "--", "isolated-proxy-fixture")
	if out, e := check.CombinedOutput(); e != nil || !strings.Contains(string(out), "Master running") {
		t.Fatal("fixture user's master was closed")
	}
}
