package connection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

var commandContext = exec.CommandContext

// AuthRequiredError is a terminal handoff request, not an authentication prompt.
// Background work uses BatchMode, so no hidden process competes for TUI input.
type AuthRequiredError struct{ Host string }

func (e *AuthRequiredError) Error() string {
	return fmt.Sprintf("SSH authentication or host-key approval required for %s; authenticate in a terminal and retry", e.Host)
}
func IsAuthRequired(err error) bool { var e *AuthRequiredError; return errors.As(err, &e) }

type authentication struct{ dir, path string }

var authentications = struct {
	sync.Mutex
	hosts map[string]authentication
}{hosts: map[string]authentication{}}

// AuthenticateCommand creates an app-owned multiplexed connection. Execute it
// using the real terminal (tea.ExecProcess in the TUI), then retry once. Call
// CloseAuthentications on application exit. The master also expires after 60s
// idle if the application cannot run its cleanup.
func AuthenticateCommand(ctx context.Context, host string) (*exec.Cmd, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	authentications.Lock()
	a, ok := authentications.hosts[host]
	if !ok {
		dir, err := os.MkdirTemp("", "lazyclash-ssh-")
		if err != nil {
			authentications.Unlock()
			return nil, err
		}
		a = authentication{dir: dir, path: filepath.Join(dir, "control")}
		authentications.hosts[host] = a
	}
	authentications.Unlock()
	return commandContext(ctx, "ssh", "-o", "BatchMode=no", "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto", "-o", "ControlPersist=60", "-o", "ControlPath="+a.path, "-T", "--", host, "true"), nil
}

func CloseAuthentications() error {
	authentications.Lock()
	owned := authentications.hosts
	authentications.hosts = map[string]authentication{}
	authentications.Unlock()
	for host, a := range owned {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = commandContext(ctx, "ssh", "-o", "BatchMode=yes", "-S", a.path, "-O", "exit", "--", host).Run()
		cancel()
		_ = os.RemoveAll(a.dir)
	}
	return nil
}

func validateHost(host string) error {
	if host == "" {
		return errors.New("SSH host is required")
	}
	return config.ValidateTarget(config.Target{Controller: "http://127.0.0.1:9090", SSHHost: host})
}

func sshArgs(host string) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-o", "ControlMaster=no"}
	authentications.Lock()
	a, ok := authentications.hosts[host]
	authentications.Unlock()
	if ok {
		args = append(args, "-o", "ControlPath="+a.path)
	} else {
		args = append(args, "-o", "ControlPath=none")
	}
	return args
}

// Remote command strings contain only fixed script text or single-quoted paths.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func remoteCommand(ctx context.Context, host, script string, limit int) ([]byte, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	args := append(sshArgs(host), "-T", "--", host, script)
	cmd := commandContext(ctx, "ssh", args...)
	var out limitedBuffer
	out.limit = limit
	var diagnostic limitedBuffer
	diagnostic.limit = 8192
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("SSH request: %w", ctx.Err())
		}
		if needsAuthentication(diagnostic.String()) {
			return nil, &AuthRequiredError{Host: host}
		}
		return nil, errors.New("SSH remote read failed; check the host, path and SSH configuration")
	}
	return out.Bytes(), nil
}

func remoteRead(ctx context.Context, host, path string) ([]byte, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("remote source path must be absolute")
	}
	return remoteCommand(ctx, host, "test -f "+shellQuote(path)+" && cat < "+shellQuote(path), maxConfigBytes)
}

type limitedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(p) > b.limit {
		return 0, errors.New("subprocess output exceeds size limit")
	}
	return b.buffer.Write(p)
}
func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buffer.Bytes()...)
}
func (b *limitedBuffer) String() string { return string(b.Bytes()) }

func needsAuthentication(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "permission denied") || strings.Contains(s, "host key verification failed") || strings.Contains(s, "no supported authentication methods") || strings.Contains(s, "read_passphrase") || strings.Contains(s, "authenticity of host")
}

type tunnel struct {
	address      string
	cmd          *exec.Cmd
	done         chan struct{}
	mu           sync.Mutex
	err          error
	once         sync.Once
	cancel       context.CancelFunc
	closeForward func()
}

func (t *tunnel) Close() error {
	t.once.Do(func() {
		t.cancel()
		if t.closeForward != nil {
			t.closeForward()
			return
		}
		select {
		case <-t.done:
		case <-time.After(2 * time.Second):
			if t.cmd.Process != nil {
				_ = t.cmd.Process.Kill()
			}
			<-t.done
		}
	})
	return nil
}

func openTunnel(ctx context.Context, host string, u *url.URL) (*tunnel, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	// Reserve a loopback port, then release immediately before SSH binds it.
	// ExitOnForwardFailure makes the unavoidable bind race a reported failure.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	address := listener.Addr().String()
	_ = listener.Close()
	remoteHost := u.Hostname()
	if strings.Contains(remoteHost, ":") {
		remoteHost = "[" + remoteHost + "]"
	}
	forward := address + ":" + remoteHost + ":" + port
	authentications.Lock()
	auth, hasAuth := authentications.hosts[host]
	authentications.Unlock()
	if hasAuth {
		return openMasterForward(ctx, host, address, forward, auth)
	}
	args := append(sshArgs(host), "-o", "ExitOnForwardFailure=yes", "-N", "-T", "-L", forward, "--", host)
	tunnelCtx, cancel := context.WithCancel(ctx)
	cmd := commandContext(tunnelCtx, "ssh", args...)
	diagnostic := &limitedBuffer{limit: 8192}
	cmd.Stderr = diagnostic
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, errors.New("cannot start SSH; ensure OpenSSH is installed")
	}
	t := &tunnel{address: address, cmd: cmd, done: make(chan struct{}), cancel: cancel}
	go func() { err := cmd.Wait(); t.mu.Lock(); t.err = err; t.mu.Unlock(); close(t.done) }()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = t.Close()
			return nil, ctx.Err()
		case <-deadline.C:
			_ = t.Close()
			return nil, errors.New("SSH tunnel was not ready within 10 seconds")
		case <-t.done:
			cancel()
			if needsAuthentication(diagnostic.String()) {
				return nil, &AuthRequiredError{Host: host}
			}
			return nil, errors.New("SSH tunnel exited before becoming ready; check forwarding permissions and controller address")
		case <-tick.C:
			conn, err := net.DialTimeout("tcp", address, 60*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				select {
				case <-t.done:
					_ = t.Close()
					return nil, errors.New("SSH tunnel exited during startup")
				default:
					return t, nil
				}
			}
		}
	}
}

// App-owned authenticated masters use explicit forward/cancel control messages;
// killing a multiplex client alone would otherwise leave its forward behind.
func openMasterForward(ctx context.Context, host, address, forward string, auth authentication) (*tunnel, error) {
	setupCtx, cancelSetup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSetup()
	args := []string{"-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-S", auth.path, "-O", "forward", "-L", forward, "--", host}
	var diagnostic limitedBuffer
	diagnostic.limit = 8192
	cmd := commandContext(setupCtx, "ssh", args...)
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		if setupCtx.Err() != nil {
			return nil, setupCtx.Err()
		}
		if needsAuthentication(diagnostic.String()) || strings.Contains(strings.ToLower(diagnostic.String()), "control socket") {
			return nil, &AuthRequiredError{Host: host}
		}
		return nil, errors.New("SSH tunnel forwarding failed")
	}
	tunnelCtx, cancel := context.WithCancel(ctx)
	t := &tunnel{address: address, cancel: cancel}
	t.closeForward = func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cleanupCancel()
		_ = commandContext(cleanupCtx, "ssh", "-o", "BatchMode=yes", "-S", auth.path, "-O", "cancel", "-L", forward, "--", host).Run()
	}
	go func() { <-tunnelCtx.Done(); _ = t.Close() }()
	return t, nil
}
