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

// AuthenticateCommand uses persistent user multiplexing policy when available;
// otherwise it creates a private, invocation-scoped 60s master. Execute on the
// real terminal, then retry once. Configured sockets are never app-owned.
func AuthenticateCommand(ctx context.Context, host string) (*exec.Cmd, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateHost(host); err != nil {
		return nil, err
	}
	policy, err := resolveMultiplexPolicy(ctx, host)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	useConfigured, master := policy.persistent(), policy.master
	if policy.path != "" {
		alive, err := configuredMasterAlive(ctx, host, policy.path)
		if err != nil {
			return nil, err
		}
		if alive {
			useConfigured, master = true, "no"
		}
	}
	authentications.Lock()
	a, ok := authentications.hosts[host]
	if !ok && useConfigured {
		authentications.Unlock()
		return commandContext(ctx, "ssh", "-o", "BatchMode=no", "-o", "ConnectTimeout=15", "-o", "ClearAllForwardings=yes", "-o", "ControlMaster="+master, "-o", "ControlPersist="+policy.persist, "-o", "ControlPath="+controlSocketArgument(policy.path), "-T", "--", host, "true"), nil
	}
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
	return commandContext(ctx, "ssh", "-o", "BatchMode=no", "-o", "ConnectTimeout=15", "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=auto", "-o", "ControlPersist=60", "-o", "ControlPath="+controlSocketArgument(a.path), "-T", "--", host, "true"), nil
}

func CloseAuthentications() error {
	authentications.Lock()
	owned := authentications.hosts
	authentications.hosts = map[string]authentication{}
	authentications.Unlock()
	clearMultiplexPolicies()
	for host, a := range owned {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = commandContext(ctx, "ssh", append(masterControlArgs(a.path, "exit"), "--", host)...).Run()
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

func batchSSHArgs(controlPath string) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-o", "ControlMaster=no"}
	if controlPath == "" {
		controlPath = "none"
	}
	return append(args, "-o", "ControlPath="+controlSocketArgument(controlPath))
}

func sshArgs(host string) []string {
	var policy multiplexPolicy
	multiplexPolicies.Lock()
	if entry := multiplexPolicies.entries[host]; entry != nil && entry.ready == nil {
		policy = entry.policy
	}
	multiplexPolicies.Unlock()
	authentications.Lock()
	a, ok := authentications.hosts[host]
	authentications.Unlock()
	if ok {
		return append(batchSSHArgs(a.path), "-o", "ClearAllForwardings=yes")
	}
	return append(batchSSHArgs(policy.path), "-o", "ClearAllForwardings=yes")
}

func sshArgsContext(ctx context.Context, host string) ([]string, error) {
	if _, err := resolveMultiplexPolicy(ctx, host); err != nil {
		return nil, err
	}
	return sshArgs(host), nil
}

// Remote command strings contain only fixed script text or single-quoted paths.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func remoteCommand(ctx context.Context, host, script string, limit int) ([]byte, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	base, err := sshArgsContext(ctx, host)
	if err != nil {
		return nil, err
	}
	args := append(base, "-T", "--", host, script)
	cmd := commandContext(ctx, "ssh", args...)
	var out limitedBuffer
	out.limit = limit
	var diagnostic limitedBuffer
	diagnostic.limit = 8192
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	err = cmd.Run()
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
	mu       sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buffer.Len()+len(p) > b.limit {
		b.exceeded = true
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
func (b *limitedBuffer) Exceeded() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.exceeded }

func needsAuthentication(stderr string) bool {
	s := strings.ToLower(stderr)
	if strings.Contains(s, "host key verification failed") || strings.Contains(s, "no supported authentication methods") || strings.Contains(s, "read_passphrase") || strings.Contains(s, "authenticity of host") {
		return true
	}
	for _, line := range strings.Split(s, "\n") {
		_, tail, ok := strings.Cut(line, "permission denied")
		if !ok {
			continue
		}
		tail = strings.TrimSpace(tail)
		if strings.HasPrefix(tail, ", please try again") {
			return true
		}
		if strings.HasPrefix(tail, "(") {
			methods, _, closed := strings.Cut(tail[1:], ")")
			if !closed {
				continue
			}
			for _, method := range strings.Split(methods, ",") {
				switch strings.TrimSpace(method) {
				case "publickey", "password", "keyboard-interactive", "hostbased", "gssapi-with-mic", "gssapi-keyex":
					return true
				}
			}
		}
	}
	return false
}

func missingControlMaster(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "control socket") && (strings.Contains(s, "no such file") || strings.Contains(s, "connection refused") || strings.Contains(s, "connection reset"))
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
	policy, err := resolveMultiplexPolicy(ctx, host)
	if err != nil {
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
	alive, err := configuredMasterAlive(ctx, host, policy.path)
	if err != nil {
		return nil, err
	}
	if alive {
		return openMasterForward(ctx, host, address, forward, authentication{path: policy.path})
	}
	// A dedicated child must not opportunistically attach its -L forwarding to
	// a configured master. Such forwarding would survive killing this child.
	args := append(batchSSHArgs("none"), "-o", "ExitOnForwardFailure=yes", "-N", "-T", "-L", forward, "--", host)
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

// Both private and configured masters use exact forward/cancel messages. Only
// the forwarding belongs to this tunnel; the configured master never does.
func openMasterForward(ctx context.Context, host, address, forward string, auth authentication) (*tunnel, error) {
	setupCtx, cancelSetup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSetup()
	args := append(masterControlArgs(auth.path, "forward"), "-o", "ExitOnForwardFailure=yes", "-L", forward, "--", host)
	cancelForward := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cleanupCancel()
		_ = commandContext(cleanupCtx, "ssh", append(masterControlArgs(auth.path, "cancel"), "-L", forward, "--", host)...).Run()
	}
	var diagnostic limitedBuffer
	diagnostic.limit = 8192
	cmd := commandContext(setupCtx, "ssh", args...)
	cmd.Stderr = &diagnostic
	if err := cmd.Run(); err != nil {
		// A lost control reply may hide a successful forwarding request. Cancel
		// only our exact ephemeral forwarding, never the shared master.
		cancelForward()
		if setupCtx.Err() != nil {
			return nil, setupCtx.Err()
		}
		if needsAuthentication(diagnostic.String()) || missingControlMaster(diagnostic.String()) {
			return nil, &AuthRequiredError{Host: host}
		}
		return nil, errors.New("SSH tunnel forwarding failed")
	}
	tunnelCtx, cancel := context.WithCancel(ctx)
	t := &tunnel{address: address, cancel: cancel}
	t.closeForward = cancelForward
	go func() { <-tunnelCtx.Done(); _ = t.Close() }()
	return t, nil
}
