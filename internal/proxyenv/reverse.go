package proxyenv

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// ReverseSession is an invocation-owned lease in the existing private session
// registry. Its endpoints are meaningful on Host, never on the local machine.
type ReverseSession struct {
	Host          string `json:"host"`
	Remote        Plan   `json:"remote"`
	OwnerPID      int    `json:"owner_pid"`
	OwnerIdentity string `json:"owner_identity"`
}

type ReverseOptions struct {
	Host                string
	HTTPPort, SocksPort int // zero asks sshd to allocate an unused remote port
}

func validateReverseSource(p Plan, o ReverseOptions) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.SSHHost != "" {
		return errors.New("reverse SSH requires a locally reachable proxy; chained source SSH is not supported")
	}
	if p.Username != "" || p.PasswordEnv != "" || p.PasswordFile != "" || p.CAFile != "" {
		return errors.New("reverse SSH currently requires an HTTP/SOCKS proxy without data credentials or a custom CA")
	}
	for _, raw := range []string{p.HTTP, p.All} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			return errors.New("reverse SSH supports HTTP/SOCKS data endpoints; HTTPS proxy endpoints are not supported")
		}
	}
	if o.Host == "" {
		return errors.New("destination SSH host is required")
	}
	if err := config.ValidateTarget(config.Target{Controller: "http://127.0.0.1:9090", SSHHost: o.Host}); err != nil {
		return errors.New("invalid destination SSH host")
	}
	if o.HTTPPort < 0 || o.HTTPPort > 65535 || o.SocksPort < 0 || o.SocksPort > 65535 {
		return errors.New("remote ports must be 0 (automatic) or 1 through 65535")
	}
	a, _ := url.Parse(p.HTTP)
	b, _ := url.Parse(p.All)
	if o.HTTPPort != 0 && o.HTTPPort == o.SocksPort && a.Host != b.Host {
		return errors.New("different HTTP and SOCKS source endpoints need different remote ports")
	}
	return nil
}

func validateReverseRecord(s Session) error {
	r := s.Reverse
	if r == nil || r.OwnerPID < 1 || r.OwnerIdentity == "" {
		return errors.New("invalid reverse session owner")
	}
	if err := validateReverseSource(s.Plan, ReverseOptions{Host: r.Host}); err != nil {
		return err
	}
	if s.State == "ready" {
		if err := validateReverseSource(r.Remote, ReverseOptions{Host: r.Host}); err != nil {
			return fmt.Errorf("invalid reverse session endpoints: %w", err)
		}
		for _, raw := range []string{r.Remote.HTTP, r.Remote.All} {
			u, _ := url.Parse(raw)
			if u.Hostname() != "127.0.0.1" || r.Remote.SSHHost != "" {
				return errors.New("reverse session endpoint is not remote loopback")
			}
		}
	}
	return nil
}

// PrepareReverse authenticates once, creates explicit remote TCP forwards, and
// verifies their actual bind addresses before returning. Callers own Stop.
func PrepareReverse(ctx context.Context, p Plan, ro ReverseOptions, opts SessionOptions) (s Session, err error) {
	// Normalize cancellation after the cleanup defer has run. Keep its error
	// alongside the original failure so an uncertain lease remains visible.
	defer func() {
		if err != nil && ctx.Err() != nil && !errors.Is(err, ctx.Err()) {
			err = errors.Join(ctx.Err(), err)
		}
	}()
	if p.All == "" {
		p.All = p.HTTP
	}
	if err = validateReverseSource(p, ro); err != nil {
		return s, err
	}
	if e := ValidateConsumer(p, "service", ConsumerOptions{Directory: opts.Directory}); e != nil {
		if errors.Is(e, ErrTemporaryProxy) {
			return s, errors.New("reverse SSH source is a temporary SSH endpoint; chained forwarding is not supported")
		}
		return s, e
	}
	if err = ctx.Err(); err != nil {
		return s, err
	}
	// Validate the data endpoints before SSH authentication. This is only TCP
	// reachability, not a claim that arbitrary destinations work through them.
	seen := map[string]bool{}
	for _, raw := range []string{p.HTTP, p.All} {
		u, _ := url.Parse(raw)
		if seen[u.Host] {
			continue
		}
		seen[u.Host] = true
		conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", u.Host)
		if e != nil {
			return s, errors.New("local data proxy is not reachable; start it or choose an explicit reachable endpoint")
		}
		_ = conn.Close()
	}
	id, err := NewID()
	if err != nil {
		return s, err
	}
	identity, err := processIdentity(os.Getpid())
	if err != nil || identity == "" {
		return s, errors.New("cannot identify the reverse proxy invocation")
	}
	dir, err := sessionDir(opts, true)
	if err != nil {
		return s, err
	}
	lock, err := lockFile(filepath.Join(dir, id+".lock"))
	if err != nil {
		return s, err
	}
	defer unlockFile(lock)
	s = Session{ID: id, State: "preparing", Created: time.Now().UTC(), Plan: p, Local: p, Reverse: &ReverseSession{Host: ro.Host, OwnerPID: os.Getpid(), OwnerIdentity: identity}}
	s.SocketDir, err = os.MkdirTemp("", "lazyclash-proxy-")
	if err != nil {
		return s, err
	}
	s.Socket = filepath.Join(s.SocketDir, "control")
	if err = saveSession(dir, s); err != nil {
		_ = os.Remove(s.SocketDir)
		return s, err
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if e := stopSession(cleanup, dir, s, opts); e != nil {
				err = errors.Join(err, fmt.Errorf("reverse lease %s needs inspection: %w", s.ID, e))
			}
		}
	}()
	if err = startReverseMaster(ctx, &s, opts); err != nil {
		return s, err
	}
	if err = saveSession(dir, s); err != nil {
		return s, err
	}
	remote := p
	remote.Source = "temporary reverse SSH"
	remote.Origin = ""
	mapped := map[string]int{}
	ports := []int{}
	for i, raw := range []string{p.HTTP, p.All} {
		u, _ := url.Parse(raw)
		requested := ro.HTTPPort
		if i == 1 {
			requested = ro.SocksPort
		}
		// A mixed listener shares its remote port unless distinct fixed ports
		// were explicitly requested. Prefer the one specified fixed port.
		other, _ := url.Parse(p.All)
		if i == 0 && requested == 0 && other.Host == u.Host {
			requested = ro.SocksPort
		}
		key := u.Host
		port := mapped[key]
		if port == 0 || (requested != 0 && requested != port) {
			forward := "127.0.0.1:" + strconv.Itoa(requested) + ":" + net.JoinHostPort(u.Hostname(), u.Port())
			// Persist the intent before asking the master; an uncertain control
			// result is cleaned up by closing only this private master.
			s.Forwards = append(s.Forwards, forward)
			if err = saveSession(dir, s); err != nil {
				return s, err
			}
			port, err = reverseForward(ctx, s, forward, requested, opts)
			if err != nil {
				return s, err
			}
			s.Forwards[len(s.Forwards)-1] = "127.0.0.1:" + strconv.Itoa(port) + ":" + net.JoinHostPort(u.Hostname(), u.Port())
			mapped[key] = port
			ports = append(ports, port)
		}
		u.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		if i == 0 {
			remote.HTTP = u.String()
		} else {
			remote.All = u.String()
		}
	}
	s.Reverse.Remote = remote
	if err = verifyReverseListeners(ctx, s, ports, opts); err != nil {
		return s, err
	}
	s.Reverse.Remote.Origin, err = TemporaryOrigin(remote, "ssh-reverse")
	if err != nil {
		return s, err
	}
	s.State = "ready"
	if err = saveSession(dir, s); err != nil {
		return s, err
	}
	committed = true
	return s, nil
}

func startReverseMaster(ctx context.Context, s *Session, opts SessionOptions) error {
	batch := "yes"
	if opts.Interactive {
		batch = "no"
	}
	args := []string{"-M", "-N", "-f", "-T", "-o", "ControlMaster=yes", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes", "-o", "ControlPath=" + strings.ReplaceAll(s.Socket, "%", "%%"), "-o", "BatchMode=" + batch, "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-o", "RemoteCommand=none", "-o", "PermitLocalCommand=no", "-o", "ForwardAgent=no", "-o", "ForwardX11=no"}
	if !opts.Interactive {
		args = append(args, "-o", "StrictHostKeyChecking=yes")
	}
	args = append(args, "--", sessionHost(*s))
	authCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(authCtx, "ssh", args...)
	cmd.WaitDelay = time.Second
	var diagnostic cappedBuffer
	diagnostic.limit = 8192
	if opts.Interactive {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.In, opts.Err, opts.Err
	} else {
		cmd.Stdout, cmd.Stderr = &diagnostic, &diagnostic
	}
	err := runSessionCommand(cmd, opts)
	s.SocketIdentity, _ = socketIdentity(s.Socket)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !opts.Interactive && authFailure(diagnostic.String()) {
			return &connection.AuthRequiredError{Host: sessionHost(*s)}
		}
		return errors.New("reverse SSH could not authenticate; check the host and SSH configuration")
	}
	if s.SocketIdentity == "" {
		return errors.New("reverse SSH did not create its private control socket")
	}
	s.MasterPID, err = checkMaster(ctx, *s, opts)
	if err != nil {
		return err
	}
	s.MasterIdentity, err = processIdentity(s.MasterPID)
	if err != nil || s.MasterIdentity == "" {
		return errors.New("reverse SSH master identity unavailable")
	}
	return nil
}

func reverseForward(ctx context.Context, s Session, spec string, requested int, opts SessionOptions) (int, error) {
	if _, err := checkMaster(ctx, s, opts); err != nil {
		return 0, err
	}
	query, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{"-F", os.DevNull, "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-S", strings.ReplaceAll(s.Socket, "%", "%%"), "-O", "forward", "-o", "ExitOnForwardFailure=yes", "-R", spec, "--", sessionHost(s)}
	cmd := exec.CommandContext(query, "ssh", args...)
	cmd.WaitDelay = time.Second
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = 1024, 8192
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := runSessionCommand(cmd, opts); err != nil {
		return 0, errors.New("reverse SSH forwarding failed; the remote port or forwarding policy prevents it")
	}
	if requested != 0 {
		return requested, nil
	}
	port, err := strconv.Atoi(strings.TrimSpace(stdout.String()))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("reverse SSH did not report an unambiguous allocated port")
	}
	return port, nil
}

// A disappearing private master must fail closed, never create a fresh SSH
// transport that might execute a command a second time without its forwards.
func reverseCommand(ctx context.Context, s Session, command string, tty bool) *exec.Cmd {
	args := []string{"-F", os.DevNull, "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPersist=no", "-o", "ProxyCommand=false", "-o", "ClearAllForwardings=yes", "-S", strings.ReplaceAll(s.Socket, "%", "%%")}
	if tty {
		args = append(args, "-t")
	} else {
		args = append(args, "-T")
	}
	args = append(args, "--", sessionHost(s), command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	configureChild(cmd)
	return cmd
}

func reverseShellCommand(p Plan, argv []string, clean bool) (string, error) {
	if clean && len(argv) != 0 {
		return "", errors.New("clean-shell applies only to an interactive shell")
	}
	values, err := Values(p)
	if err != nil {
		return "", err
	}
	args := []string{"exec", "/usr/bin/env", "-u", "LAZYCLASH_PROXY_SESSION"}
	if clean {
		args = append(args, "-u", "ENV", "-u", "BASH_ENV")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, Quote(key+"="+values[key]))
	}
	if len(argv) == 0 {
		if clean {
			argv = []string{"/bin/sh", "-i"}
		} else {
			argv = []string{"/bin/sh", "-c", `exec "${SHELL:-/bin/sh}" -l`}
		}
	}
	for _, arg := range argv {
		if strings.ContainsRune(arg, 0) {
			return "", errors.New("remote command arguments cannot contain NUL")
		}
		args = append(args, Quote(arg))
	}
	return strings.Join(args, " "), nil
}

func RunReverseSSH(ctx context.Context, s Session, argv []string, clean bool, opts SessionOptions) error {
	if s.Reverse == nil || s.State != "ready" {
		return errors.New("reverse SSH session is not ready")
	}
	if err := validateReverseRecord(s); err != nil {
		return err
	}
	if len(argv) == 0 && !opts.Interactive {
		return errors.New("remote shell requires an interactive terminal; provide a command after --")
	}
	if _, err := checkMaster(ctx, s, opts); err != nil {
		return err
	}
	command, err := reverseShellCommand(s.Reverse.Remote, argv, clean)
	if err != nil {
		return err
	}
	cmd := reverseCommand(ctx, s, command, len(argv) == 0)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.In, opts.Out, opts.Err
	err = runSessionCommand(cmd, opts)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		code := exited.ExitCode()
		if code < 0 {
			code = signalExitCode(exited)
		}
		return &ExitError{Code: code}
	}
	if err != nil {
		return errors.New("remote SSH command could not be started; it was not retried")
	}
	return nil
}

func WaitReverse(ctx context.Context, s Session, opts SessionOptions) error {
	if s.Reverse == nil || s.State != "ready" {
		return errors.New("reverse SSH session is not ready")
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := checkMaster(ctx, s, opts); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errors.New("reverse SSH connection ended; this share is no longer available")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
