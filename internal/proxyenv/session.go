package proxyenv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var sessionID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var masterPID = regexp.MustCompile(`Master running \(pid=([0-9]+)\)`)

type Session struct {
	ID             string          `json:"id"`
	State          string          `json:"state"`
	ShellPID       int             `json:"shell_pid"`
	ShellIdentity  string          `json:"shell_identity"`
	Created        time.Time       `json:"created"`
	Plan           Plan            `json:"plan"`
	Local          Plan            `json:"local"`
	Username       string          `json:"username,omitempty"`
	PasswordEnv    string          `json:"password_env,omitempty"`
	PasswordFile   string          `json:"password_file,omitempty"`
	CAFile         string          `json:"ca_file,omitempty"`
	SocketDir      string          `json:"socket_dir,omitempty"`
	Socket         string          `json:"socket,omitempty"`
	SocketIdentity string          `json:"socket_identity,omitempty"`
	MasterPID      int             `json:"master_pid,omitempty"`
	MasterIdentity string          `json:"master_identity,omitempty"`
	Forwards       []string        `json:"forwards,omitempty"`
	Reverse        *ReverseSession `json:"reverse,omitempty"`
}

type SessionOptions struct {
	Directory   string
	Run         Runner
	Interactive bool
	In          io.Reader
	Out         io.Writer
	Err         io.Writer
}

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func SessionDirectory() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "lazyclash", "proxy-sessions"), nil
}
func sessionDir(opts SessionOptions, create bool) (string, error) {
	dir := opts.Directory
	var err error
	if dir == "" {
		dir, err = SessionDirectory()
		if err != nil {
			return "", err
		}
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("session directory must be absolute")
	}
	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !privateInfo(info) {
		return "", errors.New("session directory must be owned by this user with mode 0700 and cannot be a symlink")
	}
	return dir, nil
}
func sessionPath(dir, id string) (string, error) {
	if !sessionID.MatchString(id) {
		return "", errors.New("invalid proxy session ID")
	}
	return filepath.Join(dir, id+".json"), nil
}
func readSession(dir, id string) (Session, error) {
	var s Session
	path, err := sessionPath(dir, id)
	if err != nil {
		return s, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return s, err
	}
	if !info.Mode().IsRegular() || !privateInfo(info) || info.Size() > 65536 {
		return s, errors.New("invalid private session record")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(data, &s); err != nil || s.ID != id {
		return s, errors.New("invalid session record")
	}
	s.Local.Username, s.Local.PasswordEnv, s.Local.PasswordFile, s.Local.CAFile = s.Username, s.PasswordEnv, s.PasswordFile, s.CAFile
	if s.Reverse != nil {
		if err := validateReverseRecord(s); err != nil {
			return s, err
		}
		if s.State == "ready" {
			s.Reverse.Remote.Origin, err = TemporaryOrigin(s.Reverse.Remote, "ssh-reverse")
		}
	} else if s.Plan.SSHHost != "" {
		s.Local.Origin, err = TemporaryOrigin(s.Local, "ssh-forward")
	}
	if err != nil {
		return s, err
	}
	if s.Socket != "" && (filepath.Dir(s.Socket) != s.SocketDir || filepath.Base(s.Socket) != "control" || !strings.HasPrefix(filepath.Base(s.SocketDir), "lazyclash-proxy-")) {
		return s, errors.New("invalid session control path")
	}
	if s.SocketDir != "" {
		info, e := os.Lstat(s.SocketDir)
		if e == nil && (!info.IsDir() || !privateInfo(info)) {
			return s, errors.New("session socket directory is not private")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return s, e
		}
	}
	return s, nil
}
func saveSession(dir string, s Session) error {
	path, err := sessionPath(dir, s.ID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".session-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

// Start creates a private session that intentionally outlives this invocation.
// A private -MNf master never attaches forwarding to a user's ControlMaster.
func Start(ctx context.Context, id string, shellPID int, p Plan, opts SessionOptions) (Session, error) {
	var s Session
	if err := ctx.Err(); err != nil {
		return s, err
	}
	if !sessionID.MatchString(id) {
		return s, errors.New("invalid proxy session ID")
	}
	if err := p.Validate(); err != nil {
		return s, err
	}
	if p.SSHHost != "" {
		for _, endpoint := range []string{p.HTTP, p.All} {
			u, _ := url.Parse(endpoint)
			if u.Scheme == "https" {
				return s, errors.New("HTTPS proxy over SSH cannot be exported with a loopback TLS hostname; use an HTTP/SOCKS data endpoint or direct HTTPS endpoint")
			}
		}
	}
	identity, err := processIdentity(shellPID)
	if err != nil {
		return s, err
	}
	if identity == "" {
		return s, errors.New("shell process is no longer running")
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
	path, _ := sessionPath(dir, id)
	if _, err = os.Lstat(path); err == nil {
		return s, errors.New("proxy session already exists; use a new session ID")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	s = Session{ID: id, State: "preparing", ShellPID: shellPID, ShellIdentity: identity, Created: time.Now().UTC(), Plan: p, Local: p, Username: p.Username, PasswordEnv: p.PasswordEnv, PasswordFile: p.PasswordFile, CAFile: p.CAFile}
	s.Local.SSHHost = ""
	if p.SSHHost != "" {
		s.SocketDir, err = os.MkdirTemp("", "lazyclash-proxy-")
		if err != nil {
			return s, err
		}
		s.Socket = filepath.Join(s.SocketDir, "control")
	}
	if err = saveSession(dir, s); err != nil {
		if s.SocketDir != "" {
			_ = os.Remove(s.SocketDir)
		}
		return s, err
	}
	committed := false
	defer func() {
		if !committed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			_ = stopSession(cleanupCtx, dir, s, opts)
		}
	}()
	if p.SSHHost != "" {
		batch := "yes"
		if opts.Interactive {
			batch = "no"
		}
		args := []string{"-M", "-N", "-f", "-T", "-o", "ControlMaster=yes", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes", "-o", "ControlPath=" + strings.ReplaceAll(s.Socket, "%", "%%"), "-o", "BatchMode=" + batch, "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2"}
		if !opts.Interactive {
			args = append(args, "-o", "StrictHostKeyChecking=yes")
		}
		args = append(args, "--", p.SSHHost)
		authCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		cmd := exec.CommandContext(authCtx, "ssh", args...)
		cmd.WaitDelay = time.Second
		var output cappedBuffer
		output.limit = 8192
		if opts.Interactive {
			cmd.Stdin, cmd.Stdout, cmd.Stderr = opts.In, opts.Err, opts.Err
		} else {
			cmd.Stdout, cmd.Stderr = &output, &output
		}
		err = runSessionCommand(cmd, opts)
		cancel()
		// Even a canceled client may have completed its background fork. Bind
		// cleanup to the newly-created private socket before returning failure.
		s.SocketIdentity, _ = socketIdentity(s.Socket)
		if err != nil {
			if ctx.Err() != nil {
				return s, ctx.Err()
			}
			if !opts.Interactive && authFailure(output.String()) {
				return s, &connection.AuthRequiredError{Host: p.SSHHost}
			}
			return s, errors.New("SSH proxy session could not authenticate; retry proxy-on in a terminal")
		}
		if s.SocketIdentity == "" {
			return s, errors.New("SSH did not create its private control socket")
		}
		pid, e := checkMaster(ctx, s, opts)
		if e != nil {
			return s, e
		}
		s.MasterPID = pid
		s.MasterIdentity, err = processIdentity(pid)
		if err != nil || s.MasterIdentity == "" {
			return s, errors.New("SSH master process identity unavailable")
		}
		// Persist identity before forwards so crash cleanup is exact.
		if err = saveSession(dir, s); err != nil {
			return s, err
		}
		mapped := map[string]string{}
		for i, raw := range []string{p.HTTP, p.All} {
			u, _ := url.Parse(raw)
			address := mapped[u.Host]
			if address == "" {
				ln, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					return s, e
				}
				address = ln.Addr().String()
				_ = ln.Close()
				forward := address + ":" + net.JoinHostPort(u.Hostname(), u.Port())
				s.Forwards = append(s.Forwards, forward)
				if err = saveSession(dir, s); err != nil {
					return s, err
				}
				if _, e = control(ctx, s, "forward", []string{"-o", "ExitOnForwardFailure=yes", "-L", forward}, opts); e != nil {
					return s, errors.New("SSH proxy forwarding failed; remote forwarding policy or local port may prevent it")
				}
				mapped[u.Host] = address
			}
			u.Host = address
			if i == 0 {
				s.Local.HTTP = u.String()
			} else {
				s.Local.All = u.String()
			}
		}
	}
	s.State = "ready"
	if p.SSHHost != "" {
		s.Local.Origin, err = TemporaryOrigin(s.Local, "ssh-forward")
		if err != nil {
			return s, err
		}
	}
	if err = saveSession(dir, s); err != nil {
		return s, err
	}
	committed = true
	return s, nil
}

func runSessionCommand(cmd *exec.Cmd, opts SessionOptions) error {
	if opts.Run != nil {
		return opts.Run(cmd)
	}
	return cmd.Run()
}
func authFailure(value string) bool {
	v := strings.ToLower(value)
	return strings.Contains(v, "permission denied (") || strings.Contains(v, "host key verification failed") || strings.Contains(v, "read_passphrase") || strings.Contains(v, "authentication")
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("command output limit exceeded")
	}
	return b.Buffer.Write(p)
}
func control(ctx context.Context, s Session, operation string, extra []string, opts SessionOptions) (string, error) {
	identity, err := socketIdentity(s.Socket)
	if err != nil {
		return "", err
	}
	if s.SocketIdentity == "" || identity != s.SocketIdentity {
		return "", errors.New("SSH control socket identity changed; refusing to control it")
	}
	query, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := []string{"-F", os.DevNull, "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-S", strings.ReplaceAll(s.Socket, "%", "%%"), "-O", operation}
	args = append(args, extra...)
	args = append(args, "--", sessionHost(s))
	cmd := exec.CommandContext(query, "ssh", args...)
	cmd.WaitDelay = time.Second
	var b cappedBuffer
	b.limit = 8192
	cmd.Stdout, cmd.Stderr = &b, &b
	if err = runSessionCommand(cmd, opts); err != nil {
		if query.Err() != nil {
			return "", query.Err()
		}
		return "", errors.New("SSH control operation failed")
	}
	return b.String(), nil
}
func checkMaster(ctx context.Context, s Session, opts SessionOptions) (int, error) {
	text, err := control(ctx, s, "check", nil, opts)
	if err != nil {
		return 0, err
	}
	m := masterPID.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0, errors.New("SSH master identity unavailable")
	}
	pid, _ := strconv.Atoi(m[1])
	if s.MasterPID != 0 && s.MasterPID != pid {
		return 0, errors.New("SSH master identity changed")
	}
	if s.MasterIdentity != "" {
		identity, e := processIdentity(pid)
		if e != nil || identity != s.MasterIdentity {
			return 0, errors.New("SSH master process identity changed")
		}
	}
	return pid, nil
}

func Status(ctx context.Context, id string, opts SessionOptions) (Session, error) {
	dir, err := sessionDir(opts, false)
	if err != nil {
		return Session{}, err
	}
	s, err := readSession(dir, id)
	if err != nil {
		return s, err
	}
	ownerPID, ownerIdentity := sessionOwner(s)
	identity, err := processIdentity(ownerPID)
	if err != nil {
		return s, err
	}
	if identity != ownerIdentity {
		s.State = "orphaned"
		return s, nil
	}
	if s.Socket != "" {
		if _, err := checkMaster(ctx, s, opts); err != nil {
			s.State = "unavailable"
		}
	}
	return s, nil
}
func SessionPlan(ctx context.Context, id string, opts SessionOptions) (Plan, error) {
	s, err := Status(ctx, id, opts)
	if err != nil {
		return Plan{}, err
	}
	if s.State != "ready" {
		return Plan{}, errors.New("proxy session is unavailable; run proxy-on to recreate it")
	}
	if s.Reverse != nil {
		return Plan{}, errors.New("reverse SSH endpoints belong on the remote host; use proxy tunnel share or proxy ssh, not a local shell session")
	}
	return s.Local, nil
}

func Stop(ctx context.Context, id string, opts SessionOptions) error {
	dir, err := sessionDir(opts, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !sessionID.MatchString(id) {
		return errors.New("invalid session ID")
	}
	lock, err := lockFile(filepath.Join(dir, id+".lock"))
	if err != nil {
		return err
	}
	defer unlockFile(lock)
	s, err := readSession(dir, id)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return stopSession(ctx, dir, s, opts)
}
func stopSession(ctx context.Context, dir string, s Session, opts SessionOptions) error {
	if s.Socket != "" {
		identity, err := socketIdentity(s.Socket)
		if err == nil {
			if s.SocketIdentity == "" {
				s.SocketIdentity = identity
			} // pending record owns its random private directory
			if identity != s.SocketIdentity {
				return errors.New("session socket changed; refusing cleanup")
			}
			if _, err = checkMaster(ctx, s, opts); err != nil {
				// A dead owned master can leave its socket behind. Never infer
				// death merely from an unresponsive socket or failed ps query.
				alive, identityErr := processIdentity(s.MasterPID)
				if s.MasterPID == 0 || identityErr != nil || alive != "" {
					return errors.New("cannot verify session master for cleanup; record retained")
				}
			} else if _, err = control(ctx, s, "exit", nil, opts); err != nil {
				return errors.New("session shutdown uncertain; record retained")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if s.MasterPID != 0 {
			alive, e := processIdentity(s.MasterPID)
			if e != nil {
				return e
			}
			if alive == s.MasterIdentity && alive != "" {
				return errors.New("owned SSH master is still running but its control socket is missing; record retained")
			}
		}
		// Never recursively delete: unexpected files or a replacement socket
		// remain for inspection instead of touching another process's state.
		if _, err := os.Lstat(s.Socket); err == nil {
			if current, e := socketIdentity(s.Socket); e == nil && current == s.SocketIdentity {
				_ = os.Remove(s.Socket)
			}
		}
		_ = os.Remove(s.SocketDir)
	}
	path, _ := sessionPath(dir, s.ID)
	return os.Remove(path)
}

func Cleanup(ctx context.Context, opts SessionOptions) ([]string, error) {
	dir, err := sessionDir(opts, false)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var removed []string
	scanned := 0
	for _, entry := range entries {
		if scanned >= 256 {
			break
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !sessionID.MatchString(id) || entry.Name() != id+".json" {
			continue
		}
		scanned++
		s, e := readSession(dir, id)
		if e != nil {
			return removed, e
		}
		ownerPID, ownerIdentity := sessionOwner(s)
		identity, e := processIdentity(ownerPID)
		if e != nil {
			return removed, e
		}
		if identity == ownerIdentity {
			continue
		}
		if e = Stop(ctx, id, opts); e != nil {
			return removed, e
		}
		removed = append(removed, id)
	}
	return removed, nil
}

func SessionSummary(s Session) map[string]any {
	if s.Reverse != nil {
		return map[string]any{"id": s.ID, "state": s.State, "direction": "reverse", "owner_kind": "invocation", "owner_pid": s.Reverse.OwnerPID, "target_id": s.Plan.TargetID, "source": s.Plan.Source, "local": s.Local, "remote": s.Reverse.Remote, "ssh_host": s.Reverse.Host, "created": s.Created}
	}
	direction := "local"
	if s.Plan.SSHHost != "" {
		direction = "forward"
	}
	return map[string]any{"id": s.ID, "state": s.State, "direction": direction, "owner_kind": "shell", "target_id": s.Plan.TargetID, "source": s.Plan.Source, "http_proxy": s.Local.HTTP, "all_proxy": s.Local.All, "ssh_host": s.Plan.SSHHost, "shell_pid": s.ShellPID, "created": s.Created}
}

func sessionHost(s Session) string {
	if s.Reverse != nil {
		return s.Reverse.Host
	}
	return s.Plan.SSHHost
}

func sessionOwner(s Session) (int, string) {
	if s.Reverse != nil {
		return s.Reverse.OwnerPID, s.Reverse.OwnerIdentity
	}
	return s.ShellPID, s.ShellIdentity
}

func listSessions(ctx context.Context, opts SessionOptions) ([]Session, error) {
	dir, err := sessionDir(opts, false)
	if errors.Is(err, os.ErrNotExist) {
		return []Session{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !sessionID.MatchString(id) || entry.Name() != id+".json" {
			continue
		}
		s, e := Status(ctx, id, opts)
		if e != nil {
			return nil, fmt.Errorf("cannot inspect proxy session: %w", e)
		}
		out = append(out, s)
		if len(out) >= 256 {
			break
		}
	}
	return out, nil
}
func Sessions(ctx context.Context, opts SessionOptions) ([]map[string]any, error) {
	records, err := listSessions(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(records))
	for _, s := range records {
		out = append(out, SessionSummary(s))
	}
	return out, nil
}
