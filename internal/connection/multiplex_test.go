package connection

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type muxReply struct {
	Out, Err string
	Code     int
	Hold     bool
}

func TestMuxReplyProcess(t *testing.T) {
	encoded := os.Getenv("LAZYCLASH_MUX_REPLY")
	if encoded == "" {
		return
	}
	data, _ := base64.StdEncoding.DecodeString(encoded)
	var reply muxReply
	json.Unmarshal(data, &reply)
	if reply.Hold {
		time.Sleep(30 * time.Second)
	}
	fmt.Fprint(os.Stdout, reply.Out)
	fmt.Fprint(os.Stderr, reply.Err)
	os.Exit(reply.Code)
}

type muxFixture struct {
	mu                                                        sync.Mutex
	path, master, persist                                     string
	alive                                                     map[string]bool
	listeners                                                 map[string]net.Listener
	calls                                                     [][]string
	configFail, authFail, authHold, forwardFail, remoteDenied bool
}

func muxValue(args []string, key string) string {
	for i, arg := range args {
		if arg == key && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
func muxOption(args []string, key string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, key+"=") {
			return strings.TrimPrefix(arg, key+"=")
		}
	}
	return ""
}

func newMuxFixture(t *testing.T) *muxFixture {
	t.Helper()
	clearMultiplexPolicies()
	h := &muxFixture{path: filepath.Join(t.TempDir(), "user-control"), master: "auto", persist: "600", alive: map[string]bool{}, listeners: map[string]net.Listener{}}
	old := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.calls = append(h.calls, append([]string{}, args...))
		reply := muxReply{}
		op := muxValue(args, "-O")
		path := strings.ReplaceAll(muxValue(args, "-S"), "%%", "%")
		switch {
		case len(args) > 0 && args[0] == "-G":
			if h.configFail {
				reply.Err = "bad SSH config PRIVATE"
				reply.Code = 255
			} else {
				reply.Out = fmt.Sprintf("controlpath %s\ncontrolmaster %s\ncontrolpersist %s\nsetenv PRIVATE=do-not-print\n", h.path, h.master, h.persist)
			}
		case op == "check":
			if !h.alive[path] {
				reply.Err = "Control socket connect: No such file or directory"
				reply.Code = 255
			}
		case op == "forward":
			forward := muxValue(args, "-L")
			parts := strings.SplitN(forward, ":", 3)
			listener, err := net.Listen("tcp", parts[0]+":"+parts[1])
			if err != nil {
				reply.Err = "forward failed"
				reply.Code = 255
			} else {
				h.listeners[forward] = listener
			}
			if h.forwardFail {
				reply.Err = "Control socket connect: Connection reset"
				reply.Code = 255
			}
		case op == "cancel":
			forward := muxValue(args, "-L")
			if listener := h.listeners[forward]; listener != nil {
				listener.Close()
				delete(h.listeners, forward)
			}
		case op == "exit":
			h.alive[path] = false
		case muxOption(args, "BatchMode") == "no":
			reply.Hold = h.authHold
			if h.authFail {
				reply.Err = "Permission denied (publickey,password)."
				reply.Code = 255
			} else {
				h.alive[strings.ReplaceAll(muxOption(args, "ControlPath"), "%%", "%")] = true
			}
		case muxValue(args, "-L") != "":
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=TestSSHHelperProcess", "--"}, args...)...)
			cmd.Env = append(os.Environ(), "LAZYCLASH_SSH_HELPER=auth", "GORACE=atexit_sleep_ms=0")
			return cmd
		default:
			if h.remoteDenied {
				reply.Err = "cat: /root/password-file: Permission denied"
				reply.Code = 1
			} else {
				reply.Out = "remote result"
			}
		}
		data, _ := json.Marshal(reply)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMuxReplyProcess")
		cmd.Env = append(os.Environ(), "LAZYCLASH_MUX_REPLY="+base64.StdEncoding.EncodeToString(data), "GORACE=atexit_sleep_ms=0")
		return cmd
	}
	t.Cleanup(func() {
		CloseAuthentications()
		commandContext = old
		clearMultiplexPolicies()
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, listener := range h.listeners {
			listener.Close()
		}
	})
	return h
}

func TestConfiguredMasterSurvivesInvocationsAndTwoForwards(t *testing.T) {
	h := newMuxFixture(t)
	h.alive[h.path] = true
	u1, _ := url.Parse("http://127.0.0.1:9090")
	u2, _ := url.Parse("http://127.0.0.1:9091")
	first, err := openTunnel(context.Background(), "shared-host", u1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := openTunnel(context.Background(), "shared-host", u2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remoteCommand(context.Background(), "shared-host", "true", 1024); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecutePython(context.Background(), "shared-host", "print('ok')", nil, 1024); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second.Close()
	CloseAuthentications()
	h.mu.Lock()
	if !h.alive[h.path] || len(h.listeners) != 0 {
		t.Fatal("borrowed master or owned forwards were not preserved/cleaned correctly")
	}
	calls := append([][]string{}, h.calls...)
	h.mu.Unlock()
	for _, args := range calls {
		if op := muxValue(args, "-O"); op != "" {
			if op == "exit" || muxValue(args, "-F") != os.DevNull {
				t.Fatalf("unsafe configured master control: %v", args)
			}
		}
		if args[len(args)-1] == "true" || strings.HasPrefix(args[len(args)-1], "python3 -c") {
			if muxOption(args, "ControlPath") != h.path || muxOption(args, "ControlMaster") != "no" || muxOption(args, "ClearAllForwardings") != "yes" {
				t.Fatalf("remote session ignored configured policy: %v", args)
			}
		}
	}
	// A later invocation has no private authentication map but still borrows the
	// configured master created/authenticated outside this invocation.
	third, err := openTunnel(context.Background(), "shared-host", u1)
	if err != nil {
		t.Fatal(err)
	}
	third.Close()
}

func TestNativeAuthenticationUsesPersistentPolicyAndNeverOwnsSocket(t *testing.T) {
	h := newMuxFixture(t)
	cmd, err := AuthenticateCommand(context.Background(), "configured-host")
	if err != nil {
		t.Fatal(err)
	}
	// The mocked subprocess uses a helper executable; captured SSH args prove
	// the terminal handoff keeps the user's policy instead of a private socket.
	if err = cmd.Run(); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	args := append([]string{}, h.calls[len(h.calls)-1]...)
	h.mu.Unlock()
	if muxOption(args, "ControlPath") != h.path || muxOption(args, "ControlPersist") != "600" || muxOption(args, "ControlMaster") != "auto" || muxOption(args, "ClearAllForwardings") != "yes" {
		t.Fatal(args)
	}
	CloseAuthentications()
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.alive[h.path] {
		t.Fatal("configured master was closed")
	}
	for _, args := range h.calls {
		if muxValue(args, "-O") == "exit" {
			t.Fatal("configured master was treated as owned")
		}
	}
}

func TestNonpersistentPolicyUsesOwnedFallbackAndCleansFailedAuth(t *testing.T) {
	for _, failure := range []string{"failed", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			h := newMuxFixture(t)
			h.persist = "no"
			h.authFail = failure == "failed"
			h.authHold = failure == "canceled"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd, err := AuthenticateCommand(ctx, "private-host")
			if err != nil {
				t.Fatal(err)
			}
			authentications.Lock()
			auth, ok := authentications.hosts["private-host"]
			authentications.Unlock()
			if !ok || auth.path == h.path {
				t.Fatal("private fallback not owned")
			}
			if failure == "canceled" {
				go func() { time.Sleep(20 * time.Millisecond); cancel() }()
			}
			if err = cmd.Run(); err == nil {
				t.Fatal("authentication should fail")
			}
			CloseAuthentications()
			if _, err = os.Stat(auth.dir); !os.IsNotExist(err) {
				t.Fatal("private auth directory leaked")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			for _, args := range h.calls {
				if muxValue(args, "-O") == "exit" && muxValue(args, "-S") != controlSocketArgument(auth.path) {
					t.Fatal("foreign socket closed")
				}
			}
		})
	}
}

func TestFailedOrCanceledConfiguredAuthenticationNeverCleansUserMaster(t *testing.T) {
	for _, failure := range []string{"failed", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			h := newMuxFixture(t)
			h.alive[h.path] = true
			h.authFail = failure == "failed"
			h.authHold = failure == "canceled"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd, err := AuthenticateCommand(ctx, "configured-failure")
			if err != nil {
				t.Fatal(err)
			}
			if failure == "canceled" {
				go func() { time.Sleep(20 * time.Millisecond); cancel() }()
			}
			if err = cmd.Run(); err == nil {
				t.Fatal("expected authentication interruption")
			}
			CloseAuthentications()
			h.mu.Lock()
			defer h.mu.Unlock()
			if !h.alive[h.path] {
				t.Fatal("user master closed after interrupted authentication")
			}
			for _, args := range h.calls {
				if muxValue(args, "-O") == "exit" {
					t.Fatal("user master received exit")
				}
			}
		})
	}
}

func TestExpiredMasterFallsBackToNonmultiplexedBatchAndReportsAuth(t *testing.T) {
	h := newMuxFixture(t)
	u, _ := url.Parse("http://127.0.0.1:9090")
	if _, err := openTunnel(context.Background(), "expired-host", u); !IsAuthRequired(err) {
		t.Fatalf("expired password-only host: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	found := false
	for _, args := range h.calls {
		if muxValue(args, "-L") != "" && muxValue(args, "-O") == "" {
			found = true
			if muxOption(args, "ControlPath") != "none" {
				t.Fatal("dedicated tunnel may leak a borrowed forward")
			}
		}
	}
	if !found {
		t.Fatal("no safe dedicated fallback")
	}
}

func TestUncertainForwardCancelsOnlyPinnedSocketAndForward(t *testing.T) {
	h := newMuxFixture(t)
	h.alive[h.path] = true
	h.forwardFail = true
	u, _ := url.Parse("http://127.0.0.1:9090")
	if _, err := openTunnel(context.Background(), "reset-host", u); err == nil {
		t.Fatal("uncertain forward succeeded")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.listeners) != 0 || !h.alive[h.path] {
		t.Fatal("uncertain forwarding not cleaned safely")
	}
	var forward, cancel []string
	for _, args := range h.calls {
		switch muxValue(args, "-O") {
		case "forward":
			forward = args
		case "cancel":
			cancel = args
		}
	}
	if muxValue(forward, "-S") != muxValue(cancel, "-S") || muxValue(forward, "-L") != muxValue(cancel, "-L") {
		t.Fatal("cleanup did not pin exact forwarding")
	}
}

func TestPolicyLookupCachesConcurrentRequestsAndFailuresRecover(t *testing.T) {
	h := newMuxFixture(t)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := resolveMultiplexPolicy(context.Background(), "cached-host"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	h.mu.Lock()
	queries := 0
	for _, args := range h.calls {
		if args[0] == "-G" {
			queries++
		}
	}
	h.configFail = true
	h.mu.Unlock()
	if queries != 1 {
		t.Fatalf("got %d simultaneous config lookups", queries)
	}
	_, err := resolveMultiplexPolicy(context.Background(), "failed-host")
	if err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("config failure was hidden or leaked")
	}
	h.mu.Lock()
	h.configFail = false
	h.mu.Unlock()
	if _, err = resolveMultiplexPolicy(context.Background(), "failed-host"); err != nil {
		t.Fatal("failed lookup poisoned cache", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = resolveMultiplexPolicy(ctx, "cached-host"); !errors.Is(err, context.Canceled) {
		t.Fatal("cached lookup ignored cancellation")
	}
}

func TestSSHAuthClassifierExcludesFileAndSocketPermissions(t *testing.T) {
	for _, message := range []string{"Permission denied (publickey,password).", "Permission denied (keyboard-interactive).", "Permission denied, please try again.", "Host key verification failed.", "read_passphrase: cannot open /dev/tty"} {
		if !needsAuthentication(message) {
			t.Errorf("missed SSH auth: %s", message)
		}
	}
	for _, message := range []string{"cat: /root/password: Permission denied", "python3: can't open file: Permission denied", "Control socket connect(/private/control): Permission denied"} {
		if needsAuthentication(message) || missingControlMaster(message) {
			t.Errorf("filesystem error treated as auth: %s", message)
		}
	}
	h := newMuxFixture(t)
	h.remoteDenied = true
	_, err := remoteCommand(context.Background(), "file-denied-host", "cat /root/password-file", 1024)
	if err == nil || IsAuthRequired(err) || strings.Contains(err.Error(), "password-file") {
		t.Fatalf("file access failed as SSH auth or leaked path: %v", err)
	}
}

func TestNativeSSHConfigExpansionAndLiteralPercentPinning(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip(err)
	}
	configFile := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(configFile, []byte("Host fixture\n  HostName example.invalid\n  ControlMaster auto\n  ControlPersist 10m\n  ControlPath ~/.ssh/cm/%C\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", "-G", "-F", configFile, "fixture").Output()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := parseMultiplexPolicy(string(out))
	if err != nil || !filepath.IsAbs(policy.path) || strings.Contains(policy.path, "%C") || strings.HasPrefix(policy.path, "~") || !policy.persistent() {
		t.Fatalf("native expansion failed: %+v %v", policy, err)
	}
	if got := controlSocketArgument("/tmp/control%literal"); got != "/tmp/control%%literal" {
		t.Fatal("literal percent will be re-expanded", got)
	}
}
