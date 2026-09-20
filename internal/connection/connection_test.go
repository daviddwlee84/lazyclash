package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestOpenResolvesSecretPerTargetAndRereadsSource(t *testing.T) {
	var want string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"version":"test-mihomo"}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(secret string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("external-controller: "+server.URL+"\nsecret: "+secret+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := config.Target{ID: "test", Controller: server.URL, SourceConfig: path}
	for _, secret := range []string{"first-token", "second-token"} {
		write(secret)
		want = secret
		client, closer, err := Open(context.Background(), target, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Version(context.Background()); err != nil {
			t.Fatal(err)
		}
		closer.Close()
		client.Close()
	}
	os.WriteFile(path, []byte("external-controller: http://different.example:9090\nsecret: unrelated-token\n"), 0600)
	if _, _, err := Open(context.Background(), target, true); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("cross-controller credentials accepted: %v", err)
	}
	t.Setenv("LAZYCLASH_TEST_TOKEN", "explicit-token")
	want = "explicit-token"
	target.SecretEnv = "LAZYCLASH_TEST_TOKEN"
	client, closer, err := Open(context.Background(), target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	defer client.Close()
	if _, err := client.Version(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSecretSourcesAndErrorsDoNotLeak(t *testing.T) {
	ctx := context.Background()
	target := config.Target{Controller: "http://localhost:9090", SecretEnv: "LAZYCLASH_TEST_MISSING"}
	if _, err := resolveSecret(ctx, target); err == nil {
		t.Fatal("missing environment value accepted")
	}
	path := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(path, []byte("has-a-secret\n"), 0600)
	target.SecretEnv = ""
	target.SecretFile = path
	secret, err := resolveSecret(ctx, target)
	if err != nil || secret != "has-a-secret" {
		t.Fatalf("secret read error=%v", err)
	}
	os.WriteFile(path, []byte("private\nvalue"), 0600)
	if _, err := resolveSecret(ctx, target); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatalf("invalid secret error leaked: %v", err)
	}
	target.SecretFile = ""
	target.SourceConfig = filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := resolveSecret(ctx, target); err == nil {
		t.Fatal("missing explicit source silently accepted")
	}
}

func TestProbeCandidatesSeparatesAuthenticatedAndAuthNeeded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/version" {
			t.Errorf("unexpected probe %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer correct" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"version":"v1"}`))
	}))
	defer server.Close()
	found := probeBatch(context.Background(), []config.Target{{ID: "a", Controller: server.URL, Secret: "wrong"}})
	if len(found) != 1 || !found[0].AuthRequired {
		t.Fatalf("401 not distinguished: %+v", found)
	}
	found = probeBatch(context.Background(), []config.Target{{ID: "bad", Controller: server.URL, Secret: "wrong"}, {ID: "good", Controller: server.URL, Secret: "correct"}})
	if len(found) != 1 || found[0].ID != "good" || found[0].AuthRequired {
		t.Fatalf("usable candidate not preferred: %+v", found)
	}
	data, _ := json.Marshal(found)
	if strings.Contains(string(data), "correct") {
		t.Fatal("discovery JSON exposed secret")
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) }))
	defer other.Close()
	if found := probeBatch(context.Background(), []config.Target{{Controller: other.URL}}); len(found) != 0 {
		t.Fatal("unrelated HTTP service identified as a controller")
	}
}

func TestProbeCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if found := probeBatch(ctx, []config.Target{{Controller: "http://127.0.0.1:1"}}); len(found) != 0 {
		t.Fatal("cancelled discovery produced result")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled discovery blocked")
	}
}

func TestRuntimeParsingAndNormalization(t *testing.T) {
	runtime, err := parseRuntime([]byte("external-controller: '0.0.0.0:9090'\nexternal-controller-tls: '[::]:9443'\nexternal-controller-unix: /tmp/mihomo.sock\nsecret: 'a: b # c'\nproxies: []\nrules: [MATCH,DIRECT]\n"))
	if err != nil {
		t.Fatal(err)
	}
	endpoints := runtime.controllers()
	want := []string{"http://127.0.0.1:9090", "https://[::1]:9443", "unix:///tmp/mihomo.sock"}
	if strings.Join(endpoints, ",") != strings.Join(want, ",") {
		t.Fatalf("endpoints=%v", endpoints)
	}
	if !runtime.complete() || runtime.Secret != "a: b # c" {
		t.Fatal("typed YAML parsing incorrect")
	}
	if _, err := parseRuntime([]byte("external-controller: [x]\nsecret: VERYSECRET")); err == nil || strings.Contains(err.Error(), "VERYSECRET") {
		t.Fatalf("malformed YAML not handled safely: %v", err)
	}
}

func TestProcessConfigPathsHandlesSpacesAndIgnoresShellContents(t *testing.T) {
	ps := `/usr/bin/mihomo -d /home/user/.config/mihomo -f /srv/core.yaml
/Applications/Verge.app/Contents/MacOS/verge-mihomo -d /Users/me/Library/Application Support/io.github.clash-verge-rev -ext-ctl 127.0.0.1:9097
/bin/sh -c 'cat /home/mihomo/config.yaml'
/usr/bin/clash --config='/srv/config with spaces.yaml'
`
	paths := processConfigPaths(ps)
	for _, want := range []string{"/srv/core.yaml", "/home/user/.config/mihomo/config.yaml", "/Users/me/Library/Application Support/io.github.clash-verge-rev/config.yaml", "/srv/config with spaces.yaml"} {
		found := false
		for _, path := range paths {
			if path == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing %s in %v", want, paths)
		}
	}
	if len(paths) != 4 {
		t.Fatalf("unexpected process paths: %v", paths)
	}
}

func TestVergeProfilesRejectsMergeScriptAndIncompleteFiles(t *testing.T) {
	index := []byte(`items:
- {uid: one, type: remote, name: Subscription, file: one.yaml}
- {uid: two, type: local, name: Local, file: two.yaml}
- {uid: three, type: merge, name: Merge, file: three.yaml}
- {uid: four, type: script, name: Script, file: four.js}
- {uid: five, type: local, name: Incomplete, file: five.yaml}
- {uid: six, type: local, name: Escape, file: ../six.yaml}
`)
	var read []string
	profiles := indexedProfiles(index, "/root/verge", func(path string) ([]byte, error) {
		read = append(read, path)
		if strings.HasSuffix(path, "five.yaml") {
			return []byte("rules: [MATCH,DIRECT]"), nil
		}
		return []byte("proxies: []\nrules: [MATCH,DIRECT]"), nil
	})
	if len(profiles) != 2 || len(read) != 3 {
		t.Fatalf("profiles=%+v reads=%v", profiles, read)
	}
}

func TestSSHArgumentSafetyAndForegroundAuthentication(t *testing.T) {
	oldCommand := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "ssh" {
			args = append([]string{"-F", "/dev/null"}, args...)
		}
		return exec.CommandContext(ctx, name, args...)
	}
	defer func() { commandContext = oldCommand; clearMultiplexPolicies() }()
	for _, host := range []string{"-oProxyCommand=evil", "host;evil", "host name", "host\nother"} {
		if _, err := AuthenticateCommand(context.Background(), host); err == nil {
			t.Errorf("invalid SSH host accepted: %q", host)
		}
	}
	cmd, err := AuthenticateCommand(context.Background(), "alias-user@host")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		authentications.Lock()
		for h, a := range authentications.hosts {
			os.RemoveAll(a.dir)
			delete(authentications.hosts, h)
		}
		authentications.Unlock()
	}()
	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "BatchMode=no") || !strings.Contains(args, "ControlPersist=60") || !strings.Contains(args, "-- alias-user@host true") {
		t.Fatalf("bad foreground args: %s", args)
	}
	background := strings.Join(sshArgs("alias-user@host"), " ")
	if !strings.Contains(background, "BatchMode=yes") || !strings.Contains(background, "ControlPath=") {
		t.Fatalf("bad background args: %s", background)
	}
	if shellQuote("/tmp/a'$(danger).yaml") != "'/tmp/a'\"'\"'$(danger).yaml'" {
		t.Fatal("unsafe shell quoting")
	}
	if !IsAuthRequired(&AuthRequiredError{Host: "host"}) || IsAuthRequired(errors.New("other")) {
		t.Fatal("typed auth classification failed")
	}
}

func TestRemoteUnixFailsExplicitly(t *testing.T) {
	_, _, err := Open(context.Background(), config.Target{Controller: "unix:///tmp/core.sock", SSHHost: "host"}, true)
	if err == nil || !strings.Contains(err.Error(), "remote Unix") {
		t.Fatalf("expected explicit remote socket error, got %v", err)
	}
}

func TestTunnelManagedChildAndAuthFailure(t *testing.T) {
	clearMultiplexPolicies()
	defer clearMultiplexPolicies()
	old := commandContext
	defer func() { commandContext = old }()
	mode := "listen"
	var captured []string
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		captured = append([]string{name}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=TestSSHHelperProcess", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "LAZYCLASH_SSH_HELPER="+mode)
		return cmd
	}
	u, _ := url.Parse("https://controller.internal:9443")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tunnel, err := openTunnel(ctx, "my-alias", u)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(captured, " ")
	if !strings.Contains(args, "127.0.0.1:") || !strings.Contains(args, ":controller.internal:9443") || !strings.Contains(args, "BatchMode=yes") {
		t.Fatalf("bad tunnel args: %s", args)
	}
	conn, err := net.Dial("tcp", tunnel.address)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", tunnel.address, 100*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("owned listener remains after close")
	}
	mode = "auth"
	if _, err := openTunnel(ctx, "my-alias", u); !IsAuthRequired(err) {
		t.Fatalf("authentication not surfaced: %v", err)
	}
}

func TestSSHHelperProcess(t *testing.T) {
	mode := os.Getenv("LAZYCLASH_SSH_HELPER")
	if mode == "" {
		return
	}
	for _, arg := range os.Args {
		if arg == "-G" {
			fmt.Print("controlmaster false\ncontrolpersist no\n")
			os.Exit(0)
		}
	}
	if mode == "auth" {
		_, _ = os.Stderr.WriteString("Permission denied (publickey,password).\n")
		os.Exit(255)
	}
	for i, arg := range os.Args {
		if arg != "-L" || i+1 >= len(os.Args) {
			continue
		}
		parts := strings.Split(os.Args[i+1], ":")
		listener, err := net.Listen("tcp", parts[0]+":"+parts[1])
		if err != nil {
			os.Exit(3)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				os.Exit(4)
			}
			conn.Close()
		}
	}
	os.Exit(5)
}

func TestRemoteFileScriptFramesAndQuotesPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile ' $(must-not-run).yaml")
	content := []byte("external-controller: 127.0.0.1:9090\nsecret: 'value#with:punctuation'\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := exec.Command("sh", "-c", remoteFileScript([]string{path, path + "-missing"})).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(path+"\x00"), content...), 0)
	if string(data) != string(want) {
		t.Fatalf("invalid binary framing: got %q", data)
	}
}

func TestOpenHandshakesAndRejectsUnknownService(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		body   string
	}{{"auth", 401, `{"message":"VERYSECRET"}`}, {"unrelated", 200, `{"hello":"world"}`}} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(scenario.status)
				_, _ = w.Write([]byte(scenario.body))
			}))
			defer server.Close()
			client, closer, err := Open(context.Background(), config.Target{Controller: server.URL}, true)
			if err == nil || client != nil || closer != nil {
				t.Fatalf("expected failed connection, got %v", err)
			}
			if strings.Contains(err.Error(), "VERYSECRET") {
				t.Fatal("response body leaked")
			}
		})
	}
}

func TestOwnedListenerDiscovery(t *testing.T) {
	ps := `42 /usr/bin/mihomo -f /tmp/config.yaml
43 /usr/bin/other-mihomo-tool
44 /usr/bin/clash-meta -d /tmp/core
45 /bin/sh -c mihomo
`
	pids := corePIDs(ps)
	if strings.Join(pids, ",") != "42,44" {
		t.Fatalf("wrong core processes %v", pids)
	}
	lsof := `p42
n127.0.0.1:12567
n*:9090
p43
n127.0.0.1:23456
p44
n[::]:9443
`
	got := parseListeners(lsof, pids)
	want := "http://127.0.0.1:12567,http://127.0.0.1:9090,http://[::1]:9443"
	if strings.Join(got, ",") != want {
		t.Fatalf("listeners=%v", got)
	}
	ss := `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0 4096 127.0.0.1:12567 0.0.0.0:* users:(("mihomo",pid=42,fd=7))
LISTEN 0 4096 127.0.0.1:23456 0.0.0.0:* users:(("other",pid=43,fd=8))
`
	if got := parseListeners(ss, pids); len(got) != 1 || got[0] != "http://127.0.0.1:12567" {
		t.Fatalf("ss listeners=%v", got)
	}
	if got := processConfigPaths(ps); strings.Join(got, ",") != "/tmp/config.yaml,/tmp/core/config.yaml" {
		t.Fatalf("pid-prefixed config paths=%v", got)
	}
}
