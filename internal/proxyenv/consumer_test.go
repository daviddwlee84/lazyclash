package proxyenv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestConsumerRejectsCopiedOwnedSSHAndAllowsLocalSessions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sessions")
	opts := ConsumerOptions{Directory: dir, Getenv: func(string) string { return "" }}
	p := Plan{HTTP: "http://127.0.0.1:43210", All: "socks5h://127.0.0.1:43211"}
	if err := ValidateConsumer(p, "service", opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("service guard created registry")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	id, _ := NewID()
	s := Session{ID: id, State: "ready", Plan: p, Local: p}
	if err := saveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConsumer(p, "service", opts); err != nil {
		t.Fatalf("local session: %v", err)
	}
	s.Plan.SSHHost = "fixture"
	s.State = "preparing"
	if err := saveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConsumer(p, "service", opts); err != nil {
		t.Fatalf("uncommitted remote source mistaken for allocated local listener: %v", err)
	}
	s.State = "ready"
	if err := saveSession(dir, s); err != nil {
		t.Fatal(err)
	}
	for _, copied := range []Plan{p, {HTTP: "http://localhost:043210", All: "http://localhost:043210"}, {HTTP: "socks5://127.0.0.1:43211", All: "socks5://127.0.0.1:43211"}} {
		if err := ValidateConsumer(copied, "service", opts); !errors.Is(err, ErrTemporaryProxy) {
			t.Fatalf("copied endpoint accepted: %+v: %v", copied, err)
		}
		if err := ValidateConsumer(copied, "process", opts); err != nil {
			t.Fatal(err)
		}
	}
	stable := Plan{HTTP: "http://127.0.0.1:7890", All: "http://127.0.0.1:7890"}
	if err := ValidateConsumer(stable, "service", opts); err != nil {
		t.Fatalf("unrelated endpoint: %v", err)
	}
	if err := ValidateConsumer(stable, "daemon", opts); err == nil {
		t.Fatal("unknown consumer accepted")
	}
	data, _ := os.ReadFile(filepath.Join(dir, id+".json"))
	if !strings.Contains(string(data), `"state": "ready"`) {
		t.Fatal("service guard mutated session")
	}
}

func TestEndpointBoundOriginAndStableOverride(t *testing.T) {
	p := Plan{HTTP: "http://127.0.0.1:45678", All: "socks5h://127.0.0.1:45678", Username: "private-user", PasswordEnv: "PRIVATE_PASSWORD"}
	marker, err := TemporaryOrigin(p, "ssh-reverse")
	if err != nil {
		t.Fatal(err)
	}
	origin, err := parseOrigin(marker)
	if err != nil || origin.Kind != "ssh-reverse" || strings.Contains(marker, "PRIVATE") {
		t.Fatalf("origin: %+v %v", origin, err)
	}
	t.Setenv(OriginVariable, marker)
	t.Setenv("PRIVATE_PASSWORD", "do-not-persist")
	opts := ConsumerOptions{Directory: filepath.Join(t.TempDir(), "absent")}
	if err := ValidateConsumer(p, "service", opts); !errors.Is(err, ErrTemporaryProxy) {
		t.Fatalf("inherited marker: %v", err)
	}
	values, err := Values(p)
	if err != nil || values[OriginVariable] != marker {
		t.Fatalf("process lost marker: %+v %v", values, err)
	}
	child := strings.Join(ChildEnvironment([]string{OriginVariable + "=stale"}, values), "\n")
	if !strings.Contains(child, OriginVariable+"="+marker) || strings.Contains(child, "=stale") {
		t.Fatal("child metadata not replaced")
	}
	stable := Plan{HTTP: "http://127.0.0.1:7890", All: "http://127.0.0.1:7890"}
	if err := ValidateConsumer(stable, "service", opts); err != nil {
		t.Fatalf("unrelated stable override blocked: %v", err)
	}
	values, err = Values(stable)
	if err != nil || values[OriginVariable] != "" {
		t.Fatalf("stale marker leaked: %+v %v", values, err)
	}
	text, err := RenderEnv(stable, "sh")
	if err != nil || !strings.Contains(text, "export "+OriginVariable+"=''\n") {
		t.Fatalf("stable export did not clear origin: %q %v", text, err)
	}
	text, err = RenderDocker(stable, DockerRenderOptions{Format: "compose", Services: []string{"web"}})
	if err != nil || strings.Contains(text, OriginVariable) {
		t.Fatalf("origin leaked into Docker: %q %v", text, err)
	}
}

func TestConsumerFailsClosedOnUntrustedRegistryWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	p := Plan{HTTP: "http://127.0.0.1:7890", All: "http://127.0.0.1:7890"}
	if err := ValidateConsumer(p, "service", ConsumerOptions{Directory: dir, Getenv: func(string) string { return "" }}); err == nil {
		t.Fatal("untrusted registry accepted")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("guard wrote files")
	}
}

func TestResolveNoProxyConfiguredIsDistinctFromDiscoveryFailure(t *testing.T) {
	empty := Options{Getenv: func(string) string { return "" }, Discover: func(context.Context, string) ([]config.Target, error) { return nil, nil }}
	if _, err := Resolve(context.Background(), config.Config{}, Request{}, empty); !errors.Is(err, ErrNoProxyConfigured) {
		t.Fatalf("no proxy: %v", err)
	}
	empty.Discover = func(context.Context, string) ([]config.Target, error) { return nil, errors.New("discovery failed") }
	if _, err := Resolve(context.Background(), config.Config{}, Request{}, empty); err == nil || errors.Is(err, ErrNoProxyConfigured) {
		t.Fatalf("failure downgraded: %v", err)
	}
}
