package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"github.com/spf13/cobra"
)

func TestReverseShellTTYDoesNotDependOnDiagnosticDestination(t *testing.T) {
	in := strings.NewReader("")
	var out, redirected bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetIn(in)
	cmd.SetOut(&out)
	cmd.SetErr(&redirected)
	o := options{deps: Dependencies{Terminal: func(r io.Reader, w io.Writer) bool { return r == in && w == &out }}}
	if !o.reverseSessionOptions(cmd, true).Interactive {
		t.Fatal("redirected stderr incorrectly disables an input/output terminal")
	}
	o.json = true
	if o.reverseSessionOptions(cmd, true).Interactive {
		t.Fatal("JSON allowed interactive authentication")
	}
}

func TestReverseCLIValidationBeforeAnyConnection(t *testing.T) {
	proxyIsolated(t)
	deps := Dependencies{
		Discover: func(context.Context, string) ([]config.Target, error) {
			t.Fatal("invalid invocation discovered sources")
			return nil, nil
		},
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			t.Fatal("invalid invocation opened a controller")
			return nil, nil, nil
		},
	}
	for _, args := range [][]string{
		{"proxy", "ssh"},
		{"proxy", "ssh", "--", "host"},
		{"proxy", "ssh", "host", "curl"},
		{"proxy", "ssh", "host", "--"},
		{"proxy", "ssh", "host"}, // redirected input cannot open a shell
		{"proxy", "ssh", "host", "--json", "--", "true"},
		{"proxy", "ssh", "host", "--clean-shell", "--", "true"},
		{"proxy", "ssh", "host", "--remote-port", "65536", "--", "true"},
		{"proxy", "tunnel", "share", "host", "--remote-socks-port", "-1"},
		{"proxy", "tunnel", "share", "bad;host"},
		{"proxy", "tunnel", "share", "host", "--ssh", "other"},
		{"--read-only", "proxy", "ssh", "host", "--", "true"},
		{"--read-only", "proxy", "tunnel", "share", "host"},
	} {
		_, _, err := run(t, deps, args...)
		if err == nil || ExitCode(err) != 2 {
			t.Fatalf("%v: expected usage error, got %v", args, err)
		}
	}
	dir, _ := proxyenv.SessionDirectory()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid invocation created proxy state")
	}
}

func TestReverseCLIRejectsSSHSourceBeforeResolvingItsPorts(t *testing.T) {
	path := proxyIsolated(t)
	cfg := config.Config{Targets: []config.Target{{ID: "remote", Controller: "http://127.0.0.1:9090", SSHHost: "source-host"}}}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("unsupported SSH source was contacted")
		return nil, nil, nil
	}}
	for _, args := range [][]string{
		{"--target", "remote", "proxy", "ssh", "destination", "--", "true"},
		{"--target", "remote", "proxy", "tunnel", "share", "destination", "--json"},
	} {
		_, _, err := run(t, deps, args...)
		if err == nil || !strings.Contains(err.Error(), "SSH source") {
			t.Fatalf("unexpected source rejection: %v", err)
		}
	}
}

func TestProxyConsumerContractAndNoProxyExit(t *testing.T) {
	proxyIsolated(t)
	t.Setenv(proxyenv.OriginVariable, "")
	noProxy := Dependencies{Discover: func(context.Context, string) ([]config.Target, error) { return nil, nil }}
	for _, child := range []string{"env", "_resolve-shell"} {
		_, _, err := run(t, noProxy, "proxy", child, "--consumer", "wrong")
		if err == nil || ExitCode(err) != 2 {
			t.Fatalf("invalid consumer: %v", err)
		}
		_, _, err = run(t, noProxy, "proxy", child, "--consumer", "service")
		if err == nil || ExitCode(err) != 4 || describeError(err).Code != "proxy-not-configured" {
			t.Fatalf("no proxy is not distinguishable: %v", err)
		}
	}
	origin, err := proxyenv.TemporaryOrigin(proxyenv.Plan{HTTP: "http://127.0.0.1:18797", All: "socks5h://127.0.0.1:18797"}, "ssh-reverse")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(proxyenv.OriginVariable, origin)
	for _, child := range []string{"env", "_resolve-shell"} {
		out, _, err := run(t, noProxy, "proxy", child, "--consumer", "service", "--endpoint", "http://localhost:18797")
		if err == nil || describeError(err).Code != "proxy-temporary" || out != "" {
			t.Fatalf("service got temporary endpoint: %q %v", out, err)
		}
		out, _, err = run(t, noProxy, "proxy", child, "--consumer", "service", "--endpoint", "http://127.0.0.1:7897")
		if err != nil || !strings.Contains(out, "7897") {
			t.Fatalf("unrelated stable endpoint rejected: %q %v", out, err)
		}
	}
	var out, errOut bytes.Buffer
	code := execute(context.Background(), []string{"proxy", "env", "--consumer", "service", "--endpoint", "http://127.0.0.1:18797", "--json"}, strings.NewReader(""), &out, &errOut, noProxy)
	var envelope struct{ Error struct{ Code string } }
	if json.Unmarshal(errOut.Bytes(), &envelope) != nil || code != 1 || envelope.Error.Code != "proxy-temporary" || out.Len() != 0 {
		t.Fatalf("guard JSON: %d %s %s", code, out.String(), errOut.String())
	}
}

func TestExplicitProxyExecDoesNotReselectInheritedSession(t *testing.T) {
	proxyIsolated(t)
	t.Setenv("LAZYCLASH_PROXY_SESSION", "parent-session")
	origin, err := proxyenv.TemporaryOrigin(proxyenv.Plan{HTTP: "http://127.0.0.1:18797", All: "http://127.0.0.1:18797"}, "ssh-forward")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(proxyenv.OriginVariable, origin)
	out, _, err := run(t, Dependencies{}, "proxy", "exec", "--endpoint", "http://127.0.0.1:7897", "--", "sh", "-c", `printf '%s|%s|%s' "$http_proxy" "${LAZYCLASH_PROXY_SESSION-unset}" "$LAZYCLASH_PROXY_ORIGIN"`)
	if err != nil || out != "http://127.0.0.1:7897|unset|" {
		t.Fatalf("child retained a different selection: %q %v", out, err)
	}
	if os.Getenv("LAZYCLASH_PROXY_SESSION") != "parent-session" {
		t.Fatal("child changed parent session metadata")
	}
}
