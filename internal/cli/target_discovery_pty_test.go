package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// TestTargetDiscoveryPTYHelper runs only in a child process controlled by the
// PTY smoke script. Its injected transport cannot reach any real host.
func TestTargetDiscoveryPTYHelper(t *testing.T) {
	if os.Getenv("LAZYCLASH_TARGET_DISCOVERY_PTY_HELPER") != "1" {
		return
	}
	args := []string{}
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	log := func(kind, host string) {
		if path := os.Getenv("LAZYCLASH_TARGET_DISCOVERY_LOG"); path != "" {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			}
			_, _ = fmt.Fprintf(f, "%s %s\n", kind, host)
			_ = f.Close()
		}
	}
	scenario := os.Getenv("LAZYCLASH_TARGET_DISCOVERY_SCENARIO")
	calls := 0
	deps := Dependencies{
		Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
			log("UNEXPECTED_OPEN", "")
			return nil, nil, errors.New("fixture prohibits opening a controller")
		},
		Discover: func(_ context.Context, host string) ([]config.Target, error) {
			calls++
			log("discover", host)
			if host != "fixture-host" {
				return nil, fmt.Errorf("unexpected fixture host %q", host)
			}
			if scenario == "zero" || (scenario == "zero-retry" && calls == 1) {
				return nil, nil
			}
			if (scenario == "auth" || scenario == "auth-failed") && calls == 1 {
				return nil, &connection.AuthRequiredError{Host: host}
			}
			candidates := []config.Target{{ID: "core-fixture1", Name: "Fixture core one", Controller: "http://127.0.0.1:19090", SSHHost: host, SourceConfig: "/fixture/one.yaml", Secret: "fixture-private-secret", Transient: true, Configs: []config.CoreConfig{{ID: "runtime", Name: "Runtime config", Path: "/fixture/one.yaml"}}}}
			if scenario == "control" {
				candidates[0].Name = "Fixture\x1b]52;c;PRIVATE_CLIPBOARD\a\x1b[31m core"
				candidates[0].RuleSource = &config.RuleSource{Kind: "file"}
				candidates[0].ConfigSource = &config.ConfigSource{Kind: "file"}
				candidates[0].Service = &config.ClientService{Kind: "systemd"}
				candidates[0].ManagedCoreID = "fixture-owner"
			}
			if scenario == "multiple" {
				candidates = append(candidates, config.Target{ID: "core-fixture2", Name: "Fixture core two", Controller: "http://127.0.0.1:19091", SSHHost: host, SourceConfig: "/fixture/two.yaml", Secret: "fixture-private-secret-two", Transient: true, AuthRequired: true, Configs: []config.CoreConfig{{ID: "runtime", Path: "/fixture/two.yaml"}}})
			}
			return candidates, nil
		},
		Authenticate: func(ctx context.Context, host string) (*exec.Cmd, error) {
			log("authenticate", host)
			if scenario == "auth-failed" {
				return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'Fixture SSH authentication failed\\n' >&2; exit 1"), nil
			}
			return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'Fixture SSH authentication completed\\n' >&2"), nil
		},
	}
	os.Exit(execute(context.Background(), args, os.Stdin, os.Stdout, os.Stderr, deps))
}
