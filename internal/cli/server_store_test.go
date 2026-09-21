package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/spf13/cobra"
)

func TestServerStoreSelectionDoesNotParseClientSettings(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "config.toml")
	if err := os.WriteFile(path, []byte("[invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, Dependencies{}, "--config", path, "servers", "list", "--json")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Fatalf("server list depends on broken client config: %q %v", out, err)
	}
	if _, err = os.Stat(filepath.Join(base, "servers.toml")); !os.IsNotExist(err) {
		t.Fatal("offline list wrote inventory")
	}
}

func TestServerWorkbenchConfigPrecedence(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LAZYCLASH_CONFIG", filepath.Join(base, "env", "config.toml"))
	t.Setenv("LAZYCLASH_SERVERS_CONFIG", "")
	o := options{path: filepath.Join(base, "explicit", "config.toml")}
	s, err := o.serverStore(&cobra.Command{})
	if err != nil || s.Path != filepath.Join(base, "explicit", "servers.toml") {
		t.Fatalf("precedence: %+v %v", s, err)
	}
	t.Setenv("LAZYCLASH_SERVERS_CONFIG", filepath.Join(base, "specific", "servers.toml"))
	s, err = o.serverStore(&cobra.Command{})
	if err != nil || s.Path != filepath.Join(base, "specific", "servers.toml") {
		t.Fatalf("specific server inventory ignored: %+v %v", s, err)
	}
}

func TestServerCompletionNeverContactsHostsOrProviders(t *testing.T) {
	isolated(t)
	dir := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(dir, "servers.toml")}
	if err := store.Update(func(i *serverstate.Inventory) error {
		if err := i.UpsertHost(serverstate.Host{ID: "home", Provider: "ssh", SSHHost: "private", PublicHost: "public.example"}); err != nil {
			return err
		}
		return i.UpsertDeployment(serverstate.Deployment{ID: "exit", HostID: "home", Recipe: "vless-reality", Backend: "native", PublicHost: "public.example", PublicPort: 443, ListenPort: 443})
	}); err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{ServerStore: store, VPS: vps.Options{Run: func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("completion called cloud CLI")
		return nil, nil
	}}}
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"servers", "status", ""}, "exit"}, {[]string{"servers", "deploy", "--host", ""}, "home"}, {[]string{"servers", "deploy", "--backend", ""}, "compose"}, {[]string{"servers", "deploy", "--recipe", ""}, "hysteria2"}, {[]string{"servers", "export", "--format", ""}, "admin-bundle"}, {[]string{"vps", "stop", ""}, "home"}, {[]string{"vps", "create", "--provider", ""}, "oracle"},
	} {
		out, _, err := run(t, deps, append([]string{"__complete"}, tt.args...)...)
		if err != nil || !strings.Contains(out, tt.want) || !strings.Contains(out, ":4") {
			t.Fatalf("completion %v: %q %v", tt.args, out, err)
		}
	}
}

func TestPartialServerBusinessFlagsNeverOpenWizard(t *testing.T) {
	isolated(t)
	for _, flags := range [][]string{{"--backend", "native"}, {"--public-host", "proxy.example"}, {"--recipe", "vless-reality"}} {
		cmd := New(Dependencies{Terminal: func(io.Reader, io.Writer) bool { return true }})
		cmd.SetIn(strings.NewReader(""))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"servers", "deploy"}, flags...))
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := cmd.ExecuteContext(ctx)
		cancel()
		if err == nil || ExitCode(err) != 2 {
			t.Fatalf("partial flags %v opened wizard or did not fail usage: %v", flags, err)
		}
	}
}
