package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"github.com/daviddwlee84/lazyclash/internal/selfupdate"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var Version = "dev"

type UsageError struct{ Message string }

func (e *UsageError) Error() string          { return e.Message }
func usage(format string, args ...any) error { return &UsageError{fmt.Sprintf(format, args...)} }

func ExitCode(err error) int {
	if errors.Is(err, context.Canceled) || errors.Is(err, wizard.ErrCanceled) {
		return 130
	}
	var child *proxyenv.ExitError
	if errors.As(err, &child) {
		return child.Code
	}
	if errors.Is(err, proxyenv.ErrNoProxyConfigured) {
		return 4
	}
	var u *UsageError
	if errors.As(err, &u) {
		return 2
	}
	if strings.HasPrefix(err.Error(), "unknown command ") {
		return 2
	}
	return 1
}

type Dependencies struct {
	Managed      managedcore.Options
	Open         func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	Discover     func(context.Context, string) ([]config.Target, error)
	Terminal     func(io.Reader, io.Writer) bool
	RunTUI       func(context.Context, tui.Options, io.Reader, io.Writer) error
	Authenticate func(context.Context, string) (*exec.Cmd, error)
	RunEditor    func(*exec.Cmd) error
	Diagnostics  diagnostics.Options
	Upgrade      func(context.Context, selfupdate.Request, io.Writer) (selfupdate.Result, error)
}

type options struct {
	path, target, controller, ssh, secretFile, secretEnv, caFile string
	json, readOnly                                               bool
	page                                                         string
	mouse                                                        bool
	deps                                                         Dependencies
}

func NewCommand() *cobra.Command { return New(Dependencies{}) }

func New(deps Dependencies) *cobra.Command {
	if deps.Open == nil {
		deps.Open = connection.Open
	}
	if deps.Discover == nil {
		deps.Discover = connection.Discover
	}
	if deps.Terminal == nil {
		deps.Terminal = terminals
	}
	if deps.Authenticate == nil {
		deps.Authenticate = connection.AuthenticateCommand
	}
	if deps.RunEditor == nil {
		deps.RunEditor = func(cmd *exec.Cmd) error { return cmd.Run() }
	}
	if deps.Upgrade == nil {
		deps.Upgrade = selfupdate.Run
	}
	if deps.RunTUI == nil {
		deps.RunTUI = func(ctx context.Context, opts tui.Options, in io.Reader, out io.Writer) error {
			model := tui.New(opts)
			defer model.Close()
			_, err := tea.NewProgram(model, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
			if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
	o := &options{deps: deps}
	root := &cobra.Command{
		Use: "lazyclash", Short: "A keyboard-first console for existing Mihomo cores",
		Long:    "Control local or remote Mihomo cores from a terminal. Run without a subcommand to open the dashboard. Agents can read the bundled operating guide with --skill.",
		Version: versionFromBuild(), SilenceErrors: true, SilenceUsage: true,
		Args: argsExact(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if skillInvocation(cmd) {
				return printSkill(cmd, "")
			}
			defer connection.CloseAuthentications()
			if o.json {
				return usage("--json requires a data command, for example: lazyclash status --json")
			}
			if !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
				return cmd.Help()
			}
			cfg, settingsPath, err := o.load(cmd)
			if err != nil {
				return err
			}
			target, explicit, err := o.choose(cmd, cfg)
			if err != nil {
				return err
			}
			baseline := append([]config.Target(nil), cfg.Targets...)
			baselineDefault := cfg.DefaultTarget
			persisted := cfg
			var saveMu sync.Mutex
			if explicit && target.ID != "" {
				cfg.Targets = appendTarget(cfg.Targets, target)
			}
			initial := target.ID
			opts := tui.Options{
				Config: cfg, InitialTarget: initial, ReadOnly: o.readOnly, Workbench: o.runWorkbench,
				StartPage: o.page, TestTarget: o.testTargetText, ProbeIP: o.probeIPText, ProbeLatency: o.probeLatencyText,
				Open: func(ctx context.Context, t config.Target) (*core.Client, io.Closer, error) {
					return o.deps.Open(ctx, t, o.readOnly)
				},
				Discover:     func(ctx context.Context) ([]config.Target, error) { return o.discoverTargets(ctx, o.ssh) },
				DiscoverHost: o.discoverTargets,
				RunCommand: func(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) error {
					prefix := []string{}
					if _, e := os.Stat(settingsPath); e == nil || o.path != "" {
						prefix = append(prefix, "--config", settingsPath)
					}
					if o.readOnly {
						prefix = append(prefix, "--read-only")
					}
					child := New(o.deps)
					child.SetArgs(append(prefix, args...))
					child.SetIn(in)
					child.SetOut(out)
					child.SetErr(errOut)
					return child.ExecuteContext(ctx)
				},
				ReloadTargets: func() (config.Config, error) {
					saveMu.Lock()
					defer saveMu.Unlock()
					fresh, e := config.Load(settingsPath, false)
					if e != nil {
						return fresh, e
					}
					persisted = fresh
					baseline = append([]config.Target(nil), fresh.Targets...)
					baselineDefault = fresh.DefaultTarget
					return fresh, nil
				},
				SaveTargets: func(c config.Config) error {
					saveMu.Lock()
					defer saveMu.Unlock()
					kept := make([]config.Target, 0, len(c.Targets))
					for _, item := range c.Targets {
						if !item.Transient {
							kept = append(kept, item)
							continue
						}
						for _, old := range baseline {
							if old.ID == item.ID {
								kept = append(kept, old)
								break
							}
						}
					}
					c.Targets = kept
					if c.DefaultTarget != "" {
						if _, e := targetIndex(c, c.DefaultTarget); e != nil {
							c.DefaultTarget = baselineDefault
							if _, e := targetIndex(c, c.DefaultTarget); e != nil {
								c.DefaultTarget = ""
								if len(kept) > 0 {
									c.DefaultTarget = kept[0].ID
								}
							}
						}
					}
					next := persisted
					next.Targets, next.DefaultTarget = c.Targets, c.DefaultTarget
					if e := config.Save(settingsPath, next); e != nil {
						return e
					}
					reloaded, e := config.Load(settingsPath, true)
					if e != nil {
						return e
					}
					persisted = reloaded
					baseline = append([]config.Target(nil), kept...)
					baselineDefault = c.DefaultTarget
					return nil
				},
				Authenticate: o.deps.Authenticate,
			}
			if cmd.Flags().Changed("mouse") {
				opts.Mouse = &o.mouse
			}
			return o.deps.RunTUI(cmd.Context(), opts, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usage("%s", err) })
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if skillInvocation(cmd) {
			return nil
		}
		if o.page != "" {
			valid := false
			for _, page := range []string{"overview", "proxies", "connections", "logs", "rules", "providers", "configs"} {
				valid = valid || o.page == page
			}
			if !valid {
				return usage("invalid --page %q; see --help", o.page)
			}
		}
		return o.validateSelection(cmd)
	}
	root.Flags().StringVar(&o.page, "page", "", "startup page: overview, proxies, connections, logs, rules, providers, configs")
	root.Flags().BoolVar(&o.mouse, "mouse", true, "enable TUI mouse interaction (toggle with M)")
	root.Flags().Bool("skill", false, "print the bundled agent operating guide without connecting")
	f := root.PersistentFlags()
	f.StringVar(&o.path, "config", "", "lazyclash TOML settings path")
	f.StringVar(&o.target, "target", "", "registered target ID")
	f.StringVar(&o.controller, "controller", "", "temporary HTTP(S) URL or unix:///path controller")
	f.StringVar(&o.ssh, "ssh", "", "SSH host alias (controller address is on that host)")
	f.StringVar(&o.secretFile, "secret-file", "", "file containing the controller secret")
	f.StringVar(&o.secretEnv, "secret-env", "", "environment variable containing the controller secret")
	f.StringVar(&o.caFile, "ca-cert", "", "PEM CA certificate for HTTPS")
	f.BoolVar(&o.json, "json", false, "JSON data output; logs emit NDJSON")
	f.BoolVar(&o.readOnly, "read-only", false, "disable control actions, latency tests and healthchecks")
	root.AddCommand(o.targetCommands(), o.configCommands(), o.statusCommand(), o.proxyCommands(), o.proxyCommand(), o.connectionCommands(), o.logsCommand(), o.rulesCommand(), o.providerCommands(), o.modeCommand(), o.tunCommand(), o.allowLANCommand(), o.settingsCommand())
	root.AddCommand(o.skillCommand(), o.diagnosticsCommand(), o.upgradeCommand(), o.groupsCommand(), o.setupCommand(), o.coresCommand())
	root.AddCommand(o.completionCommand(root))
	o.registerCompletions(root)
	return root
}

func terminals(in io.Reader, out io.Writer) bool {
	i, ok := in.(*os.File)
	if !ok {
		return false
	}
	o, ok := out.(*os.File)
	return ok && term.IsTerminal(int(i.Fd())) && term.IsTerminal(int(o.Fd()))
}

func argsExact(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return usage("%s requires %d argument(s); see --help", cmd.CommandPath(), n)
		}
		return nil
	}
}

func globalChanged(cmd *cobra.Command, name string) bool {
	return cmd.Root().PersistentFlags().Changed(name)
}

func (o *options) validateSelection(cmd *cobra.Command) error {
	if globalChanged(cmd, "target") && globalChanged(cmd, "controller") {
		return usage("--target and --controller are mutually exclusive")
	}
	if globalChanged(cmd, "secret-file") && globalChanged(cmd, "secret-env") {
		return usage("--secret-file and --secret-env are mutually exclusive")
	}
	for _, name := range []string{"target", "controller", "ssh", "secret-file", "secret-env", "ca-cert", "config"} {
		if globalChanged(cmd, name) {
			v, _ := cmd.Root().PersistentFlags().GetString(name)
			if strings.TrimSpace(v) == "" {
				return usage("--%s cannot be empty", name)
			}
		}
	}
	return nil
}

// Path resolution is deliberately independent of parsing: a broken file must
// remain reachable through settings path/edit.
func (o *options) settingsPath(cmd *cobra.Command) (string, bool, error) {
	path := o.path
	explicit := globalChanged(cmd, "config")
	if !explicit {
		if value := os.Getenv("LAZYCLASH_CONFIG"); value != "" {
			path = value
			explicit = true
		}
	}
	if path == "" {
		p, e := config.DefaultPath()
		if e != nil {
			return "", explicit, e
		}
		path = p
	}
	return path, explicit, nil
}

func (o *options) load(cmd *cobra.Command) (config.Config, string, error) {
	path, explicit, err := o.settingsPath(cmd)
	if err != nil {
		return config.Config{}, path, err
	}
	cfg, err := config.Load(path, explicit)
	if err != nil {
		return cfg, path, usage("settings: %s", err)
	}
	return cfg, path, nil
}

func (o *options) choose(cmd *cobra.Command, cfg config.Config) (config.Target, bool, error) {
	id, endpoint := o.target, o.controller
	explicitTarget := globalChanged(cmd, "target")
	explicitController := globalChanged(cmd, "controller")
	if !explicitTarget && !explicitController {
		id = os.Getenv("LAZYCLASH_TARGET")
		endpoint = os.Getenv("LAZYCLASH_CONTROLLER")
		if id == "" && endpoint == "" {
			endpoint = os.Getenv("CLASH_CONTROLLER")
		}
		if id != "" && endpoint != "" {
			return config.Target{}, false, usage("set only one of LAZYCLASH_TARGET or LAZYCLASH_CONTROLLER")
		}
	}
	var t config.Target
	temporary := endpoint != ""
	if temporary {
		if !strings.Contains(endpoint, "://") {
			endpoint = "http://" + endpoint
		}
		ephemeralID := "temporary"
		for suffix := 2; ; suffix++ {
			if _, e := targetIndex(cfg, ephemeralID); e != nil {
				break
			}
			ephemeralID = fmt.Sprintf("temporary-%d", suffix)
		}
		t = config.Target{ID: ephemeralID, Name: "Temporary controller", Controller: endpoint, Transient: true}
	} else {
		if id == "" {
			id = cfg.DefaultTarget
		}
		if id == "" && len(cfg.Targets) > 0 {
			id = cfg.Targets[0].ID
		}
		if id != "" {
			found := false
			for _, candidate := range cfg.Targets {
				if candidate.ID == id {
					t = candidate
					found = true
					break
				}
			}
			if !found {
				return t, false, usage("target %q is not registered; use targets list", id)
			}
		}
	}
	if o.ssh != "" {
		t.SSHHost = o.ssh
	}
	t = o.overrideCredentials(t)
	t.Transient = t.Transient || o.ssh != ""
	t.TransportOverride = temporary || o.ssh != ""
	// Legacy secrets only accompany an explicitly selected temporary endpoint.
	if temporary && t.SecretFile == "" && t.SecretEnv == "" {
		if os.Getenv("CLASH_SECRET") != "" {
			t.SecretEnv = "CLASH_SECRET"
		}
	}
	if t.ID != "" {
		if err := config.Validate(config.Config{Targets: []config.Target{t}}); err != nil {
			return t, false, usage("target: %s", err)
		}
	}
	return t, temporary || explicitTarget || o.ssh != "" || o.secretFile != "" || o.secretEnv != "" || o.caFile != "", nil
}

func (o *options) overrideCredentials(t config.Target) config.Target {
	if o.secretFile != "" {
		t.SecretFile = o.secretFile
		t.SecretEnv = ""
		t.Secret = ""
	}
	if o.secretEnv != "" {
		t.SecretEnv = o.secretEnv
		t.SecretFile = ""
		t.Secret = ""
	}
	if o.caFile != "" {
		t.CAFile = o.caFile
	}
	t.Transient = t.Transient || o.secretFile != "" || o.secretEnv != "" || o.caFile != ""
	return t
}

func (o *options) discoverTargets(ctx context.Context, host string) ([]config.Target, error) {
	targets, err := o.deps.Discover(ctx, host)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		targets[i] = o.overrideCredentials(targets[i])
		targets[i].Transient = true
	}
	return targets, nil
}

func (o *options) discoverCommand(cmd *cobra.Command) ([]config.Target, error) {
	targets, err := o.discoverTargets(cmd.Context(), o.ssh)
	if err != nil && connection.IsAuthRequired(err) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		auth, e := o.deps.Authenticate(cmd.Context(), o.ssh)
		if e != nil {
			return nil, e
		}
		auth.Stdin = cmd.InOrStdin()
		auth.Stdout = cmd.ErrOrStderr()
		auth.Stderr = cmd.ErrOrStderr()
		if e = auth.Run(); e != nil {
			return nil, fmt.Errorf("SSH authentication failed: %w", e)
		}
		return o.discoverTargets(cmd.Context(), o.ssh)
	}
	return targets, err
}

func appendTarget(targets []config.Target, t config.Target) []config.Target {
	result := append([]config.Target(nil), targets...)
	for i := range result {
		if result[i].ID == t.ID {
			result[i] = t
			return result
		}
	}
	return append(result, t)
}

func (o *options) withClient(cmd *cobra.Command, fn func(*core.Client, config.Target) error) error {
	defer connection.CloseAuthentications()
	cfg, _, err := o.load(cmd)
	if err != nil {
		return err
	}
	t, _, err := o.choose(cmd, cfg)
	if err != nil {
		return err
	}
	if t.ID == "" {
		candidates, e := o.discoverCommand(cmd)
		if e != nil {
			return e
		}
		if len(candidates) == 0 {
			return fmt.Errorf("no controller found; use targets discover or --controller URL")
		}
		if len(candidates) > 1 {
			return usage("found %d controllers; use targets discover, then choose --controller URL", len(candidates))
		}
		t = candidates[0]
	}
	client, closer, err := o.deps.Open(cmd.Context(), t, o.readOnly)
	if err != nil && connection.IsAuthRequired(err) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		auth, e := o.deps.Authenticate(cmd.Context(), t.SSHHost)
		if e != nil {
			return e
		}
		auth.Stdin = cmd.InOrStdin()
		auth.Stdout = cmd.ErrOrStderr()
		auth.Stderr = cmd.ErrOrStderr()
		if e = auth.Run(); e != nil {
			return fmt.Errorf("SSH authentication failed: %w", e)
		}
		client, closer, err = o.deps.Open(cmd.Context(), t, o.readOnly)
	}
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}
	defer client.Close()
	return fn(client, t)
}

func (o *options) output(cmd *cobra.Command, value any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetEscapeHTML(false)
	if !o.json {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(core.Redact(value))
}

func (o *options) result(cmd *cobra.Command, message string) error {
	if o.json {
		return o.output(cmd, core.Object{"ok": true, "message": message})
	}
	_, err := fmt.Fprintln(cmd.OutOrStdout(), core.Sanitize(message))
	return err
}

func (o *options) writable() error {
	if o.readOnly {
		return usage("control actions are disabled by --read-only")
	}
	return nil
}

func saveSettings(path string, cfg config.Config) error {
	if err := config.Validate(cfg); err != nil {
		return usage("settings: %s", err)
	}
	return config.Save(path, cfg)
}
