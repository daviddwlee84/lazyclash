package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"os"
)

func (o *options) proxyPlan(cmd *cobra.Command, endpoint, socks, id string) (proxyenv.Plan, error) {
	cfg, _, err := o.load(cmd)
	if err != nil {
		return proxyenv.Plan{}, err
	}
	if id != "" && globalChanged(cmd, "target") {
		return proxyenv.Plan{}, usage("use a target argument or --target, not both")
	}
	if id == "" {
		id = o.target
		if id == "" {
			id = os.Getenv("LAZYCLASH_TARGET")
		}
	}
	if globalChanged(cmd, "controller") || o.ssh != "" {
		t, _, e := o.choose(cmd, cfg)
		if e != nil {
			return proxyenv.Plan{}, e
		}
		if t.ID == "" {
			return proxyenv.Plan{}, usage("--ssh requires an explicit target or controller")
		}
		cfg.Targets = []config.Target{t}
		id = t.ID
	}
	opts := proxyenv.Options{Open: o.deps.Open, Discover: o.deps.Discover}
	request := proxyenv.Request{TargetID: id, Endpoint: endpoint, SocksEndpoint: socks}
	p, err := proxyenv.Resolve(cmd.Context(), cfg, request, opts)
	var authentication *connection.AuthRequiredError
	foreground := cmd.Name() == "start" || cmd.Name() == "exec" || cmd.Name() == "test"
	if foreground && errors.As(err, &authentication) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		auth, e := o.deps.Authenticate(cmd.Context(), authentication.Host)
		if e != nil {
			return p, e
		}
		auth.Stdin, auth.Stdout, auth.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr(), cmd.ErrOrStderr()
		if e = auth.Run(); e != nil {
			return p, errors.New("SSH authentication failed while resolving data proxy ports")
		}
		p, err = proxyenv.Resolve(cmd.Context(), cfg, request, opts)
	}
	var ambiguous *proxyenv.AmbiguousError
	if errors.As(err, &ambiguous) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		choices := make([]wizard.Choice, 0, len(ambiguous.Targets))
		for _, t := range ambiguous.Targets {
			choices = append(choices, wizard.Choice{Value: t.ID, Label: t.Label() + " · " + t.Controller})
		}
		selected, e := wizard.Choose(cmd.Context(), "Choose a local proxy", choices, cmd.InOrStdin(), cmd.ErrOrStderr())
		if e != nil {
			return p, e
		}
		cfg.Targets = append(cfg.Targets, ambiguous.Targets...)
		request.TargetID = selected
		return proxyenv.Resolve(cmd.Context(), cfg, request, opts)
	}
	return p, err
}

func (o *options) proxySessionOptions(cmd *cobra.Command) proxyenv.SessionOptions {
	return proxyenv.SessionOptions{Interactive: !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()), In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr()}
}

func (o *options) proxyCommand() *cobra.Command {
	var endpoint, socks string
	var consumer, compatConsumer string
	group := &cobra.Command{Use: "proxy", Short: "Use a selected data proxy in shells, commands and containers"}
	group.PersistentFlags().StringVar(&endpoint, "endpoint", "", "explicit data proxy URL; distinct from the controller API")
	group.PersistentFlags().StringVar(&socks, "socks-endpoint", "", "optional separate SOCKS5(H) endpoint with --endpoint")
	getPlan := func(cmd *cobra.Command, session string) (proxyenv.Plan, error) {
		if session == "" && endpoint == "" && o.target == "" && !globalChanged(cmd, "controller") {
			session = os.Getenv("LAZYCLASH_PROXY_SESSION")
		}
		if session != "" {
			if endpoint != "" || o.target != "" || globalChanged(cmd, "controller") {
				return proxyenv.Plan{}, usage("--session cannot be combined with endpoint/target overrides")
			}
			return proxyenv.SessionPlan(cmd.Context(), session, o.proxySessionOptions(cmd))
		}
		return o.proxyPlan(cmd, endpoint, socks, "")
	}
	compat := &cobra.Command{Use: "_resolve-shell", Hidden: true, Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if err := validateProxyConsumer(compatConsumer); err != nil {
			return err
		}
		if o.json {
			return usage("_resolve-shell emits a fixed shell assignment protocol")
		}
		p, err := getPlan(cmd, "")
		if err != nil {
			return err
		}
		if err := proxyenv.ValidateConsumer(p, compatConsumer, proxyenv.ConsumerOptions{}); err != nil {
			return err
		}
		if p.SSHHost != "" {
			return proxyenv.ErrRemoteEnv
		}
		if p.Username != "" || p.PasswordEnv != "" || p.PasswordFile != "" || p.CAFile != "" {
			return errors.New("legacy proxy helpers cannot export private credentials or custom CA settings; use lazyclash proxy exec or proxy-on")
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "_NET_PROXY_CACHE=%s\n_NET_PROXY_SOCKS_CACHE=%s\n_NET_PROXY_SOURCE_CACHE=%s\n", proxyenv.Quote(p.HTTP), proxyenv.Quote(p.All), proxyenv.Quote(p.Source))
		return err
	}}
	compat.Flags().StringVar(&compatConsumer, "consumer", "process", "process or service; service refuses known temporary SSH endpoints")
	var shell, session string
	env := &cobra.Command{Use: "env", Short: "Print shell exports (use shell-init for automatic SSH sessions)", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if err := validateProxyConsumer(consumer); err != nil {
			return err
		}
		if shell != "sh" && shell != "bash" && shell != "zsh" {
			return usage("--shell must be sh, bash or zsh")
		}
		p, err := getPlan(cmd, session)
		if err != nil {
			return err
		}
		if err := proxyenv.ValidateConsumer(p, consumer, proxyenv.ConsumerOptions{}); err != nil {
			return err
		}
		if o.json {
			return o.output(cmd, map[string]any{"proxy": p, "consumer": consumer, "credentials_redacted": true, "no_proxy": "preserved"})
		}
		text, err := proxyenv.RenderEnv(p, shell)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), text)
		return err
	}}
	env.Flags().StringVar(&shell, "shell", "sh", "shell syntax: sh, bash or zsh")
	env.Flags().StringVar(&session, "session", "", "use an existing owned shell session")
	env.Flags().StringVar(&consumer, "consumer", "process", "process or service; service refuses known temporary SSH endpoints")
	var initShell string
	var replace bool
	init := &cobra.Command{Use: "shell-init [bash|zsh]", Short: "Print standalone proxy-on/off functions and safe exit hooks", Args: argsMaxOne("shell-init"), RunE: func(cmd *cobra.Command, args []string) error {
		if o.json {
			return usage("shell-init emits shell code and cannot use --json")
		}
		if len(args) == 1 {
			if cmd.Flags().Changed("shell") {
				return usage("choose shell as an argument or --shell")
			}
			initShell = args[0]
		}
		binary, err := os.Executable()
		if err != nil {
			return err
		}
		text, err := proxyenv.ShellInit(initShell, binary, replace)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), text)
		return err
	}}
	init.Flags().StringVar(&initShell, "shell", "zsh", "shell: bash or zsh")
	init.Flags().BoolVar(&replace, "replace", false, "explicitly replace existing friendly proxy-* functions (for shell adapters)")
	status := &cobra.Command{Use: "status", Short: "Inspect proxy selection, current environment and OS proxy metadata", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		result := map[string]any{"environment": proxyenv.EnvironmentStatus(), "os_proxy": proxyenv.SystemProxy(cmd.Context())}
		if id := os.Getenv("LAZYCLASH_PROXY_SESSION"); id != "" && endpoint == "" && o.target == "" {
			s, err := proxyenv.Status(cmd.Context(), id, o.proxySessionOptions(cmd))
			if err != nil {
				return err
			}
			result["session"] = proxyenv.SessionSummary(s)
			return o.output(cmd, result)
		}
		p, err := o.proxyPlan(cmd, endpoint, socks, "")
		if err != nil {
			return err
		}
		result["proxy"] = p
		result["connectivity"] = "not tested; use proxy test"
		return o.output(cmd, result)
	}}
	test := &cobra.Command{Use: "test [URL]", Short: "Send one bounded HEAD request through the explicit proxy", Args: argsMaxOne("proxy test"), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if err := o.writable(); err != nil {
			return err
		}
		p, err := getPlan(cmd, "")
		if err != nil {
			return err
		}
		p, cleanup, err := o.proxyExecutionPlan(cmd, p)
		if err != nil {
			return err
		}
		defer cleanup()
		destination := ""
		if len(args) == 1 {
			destination = args[0]
		}
		result, err := proxyenv.Test(cmd.Context(), p, destination)
		if err != nil {
			return err
		}
		return o.output(cmd, result)
	}}
	execute := &cobra.Command{Use: "exec -- COMMAND [ARG...]", Short: "Run one command with proxy env; preserve its exit status, never retry", Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return usage("proxy exec requires a command after --")
		}
		if cmd.ArgsLenAtDash() < 0 {
			return usage("separate the child command with --")
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if o.json {
			return usage("proxy exec owns child stdout and cannot use --json")
		}
		if err := o.writable(); err != nil {
			return err
		}
		p, err := getPlan(cmd, "")
		if err != nil {
			return err
		}
		p, cleanup, err := o.proxyExecutionPlan(cmd, p)
		if err != nil {
			return err
		}
		defer cleanup()
		return proxyenv.Exec(cmd.Context(), p, args, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
	}}
	group.AddCommand(env, init, status, test, execute, compat, o.proxyReverseCommand(&endpoint, &socks, false), o.proxyTunnelCommand(&endpoint, &socks), o.proxyDockerCommand(&endpoint, &socks))
	return group
}

func validateProxyConsumer(value string) error {
	if value != "process" && value != "service" {
		return usage("--consumer must be process or service")
	}
	return nil
}

func argsMaxOne(name string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("%s accepts at most one argument", name)
		}
		return nil
	}
}

func (o *options) proxyExecutionPlan(cmd *cobra.Command, p proxyenv.Plan) (proxyenv.Plan, func(), error) {
	if p.SSHHost == "" {
		return p, func() {}, nil
	}
	id, err := proxyenv.NewID()
	if err != nil {
		return p, func() {}, err
	}
	opts := o.proxySessionOptions(cmd)
	session, err := proxyenv.Start(cmd.Context(), id, os.Getpid(), p, opts)
	if err != nil {
		return p, func() {}, err
	}
	return session.Local, func() { _ = proxyenv.Stop(context.Background(), id, opts) }, nil
}

func (o *options) proxyTunnelCommand(endpoint, socks *string) *cobra.Command {
	group := &cobra.Command{Use: "tunnel", Short: "Manage private persistent shell proxy sessions"}
	group.AddCommand(o.proxyReverseCommand(endpoint, socks, true))
	group.AddCommand(&cobra.Command{Use: "new-id", Hidden: true, Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		id, err := proxyenv.NewID()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), id)
		return err
	}})
	var lease string
	var shellPID int
	var quiet bool
	start := &cobra.Command{Use: "start [TARGET]", Short: "Authenticate and start a private shell-owned session", Args: argsMaxOne("tunnel start"), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if err := o.writable(); err != nil {
			return err
		}
		id := ""
		if len(args) == 1 {
			id = args[0]
		}
		p, err := o.proxyPlan(cmd, *endpoint, *socks, id)
		if err != nil {
			return err
		}
		if lease == "" {
			lease, err = proxyenv.NewID()
			if err != nil {
				return err
			}
		}
		if shellPID == 0 {
			shellPID = os.Getppid()
		}
		opts := o.proxySessionOptions(cmd)
		if _, err = proxyenv.Cleanup(cmd.Context(), opts); err != nil {
			return err
		}
		s, err := proxyenv.Start(cmd.Context(), lease, shellPID, p, opts)
		if err != nil {
			return err
		}
		if quiet && !o.json {
			return nil
		}
		return o.output(cmd, proxyenv.SessionSummary(s))
	}}
	start.Flags().StringVar(&lease, "lease", "", "new shell session ID (normally generated by proxy-on)")
	start.Flags().IntVar(&shellPID, "shell-pid", 0, "owning shell PID (defaults to parent process)")
	start.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress the successful session summary")
	group.AddCommand(start, &cobra.Command{Use: "status [ID]", Short: "Inspect sessions without creating connections", Args: argsMaxOne("tunnel status"), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			result, err := proxyenv.Sessions(cmd.Context(), o.proxySessionOptions(cmd))
			if err != nil {
				return err
			}
			return o.output(cmd, result)
		}
		s, err := proxyenv.Status(cmd.Context(), args[0], o.proxySessionOptions(cmd))
		if err != nil {
			return err
		}
		if err = o.output(cmd, proxyenv.SessionSummary(s)); err != nil {
			return err
		}
		if s.State != "ready" {
			return errors.New("proxy session is unavailable; run proxy-on to recreate it")
		}
		return nil
	}}, &cobra.Command{Use: "stop ID", Short: "Close only this private session; never a user's SSH master", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := proxyenv.Stop(cmd.Context(), args[0], o.proxySessionOptions(cmd)); err != nil {
			return err
		}
		return o.result(cmd, "Proxy session stopped")
	}}, &cobra.Command{Use: "cleanup", Short: "Release sessions whose owning shell has exited", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		ids, err := proxyenv.Cleanup(cmd.Context(), o.proxySessionOptions(cmd))
		if err != nil {
			return err
		}
		return o.output(cmd, map[string]any{"removed": ids})
	}})
	return group
}

func (o *options) proxyDockerCommand(endpoint, socks *string) *cobra.Command {
	group := &cobra.Command{Use: "docker", Short: "Generate container/build settings and inspect daemon guidance"}
	var format, scope, noProxy, output string
	var services []string
	var includeCredentials bool
	render := &cobra.Command{Use: "render", Short: "Generate a proxy artifact without editing Docker configuration", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if *endpoint == "" {
			return usage("Docker requires --endpoint URL reachable from the container/builder; localhost is not rewritten automatically")
		}
		if o.json {
			return usage("docker render emits an artifact; select --format client-json for JSON")
		}
		p, err := o.proxyDockerPlan(cmd, *endpoint, *socks)
		if err != nil {
			return err
		}
		text, err := proxyenv.RenderDocker(p, proxyenv.DockerRenderOptions{Format: format, Scope: scope, Services: services, NoProxy: noProxy, IncludeCredentials: includeCredentials})
		if err != nil {
			return err
		}
		if output != "" {
			if err := o.writable(); err != nil {
				return err
			}
			if err := proxyenv.WriteArtifact(output, text); err != nil {
				return err
			}
			return o.result(cmd, "Created "+output)
		}
		_, err = fmt.Fprint(cmd.OutOrStdout(), text)
		return err
	}}
	render.Flags().StringVar(&format, "format", "env-file", "env-file, compose, build-args or client-json (snippet only)")
	render.Flags().StringSliceVar(&services, "service", nil, "Compose service names to receive the overlay")
	render.Flags().StringVar(&scope, "scope", "runtime", "Compose runtime, build or both; build services must already define build configuration")
	render.Flags().StringVar(&noProxy, "no-proxy", "", "explicit exclusions, otherwise omitted")
	render.Flags().StringVar(&output, "output", "", "create a new private artifact file; never overwrite an existing file")
	render.Flags().BoolVar(&includeCredentials, "include-credentials", false, "allow sensitive proxy credentials in the generated artifact")
	var container, image, network, destination string
	test := &cobra.Command{Use: "test", Short: "Test from an existing container or local image; never pull an image", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if err := o.writable(); err != nil {
			return err
		}
		if *endpoint == "" {
			return usage("docker test requires an explicit consumer-reachable --endpoint URL")
		}
		p, err := o.proxyDockerPlan(cmd, *endpoint, *socks)
		if err != nil {
			return err
		}
		result, err := proxyenv.DockerTest(cmd.Context(), p, proxyenv.DockerTestOptions{Container: container, Image: image, Network: network, URL: destination})
		if err != nil {
			return err
		}
		return o.output(cmd, result)
	}}
	test.Flags().StringVar(&container, "container", "", "existing container containing curl")
	test.Flags().StringVar(&image, "image", "", "already-local image containing curl (--pull=never)")
	test.Flags().StringVar(&network, "network", "", "explicit network for a temporary probe container")
	test.Flags().StringVar(&destination, "url", proxyenv.DefaultTestURL, "HTTP(S) destination for the proxy HEAD request")
	group.AddCommand(render, test, &cobra.Command{Use: "doctor", Short: "Read Docker context/daemon metadata and show proxy setup guidance", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error { return o.output(cmd, proxyenv.DockerDoctor(cmd.Context())) }})
	return group
}

// Docker must name its consumer-reachable endpoint. An explicit registered
// target may supply authentication references without importing its SSH route.
func (o *options) proxyDockerPlan(cmd *cobra.Command, endpoint, socks string) (proxyenv.Plan, error) {
	p, err := proxyenv.Resolve(cmd.Context(), config.Config{}, proxyenv.Request{Endpoint: endpoint, SocksEndpoint: socks}, proxyenv.Options{})
	if err != nil {
		return p, err
	}
	if globalChanged(cmd, "controller") || o.ssh != "" {
		return p, usage("Docker uses an explicit consumer endpoint; controller/SSH transport overrides do not apply")
	}
	if o.target != "" {
		cfg, _, e := o.load(cmd)
		if e != nil {
			return p, e
		}
		i, e := targetIndex(cfg, o.target)
		if e != nil {
			return p, e
		}
		t := cfg.Targets[i]
		p.TargetID = t.ID
		p.Username, p.PasswordEnv, p.PasswordFile, p.CAFile = t.ProbeUsername, t.ProbePasswordEnv, t.ProbePasswordFile, t.ProbeCAFile
	}
	return p, nil
}
