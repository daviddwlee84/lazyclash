package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"github.com/spf13/cobra"
)

func (o *options) proxyReverseCommand(endpoint, socks *string, share bool) *cobra.Command {
	var clean bool
	var ports proxyenv.ReverseOptions
	cmd := &cobra.Command{
		Use:   "ssh HOST [-- COMMAND [ARG...]]",
		Short: "Use this machine's proxy in a remote shell or one remote command",
		Long: "Share a local HTTP/SOCKS proxy through a private reverse SSH tunnel.\n" +
			"The remote host needs OpenSSH and Linux/macOS listener inspection tools,\n" +
			"not lazyclash. The tunnel ends with this invocation; it is not a service.\n" +
			"The default login shell may override proxy variables in its startup files.\n" +
			"Use --clean-shell for an interactive /bin/sh without user startup files.",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || cmd.ArgsLenAtDash() == 0 {
				return usage("proxy ssh requires a destination HOST before --")
			}
			if len(args) > 1 && cmd.ArgsLenAtDash() != 1 {
				return usage("separate the remote command from HOST with --")
			}
			if len(args) == 1 && cmd.ArgsLenAtDash() >= 0 {
				return usage("provide a remote command after --, or omit -- to open a shell")
			}
			return nil
		},
	}
	if share {
		cmd.Use = "share HOST"
		cmd.Short = "Share a local proxy with an SSH host until this foreground command exits"
		cmd.Long = "Keep a private reverse SSH tunnel open and print remote shell exports.\n" +
			"Only loopback listeners are accepted. Copy the exports into a terminal on HOST;\n" +
			"they do not change this machine's shell. Ctrl+C closes the tunnel.\n" +
			"With --json, print one ready result and remain running. No automatic reconnect."
		cmd.Args = argsExact(1)
	} else {
		cmd.Flags().BoolVar(&clean, "clean-shell", false, "open /bin/sh -i without user startup files (interactive shell only)")
	}
	cmd.Flags().IntVar(&ports.HTTPPort, "remote-port", 0, "remote HTTP/mixed listener port (0 allocates an available port)")
	cmd.Flags().IntVar(&ports.SocksPort, "remote-socks-port", 0, "remote SOCKS listener port when the source has a separate SOCKS endpoint")
	cmd.RunE = func(cmd *cobra.Command, args []string) (result error) {
		defer connection.CloseAuthentications()
		if err := o.writable(); err != nil {
			return err
		}
		if o.ssh != "" {
			return usage("the destination SSH host is HOST; omit global --ssh")
		}
		if ports.HTTPPort < 0 || ports.HTTPPort > 65535 || ports.SocksPort < 0 || ports.SocksPort > 65535 {
			return usage("remote ports must be between 0 and 65535")
		}
		if err := config.ValidateTarget(config.Target{Controller: "http://127.0.0.1:9090", SSHHost: args[0]}); err != nil {
			return usage("destination: %s", err)
		}
		opts := o.reverseSessionOptions(cmd, !share && len(args) == 1)
		if !share {
			if o.json {
				return usage("proxy ssh owns remote stdout and cannot use --json")
			}
			if clean && len(args) > 1 {
				return usage("--clean-shell cannot be combined with a remote command")
			}
			if len(args) == 1 && !opts.Interactive {
				return usage("a remote shell requires a terminal; use proxy ssh HOST -- COMMAND")
			}
		}
		plan, err := o.reverseSourcePlan(cmd, *endpoint, *socks)
		if err != nil {
			return err
		}
		if _, err = proxyenv.Cleanup(cmd.Context(), opts); err != nil {
			return err
		}
		ports.Host = args[0]
		session, err := proxyenv.PrepareReverse(cmd.Context(), plan, ports, opts)
		if err != nil {
			return err
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := proxyenv.Stop(ctx, session.ID, opts); err != nil {
				result = errors.Join(result, fmt.Errorf("reverse tunnel cleanup: %w", err))
			}
		}()
		if !share {
			if _, err = fmt.Fprintf(cmd.ErrOrStderr(), "Proxy tunnel ready: %s → %s (%s)\n", plan.Source, ports.Host, session.Reverse.Remote.HTTP); err != nil {
				return err
			}
			if len(args) == 1 && !clean {
				fmt.Fprintln(cmd.ErrOrStderr(), "Remote shell startup files can override proxy env; --clean-shell skips user startup files.")
			}
			return proxyenv.RunReverseSSH(cmd.Context(), session, args[1:], clean, opts)
		}
		if o.json {
			if err = o.output(cmd, proxyenv.SessionSummary(session)); err != nil {
				return err
			}
		} else {
			exports, err := proxyenv.RenderEnv(session.Reverse.Remote, "sh")
			if err != nil {
				return err
			}
			if _, err = fmt.Fprintf(cmd.OutOrStdout(), "# Run on %s; keep this sharing command open. Ctrl+C stops the tunnel.\n# Tunnel ready; Internet connectivity has not been tested.\n%s", ports.Host, exports); err != nil {
				return err
			}
		}
		return proxyenv.WaitReverse(cmd.Context(), session, opts)
	}
	return cmd
}

func (o *options) reverseSessionOptions(cmd *cobra.Command, shell bool) proxyenv.SessionOptions {
	if !shell {
		return o.proxySessionOptions(cmd)
	}
	// SSH owns the input/output terminal for an interactive shell. Redirecting
	// diagnostics must not pass preflight and then fail after opening a tunnel.
	return proxyenv.SessionOptions{Interactive: !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()), In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr()}
}

// Reject an SSH source before resolving its data ports, which could otherwise
// start a second authentication/connection for a source this feature cannot use.
func (o *options) reverseSourcePlan(cmd *cobra.Command, endpoint, socks string) (proxyenv.Plan, error) {
	id := o.target
	if id == "" {
		id = os.Getenv("LAZYCLASH_TARGET")
	}
	if id != "" {
		cfg, _, err := o.load(cmd)
		if err != nil {
			return proxyenv.Plan{}, err
		}
		for _, target := range cfg.Targets {
			if target.ID == id && target.SSHHost != "" {
				return proxyenv.Plan{}, usage("reverse sharing requires a source reachable from this machine; an SSH source target is not supported")
			}
		}
	}
	return o.proxyPlan(cmd, endpoint, socks, "")
}
