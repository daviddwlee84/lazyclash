package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/spf13/cobra"
)

func (o *options) diagnosticOptions() diagnostics.Options {
	opts := o.deps.Diagnostics
	opts.ReadOnly = o.readOnly
	if opts.Open == nil {
		opts.Open = o.deps.Open
	}
	return opts
}

// Resolve the target without opening its controller. Data-plane probes can
// still work when a registered target's management API is unavailable.
func (o *options) resolveDiagnosticTarget(cmd *cobra.Command, id string) (config.Target, error) {
	cfg, _, err := o.load(cmd)
	if err != nil {
		return config.Target{}, err
	}
	if id != "" {
		if globalChanged(cmd, "target") || globalChanged(cmd, "controller") {
			return config.Target{}, usage("target ID argument cannot be combined with --target or --controller")
		}
		i, err := targetIndex(cfg, id)
		if err != nil {
			return config.Target{}, err
		}
		t := o.overrideCredentials(cfg.Targets[i])
		if o.ssh != "" {
			t.SSHHost = o.ssh
		}
		return t, nil
	}
	t, _, err := o.choose(cmd, cfg)
	if err != nil || t.ID != "" {
		return t, err
	}
	candidates, err := o.discoverCommand(cmd)
	if err != nil {
		return t, err
	}
	if len(candidates) == 0 {
		return t, fmt.Errorf("no controller found; use targets discover or --controller URL")
	}
	if len(candidates) != 1 {
		return t, usage("found %d controllers; select --target or --controller", len(candidates))
	}
	return candidates[0], nil
}

func (o *options) authenticatedDiagnostic(cmd *cobra.Command, t config.Target, run func() error) error {
	err := run()
	if !connection.IsAuthRequired(err) || o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
		return err
	}
	host := t.SSHHost
	var required *connection.AuthRequiredError
	if errors.As(err, &required) {
		host = required.Host
	}
	auth, e := o.deps.Authenticate(cmd.Context(), host)
	if e != nil {
		return e
	}
	auth.Stdin, auth.Stdout, auth.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr(), cmd.ErrOrStderr()
	if e = auth.Run(); e != nil {
		return fmt.Errorf("SSH authentication failed: %w", e)
	}
	return run()
}

func (o *options) targetTestCommand() *cobra.Command {
	return &cobra.Command{Use: "test [ID]", Short: "Test SSH/API authentication, version and readable runtime settings", Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("targets test accepts at most one target ID")
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		id := ""
		if len(args) == 1 {
			id = args[0]
		}
		t, err := o.resolveDiagnosticTarget(cmd, id)
		if err != nil {
			return err
		}
		var result diagnostics.TestResult
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			result, e = diagnostics.Test(cmd.Context(), t, o.diagnosticOptions())
			return e
		})
		if err != nil {
			return err
		}
		return o.output(cmd, result)
	}}
}

func (o *options) diagnosticsCommand() *cobra.Command {
	group := &cobra.Command{Use: "diagnostics", Short: "Manually probe egress through the selected target's explicit data proxy"}
	group.AddCommand(o.diagnosticURLCommand(), o.diagnosticNetworkCommand(), o.diagnosticChecksCommand())
	group.AddCommand(&cobra.Command{Use: "ip", Short: "Read IP.SB egress IP and location through the configured proxy", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if err := o.writable(); err != nil {
			return err
		}
		t, err := o.resolveDiagnosticTarget(cmd, "")
		if err != nil {
			return err
		}
		var result diagnostics.IPResult
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			result, e = diagnostics.IP(cmd.Context(), t, o.diagnosticOptions())
			return e
		})
		if err != nil {
			return err
		}
		return o.output(cmd, result)
	}}, &cobra.Command{Use: "latency", Short: "Measure Google, Cloudflare and GitHub response headers through the proxy", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if err := o.writable(); err != nil {
			return err
		}
		t, err := o.resolveDiagnosticTarget(cmd, "")
		if err != nil {
			return err
		}
		var result diagnostics.LatencyResult
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			result, e = diagnostics.Latency(cmd.Context(), t, o.diagnosticOptions())
			return e
		})
		if len(result.Sites) > 0 {
			if outputErr := o.output(cmd, result); outputErr != nil {
				return outputErr
			}
		}
		return err
	}})
	return group
}

func (o *options) diagnosticURLCommand() *cobra.Command {
	var via, referenceDoH string
	var observeOnly bool
	cmd := &cobra.Command{Use: "url URL", Short: "Compare host, core and explicit proxy evidence for one HTTP(S) URL", Long: "Compare local and SSH process environments, native and core DNS, bounded core events, HEAD responses, and core DIRECT/chosen-outbound URLTest samples. No mode or selector is changed. URLTest may update health/history. Reports stay in memory unless you explicitly redirect output.", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if o.readOnly && !observeOnly {
			return usage("active URL diagnostics are disabled in read-only mode; use --observe-only")
		}
		target, err := o.resolveDiagnosticTarget(cmd, "")
		if err != nil {
			return err
		}
		var result diagnostics.URLResult
		err = o.authenticatedDiagnostic(cmd, target, func() error {
			var runErr error
			result, runErr = diagnostics.RunURL(cmd.Context(), target, args[0], diagnostics.URLOptions{Options: o.diagnosticOptions(), Via: via, ObserveOnly: observeOnly, ReferenceDoH: referenceDoH})
			return runErr
		})
		if result.URL != "" {
			if o.json {
				if outputErr := o.output(cmd, result); outputErr != nil {
					return outputErr
				}
			} else {
				if _, outputErr := fmt.Fprintln(cmd.OutOrStdout(), diagnostics.FormatURL(result)); outputErr != nil {
					return outputErr
				}
			}
		}
		return err
	}}
	cmd.Flags().StringVar(&via, "via", "", "Compare this existing policy's selected leaf without changing selectors")
	cmd.Flags().BoolVar(&observeOnly, "observe-only", false, "Inspect existing evidence without DNS, HTTP or outbound URLTest probes")
	cmd.Flags().StringVar(&referenceDoH, "reference-doh", "", "Opt-in HTTPS DNS-JSON endpoint, contacted only through the explicit data proxy")
	return cmd
}

func (o *options) testTargetText(ctx context.Context, target config.Target) (string, error) {
	result, err := diagnostics.Test(ctx, target, o.diagnosticOptions())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("API connected · %s · runtime settings readable", result.Version), nil
}

func (o *options) probeIPText(ctx context.Context, target config.Target) (string, error) {
	r, err := diagnostics.IP(ctx, target, o.diagnosticOptions())
	if err != nil {
		return "", err
	}
	return core.Sanitize(fmt.Sprintf("IP.SB egress: %s · %s, %s · %s · ASN %v\nRoute: %s · %s\nRule mode may route other destinations differently.", r.IP, r.City, r.Country, r.Organization, r.ASN, r.Route, r.SampledAt.Format("15:04:05"))), nil
}

func (o *options) probeLatencyText(ctx context.Context, target config.Target) (string, error) {
	r, err := diagnostics.Latency(ctx, target, o.diagnosticOptions())
	var lines []string
	for _, site := range r.Sites {
		line := fmt.Sprintf("%s: %.0f ms (HTTP %d)", site.Name, site.Milliseconds, site.StatusCode)
		if site.Error != "" {
			line += " · " + site.Error
		}
		lines = append(lines, line)
	}
	if len(lines) > 0 {
		lines = append(lines, fmt.Sprintf("Route: %s · %s", r.Route, r.SampledAt.Format("15:04:05")))
	}
	return core.Sanitize(strings.Join(lines, "\n")), err
}
