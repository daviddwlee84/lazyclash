package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/daviddwlee84/lazyclash/internal/compare"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/spf13/cobra"
)

func (o *options) comparisonTargets(cmd *cobra.Command, args []string) (config.Target, config.Target, error) {
	for _, name := range []string{"target", "controller", "ssh", "secret-file", "secret-env", "ca-cert"} {
		if globalChanged(cmd, name) {
			return config.Target{}, config.Target{}, usage("two-target operations cannot use --%s; each saved target supplies its own connection settings", name)
		}
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return config.Target{}, config.Target{}, err
	}
	a, err := targetIndex(cfg, args[0])
	if err != nil {
		return config.Target{}, config.Target{}, err
	}
	b, err := targetIndex(cfg, args[1])
	if err != nil {
		return config.Target{}, config.Target{}, err
	}
	return cfg.Targets[a], cfg.Targets[b], nil
}

func (o *options) comparisonOptions(cmd *cobra.Command) compare.Options {
	return compare.Options{ReadOnly: o.readOnly, Open: func(ctx context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		// Only connection establishment can hand off authentication. A mutation
		// is never retried as part of authenticating the other target.
		client, closer, err := o.deps.Open(ctx, target, readOnly)
		if !connection.IsAuthRequired(err) || o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
			return client, closer, err
		}
		if client != nil {
			_ = client.Close()
		}
		if closer != nil {
			_ = closer.Close()
		}
		auth, err := o.deps.Authenticate(ctx, target.SSHHost)
		if err != nil {
			return nil, nil, err
		}
		auth.Stdin, auth.Stdout, auth.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr(), cmd.ErrOrStderr()
		if err := auth.Run(); err != nil {
			return nil, nil, fmt.Errorf("SSH authentication failed: %w", err)
		}
		return o.deps.Open(ctx, target, readOnly)
	}}
}

func comparisonError(err error) error {
	var validation *compare.ValidationError
	if errors.As(err, &validation) {
		return usage("%s", validation.Message)
	}
	return err
}

func (o *options) targetDiffCommand() *cobra.Command {
	return &cobra.Command{Use: "diff SOURCE DEST", Short: "Compare saved targets' reported runtime settings and manual proxy groups", Args: argsExact(2), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		source, destination, err := o.comparisonTargets(cmd, args)
		if err != nil {
			return err
		}
		result, err := compare.Diff(cmd.Context(), source, destination, o.comparisonOptions(cmd))
		if err != nil {
			return comparisonError(err)
		}
		return o.output(cmd, result)
	}}
}

func (o *options) targetCopySettingsCommand() *cobra.Command {
	var selection compare.Selection
	var yes bool
	var expected string
	cmd := &cobra.Command{
		Use: "copy-settings SOURCE DEST", Short: "Preview selected runtime fields and manual selections; apply with --yes --expect DIGEST",
		Long: "Copy only explicitly selected mode, log-level, and manual Selector choices between saved targets. Preview is the default. Apply requires --yes and the preview digest in --expect, rechecks both targets, and stops at the first failed or uncertain write. It changes runtime state only; it does not copy credentials, ports, TUN settings, YAML files or native client profiles.",
		Args: argsExact(2), RunE: func(cmd *cobra.Command, args []string) error {
			defer connection.CloseAuthentications()
			if yes && expected == "" {
				return usage("--yes requires --expect DIGEST from a copy-settings preview")
			}
			if !yes && cmd.Flags().Changed("expect") {
				return usage("--expect is used with --yes; omit both to preview")
			}
			source, destination, err := o.comparisonTargets(cmd, args)
			if err != nil {
				return err
			}
			opts := o.comparisonOptions(cmd)
			if !yes {
				plan, err := compare.Preview(cmd.Context(), source, destination, selection, opts)
				if err != nil {
					return comparisonError(err)
				}
				return o.output(cmd, plan)
			}
			result, err := compare.Apply(cmd.Context(), source, destination, selection, expected, opts)
			// Retain partial receipts on stdout; the process boundary emits the
			// failure once on stderr and preserves its typed error/exit status.
			if result.Plan.Digest != "" {
				if outputErr := o.output(cmd, result); outputErr != nil {
					return outputErr
				}
			}
			return comparisonError(err)
		},
	}
	cmd.Flags().StringArrayVar(&selection.Fields, "field", nil, "runtime field to copy: mode or log-level (repeatable)")
	cmd.Flags().StringArrayVar(&selection.Groups, "group", nil, "manual Selector group whose current member to copy (repeatable)")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the explicitly selected preview")
	cmd.Flags().StringVar(&expected, "expect", "", "digest returned by the matching preview")
	return cmd
}
