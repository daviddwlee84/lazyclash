package cli

import (
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/spf13/cobra"
)

func (o *options) ruleOptions() rulework.Options {
	return rulework.Options{ReadOnly: o.readOnly, Open: o.deps.Open}
}

func (o *options) ruleTarget(cmd *cobra.Command) (config.Target, error) {
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return config.Target{}, usage("persistent rule operations use the registered endpoint and SSH host; edit the target before rebinding its rule source")
	}
	cfg, _, i, err := o.registered(cmd)
	if err != nil {
		return config.Target{}, err
	}
	return o.overrideCredentials(cfg.Targets[i]), nil
}

func (o *options) ruleEditCommands() []*cobra.Command {
	source := &cobra.Command{Use: "source", Short: "Bind the persistent owner used by rule repair"}
	source.AddCommand(&cobra.Command{Use: "show", Short: "Show the explicit rule source binding", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		return o.output(cmd, map[string]any{"target_id": t.ID, "rule_source": t.RuleSource})
	}})
	var binding config.RuleSource
	set := &cobra.Command{Use: "set --kind mihomo|verge", Short: "Bind an existing standalone YAML or current Verge profile Rules companion", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
			return usage("rule source binding requires the registered endpoint and SSH host")
		}
		cfg, path, i, err := o.registered(cmd)
		if err != nil {
			return err
		}
		cfg.Targets[i].RuleSource = &binding
		if err = config.ValidateRuleSource(cfg.Targets[i]); err != nil {
			return usage("%s", err)
		}
		var owner rulework.Source
		err = o.authenticatedDiagnostic(cmd, cfg.Targets[i], func() error { var e error; owner, e = rulework.InspectSource(cmd.Context(), cfg.Targets[i]); return e })
		if err != nil {
			return err
		}
		if err = saveSettings(path, cfg); err != nil {
			return err
		}
		return o.output(cmd, map[string]any{"target_id": cfg.Targets[i].ID, "rule_source": binding, "owner": owner})
	}}
	set.Flags().StringVar(&binding.Kind, "kind", "", "persistent owner: mihomo or verge")
	set.Flags().StringVar(&binding.Version, "owner-version", "", "declared Verge compatibility version (supported: 2.5.2)")
	set.Flags().StringVar(&binding.ConfigID, "config-id", "", "registered standalone config ID")
	set.Flags().StringVar(&binding.Binary, "binary", "", "absolute Mihomo validator binary on the core host")
	set.Flags().StringVar(&binding.Home, "home", "", "absolute existing Mihomo home for copying validation resources")
	set.Flags().StringVar(&binding.DataDir, "data-dir", "", "absolute Clash Verge data directory on the target host")
	set.Flags().StringVar(&binding.ProfileUID, "profile", "", "explicit current Verge profile UID")
	source.AddCommand(set)
	var policy, expected string
	var yes bool
	add := &cobra.Command{Use: "add-domain HOST --via POLICY", Short: "Preview an exact DOMAIN rule; apply with --yes --expect DIGEST", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if policy == "" {
			return usage("--via must select an existing proxy or group")
		}
		if yes && expected == "" {
			return usage("--yes requires --expect with the digest printed by a preview")
		}
		if !yes && expected != "" {
			return usage("--expect is used together with --yes")
		}
		if yes {
			if err := o.writable(); err != nil {
				return err
			}
		}
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		if !yes {
			var plan rulework.Plan
			err = o.authenticatedDiagnostic(cmd, t, func() error {
				var e error
				plan, e = rulework.Preview(cmd.Context(), t, args[0], policy, o.ruleOptions())
				return e
			})
			if err != nil {
				return err
			}
			return o.output(cmd, plan)
		}
		// Do not wrap a write in authentication retry: the result could already
		// have reached the remote owner. Authenticate with a read-only preview
		// first, then execute the guarded write exactly once.
		var checked rulework.Plan
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			checked, e = rulework.Preview(cmd.Context(), t, args[0], policy, o.ruleOptions())
			return e
		})
		if err != nil {
			return err
		}
		if checked.Digest != expected {
			return usage("rule preview changed; review a new preview before applying")
		}
		receipt, err := rulework.Apply(cmd.Context(), t, args[0], policy, expected, o.ruleOptions())
		if receipt.ID != "" {
			if e := o.output(cmd, receipt); e != nil {
				return e
			}
		}
		return err
	}}
	add.Flags().StringVar(&policy, "via", "", "existing outbound/group to use for this hostname")
	add.Flags().BoolVar(&yes, "yes", false, "apply the reviewed persistent rule edit")
	add.Flags().StringVar(&expected, "expect", "", "digest of the reviewed source and proposed rule")
	verify := &cobra.Command{Use: "verify RECEIPT", Short: "Verify persistent bytes and the first runtime rule after owner reload", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		var r rulework.Receipt
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			r, e = rulework.Verify(cmd.Context(), t, args[0], o.ruleOptions())
			return e
		})
		if r.ID != "" {
			if e := o.output(cmd, r); e != nil {
				return e
			}
		}
		return err
	}}
	var restoreYes bool
	restore := &cobra.Command{Use: "restore RECEIPT --yes", Short: "Restore the private backup if no intervening edit exists", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if !restoreYes {
			return usage("restoring a rule source requires --yes")
		}
		if err := o.writable(); err != nil {
			return err
		}
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		err = o.authenticatedDiagnostic(cmd, t, func() error { _, e := rulework.InspectSource(cmd.Context(), t); return e })
		if err != nil {
			return err
		}
		r, err := rulework.Restore(cmd.Context(), t, args[0], o.ruleOptions())
		if r.ID != "" {
			if e := o.output(cmd, r); e != nil {
				return e
			}
		}
		return err
	}}
	restore.Flags().BoolVar(&restoreYes, "yes", false, "restore this receipt's original source and reload standalone runtime")
	return []*cobra.Command{source, add, verify, restore}
}
