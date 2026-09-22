package cli

import (
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
	"github.com/spf13/cobra"
)

func (o *options) diagnosticChecksCommand() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{Use: "checks", Short: "Save and run reusable connectivity checks on this target", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if interactive {
			return o.runDiagnosticChecksInteractive(cmd)
		}
		return o.listSavedDiagnosticChecks(cmd)
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "review, manage or run saved checks in a terminal")
	cmd.AddCommand(&cobra.Command{Use: "list", Short: "Read saved checks without contacting the target", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error { return o.listSavedDiagnosticChecks(cmd) }})
	var check config.DiagnosticCheck
	var replace bool
	add := &cobra.Command{Use: "add ID --url URL", Short: "Save an unauthenticated HTTP(S) check; no request is sent", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		check.ID = args[0]
		if check.URL == "" {
			return usage("checks add requires --url")
		}
		return o.upsertSavedDiagnosticCheck(cmd, check, replace)
	}}
	add.Flags().StringVar(&check.URL, "url", "", "public HTTP(S) URL without credentials, query or fragment")
	add.Flags().StringVar(&check.Name, "name", "", "display name")
	add.Flags().IntSliceVar(&check.ExpectedStatuses, "status", nil, "expected HTTP status codes, comma-separated (default: any 2xx/3xx)")
	add.Flags().StringVar(&check.Via, "via", "", "optional existing core policy for a separate URLTest comparison; does not change selectors")
	add.Flags().BoolVar(&replace, "replace", false, "replace the saved definition with this ID")
	cmd.AddCommand(add, &cobra.Command{Use: "remove ID", Short: "Remove this target's saved check", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error { return o.removeSavedDiagnosticCheck(cmd, args[0]) }})
	var all bool
	run := &cobra.Command{Use: "run [ID]", Short: "Run one saved check or --all sequentially through the explicit data proxy", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		id := ""
		if len(args) == 1 {
			id = args[0]
		}
		return o.runSavedDiagnosticChecks(cmd, id, all)
	}}
	run.Flags().BoolVar(&all, "all", false, "run all saved checks once, sequentially")
	cmd.AddCommand(run)
	return cmd
}

func (o *options) savedDiagnosticChecks(cmd *cobra.Command) (config.Config, string, int, error) {
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return config.Config{}, "", -1, usage("saved checks require a registered target without temporary endpoint/SSH overrides")
	}
	return o.registered(cmd)
}

func (o *options) listSavedDiagnosticChecks(cmd *cobra.Command) error {
	cfg, _, i, err := o.savedDiagnosticChecks(cmd)
	if err != nil {
		return err
	}
	checks := cfg.Targets[i].Checks
	if checks == nil {
		checks = []config.DiagnosticCheck{}
	}
	return o.output(cmd, map[string]any{"target_id": cfg.Targets[i].ID, "checks": checks})
}

func (o *options) upsertSavedDiagnosticCheck(cmd *cobra.Command, check config.DiagnosticCheck, replace bool) error {
	if err := o.writable(); err != nil {
		return err
	}
	if err := config.ValidateDiagnosticChecks([]config.DiagnosticCheck{check}); err != nil {
		return usage("%s", err)
	}
	cfg, path, i, err := o.savedDiagnosticChecks(cmd)
	if err != nil {
		return err
	}
	index := -1
	for j, item := range cfg.Targets[i].Checks {
		if item.ID == check.ID {
			index = j
			break
		}
	}
	if index >= 0 {
		if !replace {
			return usage("check %q already exists; use --replace to edit it", check.ID)
		}
		cfg.Targets[i].Checks[index] = check
	} else {
		if replace {
			return usage("check %q is not saved; omit --replace to add it", check.ID)
		}
		cfg.Targets[i].Checks = append(cfg.Targets[i].Checks, check)
	}
	if err = saveSettings(path, cfg); err != nil {
		return err
	}
	return o.result(cmd, "Saved connectivity check "+check.ID+" on "+cfg.Targets[i].ID+"; no request sent")
}

func (o *options) removeSavedDiagnosticCheck(cmd *cobra.Command, id string) error {
	if err := o.writable(); err != nil {
		return err
	}
	cfg, path, i, err := o.savedDiagnosticChecks(cmd)
	if err != nil {
		return err
	}
	index := -1
	for j, c := range cfg.Targets[i].Checks {
		if c.ID == id {
			index = j
			break
		}
	}
	if index < 0 {
		return usage("check %q is not saved", id)
	}
	cfg.Targets[i].Checks = append(cfg.Targets[i].Checks[:index], cfg.Targets[i].Checks[index+1:]...)
	if err = saveSettings(path, cfg); err != nil {
		return err
	}
	return o.result(cmd, "Removed connectivity check "+id+" from "+cfg.Targets[i].ID)
}

func (o *options) runSavedDiagnosticChecks(cmd *cobra.Command, id string, all bool) error {
	defer connection.CloseAuthentications()
	if id != "" && all || id == "" && !all {
		return usage("choose one check ID or --all")
	}
	if o.readOnly {
		return usage("active saved checks are disabled in read-only mode; checks list remains available")
	}
	cfg, _, i, err := o.savedDiagnosticChecks(cmd)
	if err != nil {
		return err
	}
	target := o.overrideCredentials(cfg.Targets[i])
	checks := []config.DiagnosticCheck{}
	for _, c := range target.Checks {
		if all || c.ID == id {
			checks = append(checks, c)
		}
	}
	if len(checks) == 0 {
		return usage("no matching saved checks; use diagnostics checks add")
	}
	var report diagnostics.CheckReport
	err = o.authenticatedDiagnostic(cmd, target, func() error {
		if target.ProbeProxy == "" {
			opts := o.diagnosticOptions()
			plan, e := proxyenv.Resolve(cmd.Context(), config.Config{Targets: []config.Target{target}}, proxyenv.Request{TargetID: target.ID}, proxyenv.Options{Open: opts.Open})
			if e != nil {
				if connection.IsAuthRequired(e) {
					return e
				}
				return fmt.Errorf("%w: cannot resolve this target's data endpoint; set targets edit --probe-proxy explicitly (%v)", diagnostics.ErrNoProxy, e)
			}
			if plan.TargetID != target.ID || plan.SSHHost != target.SSHHost {
				return fmt.Errorf("resolved proxy does not belong to the selected target")
			}
			target.ProbeProxy, target.ProbeUsername, target.ProbePasswordEnv, target.ProbePasswordFile, target.ProbeCAFile = plan.HTTP, plan.Username, plan.PasswordEnv, plan.PasswordFile, plan.CAFile
		}
		var e error
		report, e = diagnostics.RunChecks(cmd.Context(), target, checks, diagnostics.CheckOptions{Options: o.diagnosticOptions()})
		return e
	})
	if len(report.Checks) > 0 {
		if o.json {
			if outputErr := o.output(cmd, report); outputErr != nil {
				return outputErr
			}
		} else {
			if _, outputErr := fmt.Fprintln(cmd.OutOrStdout(), diagnostics.FormatChecks(report)); outputErr != nil {
				return outputErr
			}
		}
	}
	return err
}
