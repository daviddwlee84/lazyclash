package cli

import (
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/clientservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

func (o *options) clientServiceOptions() clientservice.Options {
	v := o.deps.ClientServices
	v.ReadOnly = o.readOnly
	return v
}
func (o *options) serviceTarget(cmd *cobra.Command, args []string) (config.Config, string, int, error) {
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return config.Config{}, "", -1, usage("service control requires a saved endpoint and SSH host")
	}
	if len(args) == 0 {
		return o.registered(cmd)
	}
	cfg, path, err := o.load(cmd)
	if err != nil {
		return cfg, path, -1, err
	}
	if o.target != "" && o.target != args[0] {
		return cfg, path, -1, usage("positional target conflicts with --target")
	}
	i, err := targetIndex(cfg, args[0])
	return cfg, path, i, err
}
func serviceArgs(cmd *cobra.Command, args []string) error {
	if len(args) > 1 {
		return usage("supply at most one target ID")
	}
	return nil
}
func (o *options) serviceInteractive(cmd *cobra.Command, interactive bool) error {
	if interactive && (o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
		return usage("--interactive requires a terminal and cannot use --json")
	}
	return nil
}
func (o *options) targetServiceCommand() *cobra.Command {
	var interactive bool
	group := &cobra.Command{Use: "service", Short: "Bind and control an existing Docker or systemd client service", Args: serviceArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if !interactive {
			return cmd.Help()
		}
		if err := o.serviceInteractive(cmd, true); err != nil {
			return err
		}
		cfg, _, i, err := o.serviceTarget(cmd, args)
		if err != nil {
			return err
		}
		if cfg.Targets[i].Service == nil {
			return o.bindService(cmd, args, config.ClientService{}, true, false, "")
		}
		choices := []wizard.Choice{{Value: "status", Label: "Inspect bound service status"}}
		if !o.readOnly {
			choices = append(choices, wizard.Choice{Value: "start", Label: "Start"}, wizard.Choice{Value: "stop", Label: "Stop"}, wizard.Choice{Value: "restart", Label: "Restart"}, wizard.Choice{Value: "enable", Label: "Enable autostart"}, wizard.Choice{Value: "disable", Label: "Disable autostart"}, wizard.Choice{Value: "stop-disable", Label: "Stop and disable autostart"})
		}
		action, err := wizard.Choose(cmd.Context(), "Existing target service", choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		disable := action == "stop-disable"
		if disable {
			action = "stop"
		}
		return o.controlService(cmd, args, action, disable, true, false, "")
	}}
	group.Flags().BoolVar(&interactive, "interactive", false, "open the shared existing-service action menu")
	var candidate config.ClientService
	var bindYes, bindInteractive bool
	var bindExpect string
	bind := &cobra.Command{Use: "bind [TARGET]", Short: "Preview an exact existing service binding; apply with --yes --expect DIGEST", Args: serviceArgs, RunE: func(cmd *cobra.Command, args []string) error {
		return o.bindService(cmd, args, candidate, bindInteractive, bindYes, bindExpect)
	}}
	bind.Flags().StringVar(&candidate.Kind, "kind", "", "docker or systemd")
	bind.Flags().StringVar(&candidate.DockerHost, "docker-host", "", "explicit unix:///socket on the target host")
	bind.Flags().StringVar(&candidate.Container, "container", "", "existing Docker container name or ID")
	bind.Flags().StringVar(&candidate.Unit, "unit", "", "existing systemd .service unit")
	bind.Flags().StringVar(&candidate.Scope, "scope", "user", "systemd user or system scope")
	bind.Flags().BoolVar(&bindInteractive, "interactive", false, "inspect and review the binding interactively")
	bind.Flags().BoolVar(&bindYes, "yes", false, "save the reviewed binding")
	bind.Flags().StringVar(&bindExpect, "expect", "", "required reviewed preview digest")
	group.AddCommand(bind)
	for _, action := range []string{"status", "start", "stop", "restart", "enable", "disable"} {
		action := action
		var yes, interactive, disable bool
		var expect string
		cmd := &cobra.Command{Use: action + " [TARGET]", Short: action + " the explicitly bound existing service", Args: serviceArgs, RunE: func(cmd *cobra.Command, args []string) error {
			return o.controlService(cmd, args, action, disable, interactive, yes, expect)
		}}
		if action != "status" {
			cmd.Flags().BoolVar(&yes, "yes", false, "apply the reviewed action")
			cmd.Flags().StringVar(&expect, "expect", "", "required reviewed preview digest")
			cmd.Flags().BoolVar(&interactive, "interactive", false, "review the action interactively")
		}
		if action == "stop" {
			cmd.Flags().BoolVar(&disable, "disable-autostart", false, "also disable startup policy and its Compose source")
		}
		group.AddCommand(cmd)
	}
	return group
}
func (o *options) bindService(cmd *cobra.Command, args []string, candidate config.ClientService, interactive, yes bool, expect string) error {
	defer connection.CloseAuthentications()
	if err := o.serviceInteractive(cmd, interactive); err != nil {
		return err
	}
	cfg, path, i, err := o.serviceTarget(cmd, args)
	if err != nil {
		return err
	}
	if interactive {
		kind, err := wizard.Choose(cmd.Context(), "Existing service owner", []wizard.Choice{{Value: "docker", Label: "Docker container (including rootless)"}, {Value: "systemd", Label: "Linux systemd service"}}, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		candidate.Kind = kind
		var fields []wizard.Field
		if kind == "docker" {
			fields = []wizard.Field{{Key: "host", Label: "Docker socket on target host", Value: candidate.DockerHost, Required: true}, {Key: "container", Label: "Container name or ID", Value: candidate.Container, Required: true}}
		} else {
			fields = []wizard.Field{{Key: "unit", Label: "Systemd service unit", Value: candidate.Unit, Required: true}, {Key: "scope", Label: "Scope: user or system", Value: "user", Required: true}}
		}
		values, err := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Bind existing service", Description: "Inspect an existing owner without installing or replacing it.", SubmitLabel: "Inspect", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		candidate.DockerHost, candidate.Container, candidate.Unit, candidate.Scope = values["host"], values["container"], values["unit"], values["scope"]
	}
	if candidate.Kind == "docker" {
		candidate.Scope = ""
	}
	var plan clientservice.Plan
	err = o.authenticatedDiagnostic(cmd, cfg.Targets[i], func() error {
		var e error
		plan, e = clientservice.PrepareBind(cmd.Context(), cfg.Targets[i], candidate, o.clientServiceOptions())
		return e
	})
	if err != nil {
		return err
	}
	if interactive {
		accepted, e := wizard.Confirm(cmd.Context(), "Bind existing service", fmt.Sprintf("Target: %s\nOwner: %s\nService: %s%s\nDigest: %s", plan.TargetID, plan.Before.Binding.Kind, plan.Before.Binding.Container, plan.Before.Binding.Unit, plan.Digest), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !accepted {
			return wizard.ErrCanceled
		}
		yes, expect = true, plan.Digest
	}
	if !yes {
		return o.output(cmd, plan)
	}
	if err = o.writable(); err != nil {
		return err
	}
	if err = clientservice.ReviewedBind(plan, expect); err != nil {
		return err
	}
	cfg.Targets[i].Service = &plan.Before.Binding
	if err = saveSettings(path, cfg); err != nil {
		return err
	}
	return o.output(cmd, map[string]any{"target_id": cfg.Targets[i].ID, "service": plan.Before.Binding, "status": "bound"})
}
func (o *options) controlService(cmd *cobra.Command, args []string, action string, disable, interactive, yes bool, expect string) error {
	defer connection.CloseAuthentications()
	if err := o.serviceInteractive(cmd, interactive); err != nil {
		return err
	}
	cfg, _, i, err := o.serviceTarget(cmd, args)
	if err != nil {
		return err
	}
	t := cfg.Targets[i]
	if action == "status" {
		var status clientservice.Status
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			status, e = clientservice.Inspect(cmd.Context(), t, o.clientServiceOptions())
			return e
		})
		if err != nil {
			return err
		}
		return o.output(cmd, status)
	}
	var p clientservice.Plan
	err = o.authenticatedDiagnostic(cmd, t, func() error {
		var e error
		p, e = clientservice.Preview(cmd.Context(), t, action, disable, o.clientServiceOptions())
		return e
	})
	if err != nil {
		return err
	}
	if interactive {
		accepted, e := wizard.Confirm(cmd.Context(), "Review service action", fmt.Sprintf("Target: %s\nAction: %s\n%s\nDigest: %s", t.ID, action, strings.Join(p.Changes, "\n"), p.Digest), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !accepted {
			return wizard.ErrCanceled
		}
		yes, expect = true, p.Digest
	}
	if !yes {
		return o.output(cmd, p)
	}
	if err = o.writable(); err != nil {
		return err
	}
	// Authentication happens during the read-only preview; never retry a mutation.
	receipt, err := clientservice.Apply(cmd.Context(), t, action, disable, expect, o.clientServiceOptions())
	if receipt.ID != "" {
		if e := o.output(cmd, receipt); e != nil {
			return e
		}
	}
	return err
}
