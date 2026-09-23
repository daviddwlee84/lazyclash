package cli

import (
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/spf13/cobra"
)

func (o *options) coresCommand() *cobra.Command {
	group := &cobra.Command{Use: "cores", Short: "Inspect and control only explicitly lazyclash-owned client installations"}
	group.AddCommand(&cobra.Command{Use: "list", Short: "List local managed-instance registrations without connecting", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		instances, err := managedcore.List(o.managedOptions(cmd))
		if err != nil {
			return err
		}
		return o.output(cmd, instances)
	}})
	group.AddCommand(&cobra.Command{Use: "status ID", Short: "Inspect owned service identity and controller reachability", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		instance, err := managedcore.GetInstance(args[0], o.managedOptions(cmd))
		if err != nil {
			return err
		}
		var status managedcore.Status
		err = o.authenticatedDiagnostic(cmd, instance.Target, func() error {
			var e error
			status, e = managedcore.GetStatus(cmd.Context(), args[0], o.managedOptions(cmd))
			return e
		})
		if status.Instance.ID != "" {
			if e := o.output(cmd, status); e != nil {
				return e
			}
		}
		return err
	}})
	group.AddCommand(&cobra.Command{Use: "resume ID", Short: "Inspect and resume an interrupted owned Windows deployment without reinstalling", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if o.readOnly {
			return usage("deployment resume is disabled in read-only mode")
		}
		instance, err := managedcore.GetInstance(args[0], o.managedOptions(cmd))
		if err != nil {
			return err
		}
		if instance.OS != "windows" {
			return usage("resume currently supports owned Windows deployments; inspect cores status for this instance")
		}
		// Authenticate with a read before the single mutation; never replay a
		// partial resume automatically after an authentication failure.
		err = o.authenticatedDiagnostic(cmd, instance.Target, func() error {
			_, e := managedcore.WindowsStatus(cmd.Context(), args[0], o.managedOptions(cmd))
			return e
		})
		if err != nil {
			return err
		}
		receipt, err := managedcore.ResumeWindows(cmd.Context(), args[0], o.managedOptions(cmd))
		if receipt.ID != "" {
			if e := o.output(cmd, receipt); e != nil {
				return e
			}
		}
		return err
	}})
	for _, operation := range []string{"start", "stop", "restart", "remove"} {
		var yes bool
		var expect string
		cmd := &cobra.Command{Use: operation + " ID", Short: "Preview " + operation + "; apply the reviewed digest with --yes --expect", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
			defer connection.CloseAuthentications()
			if yes && o.readOnly {
				return usage("managed lifecycle changes are disabled in read-only mode")
			}
			if yes && expect == "" {
				return usage("--yes requires --expect DIGEST")
			}
			instance, err := managedcore.GetInstance(args[0], o.managedOptions(cmd))
			if err != nil {
				return err
			}
			var plan managedcore.ActionPlan
			var receipt managedcore.Receipt
			err = o.authenticatedDiagnostic(cmd, instance.Target, func() error {
				var e error
				plan, e = managedcore.PreviewAction(cmd.Context(), args[0], operation, o.managedOptions(cmd))
				return e
			})
			if err == nil && yes {
				receipt, err = managedcore.ApplyAction(cmd.Context(), args[0], operation, expect, o.managedOptions(cmd))
			}

			if yes && receipt.ID != "" {
				if e := o.output(cmd, receipt); e != nil {
					return e
				}
			} else if !yes && plan.ID != "" {
				if e := o.output(cmd, plan); e != nil {
					return e
				}
			}
			return err
		}}
		cmd.Flags().BoolVar(&yes, "yes", false, "apply exactly this reviewed lifecycle change")
		cmd.Flags().StringVar(&expect, "expect", "", "reviewed lifecycle digest")
		group.AddCommand(cmd)
	}
	flags := &setupFlags{}
	configure := &cobra.Command{Use: "configure ID", Short: "Preview or interactively edit an owned core's profile and network choices", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if cmd.Flags().Changed("from-target") {
			return usage("--from-target creates a new deployment with setup; configure edits this instance's saved snapshot")
		}
		request, err := managedcore.LoadRequest(args[0], o.managedOptions(cmd))
		if err != nil {
			return err
		}
		if flags.yes && o.readOnly {
			return usage("managed configuration changes are disabled in read-only mode")
		}
		if flags.yes && flags.expect == "" {
			return usage("--yes requires --expect DIGEST")
		}
		mergeSetupFlags(cmd, &request, flags.request)
		if flags.input != "" {
			if err := loadSetupInput(cmd, &request, flags.input); err != nil {
				return err
			}
		}
		interactive := flags.interactive || !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) && !changedSetupBusiness(cmd)
		if interactive {
			if o.readOnly {
				return usage("configuration wizard is disabled in read-only mode")
			}
			if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
				return usage("interactive configuration requires a terminal and cannot use --json")
			}
			return o.runSetupWizard(cmd, request, args[0], flags.input)
		}
		return o.runManagedPreviewApply(cmd, request, args[0], flags.yes, flags.expect)
	}}
	addSetupFlags(configure, flags)
	group.AddCommand(configure)
	for _, child := range group.Commands() {
		handler := child.RunE
		if handler == nil {
			continue
		}
		child.RunE = func(cmd *cobra.Command, args []string) error {
			if err := validateManagedOverrides(cmd, false, false); err != nil {
				return err
			}
			if len(args) > 0 {
				if err := o.rejectRPiTakeover(cmd, args[0], ""); err != nil {
					return err
				}
				if instance, err := managedcore.GetInstance(args[0], o.managedOptions(cmd)); err == nil {
					if err := o.rejectRPiTakeover(cmd, args[0], instance.Target.SSHHost); err != nil {
						return err
					}
				}
			}
			return handler(cmd, args)
		}
	}
	return group
}

func changedSetupBusiness(cmd *cobra.Command) bool {
	for _, name := range []string{"client", "client-version", "host-os", "from-target", "backend", "input-kind", "input", "preset", "category", "policy", "service-scope", "boot", "tun", "system-proxy", "network-service", "exclude-route", "controller-port", "mixed-port", "core-version", "docker-context", "artifact", "artifact-sha256", "yes", "expect", "routing-owner", "bootstrap-target", "docker-archive", "docker-archive-sha256"} {
		if cmd.Flags().Changed(name) {
			return true
		}
	}
	return false
}

func mergeSetupFlags(cmd *cobra.Command, to *managedcore.Request, from managedcore.Request) {
	for name, fields := range map[string][2]*string{"client": {&to.Client, &from.Client}, "client-version": {&to.ClientVersion, &from.ClientVersion}, "host-os": {&to.HostOS, &from.HostOS}, "docker-archive": {&to.DockerArchive, &from.DockerArchive}, "docker-archive-sha256": {&to.DockerArchiveSHA256, &from.DockerArchiveSHA256}, "bootstrap-target": {&to.BootstrapTarget, &from.BootstrapTarget}, "backend": {&to.Backend, &from.Backend}, "input-kind": {&to.InputKind, &from.InputKind}, "preset": {&to.Preset, &from.Preset}, "service-scope": {&to.ServiceScope, &from.ServiceScope}, "core-version": {&to.Version, &from.Version}, "docker-context": {&to.DockerContext, &from.DockerContext}, "artifact": {&to.ArtifactFile, &from.ArtifactFile}, "artifact-sha256": {&to.ArtifactSHA256, &from.ArtifactSHA256}, "routing-owner": {&to.Network.RoutingOwner, &from.Network.RoutingOwner}} {
		if cmd.Flags().Changed(name) {
			*fields[0] = *fields[1]
		}
	}
	if cmd.Flags().Changed("category") {
		to.Categories = from.Categories
	}
	if cmd.Flags().Changed("policy") {
		to.PolicyRoles = from.PolicyRoles
	}
	if cmd.Flags().Changed("boot") {
		to.Boot = from.Boot
	}
	if cmd.Flags().Changed("tun") {
		to.Network.TUN = from.Network.TUN
	}
	if cmd.Flags().Changed("system-proxy") {
		to.Network.SystemProxy = from.Network.SystemProxy
	}
	if cmd.Flags().Changed("network-service") {
		to.Network.Services = from.Network.Services
	}
	if cmd.Flags().Changed("exclude-route") {
		to.Network.ExcludedRoutes = from.Network.ExcludedRoutes
	}
	if cmd.Flags().Changed("controller-port") {
		to.ControllerPort = from.ControllerPort
	}
	if cmd.Flags().Changed("mixed-port") {
		to.MixedPort = from.MixedPort
	}
}

func (o *options) managedPresetTarget(cmd *cobra.Command, id string) (string, error) {
	if id != "" {
		if managedFlagChanged(cmd, "target") {
			return "", usage("use either --core or --target for a routing preset")
		}
		return id, nil
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return "", err
	}
	target, _, err := o.choose(cmd, cfg)
	if err != nil {
		return "", err
	}
	if target.ManagedCoreID == "" {
		return "", usage("choose --core ID or an explicitly managed --target")
	}
	return target.ManagedCoreID, nil
}
