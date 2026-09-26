package cli

import (
	"context"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
	"github.com/spf13/cobra"
	"strings"
)

func (o *options) ruleOptions(cmd *cobra.Command) rulework.Options {
	return rulework.Options{ReadOnly: o.readOnly, Open: o.deps.Open, ClientServices: o.deps.ClientServices,
		Host: func(ctx context.Context, target config.Target, request rulework.HostRequest) (rulework.HostFile, error) {
			operation := configwork.HostRequest{Op: request.Op, Path: request.Path, Data: request.Data, Guards: request.Guards, Binary: request.Binary, Home: request.Home, Version: request.Version, Document: request.Document, ValidationDockerHost: request.ValidationDockerHost, ValidationImage: request.ValidationImage}
			if target.ManagedCoreID != "" {
				result, err := managedcore.RuleSourceOperation(ctx, target, operation, o.managedOptions(cmd))
				return result.File, err
			}
			result, err := configwork.DefaultHostOperation(ctx, target, operation)
			return result.File, err
		},
		Docker: func(ctx context.Context, target config.Target, request rulework.DockerRequest) (rulework.DockerInfo, error) {
			if target.ManagedCoreID == "" {
				return sourceowner.DockerOperation(ctx, target.SSHHost, request)
			}
			operation := configwork.HostRequest{Op: "docker-" + request.Op, Container: request.Container, HostPath: request.HostPath, CorePath: request.CorePath, Binary: request.Binary, Home: request.Home, Version: request.Version, Document: request.Document}
			result, err := managedcore.RuleSourceOperation(ctx, target, operation, o.managedOptions(cmd))
			return rulework.DockerInfo{ContainerID: result.ContainerID, Image: result.Image, SourceSHA256: result.SourceSHA256, SingleFile: result.SingleFile}, err
		},
		ActivateOwner: func(ctx context.Context, target config.Target) error {
			return managedcore.ActivateSource(ctx, target, o.managedOptions(cmd))
		},
	}
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
	var fromConfig bool
	set := &cobra.Command{Use: "set --kind mihomo|docker|verge", Short: "Bind an existing persistent rule owner, or explicitly reuse --from-config-source", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if err := o.writable(); err != nil {
			return err
		}
		if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
			return usage("rule source binding requires the registered endpoint and SSH host")
		}
		cfg, path, i, err := o.registered(cmd)
		if err != nil {
			return err
		}
		if fromConfig {
			for _, name := range []string{"kind", "config-id", "binary", "home", "data-dir", "profile", "owner-version", "host-path", "core-path", "container", "docker-host", "validation-docker-host", "validation-image"} {
				if cmd.Flags().Changed(name) {
					return usage("--from-config-source cannot be combined with --%s", name)
				}
			}
			copied, e := config.RuleSourceFromConfigSource(cfg.Targets[i])
			if e != nil {
				return e
			}
			binding = *copied
		}
		cfg.Targets[i].RuleSource = &binding
		if err = config.ValidateRuleSource(cfg.Targets[i]); err != nil {
			return usage("%s", err)
		}
		var owner rulework.Source
		err = o.authenticatedDiagnostic(cmd, cfg.Targets[i], func() error {
			var e error
			owner, e = rulework.InspectSourceWithOptions(cmd.Context(), cfg.Targets[i], o.ruleOptions(cmd))
			return e
		})
		if err != nil {
			return err
		}
		if err = saveSettings(path, cfg); err != nil {
			return err
		}
		return o.output(cmd, map[string]any{"target_id": cfg.Targets[i].ID, "rule_source": binding, "owner": owner})
	}}
	set.Flags().BoolVar(&fromConfig, "from-config-source", false, "inspect and copy the node/group source into an independent rule binding")
	set.Flags().StringVar(&binding.Kind, "kind", "", "persistent owner: mihomo, docker or verge")
	set.Flags().StringVar(&binding.Version, "owner-version", "", "declared Verge compatibility version (supported: 2.5.2)")
	set.Flags().StringVar(&binding.ConfigID, "config-id", "", "registered standalone config ID")
	set.Flags().StringVar(&binding.Binary, "binary", "", "absolute Mihomo validator binary on the core host")
	set.Flags().StringVar(&binding.Home, "home", "", "absolute existing Mihomo home for copying validation resources")
	set.Flags().StringVar(&binding.DataDir, "data-dir", "", "absolute Clash Verge data directory on the target host")
	set.Flags().StringVar(&binding.ProfileUID, "profile", "", "explicit current Verge profile UID")
	set.Flags().StringVar(&binding.HostPath, "host-path", "", "host-side absolute YAML path of the Docker bind mount")
	set.Flags().StringVar(&binding.CorePath, "core-path", "", "absolute config path inside the container")
	set.Flags().StringVar(&binding.Container, "container", "", "existing Docker container name")
	set.Flags().StringVar(&binding.DockerHost, "docker-host", "", "Docker daemon unix socket on the selected host")
	set.Flags().StringVar(&binding.ValidationDockerHost, "validation-docker-host", "", "optional native validation sandbox Docker socket")
	set.Flags().StringVar(&binding.ValidationImage, "validation-image", "", "pinned sha256 image ID for the native validation sandbox")
	source.AddCommand(set)
	verify := &cobra.Command{Use: "verify RECEIPT", Short: "Verify persistent bytes and the first runtime rule after owner reload", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		t, err := o.ruleTarget(cmd)
		if err != nil {
			return err
		}
		var r rulework.Receipt
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			var e error
			r, e = rulework.Verify(cmd.Context(), t, args[0], o.ruleOptions(cmd))
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
		err = o.authenticatedDiagnostic(cmd, t, func() error {
			_, e := rulework.InspectSourceWithOptions(cmd.Context(), t, o.ruleOptions(cmd))
			return e
		})
		if err != nil {
			return err
		}
		r, err := rulework.Restore(cmd.Context(), t, args[0], o.ruleOptions(cmd))
		if r.ID != "" {
			if e := o.output(cmd, r); e != nil {
				return e
			}
		}
		return err
	}}
	restore.Flags().BoolVar(&restoreYes, "yes", false, "restore this receipt's original source and reload standalone runtime")
	return []*cobra.Command{source, o.ruleAddCommand(false), o.ruleAddCommand(true), verify, restore}
}

func (o *options) ruleAddCommand(ip bool) *cobra.Command {
	var policy, expected string
	flag, use, short, help := "via", "add-domain HOST --via POLICY", "Preview an exact DOMAIN rule; apply with --yes --expect DIGEST", "existing outbound/group to use for this hostname"
	preview, apply := rulework.Preview, rulework.Apply
	if ip {
		flag, use, short, help = "policy", "add-ip IP_OR_CIDR --policy POLICY", "Preview a canonical IP-CIDR/IP-CIDR6 rule with no-resolve; apply with --yes --expect DIGEST", "existing outbound/group to use for this IP prefix"
		preview, apply = rulework.PreviewIP, rulework.ApplyIP
	}
	var yes bool
	add := &cobra.Command{Use: use, Short: short, Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if strings.Contains(args[0], ",") || strings.HasPrefix(strings.TrimSpace(args[0]), "- ") {
			value := "a hostname"
			if ip {
				value = "an IP address or prefix"
			}
			return usage("%s accepts %s, not a complete rule; use rules apply --dry-run -- %s (keep your --target selection)", cmd.Name(), value, "'"+strings.ReplaceAll(args[0], "'", "'\"'\"'")+"'")
		}
		if policy == "" {
			return usage("--%s must select an existing proxy or group", flag)
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
				plan, e = preview(cmd.Context(), t, args[0], policy, o.ruleOptions(cmd))
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
			checked, e = preview(cmd.Context(), t, args[0], policy, o.ruleOptions(cmd))
			return e
		})
		if err != nil {
			return err
		}
		if checked.Digest != expected {
			return usage("rule preview changed; review a new preview before applying")
		}
		receipt, err := apply(cmd.Context(), t, args[0], policy, expected, o.ruleOptions(cmd))
		if receipt.ID != "" {
			if e := o.output(cmd, receipt); e != nil {
				return e
			}
		}
		return err
	}}
	add.Flags().StringVar(&policy, flag, "", help)
	add.Flags().BoolVar(&yes, "yes", false, "apply the reviewed persistent rule edit")
	add.Flags().StringVar(&expected, "expect", "", "digest of the reviewed source and proposed rule")
	return add
}
