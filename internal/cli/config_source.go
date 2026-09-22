package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (o *options) configWorkOptions(cmd *cobra.Command) configwork.Options {
	return configwork.Options{ReadOnly: o.readOnly, ClientServices: o.clientServiceOptions(), Open: o.deps.Open, Host: func(ctx context.Context, t config.Target, req configwork.HostRequest) (configwork.HostResponse, error) {
		if t.ManagedCoreID != "" {
			return managedcore.SourceOperation(ctx, t, req, o.managedOptions(cmd))
		}
		return configwork.DefaultHostOperation(ctx, t, req)
	}}
}
func (o *options) configWorkTarget(cmd *cobra.Command) (config.Target, error) {
	if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
		return config.Target{}, usage("source edits require a saved endpoint/SSH host; save and bind that target first")
	}
	cfg, _, i, e := o.registered(cmd)
	if e != nil {
		return config.Target{}, e
	}
	return o.overrideCredentials(cfg.Targets[i]), nil
}
func (o *options) sourceInteractive(cmd *cobra.Command, explicit, bare bool) (bool, error) {
	if explicit && (o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
		return false, usage("--interactive requires a terminal and cannot use --json")
	}
	return explicit || (bare && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())), nil
}
func (o *options) configSourceCommand() *cobra.Command {
	parent := &cobra.Command{Use: "source", Short: "Bind the persistent owner for nodes and groups (independent of rule repair)"}
	parent.AddCommand(&cobra.Command{Use: "show", Short: "Show and inspect the explicit node/group owner", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		t, e := o.configWorkTarget(cmd)
		if e != nil {
			return e
		}
		if t.ConfigSource == nil {
			return o.output(cmd, map[string]any{"target_id": t.ID, "config_source": nil})
		}
		var catalog configwork.Catalog
		e = o.authenticatedDiagnostic(cmd, t, func() error {
			var err error
			catalog, err = configwork.Inspect(cmd.Context(), t, o.configWorkOptions(cmd))
			return err
		})
		if e != nil {
			return e
		}
		return o.output(cmd, map[string]any{"target_id": t.ID, "config_source": t.ConfigSource, "catalog": catalog})
	}}, &cobra.Command{Use: "clear", Short: "Remove the node/group write binding without editing any source", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, path, i, e := o.registered(cmd)
		if e != nil {
			return e
		}
		cfg.Targets[i].ConfigSource = nil
		if e = saveSettings(path, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Node/group source unbound")
	}})
	var s config.ConfigSource
	var interactive bool
	set := &cobra.Command{Use: "set", Short: "Bind native, Docker or existing Verge 2.5.2 source companions", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		if globalChanged(cmd, "controller") || globalChanged(cmd, "ssh") {
			return usage("source binding requires the saved target endpoint and SSH host")
		}
		bare := true
		cmd.LocalNonPersistentFlags().Visit(func(f *pflag.Flag) {
			if f.Name != "interactive" {
				bare = false
			}
		})
		ui, e := o.sourceInteractive(cmd, interactive, bare)
		if e != nil {
			return e
		}
		cfg, path, i, e := o.registered(cmd)
		if e != nil {
			return e
		}
		if ui {
			kind := s.Kind
			if kind == "" {
				kind, e = wizard.Choose(cmd.Context(), "Persistent node/group owner", []wizard.Choice{{Value: "native", Label: "Standalone Mihomo"}, {Value: "docker", Label: "Docker bind-mounted configuration"}, {Value: "verge", Label: "Clash Verge Rev 2.5.2"}}, cmd.InOrStdin(), cmd.OutOrStdout())
				if e != nil {
					return e
				}
			}
			s.Kind = kind
			fields := []wizard.Field{}
			switch kind {
			case "native", "mihomo":
				fields = []wizard.Field{{Key: "config_id", Label: "Registered config ID", Value: s.ConfigID, Required: true}, {Key: "binary", Label: "Core-host validator binary", Value: s.Binary, Required: true}, {Key: "home", Label: "Core-host Mihomo home", Value: s.Home, Required: true}, {Key: "validation_docker_host", Label: "Optional validation Docker unix socket", Value: s.ValidationDockerHost}, {Key: "validation_image", Label: "Validation local image SHA256 (required with socket)", Value: s.ValidationImage}}
			case "docker":
				fields = []wizard.Field{{Key: "docker_host", Label: "Docker daemon unix socket (on selected host)", Value: s.DockerHost}, {Key: "container", Label: "Container ID or name", Value: s.Container, Required: true}, {Key: "host_path", Label: "Host-side bound YAML path", Value: s.HostPath, Required: true}, {Key: "core_path", Label: "Container-side YAML path", Value: s.CorePath, Required: true}, {Key: "binary", Label: "Binary inside container", Value: s.Binary, Required: true}, {Key: "home", Label: "Mihomo home inside container", Value: s.Home, Required: true}}
			case "verge":
				fields = []wizard.Field{{Key: "data_dir", Label: "Verge data directory", Value: s.DataDir, Required: true}, {Key: "profile", Label: "Current profile UID", Value: s.ProfileUID, Required: true}, {Key: "version", Label: "Declared owner version", Value: "2.5.2", Required: true}, {Key: "binary", Label: "Optional actual Mihomo validator binary", Value: s.Binary}, {Key: "home", Label: "Validator resources home (required with binary)", Value: s.Home}}
			default:
				return usage("invalid source kind")
			}
			description := "This binding permits persistent node/group source edits. Credential discovery and rules have separate bindings."
			for {
				values, err := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Bind source", Description: description, SubmitLabel: "Inspect source", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				for j := range fields {
					fields[j].Value = values[fields[j].Key]
				}
				s.ConfigID = values["config_id"]
				s.HostPath = values["host_path"]
				s.CorePath = values["core_path"]
				s.Binary = values["binary"]
				s.Home = values["home"]
				s.Container = values["container"]
				s.DockerHost = values["docker_host"]
				s.ValidationDockerHost = values["validation_docker_host"]
				s.ValidationImage = values["validation_image"]
				s.DataDir = values["data_dir"]
				s.ProfileUID = values["profile"]
				s.Version = values["version"]
				candidate := cfg.Targets[i]
				candidate.ConfigSource = &s
				if err = config.ValidateConfigSource(candidate); err != nil {
					description = err.Error()
					continue
				}
				var catalog configwork.Catalog
				err = o.authenticatedDiagnostic(cmd, candidate, func() error {
					var e error
					catalog, e = configwork.Inspect(cmd.Context(), candidate, o.configWorkOptions(cmd))
					return e
				})
				if err != nil {
					description = err.Error()
					continue
				}
				accepted, err := wizard.Confirm(cmd.Context(), "Bind persistent source", fmt.Sprintf("Target: %s\nOwner: %s\nFiles: %v\n%s", candidate.ID, s.Kind, catalog.Files, strings.Join(catalog.Warnings, "\n")), cmd.InOrStdin(), cmd.OutOrStdout())
				if err != nil {
					return err
				}
				if !accepted {
					return wizard.ErrCanceled
				}
				break
			}
		}
		cfg.Targets[i].ConfigSource = &s
		if e = config.ValidateConfigSource(cfg.Targets[i]); e != nil {
			return usage("%s", e)
		}
		if !ui {
			e = o.authenticatedDiagnostic(cmd, cfg.Targets[i], func() error {
				_, err := configwork.Inspect(cmd.Context(), cfg.Targets[i], o.configWorkOptions(cmd))
				return err
			})
			if e != nil {
				return e
			}
		}
		if e = saveSettings(path, cfg); e != nil {
			return e
		}
		return o.output(cmd, map[string]any{"target_id": cfg.Targets[i].ID, "config_source": s})
	}}
	set.Flags().StringVar(&s.Kind, "kind", "", "native, docker or verge")
	set.Flags().StringVar(&s.ConfigID, "config-id", "", "registered complete YAML ID (native)")
	set.Flags().StringVar(&s.HostPath, "host-path", "", "host path corresponding to a Docker bind mount")
	set.Flags().StringVar(&s.CorePath, "core-path", "", "container config path used for API reload")
	set.Flags().StringVar(&s.DockerHost, "docker-host", "", "explicit unix:///path Docker socket on the selected host")
	set.Flags().StringVar(&s.ValidationDockerHost, "validation-docker-host", "", "explicit local unix socket for isolated native core validation")
	set.Flags().StringVar(&s.ValidationImage, "validation-image", "", "full sha256 ID of an already present validation image (native only; no pulls)")
	set.Flags().StringVar(&s.Container, "container", "", "explicit Docker container ID/name")
	set.Flags().StringVar(&s.Binary, "binary", "", "absolute validator binary (inside container for Docker)")
	set.Flags().StringVar(&s.Home, "home", "", "absolute core home (inside container for Docker)")
	set.Flags().StringVar(&s.DataDir, "data-dir", "", "absolute Verge data directory")
	set.Flags().StringVar(&s.ProfileUID, "profile", "", "current Verge profile UID")
	set.Flags().StringVar(&s.Version, "owner-version", "", "supported Verge compatibility version: 2.5.2")
	set.Flags().BoolVar(&interactive, "interactive", false, "open a prefilled owner-binding wizard")
	parent.AddCommand(set)
	return parent
}
func (o *options) configWorkCommands() []*cobra.Command {
	verify := &cobra.Command{Use: "verify RECEIPT", Short: "Verify persisted node/group bytes and owner/runtime observations", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		t, e := o.configWorkTarget(cmd)
		if e != nil {
			return e
		}
		var r configwork.Receipt
		e = o.authenticatedDiagnostic(cmd, t, func() error {
			var err error
			r, err = configwork.Verify(cmd.Context(), t, args[0], o.configWorkOptions(cmd))
			return err
		})
		if r.ID != "" {
			if err := o.output(cmd, r); err != nil {
				return err
			}
		}
		return e
	}}
	var yes bool
	restore := &cobra.Command{Use: "restore RECEIPT --yes", Short: "Restore source backups if current bytes still belong to this receipt", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if !yes {
			return usage("restore requires --yes")
		}
		if e := o.writable(); e != nil {
			return e
		}
		t, e := o.configWorkTarget(cmd)
		if e != nil {
			return e
		}
		e = o.authenticatedDiagnostic(cmd, t, func() error { _, err := configwork.Inspect(cmd.Context(), t, o.configWorkOptions(cmd)); return err })
		if e != nil {
			return e
		}
		r, e := configwork.Restore(cmd.Context(), t, args[0], o.configWorkOptions(cmd))
		if r.ID != "" {
			if err := o.output(cmd, r); err != nil {
				return err
			}
		}
		return e
	}}
	restore.Flags().BoolVar(&yes, "yes", false, "restore the reviewed private source backup")
	return []*cobra.Command{o.configSourceCommand(), verify, restore}
}
