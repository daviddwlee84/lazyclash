package cli

import (
	"fmt"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/spf13/cobra"
)

func (o *options) registered(cmd *cobra.Command) (config.Config, string, int, error) {
	cfg, path, err := o.load(cmd)
	if err != nil {
		return cfg, path, -1, err
	}
	t, _, err := o.choose(cmd, cfg)
	if err != nil {
		return cfg, path, -1, err
	}
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == t.ID {
			return cfg, path, i, nil
		}
	}
	return cfg, path, -1, usage("no registered target selected; use targets add or --target NAME")
}

func (o *options) configCommands() *cobra.Command {
	group := &cobra.Command{Use: "configs", Short: "Register and apply complete core-host YAML files", Long: "Configs are complete YAML files on the core host. Applying one changes runtime settings, not the startup source or a GUI client's profile selection. Relative resources still use the core's existing home directory."}
	group.AddCommand(&cobra.Command{Use: "list", Short: "List YAML files registered for this target", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, i, e := o.registered(cmd)
		if e != nil {
			return e
		}
		return o.output(cmd, cfg.Targets[i].Configs)
	}}, &cobra.Command{Use: "show", Short: "Read general runtime settings (not complete YAML)", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			v, e := c.Config(cmd.Context())
			if e != nil {
				return e
			}
			return o.output(cmd, v)
		})
	}})
	var path, name string
	add := &cobra.Command{Use: "add ID --path /core/host/config.yaml", Short: "Register an existing complete YAML", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if path == "" {
			return usage("--path must name an absolute YAML path on the core host")
		}
		cfg, file, i, e := o.registered(cmd)
		if e != nil {
			return e
		}
		for _, existing := range cfg.Targets[i].Configs {
			if existing.ID == args[0] {
				return usage("config %q already exists", args[0])
			}
		}
		cfg.Targets[i].Configs = append(cfg.Targets[i].Configs, config.CoreConfig{ID: args[0], Name: name, Path: path})
		if e = saveSettings(file, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Registered "+args[0]+" on "+cfg.Targets[i].ID)
	}}
	add.Flags().StringVar(&path, "path", "", "absolute path readable by the core, subject to its SAFE_PATHS")
	add.Flags().StringVar(&name, "name", "", "display name")
	group.AddCommand(add, &cobra.Command{Use: "remove ID", Short: "Remove a registration without deleting its YAML file", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, file, i, e := o.registered(cmd)
		if e != nil {
			return e
		}
		found := -1
		for j, c := range cfg.Targets[i].Configs {
			if c.ID == args[0] {
				found = j
				break
			}
		}
		if found < 0 {
			return usage("config %q is not registered", args[0])
		}
		cfg.Targets[i].Configs = append(cfg.Targets[i].Configs[:found], cfg.Targets[i].Configs[found+1:]...)
		if e = saveSettings(file, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Removed registration "+args[0])
	}})
	var yes bool
	apply := &cobra.Command{Use: "apply ID --yes", Short: "Apply a registered YAML to runtime; does not change the startup source", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		if e := o.writable(); e != nil {
			return e
		}
		cfg, _, i, e := o.registered(cmd)
		if e != nil {
			return e
		}
		var selected *config.CoreConfig
		for _, item := range cfg.Targets[i].Configs {
			if item.ID == args[0] {
				v := item
				selected = &v
				break
			}
		}
		if selected == nil {
			return usage("config %q is not registered for %s", args[0], cfg.Targets[i].ID)
		}
		if !yes {
			return usage("applying %s on %s can change proxy ports, DNS, rules and TUN; pass --yes (startup source and Verge profile stay unchanged)", core.Sanitize(selected.Path), cfg.Targets[i].ID)
		}
		return o.withClient(cmd, func(c *core.Client, t config.Target) error {
			v, err := c.ApplyConfig(cmd.Context(), selected.Path)
			if err != nil {
				return err
			}
			return o.output(cmd, core.Object{"target": t.ID, "last_confirmed_apply": selected.Path, "applied_at": time.Now().UTC().Format(time.RFC3339), "runtime": v, "note": "Runtime apply only; not authoritative active-profile state. Startup source and GUI profile are unchanged."})
		})
	}}
	apply.Flags().BoolVar(&yes, "yes", false, "confirm applying runtime configuration to the selected target")
	group.AddCommand(apply)
	return group
}

func (o *options) settingsCommand() *cobra.Command {
	group := &cobra.Command{Use: "settings", Short: "Inspect lazyclash preferences"}
	group.AddCommand(&cobra.Command{Use: "show", Short: "Show redacted saved settings", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, path, e := o.load(cmd)
		if e != nil {
			return e
		}
		return o.output(cmd, map[string]any{"path": path, "settings": cfg})
	}}, &cobra.Command{Use: "path", Short: "Print the settings path", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		_, path, e := o.load(cmd)
		if e != nil {
			return e
		}
		_, e = fmt.Fprintln(cmd.OutOrStdout(), path)
		return e
	}})
	return group
}
