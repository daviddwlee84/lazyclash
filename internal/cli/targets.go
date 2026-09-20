package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/spf13/cobra"
)

func targetIndex(cfg config.Config, id string) (int, error) {
	for i := range cfg.Targets {
		if cfg.Targets[i].ID == id {
			return i, nil
		}
	}
	return -1, usage("target %q is not registered", id)
}

func (o *options) targetCommands() *cobra.Command {
	group := &cobra.Command{Use: "targets", Short: "Manage ordered controller targets"}
	group.AddCommand(&cobra.Command{Use: "list", Short: "List saved targets in display order", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _, e := o.load(cmd)
		if e != nil {
			return e
		}
		if o.json {
			return o.output(cmd, cfg)
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "DEFAULT\tID\tNAME\tCONTROLLER\tSSH")
		for _, t := range cfg.Targets {
			d := ""
			if t.ID == cfg.DefaultTarget {
				d = "*"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", d, core.Sanitize(t.ID), core.Sanitize(t.Label()), core.Sanitize(t.Controller), core.Sanitize(t.SSHHost))
		}
		return w.Flush()
	}}, &cobra.Command{Use: "discover", Short: "Find local controllers, or controllers on --ssh HOST", Args: argsExact(0), RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		candidates, e := o.discoverCommand(cmd)
		if e != nil {
			return e
		}
		return o.output(cmd, candidates)
	}}, &cobra.Command{Use: "default ID", Short: "Choose the default target", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, path, e := o.load(cmd)
		if e != nil {
			return e
		}
		if _, e = targetIndex(cfg, args[0]); e != nil {
			return e
		}
		cfg.DefaultTarget = args[0]
		if e = saveSettings(path, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Default target: "+args[0])
	}}, &cobra.Command{Use: "remove ID", Short: "Forget a target without touching its core", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, path, e := o.load(cmd)
		if e != nil {
			return e
		}
		i, e := targetIndex(cfg, args[0])
		if e != nil {
			return e
		}
		cfg.Targets = append(cfg.Targets[:i], cfg.Targets[i+1:]...)
		if cfg.DefaultTarget == args[0] {
			cfg.DefaultTarget = ""
			if len(cfg.Targets) > 0 {
				cfg.DefaultTarget = cfg.Targets[0].ID
			}
		}
		if e = saveSettings(path, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Removed "+args[0])
	}}, &cobra.Command{Use: "move ID [up|down|first|last]", Short: "Reorder a target", Args: argsExact(2), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, path, e := o.load(cmd)
		if e != nil {
			return e
		}
		i, e := targetIndex(cfg, args[0])
		if e != nil {
			return e
		}
		j := i
		switch args[1] {
		case "up":
			if i > 0 {
				j = i - 1
			}
		case "down":
			if i+1 < len(cfg.Targets) {
				j = i + 1
			}
		case "first":
			j = 0
		case "last":
			j = len(cfg.Targets) - 1
		default:
			return usage("position must be up, down, first or last")
		}
		t := cfg.Targets[i]
		cfg.Targets = append(cfg.Targets[:i], cfg.Targets[i+1:]...)
		cfg.Targets = append(cfg.Targets, config.Target{})
		copy(cfg.Targets[j+1:], cfg.Targets[j:])
		cfg.Targets[j] = t
		if e = saveSettings(path, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Moved "+args[0])
	}})
	group.AddCommand(o.targetWriteCommand(false), o.targetWriteCommand(true), o.targetTestCommand(), o.targetDiffCommand(), o.targetCopySettingsCommand())
	return group
}

func (o *options) targetWriteCommand(edit bool) *cobra.Command {
	var draft config.Target
	verb, short := "add", "Register a controller; bare invocation opens a guided prompt"
	if edit {
		verb = "edit"
		short = "Change fields on a saved target"
	}
	cmd := &cobra.Command{Use: verb + " [ID] --controller URL", Short: short, Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("%s accepts one target ID", cmd.CommandPath())
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("secret-file") && cmd.Flags().Changed("secret-env") {
			return usage("--secret-file and --secret-env are mutually exclusive")
		}
		if cmd.Flags().Changed("probe-password-file") && cmd.Flags().Changed("probe-password-env") {
			return usage("--probe-password-file and --probe-password-env are mutually exclusive")
		}
		cfg, path, err := o.load(cmd)
		if err != nil {
			return err
		}
		interactive := !edit && len(args) == 0 && !businessChanged(cmd) && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())
		if interactive {
			var e error
			draft, e = promptTarget(cmd.InOrStdin(), cmd.OutOrStdout(), path)
			if e != nil {
				return e
			}
			if draft.ID == "" {
				return o.result(cmd, "Cancelled")
			}
		} else {
			if len(args) != 1 {
				return usage("supply a target ID and --controller URL; run bare targets add in a terminal for a guided prompt")
			}
			draft.ID = args[0]
		}
		index, findErr := targetIndex(cfg, draft.ID)
		if edit {
			if findErr != nil {
				return findErr
			}
			if !businessChanged(cmd) {
				return usage("supply at least one field to edit, such as --name or --controller")
			}
			previous := cfg.Targets[index]
			oldController, oldSSH := previous.Controller, previous.SSHHost
			for name, dst := range map[string]*string{"name": &previous.Name, "controller": &previous.Controller, "ssh": &previous.SSHHost, "secret-file": &previous.SecretFile, "secret-env": &previous.SecretEnv, "ca-cert": &previous.CAFile, "source-config": &previous.SourceConfig, "probe-proxy": &previous.ProbeProxy, "probe-username": &previous.ProbeUsername, "probe-password-env": &previous.ProbePasswordEnv, "probe-password-file": &previous.ProbePasswordFile, "probe-ca-cert": &previous.ProbeCAFile} {
				if cmd.Flags().Changed(name) {
					*dst, _ = cmd.Flags().GetString(name)
				}
			}
			if cmd.Flags().Changed("secret-file") {
				previous.SecretEnv = ""
			}
			if cmd.Flags().Changed("secret-env") {
				previous.SecretFile = ""
			}
			if cmd.Flags().Changed("probe-password-file") {
				previous.ProbePasswordEnv = ""
			}
			if cmd.Flags().Changed("probe-password-env") {
				previous.ProbePasswordFile = ""
			}
			if !strings.Contains(previous.Controller, "://") {
				previous.Controller = "http://" + previous.Controller
			}
			if previous.TransportOverride || previous.Controller != oldController || previous.SSHHost != oldSSH {
				previous.RuleSource = nil
			}
			previous.TransportOverride = false
			draft = previous
			cfg.Targets[index] = draft
		} else {
			if findErr == nil {
				return usage("target %q already exists; use targets edit", draft.ID)
			}
			if draft.Controller == "" {
				return usage("--controller URL is required")
			}
			cfg.Targets = append(cfg.Targets, draft)
			if cfg.DefaultTarget == "" {
				cfg.DefaultTarget = draft.ID
			}
		}
		if !strings.Contains(draft.Controller, "://") {
			draft.Controller = "http://" + draft.Controller
			if edit {
				cfg.Targets[index] = draft
			} else {
				cfg.Targets[len(cfg.Targets)-1] = draft
			}
		}
		if e := saveSettings(path, cfg); e != nil {
			return e
		}
		return o.result(cmd, "Saved target "+draft.ID)
	}}
	f := cmd.Flags()
	f.StringVar(&draft.Name, "name", "", "display name")
	f.StringVar(&draft.Controller, "controller", "", "controller URL (host:port implies HTTP)")
	f.StringVar(&draft.SSHHost, "ssh", "", "SSH host alias")
	f.StringVar(&draft.SecretFile, "secret-file", "", "secret file path")
	f.StringVar(&draft.SecretEnv, "secret-env", "", "secret environment variable name")
	f.StringVar(&draft.CAFile, "ca-cert", "", "HTTPS CA file")
	f.StringVar(&draft.SourceConfig, "source-config", "", "runtime YAML to read matching controller credentials from")
	f.StringVar(&draft.ProbeProxy, "probe-proxy", "", "explicit HTTP(S)/SOCKS5(H) data proxy URL with port (remote address for SSH targets)")
	f.StringVar(&draft.ProbeUsername, "probe-username", "", "data proxy authentication username")
	f.StringVar(&draft.ProbePasswordEnv, "probe-password-env", "", "environment variable containing the data proxy password")
	f.StringVar(&draft.ProbePasswordFile, "probe-password-file", "", "local file containing the data proxy password")
	f.StringVar(&draft.ProbeCAFile, "probe-ca-cert", "", "local PEM CA for an HTTPS data proxy")
	return cmd
}

func businessChanged(cmd *cobra.Command) bool {
	for _, key := range []string{"name", "controller", "ssh", "secret-file", "secret-env", "ca-cert", "source-config", "probe-proxy", "probe-username", "probe-password-env", "probe-password-file", "probe-ca-cert"} {
		if cmd.Flags().Changed(key) {
			return true
		}
	}
	return false
}

func promptTarget(in io.Reader, out io.Writer, path string) (config.Target, error) {
	r := bufio.NewReader(in)
	read := func(label string) (string, error) {
		fmt.Fprint(out, label)
		s, e := r.ReadString('\n')
		if e != nil {
			return "", e
		}
		return strings.TrimSpace(s), nil
	}
	var t config.Target
	var err error
	fmt.Fprintln(out, "Register an existing core. Leave ID empty to cancel.")
	if t.ID, err = read("Target ID: "); err != nil {
		return t, err
	}
	if t.ID == "" {
		return t, nil
	}
	if t.Controller, err = read("Controller URL: "); err != nil {
		return t, err
	}
	if t.Name, err = read("Display name (optional): "); err != nil {
		return t, err
	}
	if t.SSHHost, err = read("SSH host alias (optional): "); err != nil {
		return t, err
	}
	if t.SecretEnv, err = read("Secret environment variable (optional): "); err != nil {
		return t, err
	}
	if !strings.Contains(t.Controller, "://") {
		t.Controller = "http://" + t.Controller
	}
	if e := config.Validate(config.Config{Targets: []config.Target{t}}); e != nil {
		return t, usage("target: %s", e)
	}
	fmt.Fprintf(out, "Save %s → %s in %s\n", core.Sanitize(t.ID), core.Sanitize(t.Controller), core.Sanitize(path))
	answer, e := read("Save? [y/N]: ")
	if e != nil {
		return t, e
	}
	if strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes" {
		return config.Target{}, nil
	}
	return t, nil
}
