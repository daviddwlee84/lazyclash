package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const completionMarker = "# Managed by lazyclash completion install zsh"

type completionStatus struct {
	Path       string `json:"path"`
	State      string `json:"state"`
	Activation string `json:"activation"`
	Setup      string `json:"setup"`
}

func (o *options) completionCommand(root *cobra.Command) *cobra.Command {
	group := &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Short: "Generate, install or inspect shell completion", Args: argsExact(1), ValidArgs: []string{"bash", "zsh", "fish", "powershell"}, RunE: func(cmd *cobra.Command, args []string) error {
		if o.json {
			return usage("raw completion scripts cannot be combined with --json")
		}
		switch args[0] {
		case "bash":
			return root.GenBashCompletion(cmd.OutOrStdout())
		case "zsh":
			return root.GenZshCompletion(cmd.OutOrStdout())
		case "fish":
			return root.GenFishCompletion(cmd.OutOrStdout(), true)
		case "powershell":
			return root.GenPowerShellCompletion(cmd.OutOrStdout())
		default:
			return usage("unsupported shell %q", args[0])
		}
	}}
	for _, verb := range []string{"install", "status"} {
		var dir string
		var force bool
		child := &cobra.Command{Use: verb + " zsh", Short: strings.Title(verb) + " a user zsh completion script", Args: argsExact(1), ValidArgs: []string{"zsh"}, RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "zsh" {
				return usage("completion %s currently supports zsh", verb)
			}
			path, e := completionPath(dir)
			if e != nil {
				return e
			}
			var raw bytes.Buffer
			if e = root.GenZshCompletion(&raw); e != nil {
				return e
			}
			script := []byte("#compdef lazyclash\n" + completionMarker + "\n" + raw.String())
			state, old, e := inspectCompletion(path, script)
			if e != nil {
				return e
			}
			result := completionStatus{Path: path, State: state, Activation: "unknown: the parent shell must load completion", Setup: "fpath=(" + zshQuote(filepath.Dir(path)) + " $fpath)\n# Place fpath before your framework's compinit; without a framework:\nautoload -Uz compinit && compinit"}
			if verb == "install" && state != "current" {
				if state == "foreign" && !force {
					return usage("%s is not managed by lazyclash; review it before using --force", path)
				}
				if e = writeCompletion(path, script, old); e != nil {
					return e
				}
				result.State = "current"
			}
			if o.json {
				return o.output(cmd, result)
			}
			_, e = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\nShell activation: %s\n%s\n", result.State, result.Path, result.Activation, result.Setup)
			return e
		}}
		child.Flags().StringVar(&dir, "dir", "", "directory on zsh fpath (default: XDG data/lazyclash/completions/zsh)")
		if verb == "install" {
			child.Flags().BoolVar(&force, "force", false, "replace an existing foreign regular file")
		}
		group.AddCommand(child)
	}
	return group
}

func completionPath(dir string) (string, error) {
	if dir == "" {
		base := os.Getenv("XDG_DATA_HOME")
		if !filepath.IsAbs(base) {
			home, e := os.UserHomeDir()
			if e != nil || !filepath.IsAbs(home) {
				return "", fmt.Errorf("cannot determine home directory for lazyclash completion")
			}
			base = filepath.Join(home, ".local", "share")
		}
		dir = filepath.Join(base, "lazyclash", "completions", "zsh")
	}
	dir, e := filepath.Abs(dir)
	if e != nil {
		return "", e
	}
	return filepath.Join(dir, "_lazyclash"), nil
}
func zshQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

type completionFile struct {
	data []byte
	info os.FileInfo
}

func inspectCompletion(path string, want []byte) (string, completionFile, error) {
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return "missing", completionFile{}, nil
	}
	if e != nil {
		return "", completionFile{}, e
	}
	if !info.Mode().IsRegular() {
		return "", completionFile{}, fmt.Errorf("completion destination must be a regular file: %s", path)
	}
	if info.Size() > 2<<20 {
		return "", completionFile{}, fmt.Errorf("completion destination is unexpectedly large")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", completionFile{}, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !sameCompletionFile(info, opened) {
		return "", completionFile{}, config.ErrConflict
	}
	old, e := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if e != nil {
		return "", completionFile{}, e
	}
	after, e := os.Lstat(path)
	if e != nil || !sameCompletionFile(info, after) || len(old) > 2<<20 {
		return "", completionFile{}, config.ErrConflict
	}
	snapshot := completionFile{data: old, info: info}
	if bytes.Equal(old, want) {
		return "current", snapshot, nil
	}
	if bytes.HasPrefix(old, []byte("#compdef lazyclash\n"+completionMarker+"\n")) {
		return "outdated", snapshot, nil
	}
	return "foreign", snapshot, nil
}
func sameCompletionFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func writeCompletion(path string, script []byte, old completionFile) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".lazyclash-completion-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(script); e == nil {
		e = f.Chmod(0644)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	_, current, e := inspectCompletion(path, script)
	if e != nil {
		return e
	}
	if (current.info == nil) != (old.info == nil) || current.info != nil && !sameCompletionFile(current.info, old.info) || !bytes.Equal(current.data, old.data) {
		return config.ErrConflict
	}
	return os.Rename(f.Name(), path)
}

// Completion reads only local registrations. It never discovers controllers,
// resolves credentials, opens SSH, or changes settings.
func (o *options) registerCompletions(root *cobra.Command) {
	values := func(items ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return items, cobra.ShellCompDirectiveNoFileComp
		}
	}
	local := func(kind string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return func(cmd *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			cfg, _, e := o.load(cmd)
			if e != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var result []string
			selected := o.savedCompletionTarget(cmd, cfg)
			for _, t := range cfg.Targets {
				switch kind {
				case "targets":
					result = append(result, t.ID)
				case "ssh":
					if t.SSHHost != "" {
						result = append(result, t.SSHHost)
					}
				case "configs":
					if t.ID == selected {
						for _, c := range t.Configs {
							result = append(result, c.ID)
						}
					}
				}
			}
			sort.Strings(result)
			var unique []string
			for _, v := range result {
				if len(unique) == 0 || unique[len(unique)-1] != v {
					unique = append(unique, v)
				}
			}
			return unique, cobra.ShellCompDirectiveNoFileComp
		}
	}
	_ = root.RegisterFlagCompletionFunc("target", local("targets"))
	_ = root.RegisterFlagCompletionFunc("ssh", local("ssh"))
	_ = root.RegisterFlagCompletionFunc("page", values("overview", "proxies", "connections", "logs", "rules", "providers", "configs"))
	for _, name := range []string{"config", "secret-file", "ca-cert"} {
		_ = root.MarkPersistentFlagFilename(name)
	}
	_ = root.RegisterFlagCompletionFunc("secret-env", values())
	_ = root.RegisterFlagCompletionFunc("controller", values())
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.ValidArgsFunction == nil && len(cmd.ValidArgs) == 0 {
			cmd.ValidArgsFunction = cobra.NoFileCompletions
		}
		path := strings.TrimPrefix(cmd.CommandPath(), "lazyclash ")
		switch path {
		case "mode":
			cmd.ValidArgsFunction = values("rule", "global", "direct")
		case "tun", "allow-lan":
			cmd.ValidArgsFunction = values("on", "off")
		case "targets edit", "targets remove", "targets default", "targets test", "targets diff", "targets copy-settings":
			cmd.ValidArgsFunction = local("targets")
		case "targets move":
			cmd.ValidArgsFunction = func(c *cobra.Command, a []string, s string) ([]string, cobra.ShellCompDirective) {
				if len(a) == 0 {
					return local("targets")(c, a, s)
				}
				if len(a) == 1 {
					return values("up", "down", "first", "last")(c, a, s)
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		case "configs remove", "configs apply":
			cmd.ValidArgsFunction = local("configs")
		case "providers list", "providers update":
			cmd.ValidArgsFunction = func(_ *cobra.Command, a []string, _ string) ([]string, cobra.ShellCompDirective) {
				if len(a) == 0 {
					return []string{"proxies", "rules"}, cobra.ShellCompDirectiveNoFileComp
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		}
		for _, name := range []string{"level", "log-level"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.RegisterFlagCompletionFunc(name, values("debug", "info", "warning", "error", "silent"))
			}
		}
		if cmd.Flags().Lookup("kind") != nil {
			_ = cmd.RegisterFlagCompletionFunc("kind", values("mihomo", "verge"))
		}
		if cmd.Flags().Lookup("owner-version") != nil {
			_ = cmd.RegisterFlagCompletionFunc("owner-version", values("2.5.2"))
		}
		if cmd.Flags().Lookup("field") != nil {
			_ = cmd.RegisterFlagCompletionFunc("field", values("mode", "log-level"))
		}
		if cmd.Flags().Lookup("config-id") != nil {
			_ = cmd.RegisterFlagCompletionFunc("config-id", local("configs"))
		}
		for _, name := range []string{"dir", "data-dir"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.MarkFlagDirname(name)
			}
		}
		for _, name := range []string{"secret-file", "ca-cert", "probe-password-file", "probe-ca-cert"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.MarkFlagFilename(name)
			}
		}
		for _, name := range []string{"via", "group", "probe-proxy", "probe-username", "probe-password-env", "source-config", "path", "binary", "home", "profile"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.RegisterFlagCompletionFunc(name, values())
			}
		}
		// Unknown value kinds must not fall back to arbitrary local filenames.
		// Preserve explicit path annotations and the registered offline providers.
		for _, flags := range []*pflag.FlagSet{cmd.LocalNonPersistentFlags(), cmd.PersistentFlags()} {
			flags.VisitAll(func(flag *pflag.Flag) {
				if flag.NoOptDefVal != "" {
					return
				}
				if _, ok := flag.Annotations[cobra.BashCompFilenameExt]; ok {
					return
				}
				if _, ok := flag.Annotations[cobra.BashCompSubdirsInDir]; ok {
					return
				}
				if _, ok := cmd.GetFlagCompletionFunc(flag.Name); !ok {
					_ = cmd.RegisterFlagCompletionFunc(flag.Name, values())
				}
			})
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(root)
}

// Mirror target selection precedence without resolving credentials or creating
// a transient target. Config registrations belong only to a saved target.
func (o *options) savedCompletionTarget(cmd *cobra.Command, cfg config.Config) string {
	if globalChanged(cmd, "controller") {
		return ""
	}
	selected := o.target
	if !globalChanged(cmd, "target") {
		selected = os.Getenv("LAZYCLASH_TARGET")
		endpoint := os.Getenv("LAZYCLASH_CONTROLLER")
		if selected == "" && endpoint == "" {
			endpoint = os.Getenv("CLASH_CONTROLLER")
		}
		if endpoint != "" {
			return ""
		}
	}
	if selected == "" {
		selected = cfg.DefaultTarget
	}
	if selected == "" && len(cfg.Targets) > 0 {
		selected = cfg.Targets[0].ID
	}
	return selected
}
