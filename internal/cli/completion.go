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
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
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
				case "cores":
					if t.ManagedCoreID != "" {
						result = append(result, t.ManagedCoreID)
					}
				case "configs":
					if t.ID == selected {
						for _, c := range t.Configs {
							result = append(result, c.ID)
						}
					}
				case "checks":
					if t.ID == selected {
						for _, check := range t.Checks {
							result = append(result, check.ID)
						}
					}
				}
			}
			if kind == "cores" {
				if instances, err := managedcore.List(managedcore.Options{}); err == nil {
					for _, instance := range instances {
						if !instance.Removed {
							result = append(result, instance.ID)
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
	serverIDs := func(hosts bool) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			store, err := o.serverStore(cmd)
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			inv, err := store.Load()
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var ids []string
			if hosts {
				for _, h := range inv.Hosts {
					ids = append(ids, h.ID)
				}
			} else {
				for _, d := range inv.Deployments {
					ids = append(ids, d.ID)
				}
			}
			sort.Strings(ids)
			return ids, cobra.ShellCompDirectiveNoFileComp
		}
	}
	tailnetIDs := func(proxies bool) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			store, err := o.serverStore(cmd)
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			inv, err := store.Load()
			if err != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var ids []string
			if proxies {
				for _, p := range inv.TailnetProxies {
					ids = append(ids, p.ID)
				}
			} else {
				for _, n := range inv.TailnetNodes {
					ids = append(ids, n.ID)
				}
			}
			sort.Strings(ids)
			return ids, cobra.ShellCompDirectiveNoFileComp
		}
	}
	for _, name := range []string{"config", "secret-file", "ca-cert", "servers-config"} {
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
		case "targets edit", "targets remove", "targets default", "targets test", "targets diff", "targets copy-settings", "targets service", "targets service bind", "targets service status", "targets service start", "targets service stop", "targets service restart", "targets service enable", "targets service disable":
			cmd.ValidArgsFunction = local("targets")
		case "rules diff":
			cmd.ValidArgsFunction = func(c *cobra.Command, a []string, s string) ([]string, cobra.ShellCompDirective) {
				if len(a) < 2 {
					return local("targets")(c, a, s)
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
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
		case "proxy shell-init":
			cmd.ValidArgsFunction = values("bash", "zsh")
		case "proxy ssh", "proxy tunnel share":
			cmd.ValidArgsFunction = func(c *cobra.Command, a []string, s string) ([]string, cobra.ShellCompDirective) {
				if len(a) == 0 {
					return local("ssh")(c, a, s)
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		case "proxy tunnel start":
			cmd.ValidArgsFunction = func(c *cobra.Command, a []string, s string) ([]string, cobra.ShellCompDirective) {
				if len(a) == 0 {
					return local("targets")(c, a, s)
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		case "cores status", "cores start", "cores stop", "cores restart", "cores configure", "cores remove":
			cmd.ValidArgsFunction = local("cores")
		case "servers status", "servers start", "servers stop", "servers restart", "servers remove", "servers resume", "servers export", "servers connect", "servers manage", "servers usage":
			cmd.ValidArgsFunction = serverIDs(false)
		case "tailnet exit export", "tailnet exit status", "tailnet exit enable", "tailnet exit disable", "tailnet exit remove", "tailnet exit use", "tailnet exit manage":
			cmd.ValidArgsFunction = tailnetIDs(false)
		case "tailnet proxy status", "tailnet proxy configure", "tailnet proxy start", "tailnet proxy stop", "tailnet proxy restart", "tailnet proxy remove", "tailnet proxy export", "tailnet proxy connect", "tailnet proxy manage":
			cmd.ValidArgsFunction = tailnetIDs(true)
		case "vps status", "vps start", "vps stop", "vps reboot", "vps delete", "vps resume", "vps manage", "vps usage", "vps bind-cloud":
			cmd.ValidArgsFunction = serverIDs(true)
		case "diagnostics checks run", "diagnostics checks remove":
			cmd.ValidArgsFunction = local("checks")
		case "proxies copy":
			cmd.ValidArgsFunction = func(c *cobra.Command, a []string, s string) ([]string, cobra.ShellCompDirective) {
				if len(a) < 2 && !globalChanged(c, "target") {
					return local("targets")(c, a, s)
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		case "rules preset apply":
			cmd.ValidArgsFunction = values("cn-split", "simple")
		case "providers list", "providers update":
			cmd.ValidArgsFunction = func(_ *cobra.Command, a []string, _ string) ([]string, cobra.ShellCompDirective) {
				if len(a) == 0 {
					return []string{"proxies", "rules"}, cobra.ShellCompDirectiveNoFileComp
				}
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
		}
		if cmd.LocalNonPersistentFlags().Lookup("ssh") != nil {
			_ = cmd.RegisterFlagCompletionFunc("ssh", local("ssh"))
		}
		if strings.HasPrefix(path, "rules ") && cmd.Flags().Lookup("scope") != nil {
			_ = cmd.RegisterFlagCompletionFunc("scope", values("both", "runtime", "source"))
		}
		if path == "servers deploy" {
			_ = cmd.RegisterFlagCompletionFunc("host", serverIDs(true))
			_ = cmd.RegisterFlagCompletionFunc("recipe", values("vless-reality", "hysteria2", "legacy-vmess-ws-tls"))
		}
		if strings.HasPrefix(path, "tailnet proxy ") {
			if cmd.Flags().Lookup("node") != nil {
				_ = cmd.RegisterFlagCompletionFunc("node", tailnetIDs(false))
			}
			if cmd.Flags().Lookup("mode") != nil {
				_ = cmd.RegisterFlagCompletionFunc("mode", values("serve", "direct"))
			}
			if cmd.Flags().Lookup("egress") != nil {
				_ = cmd.RegisterFlagCompletionFunc("egress", values("direct", "upstream", "existing"))
			}
			if cmd.Flags().Lookup("format") != nil {
				_ = cmd.RegisterFlagCompletionFunc("format", values("mihomo", "starter", "client-bundle"))
			}
		}
		if strings.HasPrefix(path, "vps ") && cmd.Flags().Lookup("provider") != nil {
			_ = cmd.RegisterFlagCompletionFunc("provider", values("oracle", "vultr", "linode", "digitalocean", "azure", "aws-lightsail", "aws-ec2"))
		}
		if strings.HasPrefix(path, "vps ") && cmd.Flags().Lookup("architecture") != nil {
			_ = cmd.RegisterFlagCompletionFunc("architecture", values("auto", "amd64", "arm64"))
		}
		for _, name := range []string{"level", "log-level"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.RegisterFlagCompletionFunc(name, values("debug", "info", "warning", "error", "silent"))
			}
		}
		if cmd.Flags().Lookup("kind") != nil {
			if path == "vps discover" {
				_ = cmd.RegisterFlagCompletionFunc("kind", values("regions", "plans", "images", "keys", "zones", "subscriptions", "ads", "compartments"))
			} else if path == "configs source set" {
				_ = cmd.RegisterFlagCompletionFunc("kind", values("native", "docker", "verge"))
			} else {
				_ = cmd.RegisterFlagCompletionFunc("kind", values("mihomo", "docker", "verge"))
			}
		}
		if cmd.Flags().Lookup("shell") != nil {
			switch path {
			case "proxy env":
				_ = cmd.RegisterFlagCompletionFunc("shell", values("sh", "bash", "zsh"))
			case "proxy shell-init":
				_ = cmd.RegisterFlagCompletionFunc("shell", values("bash", "zsh"))
			}
		}
		if cmd.Flags().Lookup("format") != nil {
			switch path {
			case "topology":
				_ = cmd.RegisterFlagCompletionFunc("format", values("ascii", "mermaid"))
			case "vps guide":
				_ = cmd.RegisterFlagCompletionFunc("format", values("markdown", "agent"))
			case "proxy docker render":
				_ = cmd.RegisterFlagCompletionFunc("format", values("env-file", "compose", "build-args", "client-json"))
			case "proxies export":
				_ = cmd.RegisterFlagCompletionFunc("format", values("yaml", "json", "url"))
			case "servers export":
				_ = cmd.RegisterFlagCompletionFunc("format", values("uri", "qr", "mihomo", "starter", "client-bundle", "admin-bundle"))
			}
		}
		if path == "vps guide" {
			_ = cmd.RegisterFlagCompletionFunc("oci-auth", values("security_token", "api_key"))
		}
		if cmd.Flags().Lookup("scope") != nil && path == "proxy docker render" {
			_ = cmd.RegisterFlagCompletionFunc("scope", values("runtime", "build", "both"))
		}
		for name, items := range map[string][]string{"backend": {"native", "docker"}, "input-kind": {"links", "subscription", "yaml"}, "preset": {"auto", "cn-split", "simple", "preserve"}, "category": {"reject", "direct", "proxy", "ai", "apple", "media-global", "media-hkmt"}, "service-scope": {"user", "system"}} {
			if cmd.Flags().Lookup(name) != nil {
				if name == "backend" && path == "servers deploy" {
					items = []string{"native", "compose"}
				}
				_ = cmd.RegisterFlagCompletionFunc(name, values(items...))
			}
		}
		if cmd.Flags().Lookup("core") != nil {
			_ = cmd.RegisterFlagCompletionFunc("core", local("cores"))
		}
		if cmd.Flags().Lookup("bootstrap-target") != nil {
			_ = cmd.RegisterFlagCompletionFunc("bootstrap-target", local("targets"))
		}
		if cmd.Flags().Lookup("owner-version") != nil {
			_ = cmd.RegisterFlagCompletionFunc("owner-version", values("2.5.2"))
		}
		if cmd.Flags().Lookup("consumer") != nil {
			_ = cmd.RegisterFlagCompletionFunc("consumer", values("process", "service"))
		}
		if cmd.Flags().Lookup("field") != nil {
			_ = cmd.RegisterFlagCompletionFunc("field", values("mode", "log-level"))
		}
		if cmd.Flags().Lookup("config-id") != nil {
			_ = cmd.RegisterFlagCompletionFunc("config-id", local("configs"))
		}
		for _, name := range []string{"dir"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.MarkFlagDirname(name)
			}
		}
		if path == "topology" {
			_ = cmd.RegisterFlagCompletionFunc("view", values("graph", "relations"))
		}
		for _, name := range []string{"secret-file", "ca-cert", "probe-password-file", "probe-ca-cert", "file", "output", "input", "artifact", "destinations"} {
			if cmd.Flags().Lookup(name) != nil {
				_ = cmd.MarkFlagFilename(name)
			}
		}
		for _, name := range []string{"via", "group", "probe-proxy", "probe-username", "probe-password-env", "source-config", "source-path", "focus", "path", "binary", "home", "profile"} {
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
