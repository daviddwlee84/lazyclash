package cli

import (
	"encoding/json"
	"os/exec"
	"path/filepath"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/tailnet"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

func (o *options) tailnetService(cmd *cobra.Command) (tailnet.Service, error) {
	store, err := o.serverStore(cmd)
	opts := o.deps.Tailnet
	opts.ReadOnly = o.readOnly
	if opts.Foreground == nil {
		opts.Foreground = func(child *exec.Cmd) error {
			if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
				return &tailnet.AuthorizationRequiredError{}
			}
			child.Stdin, child.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr()
			return o.deps.RunEditor(child)
		}
	}
	return tailnet.Service{Store: store, Options: opts}, err
}

func (o *options) tailnetCommand() *cobra.Command {
	group := &cobra.Command{Use: "tailnet", Short: "Manage existing Tailscale peers, exit nodes and private proxies"}
	group.AddCommand(&cobra.Command{Use: "peers", Short: "Discover peers and exit-node availability from the local Tailscale client", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		service, err := o.tailnetService(cmd)
		if err != nil {
			return err
		}
		peers, err := service.Peers(cmd.Context())
		if err != nil {
			return err
		}
		return o.output(cmd, peers)
	}})
	group.AddCommand(&cobra.Command{Use: "list", Short: "Read saved Tailnet devices and proxies without connecting", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		store, err := o.serverStore(cmd)
		if err != nil {
			return err
		}
		inv, err := store.Load()
		if err != nil {
			return err
		}
		return o.output(cmd, map[string]any{"nodes": inv.TailnetNodes, "proxies": inv.TailnetProxies})
	}})
	add := o.tailnetExitCommand("register")
	add.Use, add.Short = "add [ID]", "Register an already joined peer without changing exit or proxy settings"
	group.AddCommand(add, o.tailnetSetupMenu())
	exit := &cobra.Command{Use: "exit", Short: "Configure an exit node or select the local internet exit"}
	for _, action := range []string{"setup", "enable", "disable", "remove", "use", "release", "status"} {
		exit.AddCommand(o.tailnetExitCommand(action))
	}
	exit.AddCommand(o.tailnetManageCommand(false), o.tailnetExitExportCommand())
	group.AddCommand(exit, o.tailnetProxyCommand())
	return group
}

func (o *options) chooseTailnetID(cmd *cobra.Command, id string, interactive, proxy bool) (string, error) {
	if id != "" {
		if err := serverstate.ValidateID(id); err != nil {
			return "", usage("%s", err)
		}
		return id, nil
	}
	if !interactive {
		return "", usage("Tailnet ID is required; see --help")
	}
	store, err := o.serverStore(cmd)
	if err != nil {
		return "", err
	}
	inv, err := store.Load()
	if err != nil {
		return "", err
	}
	choices := []wizard.Choice{}
	if proxy {
		for _, p := range inv.TailnetProxies {
			choices = append(choices, wizard.Choice{Value: p.ID, Label: p.ID + " · " + p.NodeID})
		}
	} else {
		for _, n := range inv.TailnetNodes {
			choices = append(choices, wizard.Choice{Value: n.ID, Label: n.ID + " · " + n.SSHHost})
		}
	}
	if len(choices) == 0 {
		return "", usage("no saved Tailnet %s; use tailnet add or tailnet proxy deploy", map[bool]string{true: "proxies", false: "devices"}[proxy])
	}
	return wizard.Choose(cmd.Context(), "Choose Tailnet device / proxy", choices, cmd.InOrStdin(), cmd.OutOrStdout())
}

func (o *options) tailnetAuthenticated(cmd *cobra.Command, id string, run func() error) error {
	store, err := o.serverStore(cmd)
	if err != nil {
		return err
	}
	inv, err := store.Load()
	if err != nil {
		return err
	}
	node, err := inv.TailnetNode(id)
	if err != nil {
		return err
	}
	return o.authenticatedDiagnostic(cmd, config.Target{SSHHost: node.SSHHost}, run)
}

// Selecting a local exit can only hand off a local, explicitly identifiable core.
// Saved defaults are accepted; ambiguous discovery must be resolved by selection.
func (o *options) tailnetLocalTarget(cmd *cobra.Command) (config.Target, error) {
	cfg, _, err := o.load(cmd)
	if err != nil {
		return config.Target{}, err
	}
	target, _, err := o.choose(cmd, cfg)
	if err != nil {
		return target, err
	}
	if target.ID == "" {
		candidates, e := o.discoverTargets(cmd.Context(), "")
		if e != nil {
			return target, e
		}
		if len(candidates) > 1 {
			return target, usage("multiple local controllers found; select --target or --controller for the TUN handoff")
		}
		if len(candidates) == 1 {
			target = candidates[0]
		}
	}
	if target.SSHHost != "" {
		return target, usage("the TUN handoff requires a local controller; the selected target uses SSH")
	}
	return target, nil
}

func (o *options) tailnetExitCommand(action string) *cobra.Command {
	req := tailnet.Request{Action: action}
	var interactive, yes bool
	var expected string
	use := action + " [ID]"
	if action == "release" {
		use = "release"
	}
	cmd := &cobra.Command{Use: use, Short: map[string]string{"setup": "Review or set up a joined Linux exit node; bare terminal invocation opens a wizard", "enable": "Advertise a saved exit node", "disable": "Stop advertising an exit; keep Tailscale running", "remove": "Remove owned exit-node settings and registration", "use": "Select an exit node and hand off the confirmed local Mihomo TUN", "release": "Release the selected exit and restore unchanged saved preferences", "status": "Inspect a saved exit node and the local routing handoff"}[action], Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if action == "release" && len(args) > 0 {
			return usage("release accepts no ID")
		}
		if len(args) > 0 {
			req.ID = args[0]
		}
		if err := serverReviewFlags(yes, expected); err != nil {
			return err
		}
		if yes {
			if err := o.writable(); err != nil {
				return err
			}
		}
		if action != "use" && action != "release" {
			if err := validateManagedOverrides(cmd, action == "setup" || action == "register", false); err != nil {
				return err
			}
		}
		if req.ID != "" {
			if err := serverstate.ValidateID(req.ID); err != nil {
				return usage("%s", err)
			}
		}
		ui, err := o.sourceInteractive(cmd, interactive, (action == "setup" || action == "register") && len(args) == 0 && o.ssh == "" && !serverBusinessFlags(cmd))
		if err != nil {
			return err
		}
		if action == "setup" || action == "register" {
			req.SSHHost = o.ssh
			if ui {
				values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: map[bool]string{true: "Register Tailnet device", false: "Set up Tailscale exit node"}[action == "register"], Description: "Use an existing, joined peer. Registration alone does not change forwarding or exit settings.", SubmitLabel: "Preview", Fields: []wizard.Field{{Key: "id", Label: "Device ID", Value: req.ID, Required: true}, {Key: "ssh", Label: "SSH host alias", Value: req.SSHHost, Required: true}}}, cmd.InOrStdin(), cmd.OutOrStdout())
				if e != nil {
					return e
				}
				req.ID, req.SSHHost = values["id"], values["ssh"]
			}
			if req.ID == "" || req.SSHHost == "" {
				return usage("%s requires ID and --ssh HOST; run the command without arguments in a terminal for the wizard", cmd.Name())
			}
		} else if action != "release" {
			req.ID, err = o.chooseTailnetID(cmd, req.ID, ui, false)
			if err != nil {
				return err
			}
		}
		service, err := o.tailnetService(cmd)
		if err != nil {
			return err
		}
		if action == "status" {
			var result tailnet.Result
			err = o.tailnetAuthenticated(cmd, req.ID, func() error { var e error; result, e = service.Status(cmd.Context(), req.ID); return e })
			if result.ID != "" {
				if e := o.output(cmd, result); e != nil {
					return e
				}
			}
			return err
		}
		if action == "use" {
			target, e := o.tailnetLocalTarget(cmd)
			if e != nil {
				return e
			}
			if target.ID != "" {
				req.LocalTarget = &target
				if req.ProbeProxy == "" {
					req.ProbeProxy = target.ProbeProxy
				}
			}
		}
		var plan tailnet.Plan
		preview := func() error { var e error; plan, e = service.Preview(cmd.Context(), req); return e }
		if action == "setup" || action == "register" {
			err = o.authenticatedDiagnostic(cmd, config.Target{SSHHost: req.SSHHost}, preview)
		} else if action == "use" || action == "release" {
			err = preview()
		} else {
			err = o.tailnetAuthenticated(cmd, req.ID, preview)
		}
		if err != nil {
			return err
		}
		if ui {
			if err = o.writable(); err != nil {
				return err
			}
			yes, err = wizard.Confirm(cmd.Context(), "Review exit-node "+action, workJSON(plan), cmd.InOrStdin(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if !yes {
				return wizard.ErrCanceled
			}
			expected = plan.Digest
		}
		if !yes {
			return o.output(cmd, plan)
		}
		if expected != plan.Digest {
			return usage("exit-node state changed since preview; review the new plan before applying")
		}
		result, err := service.Apply(cmd.Context(), plan, expected)
		if result.ID != "" || action == "release" {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		}
		return err
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose a device and review the operation")
	if action != "status" {
		cmd.Flags().BoolVar(&yes, "yes", false, "apply the exact reviewed operation")
		cmd.Flags().StringVar(&expected, "expect", "", "reviewed preview digest required with --yes")
	}
	if action == "use" {
		cmd.Flags().BoolVar(&req.AllowLAN, "allow-lan", false, "allow the local LAN while using the exit")
		cmd.Flags().StringVar(&req.ProbeProxy, "probe-proxy", "", "also verify the local HTTP/SOCKS proxy URL")
	}
	return cmd
}

func (o *options) tailnetManageCommand(proxy bool) *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{Use: "manage [ID]", Short: "Choose an action for a saved Tailnet resource", Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		ui, err := o.sourceInteractive(cmd, interactive, true)
		if err != nil {
			return err
		}
		if !ui {
			return usage("manage requires a terminal; use an explicit tailnet subcommand for scripting")
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseTailnetID(cmd, id, true, proxy)
		if err != nil {
			return err
		}
		actions := []string{"status", "export"}
		if !o.readOnly {
			if proxy {
				actions = append(actions, "connect", "configure", "start", "stop", "restart", "remove")
			} else {
				actions = append(actions, "use", "release", "enable", "disable", "remove")
			}
		}
		choices := []wizard.Choice{}
		for _, action := range actions {
			choices = append(choices, wizard.Choice{Value: action, Label: action})
		}
		action, err := wizard.Choose(cmd.Context(), "Manage Tailnet "+id, choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		var child *cobra.Command
		if !proxy {
			if action == "export" {
				child = o.tailnetExitExportCommand()
			} else {
				child = o.tailnetExitCommand(action)
			}
		} else {
			switch action {
			case "configure":
				child = o.tailnetProxyDeployCommand(true)
			case "export":
				child = o.tailnetProxyExportCommand()
			case "connect":
				child = o.clientNodeConnectCommand("tailnet-proxy")
			default:
				child = o.tailnetProxyActionCommand(action)
			}
		}
		child.SetContext(cmd.Context())
		child.SetIn(cmd.InOrStdin())
		child.SetOut(cmd.OutOrStdout())
		child.SetErr(cmd.ErrOrStderr())
		_ = child.Flags().Set("interactive", "true")
		args = []string{id}
		if action == "release" {
			args = nil
		}
		return child.RunE(child, args)
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "open the Tailnet action picker")
	return cmd
}

// This menu is also the TUI terminal handoff, so one input reader owns the form.
func (o *options) tailnetSetupMenu() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{Use: "setup", Short: "Choose device registration, exit setup or proxy deployment", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		ui, err := o.sourceInteractive(cmd, interactive, true)
		if err != nil {
			return err
		}
		if !ui {
			return usage("tailnet setup requires a terminal; use add, exit setup or proxy deploy")
		}
		action, err := wizard.Choose(cmd.Context(), "Tailnet setup", []wizard.Choice{{Value: "register", Label: "Register a joined device (no exit changes)"}, {Value: "exit", Label: "Configure a joined device as an exit node"}, {Value: "proxy", Label: "Deploy a private proxy on a registered device"}}, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		var child *cobra.Command
		switch action {
		case "proxy":
			child = o.tailnetProxyDeployCommand(false)
		case "exit":
			child = o.tailnetExitCommand("setup")
		default:
			child = o.tailnetExitCommand("register")
		}
		child.SetContext(cmd.Context())
		child.SetIn(cmd.InOrStdin())
		child.SetOut(cmd.OutOrStdout())
		child.SetErr(cmd.ErrOrStderr())
		_ = child.Flags().Set("interactive", "true")
		return child.RunE(child, nil)
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "open the Tailnet setup picker")
	return cmd
}

func (o *options) tailnetExitExportCommand() *cobra.Command {
	var path string
	var interactive bool
	cmd := &cobra.Command{Use: "export [ID]", Short: "Export exit-node connection instructions without Tailscale credentials", Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		ui, err := o.sourceInteractive(cmd, interactive, false)
		if err != nil {
			return err
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseTailnetID(cmd, id, ui, false)
		if err != nil {
			return err
		}
		store, err := o.serverStore(cmd)
		if err != nil {
			return err
		}
		inv, err := store.Load()
		if err != nil {
			return err
		}
		node, err := inv.TailnetNode(id)
		if err != nil {
			return err
		}
		endpoint := node.Hostname
		if len(node.IPs) > 0 {
			endpoint = node.IPs[0]
		}
		guide := map[string]any{"kind": "tailscale-exit-instructions", "peer_id": node.PeerID, "hostname": node.Hostname, "addresses": node.IPs, "prerequisites": []string{"Join a tailnet that can reach this device.", "The device must advertise an approved exit node and your identity must be allowed to use internet access.", "Resolve conflicting full-tunnel VPNs before selection."}, "select": []string{"tailscale", "set", "--exit-node=" + endpoint}, "release": []string{"tailscale", "set", "--exit-node="}, "note": "These are connection instructions, not a proxy URI. Local Mihomo TUN handoff is available through lazyclash tailnet exit use."}
		if path == "" {
			return o.output(cmd, guide)
		}
		data, err := json.MarshalIndent(guide, "", "  ")
		if err != nil {
			return err
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if err = writeServerExport(absolute, append(data, '\n')); err != nil {
			return err
		}
		return o.output(cmd, map[string]any{"id": id, "path": absolute})
	}}
	cmd.Flags().StringVar(&path, "output", "", "new private JSON file; omit to print instructions")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose a saved exit node")
	return cmd
}
