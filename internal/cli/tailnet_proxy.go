package cli

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/tailnetproxy"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
)

func (o *options) tailnetProxyService(cmd *cobra.Command) (tailnetproxy.Service, error) {
	store, err := o.serverStore(cmd)
	opts := o.deps.TailnetProxy
	opts.Store, opts.ReadOnly = store, o.readOnly
	// Preserve adapter dependencies and use the same native authorization
	// handoff as exit-node operations, including structured machine errors.
	if opts.Core.Foreground == nil {
		service, e := o.tailnetService(cmd)
		if e != nil {
			return tailnetproxy.Service{}, e
		}
		opts.Core.Foreground = service.Options.Foreground
	}
	opts.Core.ReadOnly = o.readOnly
	return tailnetproxy.Service{Options: opts}, err
}

func (o *options) tailnetProxyCommand() *cobra.Command {
	group := &cobra.Command{Use: "proxy", Short: "Deploy and share a private HTTP/SOCKS proxy over your Tailnet"}
	group.AddCommand(o.tailnetProxyDeployCommand(false), o.tailnetProxyDeployCommand(true), o.tailnetProxyExportCommand(), o.clientNodeConnectCommand("tailnet-proxy"), o.tailnetManageCommand(true))
	for _, action := range []string{"start", "stop", "restart", "remove", "status"} {
		group.AddCommand(o.tailnetProxyActionCommand(action))
	}
	return group
}

func validateTailnetProxyFlags(r tailnetproxy.Request) error {
	for _, id := range []string{r.ID, r.NodeID} {
		if id != "" {
			if err := serverstate.ValidateID(id); err != nil {
				return usage("%s", err)
			}
		}
	}
	if r.Mode != "" && r.Mode != "serve" && r.Mode != "direct" {
		return usage("mode must be serve or direct")
	}
	if r.Backend != "" && r.Backend != "native" && r.Backend != "docker" {
		return usage("backend must be native or docker")
	}
	if r.Egress != "" && r.Egress != "direct" && r.Egress != "upstream" && r.Egress != "existing" {
		return usage("egress must be direct, upstream or existing")
	}
	for _, port := range []int{r.Port, r.LocalPort, r.ControllerPort} {
		if port < 0 || port > 65535 {
			return usage("ports must be between 1 and 65535")
		}
	}
	if r.UDP && r.Mode == "serve" {
		return usage("Serve forwards TCP only; use --mode direct for UDP")
	}
	return nil
}

func (o *options) tailnetProxyDeployCommand(configure bool) *cobra.Command {
	req := tailnetproxy.Request{}
	var interactive, yes bool
	var expected string
	action := "deploy"
	if configure {
		action = "configure"
	}
	cmd := &cobra.Command{Use: action + " [ID]", Short: map[bool]string{false: "Review or deploy a private gateway; bare terminal invocation opens a wizard", true: "Review gateway configuration without changing its binding or backend"}[configure], Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		req.UDPSet = cmd.Flags().Changed("udp")
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		if len(args) > 0 {
			req.ID = args[0]
		}
		if err := serverReviewFlags(yes, expected); err != nil {
			return err
		}
		for _, flag := range []string{"port", "local-port", "controller-port"} {
			if cmd.Flags().Changed(flag) {
				value, _ := cmd.Flags().GetInt(flag)
				if value < 1 {
					return usage("--%s must be between 1 and 65535", flag)
				}
			}
		}
		if err := validateTailnetProxyFlags(req); err != nil {
			return err
		}
		if yes {
			if err := o.writable(); err != nil {
				return err
			}
		}
		ui, err := o.sourceInteractive(cmd, interactive, !configure && len(args) == 0 && !serverBusinessFlags(cmd))
		if err != nil {
			return err
		}
		if configure {
			req.ID, err = o.chooseTailnetID(cmd, req.ID, ui, true)
			if err != nil {
				return err
			}
		}
		if ui && configure {
			store, e := o.serverStore(cmd)
			if e != nil {
				return e
			}
			inv, e := store.Load()
			if e != nil {
				return e
			}
			saved, e := inv.TailnetProxy(req.ID)
			if e != nil {
				return e
			}
			if !cmd.Flags().Changed("name") {
				req.Name = saved.Name
			}
			if !cmd.Flags().Changed("egress") {
				req.Egress = saved.Egress
			}
			if !cmd.Flags().Changed("udp") {
				req.UDP = saved.UDP
			}
			req.Mode = saved.Mode
		}
		if ui {
			if req.NodeID == "" && !configure {
				req.NodeID, err = o.chooseTailnetProxyDevice(cmd)
				if err != nil {
					return err
				}
			}
			fields := []wizard.Field{{Key: "id", Label: "Proxy ID", Value: req.ID, Required: true}, {Key: "name", Label: "Client node name", Value: req.Name}, {Key: "egress", Label: "Internet exit", Value: req.Egress, Kind: wizard.Select, Options: []wizard.Choice{{Value: "direct", Label: "Machine's direct OS internet exit"}, {Value: "upstream", Label: "Existing HTTP / SOCKS upstream"}, {Value: "existing", Label: "Share existing loopback proxy without managing it"}}}, {Key: "upstream", Label: "HTTP / SOCKS upstream URL (when selected)", Value: req.Upstream}}
			if configure {
				fields = fields[1:]
			}
			fields = append(fields, wizard.Field{Key: "udp", Label: "UDP (requires direct Tailnet access)", Value: strconv.FormatBool(req.UDP), Kind: wizard.Select, Options: []wizard.Choice{{Value: "false", Label: "Disabled"}, {Value: "true", Label: "Enabled"}}})
			if !configure {
				fields = append(fields, wizard.Field{Key: "mode", Label: "Tailnet access", Value: req.Mode, Kind: wizard.Select, Options: []wizard.Choice{{Value: "serve", Label: "Tailscale Serve TCP (loopback proxy)"}, {Value: "direct", Label: "Bind directly to Tailnet IP (supports UDP)"}}}, wizard.Field{Key: "backend", Label: "Gateway backend", Value: req.Backend, Kind: wizard.Select, Options: []wizard.Choice{{Value: "native", Label: "Native service"}, {Value: "docker", Label: "Docker"}}}, wizard.Field{Key: "port", Label: "Tailnet port", Value: strconv.Itoa(req.Port), Required: true})
			}
			values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Tailnet proxy " + action, Description: "Authenticated HTTP/SOCKS gateway. Only devices with Tailnet access can use it.", SubmitLabel: "Preview", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			req.Name, req.Egress, req.Upstream = values["name"], values["egress"], values["upstream"]
			req.UDP, req.UDPSet = values["udp"] == "true", true
			if !configure {
				req.ID = values["id"]
			}
			if !configure {
				req.Mode, req.Backend = values["mode"], values["backend"]
				req.Port, e = strconv.Atoi(values["port"])
				if e != nil {
					return usage("port must be a number")
				}
			}
		}
		if req.ID == "" || (!configure && req.NodeID == "") {
			return usage("%s requires ID%s; use --interactive for guidance", action, map[bool]string{false: " and --node DEVICE_ID", true: ""}[configure])
		}
		service, err := o.tailnetProxyService(cmd)
		if err != nil {
			return err
		}
		var plan tailnetproxy.Plan
		err = o.tailnetProxyAuthenticated(cmd, req.ID, req.NodeID, func() error { var e error; plan, e = service.Preview(cmd.Context(), req); return e })
		if err != nil {
			return err
		}
		if ui {
			if err = o.writable(); err != nil {
				return err
			}
			yes, err = wizard.Confirm(cmd.Context(), "Review Tailnet proxy "+action, workJSON(plan), cmd.InOrStdin(), cmd.OutOrStdout())
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
		result, err := service.Apply(cmd.Context(), req, expected)
		if result.ID != "" {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		}
		return err
	}}
	mode, backend, egress := "serve", "native", "direct"
	port, localPort, controllerPort := tailnetproxy.DefaultPort, tailnetproxy.DefaultLocalPort, tailnetproxy.DefaultControllerPort
	if configure {
		mode, backend, egress = "", "", ""
		port, localPort, controllerPort = 0, 0, 0
	}
	cmd.Flags().StringVar(&req.NodeID, "node", "", "saved Tailnet device ID")
	cmd.Flags().StringVar(&req.Name, "name", "", "name in exported client configuration")
	cmd.Flags().StringVar(&req.Mode, "mode", mode, "serve (TCP) or direct (Tailnet IP)")
	cmd.Flags().StringVar(&req.Backend, "backend", backend, "native or docker")
	cmd.Flags().StringVar(&req.Egress, "egress", egress, "direct, upstream or existing")
	cmd.Flags().StringVar(&req.Upstream, "upstream", "", "explicit HTTP/SOCKS URL; credentials are saved privately")
	cmd.Flags().IntVar(&req.Port, "port", port, "Tailnet proxy port")
	cmd.Flags().IntVar(&req.LocalPort, "local-port", localPort, "owned loopback proxy port for Serve")
	cmd.Flags().IntVar(&req.ControllerPort, "controller-port", controllerPort, "owned loopback management port")
	cmd.Flags().BoolVar(&req.UDP, "udp", false, "enable UDP for direct Tailnet-IP SOCKS access")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "open a prefilled proxy wizard")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the exact reviewed operation")
	cmd.Flags().StringVar(&expected, "expect", "", "reviewed preview digest required with --yes")
	return cmd
}

func (o *options) tailnetProxyAuthenticated(cmd *cobra.Command, id, nodeID string, run func() error) error {
	if nodeID == "" {
		store, err := o.serverStore(cmd)
		if err != nil {
			return err
		}
		inv, err := store.Load()
		if err != nil {
			return err
		}
		p, err := inv.TailnetProxy(id)
		if err != nil {
			return err
		}
		nodeID = p.NodeID
	}
	return o.tailnetAuthenticated(cmd, nodeID, run)
}

func (o *options) tailnetProxyActionCommand(action string) *cobra.Command {
	var interactive, yes bool
	var expected string
	cmd := &cobra.Command{Use: action + " [ID]", Short: map[string]string{"start": "Start the owned gateway and share", "stop": "Stop only the owned share and gateway", "restart": "Restart the owned gateway and share", "remove": "Remove owned share and gateway files; keep Tailscale running", "status": "Inspect the saved gateway and Tailnet listener"}[action], Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		if err := serverReviewFlags(yes, expected); err != nil {
			return err
		}
		if yes {
			if err := o.writable(); err != nil {
				return err
			}
		}
		ui, err := o.sourceInteractive(cmd, interactive, false)
		if err != nil {
			return err
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseTailnetID(cmd, id, ui, true)
		if err != nil {
			return err
		}
		service, err := o.tailnetProxyService(cmd)
		if err != nil {
			return err
		}
		if action == "status" {
			var result tailnetproxy.Status
			err = o.tailnetProxyAuthenticated(cmd, id, "", func() error { var e error; result, e = service.Status(cmd.Context(), id); return e })
			if result.ID != "" {
				if e := o.output(cmd, result); e != nil {
					return e
				}
			}
			return err
		}
		var plan tailnetproxy.Plan
		err = o.tailnetProxyAuthenticated(cmd, id, "", func() error { var e error; plan, e = service.PreviewAction(cmd.Context(), id, action); return e })
		if err != nil {
			return err
		}
		if ui {
			if err = o.writable(); err != nil {
				return err
			}
			yes, err = wizard.Confirm(cmd.Context(), "Review proxy "+action, workJSON(plan), cmd.InOrStdin(), cmd.OutOrStdout())
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
		result, err := service.Action(cmd.Context(), id, action, expected)
		if result.ID != "" {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		}
		return err
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose a proxy and review the operation")
	if action != "status" {
		cmd.Flags().BoolVar(&yes, "yes", false, "apply the exact reviewed operation")
		cmd.Flags().StringVar(&expected, "expect", "", "reviewed preview digest")
	}
	return cmd
}

func (o *options) tailnetProxyExportCommand() *cobra.Command {
	var format, path string
	var interactive bool
	cmd := &cobra.Command{Use: "export [ID]", Short: "Export private Mihomo configuration for Tailnet clients", Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		if format != "mihomo" && format != "yaml" && format != "starter" && format != "client-bundle" {
			return usage("format must be mihomo, starter or client-bundle")
		}
		ui, err := o.sourceInteractive(cmd, interactive, false)
		if err != nil {
			return err
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseTailnetID(cmd, id, ui, true)
		if err != nil {
			return err
		}
		if ui {
			values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Export Tailnet proxy", Description: "The recipient needs Tailnet access. This export contains proxy credentials.", SubmitLabel: "Export", Fields: []wizard.Field{{Key: "format", Label: "Format", Value: format, Kind: wizard.Select, Options: []wizard.Choice{{Value: "mihomo", Label: "Mihomo node YAML"}, {Value: "starter", Label: "Complete starter YAML"}, {Value: "client-bundle", Label: "Client bundle JSON"}}}, {Key: "output", Label: "New private output file (empty prints to terminal)", Value: path}}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			format, path = values["format"], values["output"]
		}
		service, err := o.tailnetProxyService(cmd)
		if err != nil {
			return err
		}
		canonical := format
		if canonical == "mihomo" {
			canonical = "yaml"
		}
		data, err := service.Export(id, canonical)
		if err != nil {
			return err
		}
		if path != "" {
			absolute, e := filepath.Abs(path)
			if e != nil {
				return e
			}
			if e = writeServerExport(absolute, data); e != nil {
				return e
			}
			return o.output(cmd, map[string]any{"id": id, "format": format, "path": absolute, "private": true})
		}
		if o.json {
			return o.output(cmd, map[string]string{"id": id, "format": format, "content": string(data)})
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}}
	cmd.Flags().StringVar(&format, "format", "mihomo", "mihomo, starter or client-bundle")
	cmd.Flags().StringVar(&path, "output", "", "new private file (0600; never overwrites)")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose format and destination")
	return cmd
}

func (o *options) chooseTailnetProxyDevice(cmd *cobra.Command) (string, error) {
	store, err := o.serverStore(cmd)
	if err != nil {
		return "", err
	}
	inv, err := store.Load()
	if err != nil {
		return "", err
	}
	choices := []wizard.Choice{}
	for _, n := range inv.TailnetNodes {
		choices = append(choices, wizard.Choice{Value: n.ID, Label: n.ID + " · " + n.SSHHost})
	}
	choices = append(choices, wizard.Choice{Value: "@register", Label: "Register another joined device (no exit changes)"})
	id, err := wizard.Choose(cmd.Context(), "Choose Tailnet device", choices, cmd.InOrStdin(), cmd.OutOrStdout())
	if err != nil {
		return "", err
	}
	if id != "@register" {
		return id, nil
	}
	child := o.tailnetExitCommand("register")
	child.SetContext(cmd.Context())
	child.SetIn(cmd.InOrStdin())
	child.SetOut(cmd.OutOrStdout())
	child.SetErr(cmd.ErrOrStderr())
	_ = child.Flags().Set("interactive", "true")
	if err = child.RunE(child, nil); err != nil {
		return "", err
	}
	return o.chooseTailnetID(cmd, "", true, false)
}
