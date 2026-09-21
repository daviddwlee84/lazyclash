package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/serverdeploy"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (o *options) serverOptions(cmd *cobra.Command) (serverdeploy.Options, error) {
	opts := o.deps.Servers
	store, err := o.serverStore(cmd)
	if err != nil {
		return opts, err
	}
	opts.Store, opts.ReadOnly = store, o.readOnly
	return opts, nil
}

func serverReviewFlags(yes bool, expected string) error {
	if yes && expected == "" {
		return usage("--yes requires the reviewed --expect DIGEST")
	}
	if !yes && expected != "" {
		return usage("--expect requires --yes")
	}
	if yes {
		if value, err := hex.DecodeString(expected); err != nil || len(value) != 32 {
			return usage("--expect must be the 64-character hexadecimal preview digest")
		}
	}
	return nil
}

func serverBusinessFlags(cmd *cobra.Command) bool {
	business := false
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Changed && f.Name != "interactive" {
			business = true
		}
	})
	return business
}

func (o *options) serversCommand() *cobra.Command {
	group := &cobra.Command{Use: "servers", Short: "Deploy, operate and share proxy servers on registered VPS or SSH hosts"}
	group.AddCommand(&cobra.Command{Use: "recipes", Short: "Compare available complete protocol recipes", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error { return o.output(cmd, serverdeploy.Recipes()) }})
	group.AddCommand(&cobra.Command{Use: "list", Short: "Read saved server deployments without contacting hosts", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		store, err := o.serverStore(cmd)
		if err != nil {
			return err
		}
		inv, err := store.Load()
		if err != nil {
			return err
		}
		return o.output(cmd, inv.Deployments)
	}})
	group.AddCommand(o.serverDeployCommand(), o.serverStatusCommand(), o.serverExportCommand(), o.serverConnectCommand(), o.serverManageCommand())
	for _, action := range []string{"start", "stop", "restart", "remove", "resume"} {
		group.AddCommand(o.serverActionCommand(action))
	}
	return group
}

func validateServerRequestFlags(req serverdeploy.Request) error {
	if err := serverdeploy.ValidateDraft(req); err != nil {
		return usage("%s", err)
	}
	if req.Recipe != "" {
		found := false
		for _, recipe := range serverdeploy.Recipes() {
			found = found || recipe.ID == req.Recipe
		}
		if !found {
			return usage("unknown recipe %q; see servers recipes", req.Recipe)
		}
	}
	if req.Backend != "native" && req.Backend != "compose" && req.Backend != "" {
		return usage("backend must be native or compose")
	}
	if req.PublicPort < 1 || req.PublicPort > 65535 || req.ListenPort < 1 || req.ListenPort > 65535 {
		return usage("server ports must be between 1 and 65535")
	}
	for _, id := range []string{req.ID, req.HostID} {
		if id != "" {
			if err := serverstate.ValidateID(id); err != nil {
				return usage("%s", err)
			}
		}
	}
	return nil
}

func serverOptionalID(_ *cobra.Command, args []string) error {
	if len(args) > 1 {
		return usage("this server command accepts at most one ID")
	}
	return nil
}

func (o *options) serverDeployCommand() *cobra.Command {
	req := serverdeploy.Request{}
	var interactive, yes bool
	var expected string
	cmd := &cobra.Command{Use: "deploy [ID]", Short: "Review or deploy a proxy-server recipe; bare terminal invocation opens a wizard", Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("deploy accepts at most one server ID")
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		if len(args) == 1 {
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
		if err := validateServerRequestFlags(req); err != nil {
			return err
		}
		ui, err := o.sourceInteractive(cmd, interactive, len(args) == 0 && !serverBusinessFlags(cmd))
		if err != nil {
			return err
		}
		if ui {
			if err := o.writable(); err != nil {
				return err
			}
			return o.runServerDeployWizard(cmd, req)
		}
		if req.ID == "" || req.HostID == "" {
			return usage("deploy requires ID and --host HOST_ID; run bare servers deploy in a terminal for the wizard")
		}
		opts, err := o.serverOptions(cmd)
		if err != nil {
			return err
		}
		if yes {
			if err = o.writable(); err != nil {
				return err
			}
		}
		var plan serverdeploy.Plan
		err = o.serverAuthenticated(cmd, req.HostID, func() error { var e error; plan, e = serverdeploy.Preview(cmd.Context(), req, opts); return e })
		if err != nil {
			return err
		}
		if !yes {
			return o.output(cmd, plan)
		}
		result, err := serverdeploy.Apply(cmd.Context(), plan, expected, opts)
		if result.ID != "" {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		}
		return err
	}}
	f := cmd.Flags()
	f.StringVar(&req.HostID, "host", "", "registered VPS/SSH host ID")
	f.StringVar(&req.Recipe, "recipe", "vless-reality", "complete recipe from servers recipes")
	f.StringVar(&req.Backend, "backend", "native", "native systemd or compose")
	f.StringVar(&req.PublicHost, "public-host", "", "client-visible DNS name or IP; defaults to host registration")
	f.IntVar(&req.PublicPort, "public-port", 443, "client-visible port, including any router translation")
	f.IntVar(&req.ListenPort, "listen-port", 443, "port bound on the server")
	f.StringVar(&req.Domain, "domain", "", "DNS name for ACME certificates (Hysteria2 or legacy WS/TLS)")
	f.StringVar(&req.Email, "email", "", "ACME account email")
	f.StringVar(&req.RealityTarget, "reality-target", "www.cloudflare.com:443", "REALITY handshake destination host:port")
	f.StringVar(&req.ServerName, "server-name", "www.cloudflare.com", "REALITY TLS server name")
	f.StringVar(&req.Version, "version", "", "exact core version; default is the pinned recipe release")
	f.BoolVar(&interactive, "interactive", false, "open a prefilled deployment wizard")
	f.BoolVar(&yes, "yes", false, "apply the exact reviewed deployment")
	f.StringVar(&expected, "expect", "", "reviewed deployment digest required with --yes")
	return cmd
}

func (o *options) serverAuthenticated(cmd *cobra.Command, hostID string, run func() error) error {
	store, err := o.serverStore(cmd)
	if err != nil {
		return err
	}
	inv, err := store.Load()
	if err != nil {
		return err
	}
	host, err := inv.Host(hostID)
	if err != nil {
		return err
	}
	return o.authenticatedDiagnostic(cmd, config.Target{SSHHost: host.SSHHost}, run)
}

func (o *options) chooseServerID(cmd *cobra.Command, id string, interactive bool) (string, error) {
	if id != "" {
		return id, nil
	}
	if !interactive {
		return "", usage("server ID is required")
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
	for _, d := range inv.Deployments {
		choices = append(choices, wizard.Choice{Value: d.ID, Label: d.ID + " · " + d.Recipe + " · " + d.HostID})
	}
	if len(choices) == 0 {
		return "", usage("no saved servers; use servers deploy")
	}
	return wizard.Choose(cmd.Context(), "Choose server", choices, cmd.InOrStdin(), cmd.OutOrStdout())
}

func (o *options) serverStatusCommand() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{Use: "status [ID]", Short: "Inspect SSH and remote service status", Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		ui, err := o.sourceInteractive(cmd, interactive, false)
		if err != nil {
			return err
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseServerID(cmd, id, ui)
		if err != nil {
			return err
		}
		opts, err := o.serverOptions(cmd)
		if err != nil {
			return err
		}
		inv, err := opts.Store.Load()
		if err != nil {
			return err
		}
		d, err := inv.Deployment(id)
		if err != nil {
			return err
		}
		var status serverdeploy.Status
		err = o.serverAuthenticated(cmd, d.HostID, func() error { var e error; status, e = serverdeploy.GetStatus(cmd.Context(), id, opts); return e })
		if status.ID != "" {
			if e := o.output(cmd, status); e != nil {
				return e
			}
		}
		return err
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose a saved server")
	return cmd
}

func (o *options) serverActionCommand(action string) *cobra.Command {
	var interactive, yes bool
	var expected string
	cmd := &cobra.Command{Use: action + " [ID]", Short: map[string]string{"start": "Start an owned server service", "stop": "Stop a server service; VM billing continues", "restart": "Restart an owned server service", "remove": "Remove owned service files; keep the VPS", "resume": "Resume a recorded incomplete deployment"}[action], Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
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
		id, err = o.chooseServerID(cmd, id, ui)
		if err != nil {
			return err
		}
		opts, err := o.serverOptions(cmd)
		if err != nil {
			return err
		}
		inv, err := opts.Store.Load()
		if err != nil {
			return err
		}
		d, err := inv.Deployment(id)
		if err != nil {
			return err
		}
		var plan serverdeploy.Plan
		err = o.serverAuthenticated(cmd, d.HostID, func() error {
			var e error
			plan, e = serverdeploy.PreviewAction(cmd.Context(), id, action, opts)
			return e
		})
		if err != nil {
			return err
		}
		if ui {
			if err = o.writable(); err != nil {
				return err
			}
			yes, err = wizard.Confirm(cmd.Context(), "Review server "+action, workJSON(plan), cmd.InOrStdin(), cmd.OutOrStdout())
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
		if err = o.writable(); err != nil {
			return err
		}
		result, err := serverdeploy.ApplyAction(cmd.Context(), plan, expected, opts)
		if result.ID != "" {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		}
		return err
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose a server and review the operation")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the exact reviewed action")
	cmd.Flags().StringVar(&expected, "expect", "", "reviewed action digest required with --yes")
	return cmd
}

func (o *options) serverExportCommand() *cobra.Command {
	var format, path string
	var interactive bool
	cmd := &cobra.Command{Use: "export [ID]", Short: "Export private client configuration or an explicit management backup", Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateManagedOverrides(cmd, false, false); err != nil {
			return err
		}
		canonical, ok := serverExportFormats[format]
		if !ok {
			return usage("format must be uri, qr, mihomo, starter, client-bundle or admin-bundle")
		}
		ui, err := o.sourceInteractive(cmd, interactive, false)
		if err != nil {
			return err
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseServerID(cmd, id, ui)
		if err != nil {
			return err
		}
		if ui {
			values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Export server configuration", Description: "Exports contain credentials. QR images and management backups require an output file.", SubmitLabel: "Export", Fields: []wizard.Field{{Key: "format", Label: "Format", Value: format, Kind: wizard.Select, Options: []wizard.Choice{{Value: "uri", Label: "Client share link"}, {Value: "qr", Label: "Client QR (PNG; requires file)"}, {Value: "mihomo", Label: "Mihomo node YAML"}, {Value: "starter", Label: "Complete Mihomo starter YAML"}, {Value: "client-bundle", Label: "Client bundle (JSON)"}, {Value: "admin-bundle", Label: "Management backup including server private keys"}}}, {Key: "output", Label: "New private output file (empty prints text to terminal)", Value: path}}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			format, path = values["format"], values["output"]
			canonical = serverExportFormats[format]
		}
		if (canonical == "admin" || canonical == "qr") && path == "" {
			return usage("%s export requires --output FILE", format)
		}
		opts, err := o.serverOptions(cmd)
		if err != nil {
			return err
		}
		var data []byte
		if canonical == "admin" {
			defer connection.CloseAuthentications()
			inv, e := opts.Store.Load()
			if e != nil {
				return e
			}
			d, e := inv.Deployment(id)
			if e != nil {
				return e
			}
			err = o.serverAuthenticated(cmd, d.HostID, func() error { var e error; data, e = serverdeploy.Export(cmd.Context(), id, canonical, opts); return e })
		} else {
			data, err = serverdeploy.Export(cmd.Context(), id, canonical, opts)
		}
		if err != nil {
			return err
		}
		if path != "" {
			absolute, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if err = writeServerExport(absolute, data); err != nil {
				return err
			}
			return o.output(cmd, map[string]any{"id": id, "format": format, "path": absolute, "private": true})
		}
		if o.json {
			return o.output(cmd, map[string]string{"id": id, "format": format, "content": string(data)})
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}}
	cmd.Flags().StringVar(&format, "format", "uri", "uri, qr, mihomo, starter, client-bundle or admin-bundle")
	cmd.Flags().StringVar(&path, "output", "", "new private file (mode 0600; never overwrites)")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose export format and private destination")
	return cmd
}

var serverExportFormats = map[string]string{"uri": "uri", "qr": "qr", "yaml": "yaml", "mihomo": "yaml", "starter": "starter", "client-bundle": "client-bundle", "admin-bundle": "admin", "admin": "admin"}

func writeServerExport(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create private export: %w", err)
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return nil
}

func (o *options) serverManageCommand() *cobra.Command {
	var interactive bool
	cmd := &cobra.Command{Use: "manage [ID]", Short: "Open actions for a saved server", Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		ui, err := o.sourceInteractive(cmd, interactive, true)
		if err != nil {
			return err
		}
		if !ui {
			return usage("servers manage requires a terminal; use servers status/start/stop/export/connect for scripting")
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		id, err = o.chooseServerID(cmd, id, true)
		if err != nil {
			return err
		}
		choices := []wizard.Choice{{Value: "status", Label: "Inspect remote service status"}, {Value: "export", Label: "Export client configuration / management backup"}}
		if !o.readOnly {
			choices = append(choices, wizard.Choice{Value: "connect", Label: "Add this server to a client"}, wizard.Choice{Value: "start", Label: "Start proxy service"}, wizard.Choice{Value: "stop", Label: "Stop proxy service (VM billing continues)"}, wizard.Choice{Value: "restart", Label: "Restart proxy service"}, wizard.Choice{Value: "resume", Label: "Resume incomplete deployment"}, wizard.Choice{Value: "remove", Label: "Remove service and owned files (keep VPS)"})
		}
		action, err := wizard.Choose(cmd.Context(), "Server "+id, choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		var child *cobra.Command
		switch action {
		case "status":
			child = o.serverStatusCommand()
		case "export":
			child = o.serverExportCommand()
		case "connect":
			child = o.serverConnectCommand()
		default:
			child = o.serverActionCommand(action)
		}
		child.SetContext(cmd.Context())
		child.SetIn(cmd.InOrStdin())
		child.SetOut(cmd.OutOrStdout())
		child.SetErr(cmd.ErrOrStderr())
		_ = child.Flags().Set("interactive", "true")
		return child.RunE(child, []string{id})
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "open the server action picker")
	return cmd
}

func (o *options) serverConnectCommand() *cobra.Command {
	return o.clientNodeConnectCommand("server")
}

// Both public-server and Tailnet imports use the same persistent source preview,
// receipt recovery and native-owner activation workflow.
func (o *options) clientNodeConnectCommand(kind string) *cobra.Command {
	description := "Review importing a deployed node into a saved client configuration source"
	if kind == "tailnet-proxy" {
		description = "Review importing a private proxy into a client with Tailnet access"
	}
	var interactive, yes, verify bool
	var expected string
	var groups []string
	cmd := &cobra.Command{Use: "connect [ID]", Short: description, Args: serverOptionalID, RunE: func(cmd *cobra.Command, args []string) error {
		defer connection.CloseAuthentications()
		if err := serverReviewFlags(yes, expected); err != nil {
			return err
		}
		if verify && (yes || len(groups) > 0) {
			return usage("--verify cannot be combined with --yes or --group")
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
		if kind == "tailnet-proxy" {
			id, err = o.chooseTailnetID(cmd, id, ui, true)
		} else {
			id, err = o.chooseServerID(cmd, id, ui)
		}
		if err != nil {
			return err
		}
		if ui && o.target == "" {
			cfg, _, e := o.load(cmd)
			if e != nil {
				return e
			}
			choices := []wizard.Choice{}
			for _, t := range cfg.Targets {
				if t.ConfigSource != nil {
					choices = append(choices, wizard.Choice{Value: t.ID, Label: t.Label()})
				}
			}
			if len(choices) == 0 {
				return usage("bind a client configuration source first: configs source set")
			}
			o.target, err = wizard.Choose(cmd.Context(), "Client to receive this server", choices, cmd.InOrStdin(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
		}
		target, err := o.configWorkTarget(cmd)
		if err != nil {
			return err
		}
		opts, err := o.serverOptions(cmd)
		if err != nil {
			return err
		}
		workOpts := o.configWorkOptions(cmd)
		connectionPath, err := clientConnectionPath(opts.Store, kind, id, target)
		if err != nil {
			return err
		}
		workOpts.StateDir = filepath.Join(filepath.Dir(connectionPath), "receipts")
		record, found, err := readServerConnection(connectionPath)
		if err != nil {
			return err
		}
		if verify || found && record.Status != "failed-before-write" {
			if !found {
				return usage("no saved import for server %s and client %s", id, target.ID)
			}
			return o.verifyServerConnection(cmd, target, record, connectionPath, workOpts)
		}
		var node []byte
		if kind == "tailnet-proxy" {
			service, e := o.tailnetProxyService(cmd)
			if e != nil {
				return e
			}
			node, err = service.ClientNode(id)
		} else {
			node, err = serverdeploy.ClientNode(cmd.Context(), id, opts)
		}
		if err != nil {
			return err
		}
		if ui {
			values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Add server to client", Description: "Server: " + id + " · Client: " + target.ID, SubmitLabel: "Preview", Fields: []wizard.Field{{Key: "groups", Label: "Existing client groups (comma separated; optional)", Value: strings.Join(groups, ",")}}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			groups = splitNonempty(values["groups"])
		}
		req := configwork.Request{Kind: "proxy", Action: "import", Input: node, Groups: groups}
		var plan configwork.Plan
		err = o.authenticatedDiagnostic(cmd, target, func() error {
			var e error
			plan, e = configwork.Preview(cmd.Context(), target, req, workOpts)
			return e
		})
		if err != nil {
			return err
		}
		if ui {
			yes, err = wizard.Confirm(cmd.Context(), "Review client import", configwork.WarningsText(plan)+"\nDigest: "+plan.Digest, cmd.InOrStdin(), cmd.OutOrStdout())
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
		if err = o.writable(); err != nil {
			return err
		}
		result, err := applyClientConnection(cmd.Context(), opts.Store, kind, id, target, req, expected, connectionPath, workOpts)
		if result.ID != "" {
			if e := o.output(cmd, result); e != nil {
				return e
			}
		}
		return err
	}}
	cmd.Flags().BoolVar(&interactive, "interactive", false, "choose a client and review the persistent import")
	cmd.Flags().BoolVar(&yes, "yes", false, "apply the exact reviewed client import")
	cmd.Flags().BoolVar(&verify, "verify", false, "verify/resume the saved import receipt without importing again")
	cmd.Flags().StringVar(&expected, "expect", "", "reviewed client import digest")
	cmd.Flags().StringSliceVar(&groups, "group", nil, "existing destination group(s)")
	return cmd
}

func (o *options) runServerDeployWizard(cmd *cobra.Command, req serverdeploy.Request) error {
	store, err := o.serverStore(cmd)
	if err != nil {
		return err
	}
	if req.HostID == "" {
		inv, err := store.Load()
		if err != nil {
			return err
		}
		choices := []wizard.Choice{}
		for _, host := range inv.Hosts {
			choices = append(choices, wizard.Choice{Value: host.ID, Label: host.ID + " · " + host.Provider + " · " + host.SSHHost})
		}
		choices = append(choices, wizard.Choice{Value: "@create", Label: "Create a cloud VPS (review costs before creating)"}, wizard.Choice{Value: "@ssh", Label: "Register an existing SSH / homelab host"})
		selected, err := wizard.Choose(cmd.Context(), "Deployment host", choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		switch selected {
		case "@create":
			host, e := o.runVPSCreateWizard(cmd, vps.CreateRequest{})
			if e != nil {
				return e
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "VPS %s is saved. Waiting up to 2 minutes for its public address and SSH listener…\n", host.ID)
			waiting, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			host, e = waitForServerHost(waiting, host, func(ctx context.Context, id string) (serverstate.Host, error) {
				return vps.New(store, o.deps.VPS).Status(ctx, id)
			}, func(ctx context.Context, host serverstate.Host) error {
				c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host.PublicHost, "22"))
				if err == nil {
					_ = c.Close()
				}
				return err
			}, 3*time.Second)
			cancel()
			if e != nil {
				return fmt.Errorf("VPS %s remains saved; run vps status %s, then servers deploy --host %s after SSH is ready: %w", host.ID, host.ID, host.ID, e)
			}
			req.HostID = host.ID
		case "@ssh":
			values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Register SSH host", Description: "Use an SSH alias for custom ports, identity files or jump hosts. Public endpoint is independent of SSH.", SubmitLabel: "Review", Fields: []wizard.Field{{Key: "id", Label: "Host ID", Required: true}, {Key: "ssh", Label: "SSH alias or user@host", Required: true}, {Key: "public", Label: "Public IP or DNS name", Required: true}}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			host := serverstate.Host{ID: values["id"], Provider: "ssh", SSHHost: values["ssh"], PublicHost: values["public"]}
			accept, e := wizard.Confirm(cmd.Context(), "Register deployment host", workJSON(host), cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			if !accept {
				return wizard.ErrCanceled
			}
			if host, e = vps.New(store, o.deps.VPS).Register(host); e != nil {
				return e
			}
			req.HostID = host.ID
		default:
			req.HostID = selected
		}
	}
	inv, err := store.Load()
	if err != nil {
		return err
	}
	host, err := inv.Host(req.HostID)
	if err != nil {
		return err
	}
	if req.PublicHost == "" {
		req.PublicHost = host.PublicHost
	}
	message := "Host: " + host.ID + " · " + host.SSHHost + ". Deployments use Ubuntu 24.04 LTS. Review checks the host before changing it."
	var draft map[string]string
	for {
		spec := serverDeploySpec(req, message)
		for i := range spec.Fields {
			if value, ok := draft[spec.Fields[i].Key]; ok {
				spec.Fields[i].Value = value
			}
		}
		values, e := wizard.Edit(cmd.Context(), spec, cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		draft = values
		req.ID, req.Recipe, req.Backend = values["id"], values["recipe"], values["backend"]
		req.PublicHost, req.Domain, req.Email = values["public"], values["domain"], values["email"]
		req.RealityTarget, req.ServerName, req.Version = values["reality"], values["sni"], values["version"]
		req.PublicPort, e = strconv.Atoi(values["public_port"])
		if e != nil {
			message = "Public port must be a number"
			continue
		}
		req.ListenPort, e = strconv.Atoi(values["listen_port"])
		if e != nil {
			message = "Listen port must be a number"
			continue
		}
		if e = validateServerRequestFlags(req); e != nil {
			message = e.Error()
			continue
		}
		opts, e := o.serverOptions(cmd)
		if e != nil {
			return e
		}
		var plan serverdeploy.Plan
		e = o.serverAuthenticated(cmd, req.HostID, func() error { var err error; plan, err = serverdeploy.Preview(cmd.Context(), req, opts); return err })
		if e != nil {
			message = e.Error()
			continue
		}
		accept, e := wizard.Confirm(cmd.Context(), "Review server deployment", workJSON(plan), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !accept {
			message = "Review canceled; the draft is retained. Any previously created VPS remains registered."
			continue
		}
		result, e := serverdeploy.Apply(cmd.Context(), plan, plan.Digest, opts)
		if result.ID != "" {
			if err = o.output(cmd, result); err != nil {
				return err
			}
		}
		if e != nil {
			return e
		}
		return o.serverAfterDeploy(cmd, result.ID)
	}
}

func serverDeploySpec(req serverdeploy.Request, message string) wizard.Spec {
	if req.Recipe == "" {
		req.Recipe = "vless-reality"
	}
	if req.Backend == "" {
		req.Backend = "native"
	}
	if req.PublicPort == 0 {
		req.PublicPort = 443
	}
	if req.ListenPort == 0 {
		req.ListenPort = 443
	}
	if req.RealityTarget == "" {
		req.RealityTarget = "www.cloudflare.com:443"
	}
	if req.ServerName == "" {
		req.ServerName = "www.cloudflare.com"
	}
	choices := []wizard.Choice{}
	for _, r := range serverdeploy.Recipes() {
		choices = append(choices, wizard.Choice{Value: r.ID, Label: r.Name + " · " + r.Description})
	}
	return wizard.Spec{Title: "Deploy proxy server", Description: message, SubmitLabel: "Inspect and preview", Fields: []wizard.Field{
		{Key: "id", Label: "Server ID", Value: req.ID, Required: true}, {Key: "recipe", Label: "Protocol recipe", Kind: wizard.Select, Value: req.Recipe, Options: choices}, {Key: "backend", Label: "Service backend", Kind: wizard.Select, Value: req.Backend, Options: []wizard.Choice{{Value: "native", Label: "Native systemd (default)"}, {Value: "compose", Label: "Docker Compose"}}},
		{Key: "public", Label: "Client public IP / DNS", Value: req.PublicHost, Required: true}, {Key: "public_port", Label: "Client public port", Value: strconv.Itoa(req.PublicPort), Required: true}, {Key: "listen_port", Label: "Server listen port", Value: strconv.Itoa(req.ListenPort), Required: true},
		{Key: "domain", Label: "Certificate DNS name (Hysteria2 / legacy)", Value: req.Domain}, {Key: "email", Label: "ACME account email (Hysteria2 / legacy)", Value: req.Email}, {Key: "reality", Label: "REALITY handshake destination", Value: req.RealityTarget}, {Key: "sni", Label: "REALITY TLS server name", Value: req.ServerName}, {Key: "version", Label: "Core version (empty = pinned recipe release)", Value: req.Version},
	}}
}

func (o *options) serverAfterDeploy(cmd *cobra.Command, id string) error {
	for {
		action, err := wizard.Choose(cmd.Context(), "Server "+id+" saved — next step", []wizard.Choice{{Value: "done", Label: "Done"}, {Value: "export", Label: "Export share link / client configuration"}, {Value: "connect", Label: "Add this server to a registered client"}}, cmd.InOrStdin(), cmd.OutOrStdout())
		if errors.Is(err, wizard.ErrCanceled) {
			return nil
		}
		if err != nil {
			return err
		}
		if action == "done" {
			return nil
		}
		child := o.serverExportCommand()
		if action == "connect" {
			child = o.serverConnectCommand()
		}
		child.SetContext(cmd.Context())
		child.SetIn(cmd.InOrStdin())
		child.SetOut(cmd.OutOrStdout())
		child.SetErr(cmd.ErrOrStderr())
		_ = child.Flags().Set("interactive", "true")
		err = child.RunE(child, []string{id})
		if errors.Is(err, wizard.ErrCanceled) {
			continue
		}
		if err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "Server remains saved:", err)
		}
		if err = wizard.Pause(cmd.Context(), "Return to saved server", cmd.InOrStdin(), cmd.OutOrStdout()); err != nil {
			return err
		}
	}
}

func (o *options) runServerWorkbench(ctx context.Context, r tui.WorkRequest) (tui.WorkResult, error) {
	// Use the same selected configuration path as the dashboard; no controller
	// connection is required to inspect the local server inventory.
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	store, err := o.serverStore(cmd)
	if err != nil {
		return tui.WorkResult{}, err
	}
	inv, err := store.Load()
	if err != nil {
		return tui.WorkResult{}, err
	}
	result := tui.WorkResult{Title: "Servers / VPS", Summary: "Saved inventory. Enter refreshes status; a opens actions; t sets up a Tailnet device. Service stop does not stop VM billing."}
	for _, d := range inv.Deployments {
		result.Rows = append(result.Rows, tui.WorkRow{ID: "server:" + d.ID, Label: d.ID + " · " + d.Recipe + " · " + d.Status, Detail: workJSON(d)})
	}
	for _, h := range inv.Hosts {
		result.Rows = append(result.Rows, tui.WorkRow{ID: "host:" + h.ID, Label: h.ID + " · VPS / " + h.Provider + " · " + h.Status, Detail: workJSON(h)})
	}
	for _, n := range inv.TailnetNodes {
		result.Rows = append(result.Rows, tui.WorkRow{ID: "tailnet:" + n.ID, Label: n.ID + " · Tailnet exit · " + n.ExitStatus, Detail: workJSON(n)})
	}
	for _, p := range inv.TailnetProxies {
		result.Rows = append(result.Rows, tui.WorkRow{ID: "tailnet-proxy:" + p.ID, Label: p.ID + " · Tailnet proxy / " + p.Mode + " · " + p.Status, Detail: workJSON(p)})
	}
	if len(result.Rows) == 0 {
		result.Summary = "No servers, VPS or Tailnet devices registered. Press t to set up a Tailnet device. Press n to deploy: create a VPS or register an existing SSH host."
	}
	if r.Kind == "servers-status" {
		kind, id, _ := strings.Cut(r.Receipt, ":")
		var status any
		if kind == "server" {
			opts, e := o.serverOptions(cmd)
			if e != nil {
				return result, e
			}
			status, err = serverdeploy.GetStatus(ctx, id, opts)
		} else if kind == "host" {
			service, e := o.vpsService(cmd)
			if e != nil {
				return result, e
			}
			status, err = service.Status(ctx, id)
		} else if kind == "tailnet" {
			service, e := o.tailnetService(cmd)
			if e != nil {
				return result, e
			}
			status, err = service.Status(ctx, id)
		} else if kind == "tailnet-proxy" {
			service, e := o.tailnetProxyService(cmd)
			if e != nil {
				return result, e
			}
			status, err = service.Status(ctx, id)
		} else {
			return result, errors.New("select a server, VPS or Tailnet resource first")
		}
		for i := range result.Rows {
			if result.Rows[i].ID == r.Receipt {
				if err != nil {
					result.Rows[i].Detail += "\n\nRefresh failed: " + err.Error()
				} else {
					result.Rows[i].Detail += "\n\nObserved status:\n" + workJSON(status)
				}
			}
		}
	}
	return result, err
}
