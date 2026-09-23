package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type setupFlags struct {
	request          managedcore.Request
	input            string
	interactive, yes bool
	expect           string
}

func (o *options) managedOptions(cmd *cobra.Command) managedcore.Options {
	opts := o.deps.Managed
	o.configureBootstrapDownloads(cmd, &opts)
	opts.ReadOnly = o.readOnly
	if opts.Open == nil {
		opts.Open = o.deps.Open
	}
	if opts.Foreground == nil {
		opts.Foreground = func(child *exec.Cmd) error {
			if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.ErrOrStderr()) {
				return usage("administrator authorization requires an interactive terminal; --json never prompts")
			}
			child.Stdin, child.Stderr = cmd.InOrStdin(), cmd.ErrOrStderr()
			return o.deps.RunEditor(child)
		}
	}
	if opts.Register == nil {
		opts.Register = func(target config.Target) error {
			cfg, path, err := o.load(cmd)
			if err != nil {
				return err
			}
			found := -1
			for i, saved := range cfg.Targets {
				if saved.ID == target.ID {
					if saved.ManagedCoreID != target.ManagedCoreID {
						return usage("target %q already belongs to another endpoint", target.ID)
					}
					found = i
				}
			}
			if found < 0 {
				cfg.Targets = append(cfg.Targets, target)
			} else {
				// Checks become destination-owned preferences after initial clone.
				// Lifecycle registration must not replay the saved source snapshot.
				target.Checks = cfg.Targets[found].Checks
				cfg.Targets[found] = target
			}
			if cfg.DefaultTarget == "" {
				cfg.DefaultTarget = target.ID
			}
			return saveSettings(path, cfg)
		}
	}
	if opts.Unregister == nil {
		opts.Unregister = func(id string) error {
			cfg, path, err := o.load(cmd)
			if err != nil {
				return err
			}
			out := cfg.Targets[:0]
			for _, target := range cfg.Targets {
				if target.ID == id && target.ManagedCoreID == id {
					continue
				}
				out = append(out, target)
			}
			cfg.Targets = out
			if cfg.DefaultTarget == id {
				cfg.DefaultTarget = ""
				if len(out) > 0 {
					cfg.DefaultTarget = out[0].ID
				}
			}
			return saveSettings(path, cfg)
		}
	}
	return opts
}

func addSetupFlags(cmd *cobra.Command, flags *setupFlags) {
	f := cmd.Flags()
	r := &flags.request
	f.StringVar(&r.CloneSourceID, "from-target", "", "clone the active portable configuration of a registered target")
	f.StringVar(&r.Client, "client", "mihomo", "mihomo or verge (Windows desktop client)")
	f.StringVar(&r.ClientVersion, "client-version", "", "exact supported desktop client version (Verge: 2.5.2)")
	f.StringVar(&r.HostOS, "host-os", "", "optional host platform: windows, linux or darwin; normally detected")
	f.StringVar(&r.Backend, "backend", "native", "native service or existing Docker daemon")
	f.StringVar(&r.InputKind, "input-kind", "links", "links, node subscription URL, or complete yaml")
	f.StringVar(&flags.input, "input", "", "local private input file; '-' reads stdin")
	f.StringVar(&r.Preset, "preset", "", "auto, cn-split, simple, or preserve (auto preserves full YAML)")
	f.StringSliceVar(&r.Categories, "category", nil, "optional rule categories: ai, apple, media-global, media-hkmt")
	f.StringToStringVar(&r.PolicyRoles, "policy", nil, "category=existing-policy mapping")
	f.IntVar(&r.ControllerPort, "controller-port", 9090, "unused loopback controller port")
	f.IntVar(&r.MixedPort, "mixed-port", 7890, "unused loopback HTTP/SOCKS port")
	f.StringVar(&r.Version, "core-version", managedcore.DefaultVersion, "exact official stable Mihomo release")
	f.StringVar(&r.ServiceScope, "service-scope", "", "user or system; host TUN requires system")
	f.BoolVar(&r.Boot, "boot", false, "enable the owned service at boot/login using existing host policy")
	f.BoolVar(&r.Network.TUN, "tun", false, "enable reviewed host TUN routing with rollback protection")
	f.BoolVar(&r.Network.SystemProxy, "system-proxy", false, "set explicitly selected supported host proxy settings")
	f.StringSliceVar(&r.Network.Services, "network-service", nil, "macOS network service(s) to configure")
	f.StringSliceVar(&r.Network.ExcludedRoutes, "exclude-route", nil, "additional destination CIDRs to bypass TUN")
	f.StringVar(&r.Network.RoutingOwner, "routing-owner", "", "record the chosen default-route owner after conflict review")
	f.StringVar(&r.DockerContext, "docker-context", "", "existing Docker context on the selected host")
	f.StringVar(&r.DockerArchive, "docker-archive", "", "absolute Docker save archive path already on the selected host")
	f.StringVar(&r.DockerArchiveSHA256, "docker-archive-sha256", "", "reviewed SHA-256 of the host-side Docker archive")
	f.StringVar(&r.BootstrapTarget, "bootstrap-target", "", "existing explicit proxy target for downloads; no automatic environment fallback")
	f.StringVar(&r.ArtifactFile, "artifact", "", "verified local release artifact for offline transfer (gzip, zip or Windows installer)")
	f.StringVar(&r.ArtifactSHA256, "artifact-sha256", "", "expected official artifact SHA-256")
	f.BoolVar(&flags.interactive, "interactive", false, "open the guided setup form with supplied values")
	f.BoolVar(&flags.yes, "yes", false, "apply exactly the reviewed plan")
	f.StringVar(&flags.expect, "expect", "", "reviewed plan digest required with --yes")
}

func (o *options) setupCommand() *cobra.Command {
	flags := &setupFlags{}
	cmd := &cobra.Command{Use: "setup [ID]", Short: "Install or clone a managed client locally or over SSH", Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usage("setup accepts at most one core ID")
		}
		return nil
	}, RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateManagedOverrides(cmd, true, false); err != nil {
			return err
		}
		defer connection.CloseAuthentications()
		if o.readOnly {
			return usage("setup is disabled in read-only mode")
		}
		if len(args) == 1 {
			flags.request.ID = args[0]
		}
		flags.request.SSHHost = o.ssh
		if flags.request.CloneSourceID != "" && (flags.input != "" || cmd.Flags().Changed("input-kind")) {
			return usage("--from-target cannot be combined with --input or --input-kind")
		}
		if flags.request.Client == "verge" && cmd.Flags().Changed("core-version") {
			return usage("Verge uses its bundled core; select --client-version instead of --core-version")
		}
		bare := len(args) == 0
		cmd.Flags().Visit(func(flag *pflag.Flag) {
			if flag.Name != "json" && flag.Name != "config" && flag.Name != "ssh" {
				bare = false
			}
		})
		interactive := flags.interactive || bare && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())
		if flags.interactive && (o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
			return usage("interactive setup requires a terminal and cannot use --json")
		}
		if interactive {
			return o.runSetupWizard(cmd, flags.request, "", flags.input)
		}
		if flags.request.ID == "" || flags.input == "" && flags.request.CloneSourceID == "" {
			return usage("supply ID and either --from-target SOURCE or --input FILE; run bare setup in a terminal for the wizard")
		}
		if flags.yes && flags.expect == "" {
			return usage("--yes requires the reviewed --expect digest")
		}
		if flags.request.CloneSourceID == "" {
			if err := loadSetupInput(cmd, &flags.request, flags.input); err != nil {
				return err
			}
		}
		cfg, _, err := o.load(cmd)
		if err != nil {
			return err
		}
		for _, target := range cfg.Targets {
			if target.ID == flags.request.ID {
				return usage("target ID %q is already registered; use cores configure or another ID", target.ID)
			}
		}
		return o.runManagedPreviewApply(cmd, flags.request, "", flags.yes, flags.expect)
	}}
	addSetupFlags(cmd, flags)
	return cmd
}

func loadSetupInput(cmd *cobra.Command, request *managedcore.Request, path string) error {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 8<<20+1))
	} else {
		info, e := os.Stat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return usage("input must be a readable regular file no larger than 8 MiB")
		}
		data, err = os.ReadFile(path)
		absolute, e := filepath.Abs(path)
		if e == nil {
			request.InputBaseDir = filepath.Dir(absolute)
		}
	}
	if err != nil || len(data) > 8<<20 {
		return usage("cannot read bounded setup input")
	}
	request.Input = data
	return nil
}

func (o *options) runManagedPreviewApply(cmd *cobra.Command, request managedcore.Request, configureID string, yes bool, expect string) error {
	if err := o.rejectRPiTakeover(cmd, request.ID, request.SSHHost); err != nil {
		return err
	}
	opts := o.managedOptions(cmd)
	var plan managedcore.Plan
	var receipt managedcore.Receipt
	preparedCtx := cmd.Context()
	err := o.authenticatedDiagnostic(cmd, config.Target{SSHHost: request.SSHHost}, func() error {
		var e error
		if configureID == "" {
			preparedCtx, request, e = o.prepareSetupRequest(cmd.Context(), cmd, request, opts)
			if e != nil {
				return e
			}
		}
		if configureID == "" {
			plan, e = managedcore.Preview(preparedCtx, request, opts)
		} else {
			plan, e = managedcore.PreviewConfigure(preparedCtx, configureID, request, opts)
		}
		return e
	})
	if err == nil && yes {
		// Re-read the source immediately before the single guarded apply. A
		// changed active profile or selection produces a different plan digest.
		if configureID == "" {
			preparedCtx, request, err = o.prepareSetupRequest(cmd.Context(), cmd, request, opts)
		}
		if err == nil {
			if configureID == "" {
				receipt, err = managedcore.Apply(preparedCtx, request, expect, opts)
			} else {
				receipt, err = managedcore.Configure(preparedCtx, configureID, request, expect, opts)
			}
		}
	}

	if yes && receipt.ID != "" {
		if outputErr := o.output(cmd, receipt); outputErr != nil {
			return outputErr
		}
	} else if !yes && plan.ID != "" {
		if outputErr := o.output(cmd, plan); outputErr != nil {
			return outputErr
		}
	}
	return err
}

func (o *options) prepareSetupRequest(ctx context.Context, cmd *cobra.Command, request managedcore.Request, opts managedcore.Options) (context.Context, managedcore.Request, error) {
	if request.HostOS == "" && opts.Execute == nil {
		platform, err := connection.DetectHostOS(ctx, request.SSHHost)
		if err != nil {
			return ctx, request, err
		}
		request.HostOS = platform
	}
	if request.CloneSourceID == "" {
		return ctx, request, nil
	}
	if request.CloneSourceID == request.ID {
		return ctx, request, usage("clone destination must differ from the source target")
	}
	cfg, _, err := o.load(cmd)
	if err != nil {
		return ctx, request, err
	}
	i, err := targetIndex(cfg, request.CloneSourceID)
	if err != nil {
		return ctx, request, err
	}
	snapshot, err := managedcore.SnapshotTarget(ctx, o.overrideCredentials(cfg.Targets[i]), opts)
	if err != nil {
		return ctx, request, err
	}
	return managedcore.ApplyCloneToRequest(ctx, request, snapshot)
}

func (o *options) runSetupWizard(cmd *cobra.Command, request managedcore.Request, configureID, inputPath string) error {
	message := "Create an owned instance; existing cores and VPNs are not taken over."
	var draft map[string]string
	for {
		view := request
		if configureID != "" {
			view.CloneSourceID = ""
		}
		spec := setupSpec(view, inputPath, message)
		if configureID != "" {
			fields := spec.Fields[:0]
			for _, f := range spec.Fields {
				if f.Key == "from_target" {
					continue
				}
				if f.Key == "kind" {
					choices := f.Options[:0]
					for _, c := range f.Options {
						if c.Value != "target" {
							choices = append(choices, c)
						}
					}
					f.Options = choices
				}
				fields = append(fields, f)
			}
			spec.Fields = fields
		}
		cfg, _, loadErr := o.load(cmd)
		if loadErr != nil {
			return loadErr
		}
		for i := range spec.Fields {
			if spec.Fields[i].Key == "from_target" {
				spec.Fields[i].Kind = wizard.Select
				spec.Fields[i].Options = []wizard.Choice{{Value: "", Label: "Choose a source target"}}
				for _, t := range cfg.Targets {
					spec.Fields[i].Options = append(spec.Fields[i].Options, wizard.Choice{Value: t.ID, Label: t.Label()})
				}
			}

			if value, ok := draft[spec.Fields[i].Key]; ok {
				spec.Fields[i].Value = value
			}
		}
		values, err := wizard.Edit(cmd.Context(), spec, cmd.InOrStdin(), cmd.OutOrStdout())
		if errors.Is(err, wizard.ErrCanceled) {
			return nil
		}
		if err != nil {
			return err
		}
		draft = values
		prepareSetupDraftTransition(&request, configureID, values["kind"], values["from_target"], values["ssh"], cmd.Flags().Changed("host-os"))
		request.ID, request.Name, request.SSHHost, request.Backend, request.InputKind = values["id"], values["name"], values["ssh"], values["backend"], values["kind"]
		request.Preset, request.ServiceScope, request.DockerContext = values["preset"], values["scope"], values["docker"]
		request.Client, request.ClientVersion = values["client"], values["client_version"]
		if request.InputKind == "target" {
			if request.CloneSourceID == "" {
				message = "Choose a source target"
				continue
			}
		}
		request.BootstrapTarget = values["bootstrap"]
		request.DockerArchive = values["docker_archive"]
		request.DockerArchiveSHA256 = values["docker_archive_sha"]
		request.Categories = splitNonempty(values["categories"])
		request.PolicyRoles = map[string]string{}
		policyInvalid := false
		for _, role := range splitNonempty(values["policies"]) {
			parts := strings.SplitN(role, "=", 2)
			if len(parts) == 2 {
				request.PolicyRoles[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			} else {
				message = "Policy roles use category=GROUP"
				policyInvalid = true
			}
		}
		if policyInvalid {
			continue
		}
		if configureID == "" {
			if _, exists := targetIndex(cfg, request.ID); exists == nil {
				message = fmt.Sprintf("Target ID %q is already registered; choose another ID or use cores configure", request.ID)
				continue
			}
		}
		request.Version = values["version"]
		request.ArtifactFile = values["artifact"]
		request.Network.TUN = values["tun"] == "true"
		request.Network.SystemProxy = values["proxy"] == "true"
		request.Boot = values["boot"] == "true"
		request.ControllerPort, err = strconv.Atoi(values["controller_port"])
		if err != nil {
			message = "Controller port must be a number"
			continue
		}
		request.MixedPort, err = strconv.Atoi(values["mixed_port"])
		if err != nil {
			message = "HTTP/SOCKS port must be a number"
			continue
		}
		request.Network.Services = splitNonempty(values["services"])
		request.Network.ExcludedRoutes = splitNonempty(values["excluded"])
		inputPath = values["file"]
		if configureID == "" && request.CloneSourceID != "" {
			request.Input = nil
		} else if request.InputKind == "yaml" {
			if inputPath != "" || len(request.Input) == 0 {
				if err := loadSetupInput(cmd, &request, inputPath); err != nil {
					message = err.Error()
					continue
				}
			}
		} else {
			request.Input = []byte(values["nodes"])
		}
		if err := o.rejectRPiTakeover(cmd, request.ID, request.SSHHost); err != nil {
			message = err.Error()
			continue
		}
		opts := o.managedOptions(cmd)
		var plan managedcore.Plan
		preparedCtx := cmd.Context()
		err = o.authenticatedDiagnostic(cmd, config.Target{SSHHost: request.SSHHost}, func() error {
			var e error
			if configureID == "" {
				preparedCtx, request, e = o.prepareSetupRequest(cmd.Context(), cmd, request, opts)
				if e != nil {
					return e
				}
			}
			if configureID == "" {
				plan, e = managedcore.Preview(preparedCtx, request, opts)
			} else {
				plan, e = managedcore.PreviewConfigure(preparedCtx, configureID, request, opts)
			}
			return e
		})
		if err != nil {
			message = err.Error()
			continue
		}
		if len(plan.Blockers) > 0 {
			message = strings.Join(plan.Blockers, "\n")
			continue
		}
		accepted, err := wizard.Confirm(cmd.Context(), "Review managed core setup", workJSON(plan), cmd.InOrStdin(), cmd.OutOrStdout())
		if err != nil {
			return err
		}
		if !accepted {
			message = "Review canceled; your draft is retained."
			continue
		}
		var receipt managedcore.Receipt
		if configureID == "" {
			preparedCtx, request, err = o.prepareSetupRequest(cmd.Context(), cmd, request, opts)
			if err != nil {
				return err
			}
		}
		if configureID == "" {
			receipt, err = managedcore.Apply(preparedCtx, request, plan.Digest, opts)
		} else {
			receipt, err = managedcore.Configure(preparedCtx, configureID, request, plan.Digest, opts)
		}
		if receipt.ID != "" {
			_ = o.output(cmd, receipt)
		}
		if err != nil {
			return err
		}
		return nil
	}
}

// A new setup draft must rebuild its clone snapshot for each preview. Configure
// keeps the destination's independent snapshot and recorded platform instead.
func prepareSetupDraftTransition(request *managedcore.Request, configureID, kind, sourceID, sshHost string, explicitHostOS bool) {
	if configureID != "" {
		return
	}
	if request.SSHHost != sshHost && !explicitHostOS {
		request.HostOS = ""
	}
	hadClone := request.CloneSourceID != "" || request.CloneSourceSHA256 != "" || len(request.CloneSelections) > 0 || len(request.CloneChecks) > 0
	if kind == "target" || hadClone {
		request.Input, request.InputBaseDir = nil, ""
		request.CloneSourceID, request.CloneSourceSHA256 = "", ""
		request.CloneSelections, request.CloneChecks = nil, nil
	}
	if kind == "target" {
		request.CloneSourceID = sourceID
	}
}

func splitNonempty(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}

func setupSpec(request managedcore.Request, path, message string) wizard.Spec {
	if request.Client == "" {
		request.Client = "mihomo"
	}
	if request.CloneSourceID != "" {
		request.InputKind = "target"
	}
	if request.Backend == "" {
		request.Backend = "native"
	}
	if request.InputKind == "" {
		request.InputKind = "links"
	}
	if request.Preset == "" {
		request.Preset = "auto"
	}
	if request.ServiceScope == "" {
		request.ServiceScope = "user"
		if request.Network.TUN {
			request.ServiceScope = "system"
		}
	}
	if request.Version == "" {
		request.Version = managedcore.DefaultVersion
	}
	nodes := string(request.Input)
	if request.InputKind == "yaml" {
		nodes = ""
	}
	if request.ControllerPort == 0 {
		request.ControllerPort = 9090
	}
	if request.MixedPort == 0 {
		request.MixedPort = 7890
	}
	return wizard.Spec{Title: "Deploy client", Description: message, SubmitLabel: "Preview", Fields: []wizard.Field{
		{Key: "id", Label: "Core ID", Value: request.ID, Required: true}, {Key: "name", Label: "Display name", Value: request.Name}, {Key: "ssh", Label: "SSH host (empty = local)", Value: request.SSHHost},
		{Key: "client", Label: "Client", Value: request.Client, Kind: wizard.Select, Options: []wizard.Choice{{Value: "mihomo", Label: "Background Mihomo"}, {Value: "verge", Label: "Clash Verge Rev (Windows desktop)"}}},
		{Key: "client_version", Label: "Desktop client version", Value: request.ClientVersion, Help: "Verge default: 2.5.2; its bundled core is used"},
		{Key: "from_target", Label: "Source target to copy", Value: request.CloneSourceID},
		{Key: "backend", Label: "Backend", Value: request.Backend, Kind: wizard.Select, Options: []wizard.Choice{{Value: "native", Label: "Native service"}, {Value: "docker", Label: "Existing Docker daemon"}}},
		{Key: "kind", Label: "Input format", Value: request.InputKind, Kind: wizard.Select, Options: []wizard.Choice{{Value: "target", Label: "Copy an existing target"}, {Value: "links", Label: "Node share links/YAML"}, {Value: "subscription", Label: "Node subscription HTTPS URL"}, {Value: "yaml", Label: "Complete YAML file"}}},
		{Key: "nodes", Label: "Private node links or subscription URL", Value: nodes, Kind: wizard.Multiline}, {Key: "file", Label: "Complete YAML local file", Value: path},
		{Key: "preset", Label: "Routing preset", Value: request.Preset, Kind: wizard.Select, Options: []wizard.Choice{{Value: "auto", Label: "Auto: preserve full YAML; otherwise China split"}, {Value: "cn-split", Label: "China direct / rest proxy"}, {Value: "simple", Label: "Local/VPN bypass / rest proxy"}, {Value: "preserve", Label: "Preserve complete profile rules"}}},
		{Key: "scope", Label: "Service ownership", Value: request.ServiceScope, Kind: wizard.Select, Options: []wizard.Choice{{Value: "system", Label: "System service (required for host TUN)"}, {Value: "user", Label: "User service / explicit proxy"}}},
		{Key: "tun", Label: "Host TUN", Value: strconv.FormatBool(request.Network.TUN), Kind: wizard.Toggle}, {Key: "proxy", Label: "Host system proxy", Value: strconv.FormatBool(request.Network.SystemProxy), Kind: wizard.Toggle}, {Key: "boot", Label: "Start at boot/login", Value: strconv.FormatBool(request.Boot), Kind: wizard.Toggle},
		{Key: "services", Label: "macOS network services (comma separated)", Value: strings.Join(request.Network.Services, ",")}, {Key: "excluded", Label: "Additional bypass CIDRs (comma separated)", Value: strings.Join(request.Network.ExcludedRoutes, ",")},
		{Key: "controller_port", Label: "Controller port", Value: strconv.Itoa(request.ControllerPort)}, {Key: "mixed_port", Label: "HTTP/SOCKS port", Value: strconv.Itoa(request.MixedPort)}, {Key: "docker_archive", Label: "Offline Docker archive on host", Value: request.DockerArchive, Help: "Absolute Docker save archive already on selected host"},
		{Key: "docker_archive_sha", Label: "Docker archive SHA-256", Value: request.DockerArchiveSHA256},
		{Key: "bootstrap", Label: "Bootstrap proxy target", Value: request.BootstrapTarget, Help: "Optional existing target used only for downloads"},
		{Key: "categories", Label: "Optional rule categories", Value: strings.Join(request.Categories, ","), Help: "Comma-separated ai,apple,media-global,media-hkmt"},
		{Key: "policies", Label: "Category policy roles", Value: policyText(request.PolicyRoles), Help: "category=GROUP, comma-separated"},
		{Key: "version", Label: "Core version", Value: request.Version, Help: "Exact official stable release"},
		{Key: "artifact", Label: "Offline native artifact", Value: request.ArtifactFile, Help: "Optional local verified gzip"},
		{Key: "docker", Label: "Docker context", Value: request.DockerContext},
	}}
}

func policyText(values map[string]string) string {
	var out []string
	for key, value := range values {
		out = append(out, key+"="+value)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func managedFlagChanged(cmd *cobra.Command, name string) bool {
	return cmd.Flags().Changed(name) || cmd.InheritedFlags().Changed(name)
}

// Reject known owner collisions before setup or lifecycle code contacts a host.
func (o *options) rejectRPiTakeover(cmd *cobra.Command, id, ssh string) error {
	cfg, _, err := o.load(cmd)
	if err != nil {
		return err
	}
	sshHost := ssh
	if i := strings.LastIndexByte(sshHost, '@'); i >= 0 {
		sshHost = sshHost[i+1:]
	}
	for _, target := range cfg.Targets {
		if target.ManagedRPi == nil {
			continue
		}
		endpoint, _ := url.Parse(target.Controller)
		if target.ID == id || ssh != "" && (target.SSHHost == ssh || endpoint != nil && endpoint.Hostname() == sshHost) {
			return usage("target %q belongs to RPi-ImmortalWrt; generic setup and core lifecycle cannot take over its owner", target.ID)
		}
	}
	return nil
}

func validateManagedOverrides(cmd *cobra.Command, allowSSH, allowTarget bool) error {
	names := []string{"controller", "secret-env", "secret-file", "ca-cert"}
	if !allowSSH {
		names = append(names, "ssh")
	}
	if !allowTarget {
		names = append(names, "target")
	}
	for _, name := range names {
		if managedFlagChanged(cmd, name) {
			return usage("%s does not accept --%s; managed operations use the reviewed or recorded owner", cmd.CommandPath(), name)
		}
	}
	return nil
}
