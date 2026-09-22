package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (o *options) vpsService(cmd *cobra.Command) (*vps.Service, error) {
	store, err := o.serverStore(cmd)
	if err != nil {
		return nil, err
	}
	opts := o.deps.VPS
	opts.ReadOnly = o.readOnly
	return vps.New(store, opts), nil
}

func (o *options) vpsCommand() *cobra.Command {
	group := &cobra.Command{Use: "vps", Short: "Compare, create and manage proxy-server VPS hosts through official cloud CLIs"}
	group.AddCommand(o.vpsEstimateCommand(), o.vpsGuideCommand(), o.vpsBindCloudCommand(), o.vpsUsageCommand())
	group.AddCommand(&cobra.Command{Use: "catalog", Short: "Show dated price snapshots and recommended VPS starting sizes", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error { return o.output(cmd, vps.Catalog()) }})
	group.AddCommand(&cobra.Command{Use: "list", Short: "List remembered cloud and existing SSH hosts without connecting", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		v, e := s.List()
		if e != nil {
			return e
		}
		return o.output(cmd, v)
	}})
	var q vps.CreateRequest
	quote := &cobra.Command{Use: "quote", Short: "Read a live provider plan price without creating resources", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if e := vps.ValidateDraft(q); e != nil {
			return usage("%s", e)
		}
		if q.Provider == "" || q.Plan == "" {
			return usage("quote requires --provider and --plan")
		}
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		v, e := s.Quote(cmd.Context(), q)
		if e != nil {
			return e
		}
		return o.output(cmd, v)
	}}
	quote.Flags().StringVar(&q.Provider, "provider", "", vpsProviderHelp)
	quote.Flags().StringVar(&q.Plan, "plan", "", "provider plan ID")
	quote.Flags().StringVar(&q.Region, "region", "", "provider region")
	quote.Flags().StringVar(&q.Profile, "profile", "", "official CLI profile (Vultr: config file path)")
	vpsCloudFlags(quote.Flags(), &q)
	group.AddCommand(quote)
	var discoverReq vps.CreateRequest
	var discoverKind string
	discover := &cobra.Command{Use: "discover", Short: "List live regions, small plans, Ubuntu images or SSH keys", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		if e := vps.ValidateDraft(discoverReq); e != nil {
			return usage("%s", e)
		}
		if discoverReq.Provider == "" || discoverKind == "" {
			return usage("discover requires --provider and --kind")
		}
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		choices, e := s.Discover(cmd.Context(), discoverReq, discoverKind)
		if e != nil {
			return e
		}
		return o.output(cmd, choices)
	}}
	discover.Flags().StringVar(&discoverReq.Provider, "provider", "", "cloud provider")
	discover.Flags().StringVar(&discoverReq.Profile, "profile", "", "official CLI profile")
	discover.Flags().StringVar(&discoverReq.Region, "region", "", "region for plans/images")
	discover.Flags().StringVar(&discoverReq.Plan, "plan", "", "selected plan for architecture-compatible images and zones")
	vpsCloudFlags(discover.Flags(), &discoverReq)
	discover.Flags().StringVar(&discoverReq.TenancyID, "tenancy", "", "Oracle tenancy OCID")
	discover.Flags().StringVar(&discoverReq.CompartmentID, "compartment", "", "Oracle compartment OCID")
	discover.Flags().StringVar(&discoverKind, "kind", "", "regions, plans, images, keys; Azure/AWS zones; Azure subscriptions; Oracle ads/compartments")
	group.AddCommand(discover)
	var req vps.CreateRequest
	var yes, interactive bool
	var expect string
	create := &cobra.Command{Use: "create [ID]", Short: "Preview a VM; apply with --yes --expect DIGEST, or open the bare create wizard", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			req.ID = args[0]
		}
		if err := vps.ValidateDraft(req); err != nil {
			return usage("%s", err)
		}
		if yes && o.readOnly {
			return usage("VPS creation is disabled in read-only mode")
		}
		if yes && expect == "" {
			return usage("--yes requires --expect DIGEST")
		}
		business := false
		cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
			if f.Changed && f.Name != "interactive" && f.Name != "help" {
				business = true
			}
		})
		bare := len(args) == 0 && !business
		if interactive || (bare && !o.json && o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout())) {
			if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
				return usage("--interactive requires a terminal and cannot be used with --json")
			}
			h, e := o.runVPSCreateWizard(cmd, req)
			if e != nil {
				return e
			}
			return o.output(cmd, h)
		}
		if bare {
			if o.json {
				return usage("vps create --json requires ID, --provider, --region and --ssh-key")
			}
			return cmd.Help()
		}
		if e := vps.ValidateRequest(req); e != nil {
			return usage("%s", e)
		}
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		if !yes {
			p, e := s.PlanCreate(cmd.Context(), req)
			if e != nil {
				return e
			}
			return o.output(cmd, p)
		}
		p, e := s.PlanCreate(cmd.Context(), req)
		if e != nil {
			return e
		}
		if p.Request != nil {
			req = *p.Request
		}
		h, e := s.Create(cmd.Context(), req, expect)
		if h.ID != "" {
			if out := o.output(cmd, h); out != nil {
				return out
			}
		}
		return e
	}}
	vpsCreateFlags(create.Flags(), &req, "0.0.0.0/0")
	create.Flags().BoolVar(&yes, "yes", false, "create the exactly reviewed VM")
	create.Flags().StringVar(&expect, "expect", "", "reviewed preview digest")
	create.Flags().BoolVar(&interactive, "interactive", false, "select and review VPS settings in a terminal wizard")
	group.AddCommand(create)
	var host serverstate.Host
	var registerInteractive bool
	register := &cobra.Command{Use: "register [ID]", Short: "Remember an existing cloud VM or homelab SSH host", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if o.readOnly {
			return usage("VPS registration is disabled in read-only mode")
		}
		if len(args) > 0 {
			host.ID = args[0]
		}
		if registerInteractive {
			if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
				return usage("--interactive requires a terminal and cannot be combined with --json")
			}
			vals, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Register existing server", SubmitLabel: "Save host", Fields: []wizard.Field{{Key: "id", Label: "Host ID", Value: host.ID, Required: true}, {Key: "name", Label: "Display name", Value: host.Name}, {Key: "ssh", Label: "SSH management host / alias", Value: host.SSHHost, Required: true}, {Key: "public", Label: "Public client address", Value: host.PublicHost, Required: true}}}, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
			host.ID = vals["id"]
			host.Name = vals["name"]
			host.SSHHost = vals["ssh"]
			host.PublicHost = vals["public"]
		}
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		h, e := s.Register(host)
		if e != nil {
			return e
		}
		return o.output(cmd, h)
	}}
	register.Flags().StringVar(&host.Name, "name", "", "display name")
	register.Flags().StringVar(&host.SSHHost, "ssh-host", "", "SSH alias or user@hostname used for management")
	register.Flags().StringVar(&host.PublicHost, "public-host", "", "public DNS name or IP used by proxy clients")
	register.Flags().StringVar(&host.Provider, "provider", "ssh", "descriptive provider name (azure, racknerd, homelab, ssh)")
	register.Flags().BoolVar(&registerInteractive, "interactive", false, "collect host details interactively")
	group.AddCommand(register)
	for _, action := range []string{"status"} {
		group.AddCommand(&cobra.Command{Use: action + " ID", Short: map[string]string{"status": "Refresh VM status and public endpoint", "resume": "Reconcile a pending create without issuing a second create"}[action], Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
			s, e := o.vpsService(cmd)
			if e != nil {
				return e
			}
			var h serverstate.Host
			if action == "resume" {
				if o.readOnly {
					return usage("resume saves recovered inventory and is disabled in read-only mode")
				}
				h, e = s.Resume(cmd.Context(), args[0])
			} else {
				h, e = s.Status(cmd.Context(), args[0])
			}
			if e != nil {
				return e
			}
			return o.output(cmd, h)
		}})
	}
	var resumeYes bool
	var reconcileOnly bool
	var resumeExpect string
	resume := &cobra.Command{Use: "resume ID", Short: "Preview recovery; apply --yes --expect DIGEST to reconcile and finish an unsubmitted create", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		if reconcileOnly {
			if resumeYes || resumeExpect != "" {
				return usage("--reconcile-only cannot be combined with --yes or --expect")
			}
			if o.readOnly {
				return usage("reconciliation saves recovered inventory and is disabled in read-only mode")
			}
			h, e := s.Resume(cmd.Context(), args[0])
			if e != nil {
				return e
			}
			return o.output(cmd, h)
		}
		if !resumeYes {
			p, e := s.PlanResume(cmd.Context(), args[0])
			if e != nil {
				return e
			}
			return o.output(cmd, p)
		}
		if o.readOnly {
			return usage("VPS recovery is disabled in read-only mode")
		}
		if resumeExpect == "" {
			return usage("--yes requires --expect DIGEST")
		}
		h, e := s.Resume(cmd.Context(), args[0], resumeExpect)
		if e != nil {
			return e
		}
		return o.output(cmd, h)
	}}
	resume.Flags().BoolVar(&resumeYes, "yes", false, "apply the reviewed recovery")
	resume.Flags().BoolVar(&reconcileOnly, "reconcile-only", false, "find and save existing resources without creating or attaching any cloud resource")
	resume.Flags().StringVar(&resumeExpect, "expect", "", "reviewed recovery digest")
	group.AddCommand(resume)
	for _, action := range []string{"start", "stop", "reboot", "delete"} {
		var apply bool
		var digest string
		cmd := &cobra.Command{Use: action + " ID", Short: "Preview VM " + action + "; apply with --yes --expect DIGEST", Args: argsExact(1), RunE: func(cmd *cobra.Command, args []string) error {
			if apply && o.readOnly {
				return usage("VPS changes are disabled in read-only mode")
			}
			if apply && digest == "" {
				return usage("--yes requires --expect DIGEST")
			}
			s, e := o.vpsService(cmd)
			if e != nil {
				return e
			}
			if !apply {
				p, e := s.PlanAction(cmd.Context(), args[0], action)
				if e != nil {
					return e
				}
				return o.output(cmd, p)
			}
			h, e := s.Action(cmd.Context(), args[0], action, digest)
			if e != nil {
				return e
			}
			return o.output(cmd, h)
		}}
		cmd.Flags().BoolVar(&apply, "yes", false, "apply the reviewed cloud operation")
		cmd.Flags().StringVar(&digest, "expect", "", "reviewed digest")
		group.AddCommand(cmd)
	}
	var manageInteractive bool
	manage := &cobra.Command{Use: "manage [ID]", Short: "Select an existing host and review its cloud actions", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if o.json || !o.deps.Terminal(cmd.InOrStdin(), cmd.OutOrStdout()) {
			return usage("vps manage requires a terminal; use status/start/stop/reboot/delete for scripts")
		}
		s, e := o.vpsService(cmd)
		if e != nil {
			return e
		}
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		if id == "" {
			hosts, e := s.List()
			if e != nil {
				return e
			}
			var choices []wizard.Choice
			for _, h := range hosts {
				choices = append(choices, wizard.Choice{Value: h.ID, Label: h.ID + " · " + h.Provider + " · " + h.Status})
			}
			if len(choices) == 0 {
				return fmt.Errorf("no VPS hosts; use vps create or vps register")
			}
			id, e = wizard.Choose(cmd.Context(), "Select VPS", choices, cmd.InOrStdin(), cmd.OutOrStdout())
			if e != nil {
				return e
			}
		}
		choices := []wizard.Choice{{Value: "status", Label: "Refresh status"}}
		if !o.readOnly {
			for _, a := range []string{"start", "stop", "reboot", "delete"} {
				choices = append(choices, wizard.Choice{Value: a, Label: a})
			}
		}
		a, e := wizard.Choose(cmd.Context(), "Manage "+id, choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if a == "status" {
			h, e := s.Status(cmd.Context(), id)
			if e != nil {
				return e
			}
			return o.output(cmd, h)
		}
		p, e := s.PlanAction(cmd.Context(), id, a)
		if e != nil {
			return e
		}
		ok, e := wizard.Confirm(cmd.Context(), "Review VPS "+a, workJSON(p), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return e
		}
		if !ok {
			return wizard.ErrCanceled
		}
		h, e := s.Action(cmd.Context(), id, a, p.Digest)
		if e != nil {
			return e
		}
		return o.output(cmd, h)
	}}
	manage.Flags().BoolVar(&manageInteractive, "interactive", false, "open the VPS action picker")
	group.AddCommand(manage)
	return group
}

func (o *options) runVPSCreateWizard(cmd *cobra.Command, req vps.CreateRequest) (host serverstate.Host, err error) {
	defer func() {
		if err == nil || req.Provider == "" || errors.Is(err, wizard.ErrCanceled) || errors.Is(err, context.Canceled) {
			return
		}
		binary, e := os.Executable()
		if e != nil {
			binary = "lazyclash"
		}
		parts := []string{guideQuote(binary), "vps guide --provider", guideQuote(req.Provider)}
		for _, flag := range []struct{ name, value string }{{"--profile", req.Profile}, {"--region", req.Region}, {"--subscription", req.SubscriptionID}, {"--config", o.path}, {"--servers-config", o.serversPath}} {
			if flag.value != "" {
				parts = append(parts, flag.name, guideQuote(flag.value))
			}
		}
		install := ""
		if provider, ok := vpsGuideProviders[req.Provider]; ok {
			if _, lookupErr := exec.LookPath(provider.cli); lookupErr != nil {
				install = fmt.Sprintf("\n%s is missing from PATH. On macOS with Homebrew: brew install %s", provider.cli, provider.formula)
			}
		}
		err = fmt.Errorf("%w%s\nCLI setup and copyable diagnostic/deployment steps: %s", err, install, strings.Join(parts, " "))
	}()
	if err := vps.ValidateDraft(req); err != nil {
		return serverstate.Host{}, usage("%s", err)
	}
	if o.readOnly {
		return serverstate.Host{}, usage("VPS creation is disabled in read-only mode")
	}
	if req.Provider == "" {
		v, e := wizard.Choose(cmd.Context(), "VPS provider", vpsProviderChoices(), cmd.InOrStdin(), cmd.OutOrStdout())
		if e != nil {
			return serverstate.Host{}, e
		}
		req.Provider = v
	}
	if req.SSHCIDR == "" {
		req.SSHCIDR = "0.0.0.0/0"
	}
	fields := []wizard.Field{{Key: "id", Label: "Host ID", Value: req.ID, Required: true}}
	if req.Provider != "azure" {
		fields = append(fields, wizard.Field{Key: "profile", Label: "Official CLI profile (optional; Vultr: config path)", Value: req.Profile})
	}
	fields = append(fields, wizard.Field{Key: "ssh_cidr", Label: "SSH administrator CIDR", Value: req.SSHCIDR, Required: true})
	if vpsUsesPublicKeyFile(req.Provider) {
		fields = append(fields, wizard.Field{Key: "key", Label: "SSH public key file", Value: req.SSHKey, Required: true})
	}
	fields = append(fields, vpsCloudWizardFields(req)...)
	if req.Provider == "oracle" {
		fields = append(fields, wizard.Field{Key: "tenancy", Label: "Tenancy OCID (from your OCI CLI profile)", Value: req.TenancyID, Required: true})
	}
	values, e := wizard.Edit(cmd.Context(), wizard.Spec{Title: "Create " + req.Provider + " VPS", Description: "Uses your authenticated official provider CLI. Next, choose from live regions, small plans, Ubuntu images and SSH keys before reviewing creation.", SubmitLabel: "Read available options", Fields: fields}, cmd.InOrStdin(), cmd.OutOrStdout())
	if e != nil {
		return serverstate.Host{}, e
	}
	req.ID = values["id"]
	req.Profile = values["profile"]
	req.SSHCIDR = values["ssh_cidr"]
	if vpsUsesPublicKeyFile(req.Provider) {
		req.SSHKey = values["key"]
	}
	if e = vpsApplyCloudWizardFields(&req, values); e != nil {
		return serverstate.Host{}, e
	}
	if req.Provider == "oracle" {
		req.TenancyID = values["tenancy"]
	}
	if e = vps.ValidateDraft(req); e != nil {
		return serverstate.Host{}, usage("%s", e)
	}
	s, e := o.vpsService(cmd)
	if e != nil {
		return serverstate.Host{}, e
	}
	choose := func(kind string, destination *string) error {
		if *destination != "" {
			return nil
		}
		available, err := s.Discover(cmd.Context(), req, kind)
		if err != nil {
			return err
		}
		choices := make([]wizard.Choice, 0, len(available))
		for _, c := range available {
			choices = append(choices, wizard.Choice{Value: c.ID, Label: c.Label})
		}
		if len(choices) == 1 {
			*destination = choices[0].Value
			return nil
		}
		value, err := wizard.Choose(cmd.Context(), "Select "+kind, choices, cmd.InOrStdin(), cmd.OutOrStdout())
		if err == nil {
			*destination = value
		}
		return err
	}
	if e = choose("regions", &req.Region); e != nil {
		return serverstate.Host{}, e
	}
	if req.Provider == "oracle" {
		if e = choose("compartments", &req.CompartmentID); e != nil {
			return serverstate.Host{}, e
		}
		if e = choose("ads", &req.AvailabilityDomain); e != nil {
			return serverstate.Host{}, e
		}
	}
	if e = choose("plans", &req.Plan); e != nil {
		return serverstate.Host{}, e
	}
	if e = choose("images", &req.Image); e != nil {
		return serverstate.Host{}, e
	}
	if req.Provider == "digitalocean" || req.Provider == "vultr" {
		if e = choose("keys", &req.SSHKey); e != nil {
			return serverstate.Host{}, e
		}
	}
	p, e := s.PlanCreate(cmd.Context(), req)
	if e != nil {
		return serverstate.Host{}, e
	}
	ok, e := wizard.Confirm(cmd.Context(), "Review new cloud VM", workJSON(p), cmd.InOrStdin(), cmd.OutOrStdout())
	if e != nil {
		return serverstate.Host{}, e
	}
	if !ok {
		return serverstate.Host{}, wizard.ErrCanceled
	}
	if p.Request != nil {
		req = *p.Request
	}
	return s.Create(cmd.Context(), req, p.Digest)
}

const vpsProviderHelp = "oracle, vultr, linode, digitalocean, azure, aws-lightsail, aws-ec2"

func vpsCreateFlags(flags *pflag.FlagSet, req *vps.CreateRequest, defaultSSHCIDR string) {
	flags.StringVar(&req.Name, "name", "", "cloud display name (default: ID)")
	flags.StringVar(&req.Provider, "provider", "", vpsProviderHelp)
	flags.StringVar(&req.Profile, "profile", "", "official CLI profile (Vultr: config file path)")
	flags.StringVar(&req.Region, "region", "", "provider region")
	flags.StringVar(&req.Plan, "plan", "", "provider plan (default: 1 GB baseline; Azure/AWS select a low fixed-cost compatible plan)")
	flags.StringVar(&req.Image, "image", "", "Ubuntu 24.04 image ID; Azure/AWS resolve a fixed matching image during preview")
	flags.StringVar(&req.SSHKey, "ssh-key", "", "DO/Vultr provider key ID; other providers: SSH public key file")
	flags.StringVar(&req.SSHUser, "ssh-user", "", "SSH user (root, or ubuntu for Oracle/Azure/AWS)")
	vpsCloudFlags(flags, req)
	flags.StringVar(&req.SSHCIDR, "ssh-cidr", defaultSSHCIDR, "SSH ingress CIDR for owned cloud firewall (restrict to your administrator IP when possible)")
	flags.StringVar(&req.FirewallID, "firewall", "", "reuse an existing cloud firewall/NSG (never owned or deleted)")
	flags.StringVar(&req.TenancyID, "tenancy", "", "Oracle tenancy OCID")
	flags.StringVar(&req.CompartmentID, "compartment", "", "Oracle compartment OCID")
	flags.StringVar(&req.SubnetID, "subnet", "", "Oracle existing public subnet OCID (blank: create owned public network)")
	flags.StringVar(&req.AvailabilityDomain, "availability-domain", "", "Oracle availability domain")
}

func vpsCloudFlags(flags *pflag.FlagSet, req *vps.CreateRequest) {
	flags.StringVar(&req.SubscriptionID, "subscription", "", "Azure subscription ID (does not change the CLI default)")
	flags.StringVar(&req.Architecture, "architecture", "auto", "auto, amd64 or arm64; auto allows compatible ARM plans")
	flags.StringVar(&req.AvailabilityZone, "availability-zone", "", "Azure/AWS availability zone (blank: resolve a compatible zone during preview)")
	flags.IntVar(&req.DiskGB, "disk-gb", 0, "Azure/EC2 root disk GiB (0: Azure 32 GiB Standard SSD or EC2 20 GiB encrypted gp3)")
}

func vpsProviderChoices() []wizard.Choice {
	return []wizard.Choice{
		{Value: "oracle", Label: "Oracle · strictly checked Always Free A1"},
		{Value: "vultr", Label: "Vultr · 1 GB, many regions"},
		{Value: "linode", Label: "Linode / Akamai · 1 GB baseline"},
		{Value: "digitalocean", Label: "DigitalOcean · 1 GB balanced baseline"},
		{Value: "azure", Label: "Azure · small burstable VM; disk / IPv4 / traffic priced separately"},
		{Value: "aws-lightsail", Label: "AWS Lightsail · fixed monthly Linux / IPv4 bundle"},
		{Value: "aws-ec2", Label: "AWS EC2 · burstable ARM / x86; disk / IPv4 / traffic priced separately"},
	}
}

func vpsUsesPublicKeyFile(provider string) bool {
	return provider == "linode" || provider == "oracle" || provider == "azure" || provider == "aws-lightsail" || provider == "aws-ec2"
}

func vpsCloudWizardFields(req vps.CreateRequest) []wizard.Field {
	var fields []wizard.Field
	if req.Provider == "azure" {
		fields = append(fields, wizard.Field{Key: "subscription", Label: "Azure subscription ID", Value: req.SubscriptionID, Required: true})
	}
	if req.Provider != "azure" && req.Provider != "aws-lightsail" && req.Provider != "aws-ec2" {
		return fields
	}
	fields = append(fields, wizard.Field{Key: "architecture", Label: "CPU architecture", Value: req.Architecture, Kind: wizard.Select, Options: []wizard.Choice{{Value: "auto", Label: "Auto · allow ARM and x86; compare total fixed cost"}, {Value: "amd64", Label: "AMD64 / x86_64"}, {Value: "arm64", Label: "ARM64 / aarch64"}}})
	fields = append(fields, wizard.Field{Key: "zone", Label: "Availability zone (optional)", Value: req.AvailabilityZone, Help: "Blank selects a compatible available zone during preview."})
	if req.Provider == "azure" || req.Provider == "aws-ec2" {
		value := ""
		if req.DiskGB > 0 {
			value = strconv.Itoa(req.DiskGB)
		}
		fields = append(fields, wizard.Field{Key: "disk", Label: "Root disk GiB (optional)", Value: value, Help: "Blank uses Azure 32 GiB Standard SSD / EC2 20 GiB encrypted gp3."})
	}
	return fields
}

func vpsApplyCloudWizardFields(req *vps.CreateRequest, values map[string]string) error {
	if req.Provider == "azure" {
		req.SubscriptionID = values["subscription"]
	}
	if req.Provider != "azure" && req.Provider != "aws-lightsail" && req.Provider != "aws-ec2" {
		return nil
	}
	req.Architecture, req.AvailabilityZone = values["architecture"], values["zone"]
	if req.Provider == "azure" || req.Provider == "aws-ec2" {
		req.DiskGB = 0
		if values["disk"] != "" {
			n, err := strconv.Atoi(values["disk"])
			if err != nil || n < 1 {
				return usage("root disk must be a positive integer in GiB or blank for the provider default")
			}
			req.DiskGB = n
		}
	}
	return nil
}
