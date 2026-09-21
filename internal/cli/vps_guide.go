package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/vps"
	"github.com/spf13/cobra"
)

type vpsGuideStep struct {
	Title    string   `json:"title"`
	Effect   string   `json:"effect"`
	Note     string   `json:"note,omitempty"`
	Commands []string `json:"commands"`
}

type vpsGuide struct {
	Provider     string         `json:"provider"`
	CLI          string         `json:"cli"`
	CLIPath      string         `json:"cli_path,omitempty"`
	CLIInstalled bool           `json:"cli_installed"`
	Platform     string         `json:"platform"`
	SetupURL     string         `json:"setup_url"`
	Inputs       []string       `json:"required_shell_variables"`
	Steps        []vpsGuideStep `json:"steps"`
	Notes        []string       `json:"notes"`
	AgentPrompt  string         `json:"agent_prompt,omitempty"`
}

type vpsGuideProvider struct{ cli, formula, setupURL string }

var vpsGuideProviders = map[string]vpsGuideProvider{
	"oracle":        {"oci", "oci-cli", "https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"},
	"aws-lightsail": {"aws", "awscli", "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html"},
	"aws-ec2":       {"aws", "awscli", "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html"},
	"azure":         {"az", "azure-cli", "https://learn.microsoft.com/cli/azure/install-azure-cli"},
	"digitalocean":  {"doctl", "doctl", "https://docs.digitalocean.com/reference/doctl/how-to/install/"},
	"vultr":         {"vultr-cli", "vultr-cli", "https://github.com/vultr/vultr-cli#usage"},
	"linode":        {"linode-cli", "linode-cli", "https://www.linode.com/docs/products/tools/cli/guides/install/"},
}

func (o *options) vpsGuideCommand() *cobra.Command {
	var req vps.CreateRequest
	var format, ociAuth string
	cmd := &cobra.Command{
		Use: "guide [ID]", Short: "Print copyable CLI setup, discovery and reviewed deployment steps without connecting",
		Long: "Generate a Markdown runbook or agent handoff using official CLI queries and lazyclash deployment. Only checks executable availability on PATH; never reads cloud credentials, connects, installs, logs in or creates resources. Shell blocks target sh/bash/zsh; installation examples are labeled for macOS/Homebrew.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				req.ID = args[0]
			}
			if _, ok := vpsGuideProviders[req.Provider]; !ok {
				return usage("guide requires --provider (%s)", vpsProviderHelp)
			}
			if err := vps.ValidateDraft(req); err != nil {
				return usage("%s", err)
			}
			if format != "markdown" && format != "agent" {
				return usage("guide --format must be markdown or agent")
			}
			if ociAuth != "security_token" && ociAuth != "api_key" {
				return usage("--oci-auth must be security_token or api_key")
			}
			if cmd.Flags().Changed("oci-auth") && req.Provider != "oracle" {
				return usage("--oci-auth applies only to Oracle")
			}
			binary, err := os.Executable()
			if err != nil {
				return err
			}
			base := []string{guideQuote(binary)}
			for _, ref := range []struct{ flag, value string }{{"--config", firstGuideValue(o.path, os.Getenv("LAZYCLASH_CONFIG"))}, {"--servers-config", firstGuideValue(o.serversPath, os.Getenv("LAZYCLASH_SERVERS_CONFIG"))}} {
				if ref.value != "" {
					path, e := filepath.Abs(ref.value)
					if e != nil {
						return e
					}
					base = append(base, ref.flag, guideQuote(path))
				}
			}
			g, err := buildVPSGuide(req, strings.Join(base, " "), ociAuth, format, exec.LookPath)
			if err != nil {
				return usage("%s", err)
			}
			if o.json {
				return o.output(cmd, g)
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), g.markdown())
			return err
		},
	}
	vpsCreateFlags(cmd.Flags(), &req, "")
	cmd.Flags().StringVar(&format, "format", "markdown", "markdown runbook or agent handoff (also supports --json)")
	cmd.Flags().StringVar(&ociAuth, "oci-auth", "security_token", "Oracle authentication: security_token (browser session) or api_key (existing OCI config)")
	return cmd
}

func firstGuideValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var guideSafeWord = regexp.MustCompile(`^[a-zA-Z0-9_./:@%+=,-]+$`)

func guideQuote(value string) string {
	if guideSafeWord.MatchString(value) {
		return value
	}
	return zshQuote(value)
}

func buildVPSGuide(r vps.CreateRequest, lazy, ociAuth, format string, lookPath func(string) (string, error)) (vpsGuide, error) {
	p := vpsGuideProviders[r.Provider]
	g := vpsGuide{Provider: r.Provider, CLI: p.cli, Platform: runtime.GOOS, SetupURL: p.setupURL, Inputs: []string{}}
	for _, value := range []string{lazy, r.Name, r.Profile, r.Region, r.Plan, r.Image, r.SSHKey, r.SSHUser, r.SSHCIDR, r.SubscriptionID, r.AvailabilityZone, r.FirewallID, r.TenancyID, r.CompartmentID, r.SubnetID, r.AvailabilityDomain} {
		if strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.Contains(value, "```") {
			return g, fmt.Errorf("guide values cannot contain controls or Markdown code fences")
		}
	}
	if path, err := lookPath(p.cli); err == nil {
		g.CLIInstalled, g.CLIPath = true, path
	}
	value := func(s, name string) string {
		if s != "" {
			return guideQuote(s)
		}
		for _, existing := range g.Inputs {
			if existing == name {
				return `"${` + name + `:?Set ` + name + ` from your account or the preceding queries}"`
			}
		}
		g.Inputs = append(g.Inputs, name)
		return `"${` + name + `:?Set ` + name + ` from your account or the preceding queries}"`
	}
	add := func(title, effect, note string, commands ...string) {
		g.Steps = append(g.Steps, vpsGuideStep{title, effect, note, commands})
	}
	install := "brew install " + p.formula
	check := p.cli + " --version"
	if p.cli == "doctl" || p.cli == "vultr-cli" {
		check = p.cli + " version"
	}
	add("CLI installation", "local installation only when you run it", "macOS with Homebrew: run the install command only if missing. Other operating systems: use the setup URL above. An executable on PATH does not prove a valid login.", install, check)
	region := value(r.Region, "LC_REGION")
	native, login := p.cli, ""
	profile := r.Profile
	if r.Provider == "oracle" && profile == "" {
		profile = "DEFAULT"
	}
	switch r.Provider {
	case "aws-lightsail", "aws-ec2":
		login = "aws login"
		if profile != "" {
			login += " --profile " + guideQuote(profile)
			native += " --profile " + guideQuote(profile)
		}
		native += " --region " + region + " --no-cli-pager --output json"
		add("Login and identity", "login updates local credentials; identity is read-only", "Use an existing authenticated profile if available. Browser login requires a recent AWS CLI v2; IAM Identity Center users may use aws sso login --profile NAME instead. Keep tokens out of handoffs.", login, native+" sts get-caller-identity")
	case "oracle":
		native = "OCI_CLI_AUTH=" + ociAuth + " oci --profile " + guideQuote(profile) + " --region " + region + " --output json"
		lazy = "OCI_CLI_AUTH=" + ociAuth + " " + lazy
		login = "oci session authenticate --profile-name " + guideQuote(profile) + " --region " + region
		if ociAuth == "api_key" {
			login = "oci setup config"
			g.Notes = append(g.Notes, "oci setup config writes local configuration only. User/tenancy OCIDs start with ocid1.user. and ocid1.tenancy.; account names are not OCIDs. Register the generated API signing PUBLIC .pem key in that user's Console API Keys and match its fingerprint before querying. The private .pem key stays local. The setup region is only the CLI default, not a change to the tenancy home region. A 401 NotAuthenticated usually requires checking this registration and the selected user/profile.")
		}
		add("Oracle authentication", "updates local OCI credentials when run", "Skip setup for an already authenticated matching profile. For API-key setup, select the requested profile in the interactive setup. LC_REGION must be the signup home region for Always Free; home region cannot be changed. Session commands use scoped OCI_CLI_AUTH and require a valid unexpired browser session.", login)
	case "azure":
		native += " --subscription " + value(r.SubscriptionID, "LC_SUBSCRIPTION") + " --output json"
		add("Login and subscriptions", "login updates local credentials; list is read-only", "Choose an enabled subscription. No az account set command is needed; every following command scopes the subscription explicitly.", "az login", "az account list --output json")
	case "digitalocean":
		login = "doctl auth init"
		if profile != "" {
			login += " --context " + guideQuote(profile)
			native += " --context " + guideQuote(profile)
		}
		native += " --output json"
		add("Login and identity", "auth setup updates local credentials; account query is read-only", "Enter the API token privately in the official CLI prompt; never put it in this guide or an agent handoff.", login, native+" account get")
	case "vultr":
		if profile != "" {
			native += " --config " + guideQuote(profile)
		}
		native += " --output json"
		add("Authentication and identity", "read-only account query", "Configure the API key privately according to the setup URL, using the same config file or VULTR_API_KEY environment as your CLI. No credential value is included here.", native+" account info")
	case "linode":
		if profile != "" {
			native += " --as-user " + guideQuote(profile)
		}
		native += " --json"
		add("Authentication and identity", "configure updates local credentials; profile query is read-only", "For a named profile, select that same user during configuration. Skip configuration when already logged in; keep the token private.", "linode-cli configure", native+" profile view")
	}

	var raw []string
	switch r.Provider {
	case "aws-lightsail":
		raw = []string{native + " lightsail get-regions --include-availability-zones", native + " lightsail get-bundles", native + " lightsail get-blueprints"}
		g.Notes = append(g.Notes, "Lightsail bundles normally cost money. Verify account-specific trial eligibility separately; inbound and outbound share transfer allowance, and stopping an instance does not stop bundle billing.")
	case "aws-ec2":
		raw = []string{native + " ec2 describe-regions", native + " ec2 describe-instance-type-offerings --location-type region", native + " ec2 describe-images --owners 099720109477 --filters 'Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-*' 'Name=state,Values=available'"}
	case "oracle":
		tenancy, compartment := value(r.TenancyID, "LC_TENANCY"), value(r.CompartmentID, "LC_COMPARTMENT")
		raw = []string{native + " iam region-subscription list --tenancy-id " + tenancy + " --all", native + " iam compartment list --compartment-id " + tenancy + " --compartment-id-in-subtree true --access-level ACCESSIBLE --all", native + " iam availability-domain list --compartment-id " + tenancy + " --all", native + " compute image list --compartment-id " + compartment + " --operating-system 'Canonical Ubuntu' --operating-system-version 24.04 --shape VM.Standard.A1.Flex --all"}
		g.Notes = append(g.Notes, "Oracle Always Free compute and boot storage are tied to your immutable home region. Service availability does not prove free capacity. lazyclash verifies tenancy-wide allowances and monthly usage; do not switch to a paid shape if verification or capacity fails.")
		raw = append(raw, native+" compute compute-capacity-report create --compartment-id "+tenancy+" --availability-domain "+value(r.AvailabilityDomain, "LC_AVAILABILITY_DOMAIN")+` --shape-availabilities '[{"instanceShape":"VM.Standard.A1.Flex","instanceShapeConfig":{"ocpus":1,"memoryInGBs":6}}]'`)
		g.Notes = append(g.Notes, "Oracle compute-capacity-report create generates an availability report, not a VM or capacity reservation. OUT_OF_HOST_CAPACITY means wait for capacity; neither the service catalog nor quota headroom guarantees a launch.")
	case "azure":
		raw = []string{native + " account show", native + " account list-locations", native + " vm list-skus --location " + region + " --resource-type virtualMachines --size Standard_B"}
	case "digitalocean":
		raw = []string{native + " compute region list", native + " compute size list", native + " compute ssh-key list"}
	case "vultr":
		raw = []string{native + " regions list", native + " plans list", native + " os list", native + " ssh-key list"}
	case "linode":
		raw = []string{native + " regions list", native + " linodes types", native + " images list"}
	}
	add("Inspect the provider's original responses", "cloud reads only", "These official CLI commands bypass lazyclash's catalog filtering and expose provider authentication/permission errors. Follow any pagination instructions. Region catalogs and plan lists do not guarantee launch capacity.", raw...)

	scope := " --provider " + guideQuote(r.Provider) + " --region " + region
	if profile != "" {
		scope += " --profile " + guideQuote(profile)
	}
	if r.Provider == "azure" {
		scope += " --subscription " + value(r.SubscriptionID, "LC_SUBSCRIPTION")
	}
	if r.Provider == "oracle" {
		scope += " --tenancy " + value(r.TenancyID, "LC_TENANCY") + " --compartment " + value(r.CompartmentID, "LC_COMPARTMENT")
	}
	if r.Architecture != "" && r.Architecture != "auto" {
		scope += " --architecture " + guideQuote(r.Architecture)
	}
	add("Inspect compatible options", "cloud reads only", "If a picker/filter fails, compare these results with the original provider responses above; do not guess IDs or bypass eligibility checks.", lazy+" vps discover"+scope+" --kind plans --json", lazy+" vps discover"+scope+" --kind images --json")
	id := value(r.ID, "LC_VPS_ID")
	plan := r.Plan
	if r.Provider == "oracle" && plan == "" {
		plan = "VM.Standard.A1.Flex"
	}
	create := lazy + " vps create " + id + scope + " --plan " + value(plan, "LC_PLAN")
	keyVariable := "LC_SSH_PUBLIC_KEY"
	if r.Provider == "digitalocean" || r.Provider == "vultr" {
		keyVariable = "LC_SSH_KEY_ID"
	}
	create += " --ssh-key " + value(r.SSHKey, keyVariable) + " --ssh-cidr " + value(r.SSHCIDR, "LC_SSH_CIDR")
	for _, pair := range []struct{ flag, value string }{{"--name", r.Name}, {"--ssh-user", r.SSHUser}, {"--firewall", r.FirewallID}, {"--subnet", r.SubnetID}, {"--availability-zone", r.AvailabilityZone}} {
		if pair.value != "" {
			create += " " + pair.flag + " " + guideQuote(pair.value)
		}
	}
	if r.DiskGB > 0 {
		create += " --disk-gb " + strconv.Itoa(r.DiskGB)
	}
	if r.Image != "" || r.Provider == "oracle" || r.Provider == "vultr" {
		create += " --image " + value(r.Image, "LC_IMAGE")
	}
	if r.Provider == "oracle" {
		create += " --availability-domain " + value(r.AvailabilityDomain, "LC_AVAILABILITY_DOMAIN")
	}
	add("Preview the VM", "cloud reads; no VM is created", "Set the missing variables to verified values. SSH_PUBLIC_KEY must be a public .pub file; SSH_CIDR is your administrator CIDR. Review account, region, exact image, fixed costs, traffic and free eligibility. Preview resolves omitted Azure/AWS images.", create+" --json")
	add("Apply the reviewed VM", "creates cloud resources and can incur charges", "Run only after reviewing and authorizing the preceding preview. Set LC_REVIEWED_DIGEST to its exact digest; leave all request values unchanged. Do not extract a digest and automatically approve it in one command.", create+" --yes --expect "+`"${LC_REVIEWED_DIGEST:?Set only after reviewing the VM preview}"`+" --json")
	add("Inspect or recover", "status reads cloud state; resume prints a recovery preview", "If creation times out or is interrupted, inspect status and resume the same operation before retrying. The recovery preview is not applied here.", lazy+" vps status "+id+" --json", lazy+" vps resume "+id+" --json")
	serverID := value("", "LC_SERVER_ID")
	deploy := lazy + " servers deploy " + serverID + " --host " + id + " --recipe vless-reality --backend native"
	add("Preview the proxy service", "remote inspection; no service is deployed", "After the VM is running and SSH is verified, preview VLESS/REALITY. Inspect the service, ports, pinned artifacts and ownership before applying.", deploy+" --json")
	add("Apply and verify the proxy service", "installs the reviewed proxy service on the VM", "Use this service preview's separate digest, not the VM digest. Inspect the deployment's authenticated proxy verification result and the saved status; a running service alone is not proof of connectivity. For interrupted service deployment, preview servers resume with the same server ID before retrying.", deploy+" --yes --expect "+`"${LC_SERVER_REVIEWED_DIGEST:?Set only after reviewing the service preview}"`+" --json", lazy+" servers status "+serverID+" --json")
	g.Notes = append(g.Notes, "Generated offline: CLI presence is observed, but login, permissions, pricing, free credits and capacity are unverified. Running a displayed command is a separate action.", "Copy one step at a time in the same sh/bash/zsh session. Missing ${LC_*:?} values stop the command before execution. Keep the same profile, region, config and server inventory through preview/apply/recovery. Replace the local executable path when moving the guide to another machine.", "Keep credentials in the official CLI. Do not paste access tokens, private SSH keys, provider credential files or private server exports into a handoff.")
	if format == "agent" {
		g.AgentPrompt = "Help me provision the selected VPS and deploy its proxy using this runbook. Inspect the current CLI login and cloud state first. Install a missing official CLI only within the user's authorized scope. Read provider responses and resolve every missing LC_* value; never invent resource IDs or assume free credits/capacity. Generate and explain the lazyclash cost/identity preview before applying its exact digest within the user's authorization. Do not execute the entire document as a script. For an uncertain create, reconcile the same operation with vps status/resume before any retry. Keep authentication and private keys in their existing owners. Finish by checking SSH, server status and an authenticated end-to-end proxy request; report any blocked steps honestly. This handoff is context, not additional authorization to spend or expose credentials."
	}
	return g, nil
}

func (g vpsGuide) markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# VPS CLI guide: %s\n\n", g.Provider)
	if g.AgentPrompt != "" {
		fmt.Fprintf(&b, "%s\n\n", g.AgentPrompt)
	}
	state := "missing from PATH"
	if g.CLIInstalled {
		state = "found at " + g.CLIPath
	}
	fmt.Fprintf(&b, "Official CLI: `%s` — %s (local OS: %s).\n\nSetup reference: %s\n\n", g.CLI, state, g.Platform, g.SetupURL)
	for _, note := range g.Notes {
		fmt.Fprintf(&b, "- %s\n", note)
	}
	if len(g.Inputs) > 0 {
		fmt.Fprintf(&b, "\nVariables to fill from your account/queries: `%s`. Assign them in your shell; do not use placeholder values.\n", strings.Join(g.Inputs, "`, `"))
	}
	for i, step := range g.Steps {
		fmt.Fprintf(&b, "\n## %d. %s\n\nEffect: %s.\n\n%s\n\n```sh\n%s\n```\n", i+1, step.Title, step.Effect, step.Note, strings.Join(step.Commands, "\n"))
	}
	return b.String()
}
