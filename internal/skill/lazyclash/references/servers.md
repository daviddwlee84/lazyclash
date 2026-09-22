# Proxy servers and VPSs

`setup` installs a Mihomo client. `servers deploy` installs a proxy server;
`vps` manages its machine. A server/VPS is not a controller target.

Start with `vps catalog --json`, `vps list --json`, `servers recipes --json`
and `servers list --json`. Catalog prices are dated references; quote the actual
provider region/plan before creating a machine. Oracle, Vultr, Linode,
DigitalOcean, Azure, AWS Lightsail and EC2 use their official authenticated CLIs.
API credentials remain there. Provider IDs are `azure`, `aws-lightsail` and
`aws-ec2`; Azure uses explicit `--subscription`, AWS uses the existing `--profile`.
Use a public key file for all three. No global CLI account defaults are changed.

`vps guide [ID] --provider PROVIDER [--region REGION]` prints a copyable hybrid
runbook: CLI installation/login, original official CLI queries, then lazyclash
discovery, preview, reviewed apply and recovery. `--format agent` adds a handoff
prompt; `--json` returns structured steps. Generation is offline and only checks
PATH, even with broken settings. It never reads credentials or runs commands.
Missing inputs use guarded `${LC_*:?}` shell variables; resolve them from the
actual account rather than inventing IDs. Installation commands are explicitly
labeled macOS/Homebrew; use the linked vendor instructions on other platforms.
Oracle defaults to browser sessions and scopes `OCI_CLI_AUTH=security_token` to
the emitted commands; use `--oci-auth api_key` for an existing API-key profile.
Explicit config/inventory scope is preserved; adjust local paths when handing
off to a different machine. Run one step at a time within the user's authorized
scope, review costs and identity before assigning the exact preview digest, and
never turn this document into an automatically approved script. Official CLI
queries bypass catalog filters for diagnosis; managed writes still use lazyclash
receipts and reconciliation. Missing/free-tier eligibility stays unknown.
Oracle only offers a checked Always Free A1 recipe; unknown eligibility or
capacity does not authorize a paid substitute.
New owned Oracle VMs receive a version/hash-bound cloud-init that preserves
platform INPUT rules and permits TCP 80/443 and UDP 443 at boot. It is never
applied to registered existing hosts. Custom ports need separate firewall review.

Existing public-IP homelabs, Azure VMs and arbitrary VPSs use `vps register ID
--ssh-host ALIAS --public-host HOST`. The SSH address may be private and use
OpenSSH jump hosts; it is independent of the public client endpoint. Router
forwarding, cloud firewall and host firewall are separate. SSH-only hosts cannot
be powered on remotely after shutdown without a provider management interface.

Oracle/Azure `vps usage HOST` and `servers usage SERVER` query the current UTC
month without writes; `--month YYYY-MM` selects a past UTC month and `--json`
preserves structured observations. `--read-only` is supported. The full month
must fit Monitoring retention (Oracle 90 days, Azure 93 days); future months and
older incomplete windows fail before cloud queries. TUI Servers / VPS uses `u`
for explicit current-month refresh; normal Overview does not poll cloud APIs.
Registered hosts need `vps bind-cloud HOST --provider oracle|azure --region REGION
--resource-id ID` plus Oracle `--tenancy`/optional `--profile`, or Azure explicit
`--subscription`. Preview first, then repeat with the exact reviewed `--yes
--expect DIGEST`. This only saves observation metadata; it never grants cloud
ownership or changes VM lifecycle authority. Keep the same inventory scope.
VM network bytes, provider billing meters and published shared allowances are
separate. Missing/stale samples are unknown, not zero. Preserve native billing
units, including `GB Months`, `10 GB` and `1 TB`; do not infer a byte conversion,
remaining quota, percentage, trial-credit balance or overage. Oracle billing is
tenancy-scoped; Azure Bandwidth billing is subscription-scoped and supports legacy
Usage Details only (EA/MCA Cost Details remains unsupported). Billing failures
do not erase readable VM observations; Disabled Azure subscriptions may retain
readable history. Multiple target imports share the same VPS usage source.
See the [VPS usage guide](https://github.com/daviddwlee84/lazyclash/blob/main/docs/vps-usage.md)
for binding examples, data sources and reporting limitations.

Azure/AWS creation defaults to Ubuntu 24.04 and at least 1 GiB RAM. `--architecture
auto|amd64|arm64` controls plan compatibility; auto allows ARM. Omitted plans are
resolved using available low fixed-cost plans in the requested region. Inspect
the fixed image ID/version, architecture and availability zone in the preview.
`--availability-zone` pins a zone; Azure/EC2 `--disk-gb` overrides their default
32 GiB Standard SSD / 20 GiB encrypted gp3 root disk. Azure/EC2 image IDs are fixed.
Lightsail uses the verified Ubuntu 24.04 x86 blueprint and rechecks its saved
version immediately before launch; its API accepts only the blueprint ID.
Azure/EC2 quote `monthly_usd` includes compute, root disk and static IPv4, with
components and stopped costs. Lightsail bundles include the base resources;
`vps estimate --egress N --ingress N` accounts for its two-way allowance. Missing
inbound remains uncertain, and shared account free traffic/credits are not
per-VM discounts. CPU credits and region capacity remain material constraints.
Use `discover --kind subscriptions` for Azure; `--kind zones` for Azure/AWS.

Server recipes are `vless-reality`, `hysteria2`, `legacy-vmess-ws-tls`.
Remote OS is Ubuntu 24.04 LTS amd64/arm64; native systemd is default and Compose
is optional. BYO Compose requires working Docker/Compose. Server management
requires root SSH or noninteractive sudo for the fixed Python helper.
Hysteria2 needs UDP and a trusted certificate; TLS recipes require DNS plus
TCP 80 for ACME renewal. Do not turn off certificate verification to hide errors.

Complete noninteractive commands produce a preview. Apply with `--yes --expect`
and the exact reviewed digest. Bare `servers deploy` / `vps create` guide humans
in a terminal; JSON never prompts. Keep the same `--servers-config` across stages.
The default inventory is `servers.toml` beside the chosen client settings;
private journals are stored under XDG state, isolated by inventory path.

Cloud create intent and returned resource IDs are durable before SSH deployment.
An interrupted create can have succeeded: `vps resume ID` reconciles the exact
operation marker, never blindly issues another ambiguous create. Preserve
partial resources and ownership records. Server resume retains credentials,
issued certificates and completed phases. Inspection precedes retries.
`vps resume ID --reconcile-only` saves only existing resources, without creating
or attaching cloud resources; use it to recover an unknown create before cleanup.

`servers start/stop/restart/remove` operate the proxy service. `vps start/stop/
reboot/delete` operate cloud infrastructure. Stopping a service or VM does not
generally stop billing. Delete only the reviewed owned resources; shared networks,
firewalls and keys are not cleanup authority.
Azure stop deallocates but retains disk/IP charges; EC2 stop retains EBS/EIP
charges. Lightsail stop retains its bundle charge. These new providers create
dedicated owned networks/resources rather than taking over an existing VPC or
resource group; no NAT Gateway or IAM role is created. EC2 uses IMDSv2 and
Standard CPU credits. Azure cloud/tenant/subscription or AWS partition/account
is bound to recovery; do not change account, AZ or idempotency token to retry an
ambiguous create. Lightsail static IP ownership uses saved receipts, not tags.

Status distinguishes service state, SSH and last authenticated HTTPS proxy
verification. Verification uses an isolated temporary Mihomo with no direct
fallback. A running service does not prove Mainland connectivity; a failed probe
does not erase the deployment. Incoming IP and observed exit IP may differ.
An existing TUN with TLS destination overrides can intercept an independent
REALITY verifier. After diagnosing that route, `deploy/resume/start/restart
--verify-interface NAME` explicitly binds only the temporary verifier to a local
interface; it never rewrites a live client or system routing. The default keeps
system routing, and successful status records the chosen verification interface.

`servers export ID --format uri|qr|mihomo|starter|client-bundle|admin-bundle`
is an explicit credential export. QR/admin exports require a new private output
file. Ordinary sharing contains client credentials; the explicit admin backup
also includes server keys/issued TLS files and restore metadata, never cloud
tokens or SSH private keys. Do not put these bundles in public repositories.

`--target CLIENT servers connect ID --group GROUP` previews insertion through the
existing node-source owner. It does not replace the user's routing profile.
If persistence/reload is uncertain, inspect/verify the saved import receipt rather
than importing a duplicate. Verge still needs native profile reactivation.
