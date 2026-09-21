# Proxy servers and VPSs

`setup` installs a Mihomo client. `servers deploy` installs a proxy server;
`vps` manages its machine. A server/VPS is not a controller target.

Start with `vps catalog --json`, `vps list --json`, `servers recipes --json`
and `servers list --json`. Catalog prices are dated references; quote the actual
provider region/plan before creating a machine. Oracle, Vultr, Linode and
DigitalOcean use their official authenticated CLIs. API credentials remain there.
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

Status distinguishes service state, SSH and last authenticated HTTPS proxy
verification. Verification uses an isolated temporary Mihomo with no direct
fallback. A running service does not prove Mainland connectivity; a failed probe
does not erase the deployment. Incoming IP and observed exit IP may differ.

`servers export ID --format uri|qr|mihomo|starter|client-bundle|admin-bundle`
is an explicit credential export. QR/admin exports require a new private output
file. Ordinary sharing contains client credentials; the explicit admin backup
also includes server keys/issued TLS files and restore metadata, never cloud
tokens or SSH private keys. Do not put these bundles in public repositories.

`--target CLIENT servers connect ID --group GROUP` previews insertion through the
existing node-source owner. It does not replace the user's routing profile.
If persistence/reload is uncertain, inspect/verify the saved import receipt rather
than importing a duplicate. Verge still needs native profile reactivation.
