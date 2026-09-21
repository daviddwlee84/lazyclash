# lazyclash knowledge and operating guide

Start with the [quick start](../README.md). These pages explain the behavior
behind the commands; the installed binary's `--help` is the syntax authority.
The [changelog](../CHANGELOG.md) identifies the version that introduced a feature.

| Read when… | Guide |
|---|---|
| Connecting a local/remote core, comparing servers or copying runtime choices | [Targets and configuration](targets-and-config.md) |
| Adding/editing nodes, configuring groups, copying credentials or sharing QR | [節點與群組](proxies-and-groups.md) |
| Choosing a shell/data proxy, owning SSH forwards or configuring Docker consumers | [代理環境](proxy-environment.md) |
| Sharing a local proxy with a remote shell/command and checking endpoint lifetime | [雙向 SSH 代理](ssh-proxy-sharing.md) |
| Installing an owned native/Docker client or using offline China-routing presets | [Client setup](managed-cores.md) |
| Choosing protocols/VPSs, Azure/AWS and other cloud provisioning, deploying a server or public-IP homelab, exporting client configs | [Server deployment and VPS selection](server-deployment.md) |
| Using a Tailscale Exit Node or sharing an HTTP/SOCKS proxy privately inside a tailnet | [Tailscale 出口與私有 proxy](tailnet.md) |
| Inspecting Tailscale/other VPN conflicts, split DNS, service permissions or recovery | [VPN／TUN 共存](vpn-coexistence.md) |
| Interpreting dashboard metrics or diagnosing a URL | [Diagnostics and routing](diagnostics-and-routing.md) |
| Persisting a domain override, reloading or recovering a change | [Rules and ownership](rules-and-ownership.md) |
| Installing, upgrading, activating completion or maintaining a release | [Installation, upgrades and completion](install-upgrade-completion.md) |
| Checking an upstream contract, design inspiration or research claim | [References and evidence](references.md) |

## Vocabulary and ownership

| Object | Owner and meaning |
|---|---|
| lazyclash settings | User-local TOML containing target registrations and TUI preferences |
| Target | A controller address, its transport/credential references, and optional data proxy |
| Runtime settings | The core's current general settings; `GET /configs` is not complete YAML |
| Complete config | A YAML file on the core host; registration does not upload it or make it the startup source |
| `source_config` | Credential discovery reference; it is not permission to rewrite that YAML |
| Rule source | An explicit binding to the persistent file/owner used by rule repair |
| Node/group source | A separate explicit binding for raw definitions, editing, copying and sharing |
| Managed core | An installation with a recorded service/project identity, version, digest and receipts |
| VPS host / proxy server | Separate server inventory: cloud or SSH management host, deployment, public endpoint and recovery history |
| Tailnet exit / proxy | A stable Tailscale peer, independently owned exit advertisement, local exit selection or private proxy mapping |
| Verge profile | GUI-owned source plus companion Rules/Merge/Script files and a generation pipeline |
| Data proxy | HTTP(S)/SOCKS endpoint carrying requests; an API/SSH management tunnel does not supply one |
| Receipt | A record of a specific persistent change; saving, loading, and observing route use are separate states |

## For agents and contributors

`lazyclash --skill` is an offline operating guide embedded in the executable.
It ships with that binary and does not require a checkout or `npx skills`.
The project's `go-cli-tui` skill is a separate contributor guide, maintained in
the agent-skills repository.

CLI handlers and TUI effects call the same services. Rendering performs no
network I/O. Request generations discard late results; cancellation does not
prove that a remote write was undone. Mouse rows select, explicit buttons act,
and typing retains ownership of printable keys.

Development checks are `go vet ./...`, `go test -race ./...`, and the real PTY
harnesses in `scripts/pty_smoke.py`, `scripts/auth_pty_smoke.py` and
`scripts/tools_pty_smoke.py`. `scripts/reverse_pty_smoke.py` uses an isolated sshd
for reverse forwarding, remote shells and cleanup. Tests use disposable state and controllers.
Keep actual OS execution, cross-builds, fixture checks and real-host observations
distinct in verification reports.
