# Managed client setup and network changes

`setup` is an explicit installation workflow, separate from `targets add`.
Use the interactive wizard or complete flags, inspect the real preview, then
apply with its digest. Read `cores list/status` to distinguish an installed
service, registered controller and working data proxy. An existing endpoint is
not evidence that lazyclash owns its service/container.

Native supports macOS/Linux service managers; Docker requires an existing daemon
and Compose plugin on the selected host. Official binary archives are verified
by release digest and Docker images are pinned. Privileged cores execute from
root-owned locations. Native sudo/SSH handles authorization; never collect a
password in chat or store it as an API/proxy secret.

`cn-split` bundles pinned China domain/IP and explicit category data;
`simple` is local/VPN bypass then PROXY. Full YAML defaults to preserving its
rules. `rules preset list` reports provenance; apply/update uses reviewed managed
configuration. The bundle retains distinct upstream data licenses. Offline
starter means no first-run rule download, not offline Internet access.

Use an explicitly registered, existing data proxy as `--bootstrap-target` when
downloads are blocked, or supply verified local artifacts/snapshots. Do not
bootstrap a new core through itself, inherit an unexplained environment proxy,
or claim a Docker daemon pull uses the CLI's download transport.

Run `diagnostics network` for passive local evidence, or select `--ssh`/`--target`
explicitly. Inspect routes, policy rules, scoped resolvers, tunnel interfaces and
VPN clues; process names are not proof of interception. Missing tools/permissions
are unknown evidence. Tailscale tailnet/subnet exclusions must include accepted
subnet routes and MagicDNS handling, not just the two tailnet CIDRs.

Exit-node/other full-tunnel VPN conflicts require choosing the default-route
owner; do not disable an existing VPN automatically. `exclude-interface` is not
a universal outbound VPN bypass and POSIX `nameserver: system` does not reproduce
all scoped DNS. Regional rules are not proof of unpoisoned DNS or a kill switch.

TUN is supported by native system services and rootful Linux Docker with the
host namespace/TUN device/capabilities. Rootless Docker and macOS Docker Desktop
use explicit proxy mode for this workflow. Existing Verge service/TUN remains
Verge-owned; API toggling does not install its privileged service.

Network changes arm a host-side rollback deadline. ACK requires management
verification, including a fresh SSH transport for a remote host rather than a
channel on a surviving ControlMaster. Failure/unknown state leaves a receipt and
recovery snapshot. Restoration compares owned state and does not overwrite later
external edits. System proxy is scoped to selected macOS services or the original
GNOME user session. Stop/remove retains private data; inspect any restoration
conflict before retrying a lifecycle operation.
