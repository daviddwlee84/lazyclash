# Tailscale exits and private proxies

Use `tailnet` for existing installed, logged-in Tailscale devices. An exit node
changes a client's OS routing; a tailnet proxy is an application endpoint.
Remote browser proxy settings do not imply that forwarded exit traffic uses
that proxy. Discover with `tailnet peers --json`, then retain the selected
stable peer identity and SSH alias throughout the operation.
Use `tailnet add ID --ssh HOST` to register a proxy-only host without enabling
exit advertisement. Complete flags preview by default; review before passing
`--yes --expect DIGEST`, or use the interactive workflow.

## Exit nodes

`tailnet exit setup ID --ssh HOST` inspects the actual remote peer, previews
Linux forwarding and exit advertisement, and saves an independently managed
exit registration. `enable`/`disable` affect the remote advertisement;
`use ID`/`release` affect local selection. `status ID --json` distinguishes
advertised, awaiting approval, selectable, selected and verified observations.
Follow the installed command's `--help` for reviewed apply flags.

Admin approval (or an existing autoApprover) and Internet access policy are
separate requirements. Pending approval is resumable, not a verified exit.
Do not replace tailnet-wide policy or invent success when only SSH works.
Allow native SSH/sudo terminal authentication; never collect/store passwords.
Machine-output mode must return an actionable authorization requirement.

Selecting an exit can temporarily disable an explicitly identified local
Mihomo TUN. Preserve the mode, system proxy and DNS preferences. Unknown VPNs
are blockers, not permission to stop their processes. Verify actual OS HTTPS,
DNS and the preexisting local proxy path. Retain selected exit after successful
verification; an unavailable exit is not permission to silently use direct.

TUN handoff is runtime-only. Verge may restore its native TUN preference on
restart/reload. Re-read runtime and owner-generation evidence before reporting
health or restoring snapshots; do not overwrite external changes or patch
live Verge files. Persistent native TUN preferences belong to the native UI.
After a core restart, explicit `release` can restore unchanged Tailscale
preferences while preserving the changed core (`released_tun_preserved`).
Automatic timeout restoration remains strict; externally changed exit
preferences are never cleared automatically.

Remote and local changes have separate guarded transactions. Preserve recovery
receipts after uncertain writes, inspect current state first, and resume the
owned operation rather than blindly repeating changes. Stop/remove must not
call `tailscale down`, stop tailscaled, or disable shared forwarding blindly.

## Private proxy gateways

`tailnet proxy deploy` creates an owned authenticated Mihomo gateway or shares
an explicitly selected existing proxy. Default exposure is persistent raw TCP
Serve forwarding to loopback. Direct binding to a verified Tailnet IP supports
protocol-specific UDP; Serve TCP does not relay ordinary UDP. Never fall back
to a wildcard listener when the Tailnet address disappears.
SOCKS UDP datagrams do not carry the TCP username/password: enforce access
through Tailnet identity/policy and exact binding, and distinguish UDP tests
from successful TCP HTTPS verification.

An owned gateway uses direct egress or an explicit HTTP/SOCKS upstream. Reject
recursive upstreams and keep credentials out of arguments, logs and normal
status output. Controller listeners remain loopback. A foreign proxy remains
externally owned; only its owned share mapping may be stopped or removed.
Use the per-port Serve removal operation, not `serve reset` or Funnel.

`export` produces private node YAML, starter or client bundle. `connect` reuses
the persistent client-source preview/apply/verify flow. Export Tailnet access
prerequisites with the endpoint and proxy credentials, never Tailscale auth
keys or all peers. HTTP URLs continue to mean subscriptions; an exit node is
not a proxy URI. Do not turn temporary SSH forward ports into permanent nodes.

## State and evidence

Registrations live in `servers.toml` selected with `--servers-config`;
credentials, previous-state snapshots and ownership receipts use private state
storage. Keep local selection receipts bound to this client identity. Status
must distinguish cached registration from current remote observations.

Record peer reachability, direct/relay transport, listener scope and real egress
with timestamps. Online status is not proof of Internet routing, DNS behavior,
performance or reachability in a particular country. Export/import tests,
simulated host tests and real remote deployment are different evidence.
