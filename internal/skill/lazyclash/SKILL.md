---
name: lazyclash
description: Operate Mihomo clients through lazyclash CLI/TUI. Use for controller discovery, runtime selection, source-backed node/group editing and sharing, proxy environments, Docker consumer settings, managed native/Docker client setup, VPN/TUN diagnosis, cross-target comparison and owner-bound rule repair. Native Verge profile reactivation remains owned by Verge.
---

# lazyclash

Use the CLI as the controller interface. This guide ships with the binary;
`lazyclash --help` and command-level `--help` define its exact syntax.
`lazyclash --skill` and `lazyclash skill print` return this document even when
settings are broken or no core is reachable. They output Markdown, without
`--json`.

## Operating workflow

1. Identify the intended core with `lazyclash targets list --json`; use
   `lazyclash targets discover --json` when a controller needs to be found.
   Select a registered target or an explicit controller, then keep that same
   selection on every command in the operation. Never silently switch targets
   after a failure.
2. Test reachability with `targets test ID --json` when needed. Inspect current state before choosing an action. Use JSON to obtain actual
   group and member names, including Unicode and spaces; do not invent them.
3. Perform the change within the user's authorized scope, then read back the
   relevant state. An uncertain write can have succeeded: refresh first and
   do not blindly retry or claim rollback.

For a registered target, set `TARGET` to its actual ID. Set `GROUP` and `MEMBER`
from the returned proxy data and the user's requested selection:

```sh
lazyclash --target "$TARGET" status --json
lazyclash --target "$TARGET" proxies list --json
lazyclash --target "$TARGET" proxies select "$GROUP" "$MEMBER" --json
lazyclash --target "$TARGET" proxies list --json
```

`--read-only` blocks core control actions, active egress/latency tests and healthchecks; `targets test` remains available. It
still permits local target/config registration changes; use read commands when
the request is only to inspect.

## Read the relevant topic

- [Controllers and credentials](references/controllers.md), also
  `lazyclash skill print controllers`: choose HTTP(S), local Unix sockets or SSH;
  distinguish controller ports from proxy ports and retain secret references.
- [Runtime operations](references/runtime.md), also
  `lazyclash skill print runtime`: select proxies, interpret TUN, diagnose
  connections, and apply complete YAML without confusing it with Verge profiles.
- [Automation](references/automation.md), also
  `lazyclash skill print automation`: JSON/NDJSON, bounded log collection,
  noninteractive errors, exit codes, uncertain-write recovery and local CLI upgrades.

- [URL diagnosis](references/diagnosis.md), also `lazyclash skill print diagnosis`: separate observation contexts, confidence, DNS/TUN and tentative recommendations.
- [Cross-target and rule workflows](references/workflows.md), also `lazyclash skill print workflows`: preview digests, partial writes, persistent owners and completion setup.
- [Nodes and groups](references/sources.md), also `lazyclash skill print sources`: bind the actual owner, preserve raw definitions, review field changes, copy between targets and intentionally export credentials.
- [Proxy environments](references/environment.md), also `lazyclash skill print environment`: current-shell versus child scope, both SSH forwarding directions, remote shells, service lifetime checks, Docker namespaces and consumer tests.
- [Managed setup and network ownership](references/setup.md), also `lazyclash skill print setup`: native/Docker installation, offline starter data, privilege, TUN/VPN conflicts, receipts and host rollback.
- [Proxy servers and VPSs](references/servers.md), also `lazyclash skill print servers`: separate cloud/SSH inventory, protocol recipes, reviewed creation, service lifecycle, recovery and explicit credential exports.
- [Tailscale exits and private proxies](references/tailnet.md), also `lazyclash skill print tailnet`: existing peer identity, exit advertisement versus local selection, runtime TUN handoff, private Serve/direct-IP gateways and scoped recovery.
