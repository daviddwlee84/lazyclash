---
name: lazyclash
description: Inspect and control existing Mihomo or Clash Verge-managed cores through lazyclash. Use for controller discovery, proxy selection, runtime routing settings, connection diagnosis, provider refreshes, and applying registered complete YAML files. Does not install cores or manage native Verge profiles.
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
2. Inspect current state before choosing an action. Use JSON to obtain actual
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

`--read-only` blocks core control actions, latency tests and healthchecks. It
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
  noninteractive errors, exit codes and uncertain-write recovery.
