# Quick rules, healthchecks and persistent ownership

Saving a source file, loading it into a core and observing a request use its
rule are separate outcomes. A runtime `PUT /configs` does not regenerate a
Clash Verge profile or synchronize its in-memory state.

## Apply one rule to a target or all targets

```sh
lazyclash --target server rules apply 'DOMAIN,api.enterprise.githubcopilot.com,DIRECT'
lazyclash rules apply 'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT' --all --dry-run
lazyclash rules apply 'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT' --all --yes
# A pasted YAML list item also works; put flags before the -- terminator.
lazyclash --target server rules apply --dry-run -- '- DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT'
```

Without `--all`, the selected/default saved target is used. An explicit
`--target` and `--all` are mutually exclusive. New rules are prepended to the
bound persistent source. An identical canonical rule already anywhere in that
source is skipped without moving it, writing a file or reloading the core.
Its position can still leave it shadowed; the result includes that warning.

The command inspects source and runtime rules and validates each candidate
before writing. Invalid syntax, an unavailable policy or the same selector with
different policies is an **ERROR**. Any such error aborts the batch before its
first write. Confirmed overlap and shadowing are **WARNING** findings, with the
two rules and their positions. The ordinary final `MATCH` fallback is expected.

Interactive apply shows the plan and asks **[y/N]**; Enter, No or cancellation
leaves the sources unchanged. `--dry-run` always stops after the preview.
`--yes` applies immediately after preflight, accepting warnings without a prompt
or a required digest. It never bypasses errors or concurrent-edit guards.
Use `--dry-run --json`, then `--yes --expect DIGEST`, when automation should pin
the exact reviewed plan. JSON and noninteractive execution without `--yes`
returns a preview and never prompts. Use `--dry-run` to request preview-only
behavior explicitly in either terminal mode.

`--all` attempts every saved target with its own credentials. Unreachable or
unbound targets are reported as `skipped_unavailable`; they do not prevent the
remaining usable targets from proceeding. Successful usable targets plus skips
return exit 0 with `completed_with_skips`. Existing rules count as usable;
if no selected target is usable, the command returns nonzero. Rule errors remain
batch blockers. Writes run in target-ID order. A later write/reload failure
stops remaining targets and retains earlier changes and their receipts; this
is not a transaction spanning several hosts.

The Rules page exposes **n Quick apply routing rule** and **H Rules healthcheck**;
both are also in the action palette, for one target or all targets. Preview
rows show each target's owner, findings and disposition before the default-No
confirmation.

## Choose the intended matching scope

The quick command accepts one rule, as a scalar or single YAML list item:

| Type | Example | Scope |
| --- | --- | --- |
| `DOMAIN` | `DOMAIN,api.enterprise.githubcopilot.com,DIRECT` | That exact hostname; prefer this for one API endpoint. |
| `DOMAIN-SUFFIX` | `DOMAIN-SUFFIX,example.com,DIRECT` | The base domain and its subdomains. |
| `DOMAIN-KEYWORD` | `DOMAIN-KEYWORD,github,DIRECT` | Any hostname containing the literal substring; broader than a domain suffix. |
| `IP-CIDR` | `IP-CIDR,203.0.113.7/32,DIRECT,no-resolve` | An IPv4 destination prefix, across ports. |
| `IP-CIDR6` | `IP-CIDR6,2001:db8::7/128,DIRECT,no-resolve` | An IPv6 destination prefix, across ports. |

Domains/keywords are normalized to lowercase; CIDRs are masked to their network.
CIDR type aliases normalize by address family. Policy names retain their case
and must exist on each target. Use ASCII DNS names or punycode for DOMAIN and
DOMAIN-SUFFIX. A keyword is a substring, not a URL, suffix boundary or regex.

Raw IP input requires a CIDR. Optional `no-resolve` is preserved: it prevents
that rule from initiating a DNS lookup, but can still match an IP resolved
earlier. Omitting it retains the core's resolving behavior; quick apply does
not silently add it. A source-IP `src` modifier changes the selector and is not
accepted for new quick rules. Existing source-IP rules remain distinct during
analysis. Other new rule types/modifiers require a fuller editing workflow;
they are not silently rewritten.

## Inspect rules without changing them

```sh
lazyclash --target server rules healthcheck
lazyclash rules healthcheck --all --json
lazyclash --target server --read-only rules healthcheck
```

Healthcheck reports source and runtime findings separately, rule counts by type
and policy, analyzed/opaque/invalid/disabled counts, routing mode and provider
count. It checks malformed common rules, exact-selector policy conflicts,
duplicates, confirmed overlap/shadowing and rules after MATCH. It sends no probe
traffic, refreshes no providers, and writes or reloads nothing. Errors return
nonzero; warnings alone do not.

Source coverage means the bound complete YAML, or the Verge Rules companion's
prepend/append lists. A Verge base profile, Merge and Script are not composed by
the analyzer. Runtime-only targets can still be inspected, but the controller
cannot establish original YAML syntax or all modifiers, including `no-resolve`.
A source/runtime difference is drift, not a contradictory pair within one list.
For Verge quick apply, a proposed selector conflicting with the current runtime
is also blocking: editing its companion does not remove the base profile rule.
Runtime presence does not prove a request used that rule.

Provider contents, GEO data, regex, process/port and logical expressions are
not expanded. They remain opaque with explicit limitations. Keyword relations
are reported when literal containment proves them; missing findings do not
prove disjointness. Existing domain literals outside ordinary DNS-name syntax,
including underscore labels or trailing dots, also remain opaque. The core
retains those literals, so they cannot be rewritten or treated as duplicates
of a new normalized hostname. Large lists can reach the documented overlap-analysis
limit while exact-selector checks still cover the full list. Counts describe
what was inspected, not a percentage of internet traffic covered.

## Bind the persistent owner

For a standalone local or SSH Mihomo, register a complete YAML and bind the
actual core binary/home used to validate it:

```sh
lazyclash --target server configs add main --path /home/user/.config/mihomo/config.yaml
lazyclash --target server rules source set --kind mihomo --config-id main \
  --binary /usr/local/bin/mihomo --home /home/user/.config/mihomo
lazyclash --target server rules source show
```

These are paths on the selected host. `source_config` credential discovery
does not implicitly authorize writes. The TUI has a **Bind persistent rule
source** form for the same registration.

For an existing Docker core, bind the host file and the core-visible reload path
separately:

```sh
lazyclash --target docker-mihomo rules source set --kind docker \
  --container mihomo --host-path /srv/mihomo/config.yaml \
  --core-path /root/.config/mihomo/config.yaml \
  --binary /mihomo --home /root/.config/mihomo
# Optional: --docker-host unix:///var/run/docker.sock
```

The adapter checks the container identity and bind mount, validates in a private
container stage using the same image, then reloads the container path. A replaced
single-file bind mount can still expose the old inode inside the container. With
a matching service binding, lazyclash restarts that owner and waits for its
controller before reloading once. Otherwise it reports
`persisted_pending_owner_reload`; activate the owner manually and verify the
receipt. `--config-id` is optional; when given, its registered path must equal
`--core-path`. An inaccessible Docker owner is reported rather than falling
back to an unrelated host file.

An existing node/group source can be explicitly reused with
`rules source set --from-config-source`. This copies its owner details into a
separate rule binding; it does not grant rule writes merely because a
`configs source` binding exists. For native validation in an already available
Docker sandbox, use `--validation-docker-host` with `--validation-image`; the
image must be a full local `sha256:` ID. No sandbox is installed automatically.

For Clash Verge Rev, explicitly bind the data directory, active profile UID
and declared supported owner version:

```sh
lazyclash --target desktop rules source set --kind verge \
  --data-dir "/path/to/Clash Verge data" --profile PROFILE_UID --owner-version 2.5.2
```

The version declares the compatibility contract; it is not proof of the
installed application's identity. The supported pipeline was reviewed against
Verge Rev 2.5.2. Source/schema/profile checks still run before each write.

## Existing exact-domain repair workflow

```sh
lazyclash --target server rules add-domain example.com --via PROXY
lazyclash --target server rules add-domain example.com --via PROXY \
  --yes --expect DIGEST
lazyclash --target server rules verify RECEIPT
```

The policy must exist on that target. Preview shows the exact hostname,
file, owner, rule change and digest. Existing exact DOMAIN entries are handled
without duplicating the same rule; unrelated content is retained. Applying an
old preview fails if its guarded source/context changed.

`add-domain` and `add-ip` retain their repair behavior: they replace rules for
the same selector and require `--yes --expect DIGEST`. Use `rules apply` for
add-if-absent behavior with conflicts treated as errors.

Private backups and receipts support recovery. Files are replaced atomically,
but file save and core reload are not one atomic transaction. If loading fails
or the result is uncertain, inspect the receipt and runtime before retrying.
`rules restore RECEIPT --yes` checks that the current file still matches the
recorded change before restoring its backup.

## Preview an IP address or network rule

```sh
lazyclash --target desktop rules add-ip 203.0.113.10 --policy DIRECT
lazyclash --target desktop rules add-ip 203.0.113.10 --policy DIRECT \
  --yes --expect DIGEST
lazyclash --target desktop rules verify RECEIPT
```

A bare IPv4 address becomes `/32`; a bare IPv6 address becomes `/128`. Explicit
CIDRs are masked to their canonical network in the preview. The generated rule
is `IP-CIDR` or `IP-CIDR6` with `no-resolve`, so checking the rule does not request
DNS resolution. URLs, DNS names, interface zones and IPv4-mapped IPv6 inputs are
rejected. The policy must already exist on the selected target.

Choose the smallest intended destination prefix. For example, a host rule can
keep administration traffic to a known proxy VPS direct when sending SSH through
that proxy would conflict with the VPS's source-IP restriction. An IP rule applies
to that destination prefix across ports; it is not an SSH-only exception.

Only rules with the same type and canonical prefix are replaced/deduplicated;
broader overlapping networks and unrelated rules retain their order. The same
preview digest, private backup, receipt, owner activation, verification and
restore workflow applies. IP receipts expose `prefix`, without labeling it as a
DNS domain. Verification requires the exact prefix and policy in the first
runtime rule. Mihomo reports both source rule families as runtime `IPCIDR`.
See its [rule implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/rules/common/ipcidr.go).

## Standalone Mihomo validation

Validation uses the bound binary and an isolated temporary home, with needed
resources copied rather than sharing the live cache. `mihomo -t` can initialize
files, download geodata or open a cache while parsing; pointing it at a running
core's home can cause cache-lock timeouts.

Validation requires Python 3 and OS isolation: sandbox-exec on macOS, bubblewrap
(`bwrap`) on Linux. Network access and writes outside the private staging home
are blocked. Missing isolation/resources cause an explicit pre-write failure;
lazyclash does not install dependencies or silently weaken validation.

After a validated save, the registered YAML is reloaded and runtime rules are
read back. Successful config validation alone does not prove listener ports,
TUN permissions, provider downloads or website usability.

Do not run `mihomo status` as a status check: Mihomo's core executable may treat
it as ordinary startup, creating port/TUN conflicts with the existing core.
Use `lazyclash status` or the service manager.

## Clash Verge native activation

Only the existing active profile's **Rules companion** is edited, using
`prepend`. Its schema is `prepend/append/delete`; the legacy-looking
`prepend-rules` key is not the supported Merge interface.

The pipeline is profile source → Rules/Proxies/Groups → app defaults →
global Merge → global Script → profile Merge → profile Script → restored
GUI-owned control settings. Comment-only or valid YAML-null Merge templates are
accepted as empty context; native YAML and Rules companions still require their
normal mapping schemas. A later Merge.rules or Script can replace earlier
rules. Arrays in a Merge are replacements, not implicit append operations.

Saving reports `persisted_pending_owner_reload`. Reactivate the profile in
Clash Verge's native interface, then run Verify or click the TUI Verify action.
The runtime check can detect a missing/overridden rule; a fresh URL diagnosis
is still needed to observe a particular request's route.

There is no ordinary external GUI regenerate/reload API in the reviewed
version. lazyclash does not edit generated clash-verge.yaml, create/rebind
profiles.yaml entries behind the running GUI, invoke private Tauri commands as
HTTP endpoints, or automate macOS accessibility. If a companion is missing,
create it through the native interface first.
