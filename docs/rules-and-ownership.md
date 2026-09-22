# Persistent rules and owner-aware repair

Saving a source file, loading it into a core and observing a request use its
rule are separate outcomes. A runtime `PUT /configs` does not regenerate a
Clash Verge profile or synchronize its in-memory state.

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

For Clash Verge Rev, explicitly bind the data directory, active profile UID
and declared supported owner version:

```sh
lazyclash --target desktop rules source set --kind verge \
  --data-dir "/path/to/Clash Verge data" --profile PROFILE_UID --owner-version 2.5.2
```

The version declares the compatibility contract; it is not proof of the
installed application's identity. The supported pipeline was reviewed against
Verge Rev 2.5.2. Source/schema/profile checks still run before each write.

## Preview and apply a domain rule

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
