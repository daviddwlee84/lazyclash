# Targets and configuration

## Register and monitor an SSH core

```sh
lazyclash targets discover --ssh home-server
lazyclash targets add server --ssh home-server \
  --controller http://127.0.0.1:9090 \
  --source-config /home/user/.config/mihomo/config.yaml
lazyclash targets test server
lazyclash --target server --read-only
```

The controller address and source YAML refer to the SSH host. OpenSSH host
aliases, keys and known-host checks are retained. The source configuration must
match the controller before its secret is used. Alternatively use a local
`--secret-file` or `--secret-env` reference. Secrets do not go in SSH arguments.

Changing a saved endpoint/SSH host clears its persistent rule binding; explicitly
rebind the new owner before rule repair. Temporary transport overrides cannot
reuse a saved rule owner. Credential-only overrides retain their separate role.

The TUI action menu (`:`) provides SSH discovery, target add/edit and connectivity
tests. Testing a draft neither saves it nor changes the selected core. Discovery
never silently substitutes a different core for an explicitly selected target.
JSON/noninteractive commands never open an authentication prompt.

Use `settings path`, `settings show`, or `settings edit` for local TOML.
The editor uses VISUAL, EDITOR, then vi, and remains accessible for malformed
settings. Reads do not rewrite settings; saves preserve comments/unknown fields
and detect conflicting edits.

## Management and request traffic

HTTP(S) controllers expose Mihomo's external control API. Unix socket targets
use filesystem access. SSH targets forward the management connection without
making the API public. Remote Unix socket forwarding remains future work.

Active IP/website/URL probes have a separate, explicitly registered data proxy:

```sh
lazyclash targets edit server --probe-proxy http://127.0.0.1:7890
lazyclash --target server diagnostics ip
```

For SSH, the proxy address is also on that host and receives its own forward.
Proxy authentication and custom CA references are separate from controller
credentials. There is no silent environment/direct fallback for explicit proxy
probes. A working API does not prove a working data proxy, or vice versa.

## Compare and copy

```sh
lazyclash targets diff desktop server
lazyclash targets diff desktop server --json
lazyclash targets copy-settings desktop server \
  --field mode --field log-level --group PROXY --json
# Inspect the preview, then pass its exact digest:
lazyclash targets copy-settings desktop server \
  --field mode --field log-level --group PROXY --yes --expect DIGEST
```

Both arguments must be saved targets. Each supplies its own transport and
credentials; temporary global connection overrides are rejected.

Diff compares the core-reported version, available general runtime fields,
group types/membership and manual selections. It excludes health samples and
automatic groups' changing `now` values. Secret-bearing fields are explicitly
not compared. Absent fields remain distinct from present zero/null values.
Equality means equality of the compared state, not identical binaries, YAML,
credentials or host networking.

Copy accepts only explicit `mode`, `log-level` and manual `Selector` groups.
The destination must already contain the source-selected member; identical
names are not proof of identical node credentials or servers. No YAML, ports,
TUN, authentication or provider definitions are copied.

The preview digest binds the target identities and relevant source/destination
state. Apply rereads them, then performs log-level, sorted groups, and mode,
with readback at every step. A stale preview stops before applying it. Operations
are not atomic across two cores: failure stops subsequent steps and reports
applied/failed/unknown/unattempted outcomes. Do not retry an unknown write
without inspecting the destination.

The TUI's **Compare targets / copy selected settings** action offers target
pickers and unchecked choices. Space selects a field, Preview shows the actual
changes, and Apply confirms that reviewed digest.

These changes affect runtime. Core persistence options or a native client may
retain some choices, but restart/profile reload can replace them. Complete YAML
transfer and server installation are outside this operation.
