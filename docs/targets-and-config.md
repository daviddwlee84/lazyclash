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
tests. Press Ctrl+S to validate and save from any target field, without visiting
every optional field. Ctrl+T tests connectivity independently; reachability is
not required to save valid settings. Invalid input and failed saves retain the
current field and draft. Testing a draft neither saves it nor changes the selected core. Discovery
never silently substitutes a different core for an explicitly selected target.
JSON/noninteractive commands never open an authentication prompt.

Use `settings path`, `settings show`, or `settings edit` for local TOML.
The editor uses VISUAL, EDITOR, then vi, and remains accessible for malformed
settings. Reads do not rewrite settings; saves preserve comments/unknown fields
and detect conflicting edits.

## Password-only SSH and session reuse

SSH passwords work without SSH keys. Interactive CLI commands can hand the
terminal to OpenSSH when login is required. In the TUI, a connection that needs
SSH authentication shows **Authenticate / Cancel**; Enter starts native SSH,
and A reopens the action later. Authentication is allowed in read-only mode.
Failed login or Cancel in the dialog leaves the dashboard usable without
automatic prompt retries. Ctrl+C remains an application interrupt, including
at a native SSH prompt, and restores the terminal on exit.
Other open forms and work results retain their input ownership.

The password belongs to OpenSSH. Do not put it in lazyclash's secret_file or
secret_env: those are controller API credentials. Proxy password references
likewise belong to the data proxy, not SSH login.

lazyclash honors an existing configured ControlMaster connection. When the
user's SSH configuration enables a persistent master, foreground authentication
uses that policy so subsequent CLI invocations and the TUI can reuse it. For
example, an existing SSH host block may opt into:

```sshconfig
Host home-server
    ControlMaster auto
    ControlPath ~/.ssh/cm-%C
    ControlPersist 10m
```

OpenSSH manages that session's idle timeout; lazyclash does not edit your SSH
configuration or store a password. It cancels only the individual forwards it
added and never terminates a configured master. Without usable persistent
multiplexing, a private fallback session belongs to the current lazyclash
process and closes when that process exits. A successful test command therefore
does not imply a lasting login in that fallback case.

JSON and noninteractive calls never prompt. With configured persistent sharing,
a prior interactive `targets test server` or `ssh home-server true` can establish
the session before a later JSON read. An expired session can require interactive
authentication again. Password, keyboard-interactive/MFA and host-key questions
remain OpenSSH's responsibility; host-key checks are retained.

## Docker-hosted controllers

Register each controller separately using its published **SSH host port**.
For example, after verifying an API at host 9091 and a mixed listener at 7890:

```sh
lazyclash targets add docker-mihomo --ssh home-server \
  --controller http://127.0.0.1:9091 --probe-proxy http://127.0.0.1:7890
```

Discover does not currently inspect Docker port or mount mappings. Verify the
actual API and listener type; a published redir/tproxy port is not an HTTP or
SOCKS proxy. Ordinary API monitoring/control does not require Docker socket
access or installation of lazyclash inside the container.

If credentials are needed, source_config must be a file readable on the SSH
host (the host side of a bind mount), and its controller must match the saved
endpoint. Port remapping may prevent that match; use an explicit local secret
reference in that case. A registered configs path used by configs apply instead
belongs to the core's **container filesystem**.

Persistent rule changes use an explicit Docker rule source:

```sh
lazyclash --target docker-mihomo rules source set --kind docker \
  --container mihomo --host-path /srv/mihomo/config.yaml \
  --core-path /root/.config/mihomo/config.yaml \
  --binary /mihomo --home /root/.config/mihomo
```

The adapter verifies the container and host bind, validates using its image in
private staging storage, and reloads the container-visible path. The two paths
must describe the same bound file; a host path is not a container reload path.
Host DNS/routes and a bridge-network container's DNS/routes remain different
observation contexts. See [rule ownership](rules-and-ownership.md) and the
[Docker references](references.md#host-diagnostics).

Node/group editing keeps its separate Docker-aware `configs source` binding.
Use `rules source set --from-config-source` to explicitly reuse an existing
owner for rule operations. Credential discovery alone never establishes either
write binding. See [nodes and groups](proxies-and-groups.md).
`setup` can also create an explicitly owned native/Docker client and register its
target; see [managed clients](managed-cores.md).

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
