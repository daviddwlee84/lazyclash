# lazyclash

A keyboard-first terminal console for **existing Mihomo cores**, including the core managed by Clash Verge Rev. Works locally, over HTTPS, through SSH, or over a local Unix socket. macOS and Linux are supported.

Manage runtime state, compare targets, diagnose URL routing, and repair exact domain rules through an explicitly bound persistent source. Clash Verge Rules edits require native profile reactivation. See the [knowledge and operating guide](docs/README.md), [reference index](docs/references.md), and [future milestones](TODO.md).

## Install and start

Requires Go 1.25 or newer and OpenSSH for SSH targets.

```sh
go install github.com/daviddwlee84/lazyclash/cmd/lazyclash@latest
lazyclash --version
lazyclash
```

The `/cmd/lazyclash` suffix identifies the executable package. Go installs it in
`go env GOBIN` when configured, otherwise in the first `go env GOPATH` entry's
`bin` directory (usually `~/go/bin`). Add that directory to your shell's PATH.
Repeating the install command upgrades to the latest published version. To pin
a release, use `@v0.1.5`; `@main` explicitly opts into the development
branch. `@latest` selects a published version, not necessarily the newest commit.
See [CHANGELOG.md](CHANGELOG.md) for changes between versions.

From v0.1.2 onward, the binary can check and update itself:

```sh
lazyclash upgrade --check
lazyclash upgrade --check --json
lazyclash upgrade
```

v0.1.1 has no `upgrade` command: use the `go install ...@latest` command above
once to obtain v0.1.2 or newer. `upgrade` runs without prompting, including in
pipelines; `--check` inspects versions, build provenance, the resolved executable
path and update eligibility without writing settings, locks or caches. It works
with missing/broken lazyclash settings and does not contact a Mihomo controller.
`--read-only` governs core operations; use `upgrade --check` for an update preview.

The current source-release channel requires Go for an actual update. lazyclash
pins the discovered stable release tag, builds a private candidate, verifies its
identity and version, and atomically replaces the **currently running executable's
resolved path**. A relocated Go release binary is supported; changing GOBIN or
PATH does not redirect the replacement. Symlinks are retained. Failures before
replacement leave the original binary in place; progress goes to stderr and is
suppressed with `--json`.

Development/VCS/dirty/pseudo-version builds are preserved by default. Use
`lazyclash upgrade --force` explicitly to replace one with the latest stable
release, or reinstall that release. This never pulls or edits a Git checkout.
Package-manager installations (Homebrew, mise, Nix) get their own update guidance;
unknown builds are not overwritten. `--force` does not bypass ownership or
identity checks. The updater does not use sudo, bootstrap a missing Go installation,
or check for updates at startup. An installed Go command retains the configured
`GOTOOLCHAIN` policy, including toolchain downloads when enabled. The embedded
`--skill` guide updates along with the binary.

To build a local checkout:

```sh
go build -o bin/lazyclash ./cmd/lazyclash
./bin/lazyclash
```

Source installation does not modify shell startup files. Run
`lazyclash completion install zsh` to install the user completion script and
print activation instructions; `completion status zsh` checks the file.
Existing completion directories can use `--dir ~/.zfunc`. See
[installation and completion](docs/install-upgrade-completion.md) for fpath,
compinit, Bash generation and update behavior. Homebrew and prebuilt release
archives remain a later distribution milestone.

With no saved targets, the dashboard discovers local controllers. Discovery reads known runtime configurations and process/config locations, then probes common loopback controller ports. Multiple candidates are presented for selection; an explicitly selected target never falls back to another core.

```sh
# Discover without changing settings.
lazyclash targets discover
lazyclash targets discover --ssh home-server

# Temporary connection, never automatically saved.
lazyclash --controller http://127.0.0.1:9097
lazyclash --controller https://core.example:9443 --ca-cert /absolute/private-ca.pem --secret-env MIHOMO_SECRET
lazyclash --ssh home-server --controller http://127.0.0.1:9090
lazyclash --controller unix:///absolute/path/mihomo.sock

# Bare targets add guides you in an interactive terminal.
lazyclash targets add
lazyclash targets add desktop --controller http://127.0.0.1:9097 --secret-env MIHOMO_SECRET
lazyclash targets add server --ssh home-server --controller http://127.0.0.1:9090 --secret-file /absolute/server.secret
lazyclash targets default desktop
lazyclash targets move server first
lazyclash --target server
```

If controller discovery requires authentication, configure a secret reference or save its matching `source_config` reference. Secrets are not displayed or put in SSH arguments. A Unix socket uses filesystem access, not Mihomo's HTTP secret.

## Dashboard

The header identifies the target and its runtime mode/TUN state. Overview opens
first with upload/download speed and totals, core RSS, connection count, traffic
and resource histories, protocol distribution, top outbounds and observed
routes. The existing Proxies, Connections, Logs, Rules, Providers and Configs
pages keep their numeric shortcuts (1–7). Use `--page proxies` to start in the
previous group/member/detail view.

Overview retains up to 15 minutes of history in memory per target, with 1-, 5-
and 15-minute windows. Graphs use actual sample times and leave gaps when a
target is disconnected or inactive. Each source shows its own age; samples over
five seconds old are stale. Initial zero memory is warmup, and memory means
**core RSS**, not host RAM. Core counters can reset. Connection distributions
use the full API snapshot; the browsing list is capped at 2,000 rows. Select a
distribution row and use Enter/Inspect for matching connections, or select a group
to open Proxies. Tab cycles these entries; arrows scroll the summary. `w` cycles
the time window, `v` cycles the graph style, `i` tests IP.SB and `L` tests websites.

Mouse input is enabled by default: click tabs, focus panes, select rows and
scroll with the wheel. Row clicks select; action buttons perform the named
operation. Forms support field focus and Save/Cancel/Test buttons. In target, YAML
registration and rule-source settings forms, Ctrl+S validates and saves directly
from the current field; Ctrl+T tests target connectivity. Invalid settings stay
editable, and the optional Review step remains available. Toggle mouse
capture with `M` or `--mouse=false` to use native terminal text selection.

Use `?` for contextual help and `:` for the action palette. Arrow keys and `hjkl` navigate; Tab/Shift+Tab move focus; `/` filters; Esc returns; `q` quits. Letters typed into a field remain text. Numeric page keys switch views. The target picker and action palette expose target management and SSH discovery. Narrow terminals show the focused pane.

Refreshing retains the selected object by identity. Failed refreshes retain visibly stale data. Remote text is sanitized before display; logs are bounded in memory and are not written to disk. `NO_COLOR=1` disables color. `--read-only` disables core control actions, latency tests and healthchecks; local target/config registrations can still be edited.

## Agent operating guide

The binary embeds its own operational skill, so an agent can read guidance for
the installed version without a checkout, working settings, or a running core:

```sh
lazyclash --skill
lazyclash skill print controllers
lazyclash skill print runtime
lazyclash skill print automation
```

`lazyclash skill print` and `--skill` print the same entry document. Topic names
are fixed; arbitrary filesystem paths are not accepted. These commands emit
Markdown and cannot be combined with `--json`. `--help` remains the authority
for command syntax.

For unattended operations, select a target explicitly and use JSON:

```sh
lazyclash --target desktop --json status
lazyclash --target desktop --json proxies list
lazyclash --target desktop --json logs --duration 10s --limit 100
```

JSON mode never starts a wizard or SSH authentication prompt, even inside a
PTY. It returns `ssh-auth-required` if a human authentication step is needed.
The guide explains runtime/Verge ownership, core-host paths, uncertain writes,
credential references and how to verify an operation through the CLI.

## Command line

Every core action uses the same API client as the dashboard. Read commands support `--json`; logs emit one JSON object per line. Credential-bearing runtime fields are replaced with `[redacted]` in output and details. Non-interactive invocations never prompt. Bare command groups show help.

```sh
lazyclash status --json
lazyclash proxies list --filter jp
lazyclash proxies delay 'Japan / 東京 🇯🇵'
lazyclash proxies select PROXY 'Japan / 東京 🇯🇵'
lazyclash mode rule
lazyclash tun on
lazyclash allow-lan off
lazyclash connections list --json
lazyclash connections close CONNECTION_ID
lazyclash connections close --all --yes
lazyclash logs --level debug --filter example --duration 10s --limit 100 --json
lazyclash rules list --filter example
lazyclash providers list proxies
lazyclash providers update rules NAME
lazyclash providers healthcheck NAME
lazyclash configs show --json
lazyclash settings show
lazyclash settings edit
lazyclash targets test server --json
lazyclash --target server diagnostics ip --json
lazyclash --target server diagnostics latency --json
lazyclash completion zsh
```

TUN requires a core with suitable OS privileges. After a toggle, lazyclash checks the core's reported setting; it does not claim to have verified OS routes or application traffic, and does not automatically restart the core. Proxy selections can be persisted by Mihomo's `profile.store-selected`; ordinary runtime changes may be replaced on restart or by another client.

Exit codes: `0` success, `1` runtime failure, `2` usage/settings error, `130` interrupted command. Closing an idle dashboard succeeds.

With `--json`, successful data stays on stdout and a failure is a single JSON
object on stderr, without a text prefix:

```json
{"error":{"code":"auth","message":"read version: controller authentication failed (HTTP 401)","operation":"read version","http_status":401}}
```

`operation` and `http_status` are included when applicable. Stable codes include
the controller's `auth`, `tls`, `unreachable`, `unsupported`, `invalid`,
`rejected`, `unknown-write-result`, `read-only` and `canceled`, plus `usage`,
`ssh-auth-required`, `config-conflict`, `timeout` and `runtime`. An
`unknown-write-result` means the request may already have applied; inspect the
target before deciding whether another mutation is appropriate.

Logs are NDJSON. `--duration` starts after the stream is established and ends
successfully even when no entries arrive; connection setup retains its own
timeouts. `--limit` counts successfully emitted entries after filtering. If
both are supplied, the first bound ends collection successfully; zero means
unbounded, preserving ordinary continuous log following. A count alone cannot
bound a quiet stream, so agents should supply a duration. Connection failures,
early disconnection, broken output and caller cancellation remain failures.

## Compare, diagnose and repair

```sh
lazyclash targets diff desktop server
lazyclash targets copy-settings desktop server --field mode --group PROXY
lazyclash --target server diagnostics url https://example.com --via PROXY
lazyclash --target server --read-only diagnostics url https://example.com --observe-only
lazyclash --target server rules source show
lazyclash --target server rules add-domain example.com --via PROXY
```

Copy and rule changes preview by default; applying requires `--yes --expect`
with the reviewed digest. The TUI action menu provides target comparison,
checkbox selection, URL topology/evidence inspection, rule-source binding,
preview/apply and receipt verification. Consult [targets](docs/targets-and-config.md),
[diagnostics](docs/diagnostics-and-routing.md), and
[rule ownership](docs/rules-and-ownership.md) before persistent repairs.

## Targets and settings

Preferences use `$XDG_CONFIG_HOME/lazyclash/config.toml`, falling back to `~/.config/lazyclash/config.toml` on both macOS and Linux. Relative XDG paths are ignored. Use `--config` or `LAZYCLASH_CONFIG` for a different existing file. Reads do not create directories. `settings path` prints the location even if
the file is malformed. `settings edit` opens `$VISUAL`, then `$EDITOR`, then
`vi`; executable arguments may be quoted, without shell evaluation. It requires
a terminal, creates a missing file privately, and validates after the editor
exits. Invalid edits are retained so they can be repaired.

The order of `[[targets]]` is the display order. `default_target` chooses startup; otherwise the first target is used. Explicit `--target`/`--controller` overrides environment selection (`LAZYCLASH_TARGET`/`LAZYCLASH_CONTROLLER`, with `CLASH_CONTROLLER` as a legacy fallback), which overrides the configured default. A temporary endpoint may use `CLASH_SECRET`; saved targets only use their own credential references. Secrets from one discovered target are never reused for another.

```toml
default_target = "desktop"

[tui]
start_page = "overview" # any of the seven page names
mouse = true
graph_style = "braille" # braille, block, ascii
history_window = "5m"   # 1m, 5m, 15m

[[targets]]
id = "desktop"
name = "Clash Verge"
controller = "http://127.0.0.1:9097"
secret_env = "MIHOMO_SECRET"

[[targets]]
id = "server"
name = "Home server"
controller = "http://127.0.0.1:9090"
ssh_host = "home-server"
secret_file = "/absolute/local/path/server.secret"
probe_proxy = "http://127.0.0.1:7890" # data proxy on the SSH host

[[targets.configs]]
id = "work"
name = "Work routing"
path = "/etc/mihomo/work.yaml"
```

Optional target fields: `ca_file` for a local PEM CA bundle and `source_config` for a runtime YAML on the target host. `source_config` only supplies credentials if its controller still matches the target. `secret_env` and `secret_file` are mutually exclusive and take precedence over that source. Existing `[[targets]]` array-table files preserve comments and unrelated fields when edited; unsupported compact TOML layouts require manual editing. Concurrent edits are detected before replacing the file. Saved settings have mode 0600.

SSH targets use system `ssh`, including configured aliases, keys, agent, ProxyJump and known_hosts. Password-only login is supported through native OpenSSH. The TUI offers Authenticate/Cancel when needed; A opens the authentication action. Configured ControlMaster/ControlPersist sessions are reused across commands, while private fallback sessions belong to the current process. Background/JSON commands never prompt. Each tunnel listens only on loopback; cleanup cancels its own forwards and leaves configured masters running. See [SSH session behavior](docs/targets-and-config.md#password-only-ssh-and-session-reuse). HTTPS still verifies the original controller hostname. Remote Unix-socket forwarding is not implemented; local Unix sockets are supported.

## Connectivity and egress diagnostics

`targets test [ID]` checks controller access (including SSH and authentication),
core version and readable runtime settings. It is safe with `--read-only` and
does not prove internet access. In the TUI, use `t` for the target picker,
`n`/`e` to add/edit, and Test to check a saved target or unsaved draft. A draft
test neither saves nor switches targets, and offline targets can still be saved.

For outbound diagnostics, explicitly register the selected target's **data
proxy**. The external-controller API port is a separate endpoint:

```sh
lazyclash targets edit server --probe-proxy http://127.0.0.1:7890
lazyclash targets test server --json
lazyclash --target server diagnostics ip --json
lazyclash --target server diagnostics latency --json
```

`probe_proxy` accepts HTTP, HTTPS, SOCKS5 and SOCKS5H URLs with an explicit port.
For SSH targets, that host and port are resolved from the SSH host through a
separate owned tunnel; for other targets they are reached locally. No probe
falls back to a direct, environment or system proxy route. A registered data
proxy can be tested even if the controller API is offline.

Optional `probe_username`, `probe_password_env` or `probe_password_file`, and
`probe_ca_file` configure data-proxy authentication and HTTPS trust independently
of controller credentials. Password references resolve locally and are mutually
exclusive. Use the corresponding `targets add/edit --probe-*` flags (the CA flag
is `--probe-ca-cert`); passwords do not belong in URLs or command arguments.

IP.SB egress uses an eight-second bound and identifies that request's source IP.
In rule mode other destinations may take different routes. Website checks send
fresh HEAD requests to Google, Cloudflare and GitHub, measuring time to response
headers with a five-second bound per site, excluding SSH tunnel setup. HTTP
errors retain their observed latency; any failed site gives a nonzero exit with
all available per-site results on stdout. These active requests are manual and
are disabled by `--read-only`.

## Applying existing YAML

```sh
lazyclash --target server configs add work --path /etc/mihomo/work.yaml
lazyclash --target server configs list
lazyclash --target server configs apply work --yes
```

The path belongs to the **core host/container**, must be readable there, and remains subject to Mihomo's `SAFE_PATHS`. Relative providers/geodata still resolve under the core's existing home directory, not the selected file's parent directory. No YAML is uploaded, rewritten or composed.

Applying uses `PUT /configs?force=true`: proxy listeners, DNS, rules and TUN are applied together. It does **not** change Mihomo's startup source, the external-controller connection settings, or Clash Verge's selected profile. A later restart, SIGHUP or GUI reload can replace this runtime state. `GET /configs` only returns general runtime settings, not a complete recoverable YAML. See the [upstream implementation](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/hub/route/configs.go).

The dashboard reports its last confirmed apply as an operation receipt, not authoritative active-profile state. A timeout can mean the write occurred; lazyclash never automatically retries a mutation or claims a rollback. A 204 response followed by read-back still does not prove every listener/provider is healthy.

Clash Verge Rev stores profile sources below `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/` on macOS, with metadata in sibling `profiles.yaml` and generated runtime settings in `clash-verge.yaml`. Merge/script entries are not complete configurations. This release does not change Verge's profile index or interpret its merge/script pipeline.

## Development and verification

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o bin/lazyclash ./cmd/lazyclash
go build -o bin/fakecore ./tools/fakecore
uv run scripts/pty_smoke.py
go run ./tools/fakecore
# In another terminal, connect to the loopback URL printed by fakecore.
go run ./cmd/lazyclash --controller http://127.0.0.1:PORT
```

The fixture core holds all state in memory and never changes your real proxy settings. Tests cover transport security, write verification, configuration preservation, SSH lifecycle, CLI contracts and TUI state transitions. The PTY smoke script drives two fixture controllers, checks actions/cancellation, Unicode input, resizing, target switching and shell-mode restoration. It needs Python with `pyte` (the `uv` script installs its isolated dependency). CI runs tests and the PTY scenario on macOS and Linux. Native terminal verification is separate from cross-compilation.

Licensed under the [MIT License](LICENSE).
