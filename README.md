# lazyclash

A keyboard-first terminal console for **existing Mihomo cores**, including the core managed by Clash Verge Rev. Works locally, over HTTPS, through SSH, or over a local Unix socket. macOS and Linux are supported.

This first milestone manages runtime state. It does not install Mihomo, take ownership of Clash Verge profiles, edit subscriptions, or change the OS system proxy. Those capabilities are tracked in [TODO.md](TODO.md).

## Build and start

Requires Go 1.25 or newer and OpenSSH for SSH targets.

```sh
go build -o bin/lazyclash ./cmd/lazyclash
./bin/lazyclash
```

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

The header always identifies the target and its runtime mode/TUN state. The Proxies page opens first with group, member and detail panes. Other pages provide overview/traffic, connections, live logs, ordered rules, providers and registered YAML configurations.

Use `?` for contextual help and `:` for the action palette. Arrow keys and `hjkl` navigate; Tab/Shift+Tab move focus; `/` filters; Esc returns; `q` quits. Letters typed into a field remain text. Numeric page keys switch views. The target picker and action palette expose target management and SSH discovery. Narrow terminals show the focused pane.

Refreshing retains the selected object by identity. Failed refreshes retain visibly stale data. Remote text is sanitized before display; logs are bounded in memory and are not written to disk. `NO_COLOR=1` disables color. `--read-only` disables control actions, latency tests and healthchecks.

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
lazyclash logs --level debug --filter example --json
lazyclash rules list --filter example
lazyclash providers list proxies
lazyclash providers update rules NAME
lazyclash providers healthcheck NAME
lazyclash configs show --json
lazyclash settings show
lazyclash completion zsh
```

TUN requires a core with suitable OS privileges. After a toggle, lazyclash checks the core's reported setting; it does not claim to have verified OS routes or application traffic, and does not automatically restart the core. Proxy selections can be persisted by Mihomo's `profile.store-selected`; ordinary runtime changes may be replaced on restart or by another client.

Exit codes: `0` success, `1` runtime failure, `2` usage/settings error, `130` interrupted command. Closing an idle dashboard succeeds.

## Targets and settings

Preferences use `$XDG_CONFIG_HOME/lazyclash/config.toml`, falling back to `~/.config/lazyclash/config.toml` on both macOS and Linux. Relative XDG paths are ignored. Use `--config` or `LAZYCLASH_CONFIG` for a different existing file. Reads do not create directories.

The order of `[[targets]]` is the display order. `default_target` chooses startup; otherwise the first target is used. Explicit `--target`/`--controller` overrides environment selection (`LAZYCLASH_TARGET`/`LAZYCLASH_CONTROLLER`, with `CLASH_CONTROLLER` as a legacy fallback), which overrides the configured default. A temporary endpoint may use `CLASH_SECRET`; saved targets only use their own credential references. Secrets from one discovered target are never reused for another.

```toml
default_target = "desktop"

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

[[targets.configs]]
id = "work"
name = "Work routing"
path = "/etc/mihomo/work.yaml"
```

Optional target fields: `ca_file` for a local PEM CA bundle and `source_config` for a runtime YAML on the target host. `source_config` only supplies credentials if its controller still matches the target. `secret_env` and `secret_file` are mutually exclusive and take precedence over that source. Existing `[[targets]]` array-table files preserve comments and unrelated fields when edited; unsupported compact TOML layouts require manual editing. Concurrent edits are detected before replacing the file. Saved settings have mode 0600.

SSH targets use system `ssh`, including configured aliases, keys, agent, ProxyJump and known_hosts. Background commands cannot prompt; an explicit foreground authentication action can establish a private, short-lived OpenSSH control connection. Each tunnel listens only on loopback, and cleanup closes only resources created by lazyclash. HTTPS still verifies the original controller hostname. Remote Unix-socket forwarding is not implemented; local Unix sockets are supported.

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
