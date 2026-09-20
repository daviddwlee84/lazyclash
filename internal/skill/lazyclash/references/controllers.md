# Controllers and credentials

A **target** is an existing core's controller plus connection settings. A
**config** is a registered complete YAML path for one target. Neither is a
Clash Verge native profile.

## Find and fix the target

```sh
lazyclash targets list --json
lazyclash targets discover --json
lazyclash targets discover --ssh home-server --json
```

Discovery does not register candidates. If multiple controllers appear, select
the intended one from their source/endpoint information. Use `--target ID` for
a registration or `--controller URL` for a temporary endpoint; these are mutually
exclusive. Without either, environment/default/first-target selection can apply,
so pin the target for a multi-command workflow. An explicit target failure does
not fall back to another core.

The **external controller** is the management API. HTTP/SOCKS/mixed proxy ports
carry proxied traffic and cannot be substituted for it. Port numbers below are
examples; use discovery or the actual runtime configuration. SSH's port belongs
to the SSH host configuration, not the controller URL.

```sh
lazyclash --controller http://127.0.0.1:9090 --secret-env MIHOMO_SECRET status --json
lazyclash targets add desktop --controller http://127.0.0.1:9090 --secret-env MIHOMO_SECRET --json
lazyclash targets add server --ssh home-server --controller http://127.0.0.1:9090 --secret-file /absolute/local/server.secret --json
```

The `targets add` commands save local registrations; they do not install or
start a core. Pass every required argument in automation. `--json` never opens
the registration wizard.

## Secrets and transports

- Prefer an existing `--secret-env VARIABLE` or `--secret-file /absolute/path`
  reference. Both resolve on the machine running lazyclash, including for SSH
  targets. Do not put secret values in command arguments, output, or committed
  settings. These two references are mutually exclusive.
- A registered `--source-config /core/host/runtime.yaml` can supply matching
  controller credentials from the core host's runtime YAML. Explicit secret
  references take precedence. Do not copy a credential from an unrelated
  discovered controller.
- HTTPS supports `--ca-cert /absolute/local/ca.pem`; keep hostname verification.
  The client bypasses environment HTTP proxies and refuses redirects.
- `--controller unix:///absolute/path.sock` accesses a local Unix socket using
  filesystem permissions. Remote Unix-socket forwarding is unsupported.
- For `--ssh home-server`, the controller URL is interpreted on the remote
  host. lazyclash creates a loopback tunnel through system OpenSSH and retains
  aliases, keys, agent, ProxyJump and known_hosts behavior. Do not expose the
  remote controller just to make it reachable.
- Machine output (`--json`) never hands the terminal to SSH authentication.
  On an authentication-required error, arrange authentication interactively
  outside that machine invocation, then retry the read. Do not disable host-key
  checks or invent credentials.

Settings default to `$XDG_CONFIG_HOME/lazyclash/config.toml`, or
`~/.config/lazyclash/config.toml`. `--config` selects a different settings file;
it is not a Mihomo YAML. Use `settings show --json` for saved preferences and
`status --json` for the running core.

## Connectivity and data-plane diagnostics

Use `lazyclash targets test ID --json` to test SSH/API access, version and readable
runtime settings without changing the core. It works with `--read-only`. It is
not an internet test. Do not run `mihomo status` as a substitute: Mihomo can
interpret that invocation as starting another core, producing port/TUN conflicts.

`settings path` resolves the file even if malformed. `settings edit` is a human
TTY-only editor entry ($VISUAL > $EDITOR > vi), followed by validation; failed
validation retains the edits. Agents should use scriptable target edits.

Manual `diagnostics ip --json` and `diagnostics latency --json` require the
selected target's explicit `probe_proxy`; they never infer the data route from
the controller port and never fall back to direct/environment/system proxies.
A data-proxy registration can work when its management API is offline.

```sh
lazyclash targets edit server --probe-proxy http://127.0.0.1:7890 --json
lazyclash --target server diagnostics ip --json
lazyclash --target server diagnostics latency --json
```

Use actual configured ports. The proxy URL needs HTTP(S) or SOCKS5(H), an explicit
port, and no userinfo/path/query/fragment. For an SSH target its proxy address is
on the remote host and uses a separate owned tunnel. Data-proxy credentials are
independent: `--probe-username`, `--probe-password-env` or `--probe-password-file`
(mutually exclusive), and `--probe-ca-cert`. References and CA files are local.
Do not put passwords in URLs or reuse the controller secret.

Active diagnostics are disabled by `--read-only`. IP.SB egress describes that
request, not a universal node/IP for all rule-mode traffic. Website measurements
are fresh HEAD time-to-headers (Google, Cloudflare, GitHub), exclude SSH setup,
and preserve HTTP failures with observed timing. A failed site means nonzero
exit while partial per-site results remain on stdout; inspect both streams.

In the TUI, Ctrl+S saves a target draft directly from the current field after
normal validation. Ctrl+T tests connectivity independently; valid offline
registrations can still be saved. The Review button remains available. Invalid
input or a failed save retains the draft and editing focus.
