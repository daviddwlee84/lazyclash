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
