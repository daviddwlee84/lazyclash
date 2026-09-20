# Runtime operations

Read state and issue changes against the same explicit target. Runtime settings
belong to the core. They do not change the operating system's system-proxy
preferences, install services, or select Clash Verge profiles.

## Proxies and routing

`proxies list --json` returns a map keyed by actual proxy/group names. A group's
`all` array names its members and `now` reports its current choice. Choose a
supported selectable group and one of its actual members; quote names so spaces,
Unicode and slashes remain one argument. Selection verifies the core's response.
The supported selectable types are `Selector`, `URLTest` and `Fallback`;
selecting a member of an automatic group can override its automatic choice.
`proxies delay NAME` tests one proxy and generates network activity. Avoid
substituting a direct group-delay API call, which can reset an automatic group's
manual choice.

`mode rule|global|direct`, `tun on|off`, and `allow-lan on|off` update runtime
settings and read them back. TUN needs a capable, privileged core. A successful
API response or `tun.enable=true` does not prove that OS routes, DNS, or actual
traffic work; verify those separately only when required by the task. Do not
automatically restart the core to force a result.

## Diagnose traffic and providers

```sh
lazyclash --target "$TARGET" connections list --json
lazyclash --target "$TARGET" rules list --json
lazyclash --target "$TARGET" providers list proxies --json
lazyclash --target "$TARGET" providers list rules --json
```

Connections show the observed matching rule and proxy chain. The ordered rules
list alone is not an offline rule evaluator. Missing data is unknown, not proof
that traffic, TUN, or a proxy is down. Provider updates fetch their configured
source; provider healthchecks generate traffic. Refresh the corresponding
provider data after an update.

Close a specific connection by its observed ID when requested. Closing every
connection uses `connections close --all --yes`; it disrupts active traffic.
`--yes` expresses the caller's existing intent rather than granting new scope.

## Apply a complete YAML

```sh
lazyclash --target "$TARGET" configs list --json
lazyclash --target "$TARGET" configs show --json
```

`configs list` lists locally registered paths. `configs show` reads general
runtime settings; it cannot export or reconstruct the full YAML.

For an explicitly requested apply, register a known complete file with
`configs add ID --path /core/host/config.yaml`, then use `configs apply ID --yes`.
The path must be absolute and readable by the **core host/container**, subject
to its `SAFE_PATHS`. Nothing is uploaded. Relative providers and geodata still
resolve under the core's existing home directory, not the YAML's parent.

The operation loads runtime settings with `PUT /configs?force=true`, including
proxy listeners, DNS, rules and TUN. It leaves the core's startup source,
external-controller settings and Verge's selected profile unchanged. A GUI
reload or restart may replace this runtime state. Verge merge/script snippets
are not complete configurations and cannot be applied as if they were.

A confirmed apply is an operation receipt, not authoritative active-profile
state. Read-back does not prove every provider or listener is healthy. If the
write outcome is uncertain, inspect the same core before considering a retry;
do not claim rollback or assume the old configuration remained active.
