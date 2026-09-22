# Existing client services

`targets service` controls an existing Docker container or Linux systemd service.
It is separate from controller settings, node/group source ownership, managed
`cores` installations, and VPS proxy `servers`. Binding records an inspected
identity; it does not install, replace, recreate, or delete the service.

The TUI action menu includes **Existing target service** and opens these same
CLI previews. A bound service remains controllable when its controller is stopped.

## Bind the actual owner

Use the target ID and host-local values discovered from the running service.
For SSH targets, all Docker/systemd commands run on that SSH host. Rootless Docker
requires its explicit socket; the default daemon may belong to another owner.

```sh
lazyclash targets service bind "$TARGET" --kind docker \
  --docker-host unix:///run/user/1000/docker.sock --container mihomo --json

# Review the exact identity and set REVIEWED_DIGEST from this preview.
lazyclash targets service bind "$TARGET" --kind docker \
  --docker-host unix:///run/user/1000/docker.sock --container mihomo \
  --yes --expect "${REVIEWED_DIGEST:?review the binding first}"

lazyclash targets service bind "$TARGET" --kind systemd \
  --scope user --unit mihomo.service --json
```

Docker bindings pin the socket, full container ID, image ID, mount mapping, and
Compose project/service/source when present. Systemd bindings pin the exact unit,
user/system scope, fragment and drop-in contents. Changed identities require a
new inspected binding. Editing a target's controller or SSH host clears service
control authority. Managed installations continue to use `cores` commands.

`--scope system` uses the existing systemd authorization policy; lazyclash does
not silently install sudo rules or change service ownership.

## Status and reviewed actions

```sh
lazyclash targets service status "$TARGET" --json
lazyclash targets service restart "$TARGET" --json
lazyclash targets service restart "$TARGET" \
  --yes --expect "${REVIEWED_DIGEST:?review the restart first}"

# Preview stopping this one container and disabling its automatic startup.
lazyclash targets service stop "$TARGET" --disable-autostart --json
lazyclash targets service stop "$TARGET" --disable-autostart \
  --yes --expect "${REVIEWED_DIGEST:?review the combined action first}"
```

`start`, `stop`, `restart`, `enable`, and `disable` all preview by default. Use a
fresh digest for each action. `enable` chooses `unless-stopped` for Docker;
`disable` chooses `no`. For Compose containers, autostart changes update both the
live policy and the specific service's `restart` field, preserving other services
and comments. Complex/multiple Compose sources are refused rather than rewritten.
The original Compose bytes are backed up privately before replacement.

Only the bound service is controlled. The Docker daemon, its boot hook, unrelated
containers and shared bind-mounted resources are preserved. For example, retain
a retired Clash directory if Mihomo still mounts its `Country.mmdb` file. An
explicit future `docker compose up` can intentionally start a disabled service;
`restart: "no"` prevents automatic restart, not manual administration.

A private lifecycle receipt is written before mutation under
`$XDG_STATE_HOME/lazyclash/service-receipts` (default
`~/.local/state/lazyclash/service-receipts`). An unconfirmed result requires status
inspection before another attempt. Start/restart loads startup configuration;
record and verify mode, selections and TUN when they differ from saved settings.

## Docker configuration activation

Node/group write ownership remains separately explicit:

```sh
lazyclash --target "$TARGET" configs source set --kind docker \
  --docker-host unix:///run/user/1000/docker.sock --container mihomo \
  --host-path /home/user/mihomo/config.yaml \
  --core-path /root/.config/mihomo/config.yaml \
  --binary /bin/mihomo --home /root/.config/mihomo
```

Use the same explicit Docker socket for both bindings. Before source edits,
lazyclash proves the container and host bind mapping and validates with the actual
core in isolation. After an atomic write, a single-file bind can still expose the
old inode. With an existing-service binding, the reviewed import restarts that
exact container, verifies the new bytes inside it, waits for controller readiness,
and sends its runtime reload once. It never recreates the container or falls back
to overwriting a live file in place.

Without a service binding, stale container bytes produce
`persisted_pending_owner_reload`; no reload is sent against those stale bytes.
Source save, owner activation, runtime observation and network usability remain
separate results. Restoring an import uses the same mount verification and owner
activation rules. Follow an import with receipt verification and real proxy traffic.
