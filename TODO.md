# Future milestones

The current release supports existing-core observation, runtime comparison/control, URL diagnosis and exact-domain repairs for explicitly bound owners. Remaining milestones:

- **SVG topology export (P?, M)**: optional local Mermaid CLI rendering when needed; terminal/Mermaid/JSON output ships first, without Node or Chromium. → [research](backlog/topology-svg-export.md)

- **Extended rules workbench**: edit general staged personal overrides with `$VISUAL`/`$EDITOR`; keep baseline, overrides and generated configuration separate; validate with the target core version in isolated storage; show diff, detect conflicting edits and retain previous revisions.
- **Offline rule evaluation**: preview supported deterministic rules while preserving unknown outcomes; extend the shipped active URL evidence without pretending offline estimates are observations.
- **Managed core upgrades/migration**: update/rollback core binaries and images; migrate backend/service identity/ports with complete resource and service recovery. v0.1.6 adds installation, profile configuration, lifecycle and guarded network setup.
- **Routing data updates**: optional separately downloaded verified rule bundles beyond the snapshot embedded in a binary. v0.1.6 ships offline cn-split/simple presets with immutable clash-rules provenance and category mapping.
- **Dual full-tunnel routing**: explicitly designed exit-node/TUN chaining. The current coexistence path supports split VPN destinations and reports competing default-route owners.
- **Service-owned proxy tunnels**: explicit persistent ownership, service lifecycle and recovery for background consumers; v0.1.7 provides invocation/shell forwards and rejects known temporary endpoints for service use. Keep this separate from arbitrary command replay and shell-owned leases.
- **Further proxy integration**: incrementally consolidate repeated dotfiles resolution and Docker diagnosis, then consider a TUI tunnel view and authenticated/TLS reverse proxy endpoints. Preserve Docker configuration ownership and API-gateway responsibilities.
- **Extended client adapters**: native activation bridges and broader profile/merge/script editing; the current Verge 2.5.2 adapter edits existing Rules/Proxies/Groups companions and requires manual native reactivation.
- **Remote Unix sockets**: OpenSSH stream-local forwarding, including discovery and cleanup tests.
- **Formal distribution**: publish macOS/Linux amd64/arm64 archives with stable names, checksums and completions; add a Homebrew formula in the maintainer's tap. Keep `go install` as the lightweight source channel and package-manager upgrades owned by that manager.

Useful upstream references: [Mihomo API](https://wiki.metacubex.one/api/), [rules](https://wiki.metacubex.one/config/rules/), [clash-rules wiring](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml).
