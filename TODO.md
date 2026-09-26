# Future milestones

Current functionality includes existing-core observation, runtime comparison/control, URL diagnosis, quick common-rule apply and passive rule healthchecks for explicitly bound owners. Remaining milestones:

- **VPS 每人／每裝置憑證管理 (P?, L)**: multiple UUIDs, device-specific exports, revocation and rotation with persistent configuration ownership; preserve legacy shared credentials and distinguish blocking new authentication from terminating existing sessions. → [research](backlog/server-client-identities.md)

- **SVG topology export (P?, M)**: optional local Mermaid CLI rendering when needed; terminal/Mermaid/JSON output ships first, without Node or Chromium. → [research](backlog/topology-svg-export.md)

- **Extended rules workbench**: edit general staged personal overrides with `$VISUAL`/`$EDITOR`; keep baseline, overrides and generated configuration separate; validate with the target core version in isolated storage; show diff, detect conflicting edits and retain previous revisions.
- **Advanced rule grammar and analysis (P?, L)**: extend quick input beyond common domain/CIDR rules, preserve matcher modifiers and add evidence-backed provider/logical analysis without treating unknown results as no conflict. → [research](backlog/advanced-rule-analysis.md)
- **Offline rule evaluation**: preview supported deterministic rules while preserving unknown outcomes; extend the shipped active URL evidence without pretending offline estimates are observations.
- **Managed core upgrades/migration**: update/rollback core binaries and images; migrate backend/service identity/ports with complete resource and service recovery. v0.1.6 adds installation, profile configuration, lifecycle and guarded network setup.
- **Routing data updates and upstream rules (P?, L)**: optional verified bundles beyond the binary's immutable clash-rules snapshot; design upstream policy editing/publication and target refresh as separate operations with owner-aware activation. → [research](backlog/upstream-rule-distribution.md)
- **Dual full-tunnel routing**: explicitly designed exit-node/TUN chaining. The current coexistence path supports split VPN destinations and reports competing default-route owners.
- **Service-owned proxy tunnels**: explicit persistent ownership, service lifecycle and recovery for background consumers; v0.1.7 provides invocation/shell forwards and rejects known temporary endpoints for service use. Keep this separate from arbitrary command replay and shell-owned leases.
- **Further proxy integration**: incrementally consolidate repeated dotfiles resolution and Docker diagnosis, then consider a TUI tunnel view and authenticated/TLS reverse proxy endpoints. Preserve Docker configuration ownership and API-gateway responsibilities.
- **Extended client adapters**: native activation bridges and broader profile/merge/script editing; the current Verge 2.5.2 adapter edits existing Rules/Proxies/Groups companions and requires manual native reactivation for unowned installs (owned Windows and macOS installs reactivate automatically).
- **macOS Verge follow-ups**: clone-mode choice in the setup wizard; Intel (x64) dmg; adopting an existing unowned Verge; pin the dmg TeamIdentifier after the first verified install; login-item removal when macOS privacy settings block System Events.
- **Remote Unix sockets**: OpenSSH stream-local forwarding, including discovery and cleanup tests.
- **Formal distribution**: publish macOS/Linux amd64/arm64 archives with stable names, checksums and completions; add a Homebrew formula in the maintainer's tap. Keep `go install` as the lightweight source channel and package-manager upgrades owned by that manager.

- **UX notes from provisioning a remote Mac (2026-09)**: (1) `connections list`/`targets list` could mark which target a JSON field belongs to without `--target`; (2) `setup` preview warnings mix portable-clone notes with native-mirror notes — group them by mode; (3) `targets diff` output is verbose JSON by default; a short "N fields / M groups differ" human summary first would help; (4) a `proxies speedtest`/throughput probe per node would make slow-node diagnosis (long downloads behind a filtering network) a one-liner instead of reading `connections list`.

Useful upstream references: [Mihomo API](https://wiki.metacubex.one/api/), [rules](https://wiki.metacubex.one/config/rules/), [clash-rules wiring](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml).
