# Future milestones

The current release targets existing-core observation and runtime control. Keep the following work outside that boundary until its ownership and apply workflows are implemented.

- **Rules workbench**: edit staged personal overrides with `$VISUAL`/`$EDITOR`; keep baseline, overrides and generated configuration separate; validate with the target core version in isolated storage; show diff, detect conflicting edits and retain previous revisions.
- **Rule diagnostics**: offline preview for supported deterministic rules, with explicit unknown results; real HTTP/SOCKS requests correlated with core connection/log evidence. An API tunnel is not a data-proxy tunnel. Never present offline estimates as observed routing.
- **Managed cores**: local/SSH installation, pinned official artifacts verified against release digests, update/rollback, launchd/systemd, subscriptions/profiles and OS proxy integration. Keep external and lazyclash-owned cores distinct.
- **Optional clash-rules setup**: select categories, map them to existing policy groups, preserve rule ordering and pin artifact revisions; preview generated provider wiring before apply. Use published artifacts from [clash-rules](https://github.com/daviddwlee84/clash-rules), not its environment-specific composition scripts as a generic merger.
- **Client adapters**: explicit native Clash Verge profile/merge/script support only after its ownership and compatibility contract is defined.
- **Remote Unix sockets**: OpenSSH stream-local forwarding, including discovery and cleanup tests.

Useful upstream references: [Mihomo API](https://wiki.metacubex.one/api/), [rules](https://wiki.metacubex.one/config/rules/), [clash-rules wiring](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml).
