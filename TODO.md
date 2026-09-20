# Future milestones

The current release supports existing-core observation, runtime comparison/control, URL diagnosis and exact-domain repairs for explicitly bound owners. Remaining milestones:

- **Extended rules workbench**: edit general staged personal overrides with `$VISUAL`/`$EDITOR`; keep baseline, overrides and generated configuration separate; validate with the target core version in isolated storage; show diff, detect conflicting edits and retain previous revisions.
- **Offline rule evaluation**: preview supported deterministic rules while preserving unknown outcomes; extend the shipped active URL evidence without pretending offline estimates are observations.
- **Managed cores**: local/SSH installation, pinned official artifacts verified against release digests, update/rollback, launchd/systemd, subscriptions/profiles and OS proxy integration. Keep external and lazyclash-owned cores distinct.
- **Optional clash-rules setup**: select categories, map them to existing policy groups, preserve rule ordering and pin artifact revisions; preview generated provider wiring before apply. Use published artifacts from [clash-rules](https://github.com/daviddwlee84/clash-rules), not its environment-specific composition scripts as a generic merger.
- **Extended client adapters**: native activation bridges and broader profile/merge/script editing; the current Verge 2.5.2 adapter edits existing Rules companions and requires manual native reactivation.
- **Remote Unix sockets**: OpenSSH stream-local forwarding, including discovery and cleanup tests.
- **Formal distribution**: publish macOS/Linux amd64/arm64 archives with stable names, checksums and completions; add a Homebrew formula in the maintainer's tap. Keep `go install` as the lightweight source channel and package-manager upgrades owned by that manager.

Useful upstream references: [Mihomo API](https://wiki.metacubex.one/api/), [rules](https://wiki.metacubex.one/config/rules/), [clash-rules wiring](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml).
