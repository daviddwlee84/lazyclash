# Changelog

User-facing changes are recorded here for every published version. Install a
fixed release with `go install github.com/daviddwlee84/lazyclash/cmd/lazyclash@v0.1.3`,
or use `@latest` to upgrade. Check the installed binary with `lazyclash --version`.

## Unreleased

## 0.1.3 — 2026-09-20

- Added cross-target runtime/version comparison and explicit copying of mode,
  log-level and manual Selector choices. Reviewed digests reject stale state;
  each step is read back and partial/unknown results are retained.
- Added URL diagnosis with local/SSH environment, OS/DNS/route evidence,
  separate HTTP and core outbound tests, logical topology, correlation
  confidence and tentative exact-domain recommendations. Observe-only works
  with read-only mode; missing host tools remain explicit capability gaps.
- Added persistent domain-rule preview/apply, private backups and receipts,
  guarded restore and runtime verification. Standalone Mihomo validates in an
  isolated host environment. Clash Verge Rev 2.5.2 uses existing Rules
  companions and requires native profile reactivation before verification.
- Added TUI comparison pickers and checkboxes, digest-bound review/apply,
  inspectable URL topology/evidence, rule-source forms and receipt actions.
  Mouse selection, keyboard navigation, cancellation and stale results share
  the same services as CLI operations.
- Added zsh completion install/status and offline candidates for saved targets,
  config IDs and enums. Shell activation remains explicit; candidate queries
  never connect to controllers or resolve secrets.
- Collected operating knowledge, API/owner boundaries, UX references and pinned
  source links in docs/. Expanded the bundled offline skill with diagnosis
  and cross-target/rule workflows.

## 0.1.2 — 2026-09-20

- Added `lazyclash upgrade` and `upgrade --check`, with JSON output for agents.
  Checks describe the running binary's provenance, resolved destination, latest
  stable release and update eligibility without loading controller settings.
- Go release binaries update in place, including moved copies and symlinks,
  through a fixed-tag build, candidate verification and atomic replacement.
  Concurrent updates and changed destinations are detected; failures before
  replacement retain the previous executable.
- Development builds remain unchanged unless `--force` explicitly requests the
  latest stable release. Homebrew, mise and Nix installations retain their package
  manager's ownership; unknown binaries are not overwritten.
- Updated the embedded agent guide and source-install documentation. Users on
  v0.1.1 must first run `go install ...@latest` to obtain the new upgrade command.

## 0.1.1 — 2026-09-20

- Overview now opens first, with traffic, core memory and connection histories,
  rates/totals, protocol distribution, top outbounds and observed routes.
  Choose 1-, 5- or 15-minute windows and Braille, block or ASCII graphs; stale
  samples and disconnected intervals remain visible. The seven existing pages
  and keyboard shortcuts are retained; `--page proxies` restores the old start.
- Mouse navigation across tabs, panes, rows, scrolling, forms and action buttons.
  Row clicks select; explicit actions retain their normal confirmation and
  read-only rules. Toggle mouse capture with `M` or start with `--mouse=false`.
- `settings edit` opens `$VISUAL`, `$EDITOR` or `vi`, including for a malformed
  settings file, then validates edits. `settings path` works without parsing.
- `targets test [ID]` and TUI target tests check SSH/API access and runtime
  settings without changing the core or saving a draft.
- Optional target data-proxy settings enable manual `diagnostics ip` (IP.SB)
  and `diagnostics latency` (Google, Cloudflare, GitHub). SSH targets use their
  own remote proxy tunnel; partial website failures retain individual results.
  Active probes require an explicit proxy and are disabled by `--read-only`.
- Optional `[tui]` preferences control the initial page, mouse, graph style and
  history window. Existing settings remain compatible and are not rewritten
  merely by reading them.
- Updated the bundled agent guide with connectivity and egress diagnostics.

## 0.1.0 — 2026-09-20

- First source release of the CLI and seven-page terminal console for existing
  Mihomo cores, including cores managed by Clash Verge Rev.
- Local HTTP(S), Unix sockets and SSH targets; discovery, target registration,
  credential references, private settings and comment-preserving updates.
- Proxy selection and delay checks, runtime mode/TUN/LAN controls, connections,
  bounded live logs, rules, providers and applying registered complete YAML.
- Embedded offline `--skill` guide, JSON errors, bounded NDJSON log collection,
  and release version reporting for versioned `go install`.
- macOS/Linux CI, fixture controllers, race checks and real PTY verification.

[0.1.2]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.2
[0.1.1]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.1
[0.1.0]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.0

[0.1.3]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.3
