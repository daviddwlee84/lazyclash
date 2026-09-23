# Changelog

User-facing changes are recorded here for every published version. Install a
fixed release with `go install github.com/daviddwlee84/lazyclash/cmd/lazyclash@v0.1.11`,
or use `@latest` to upgrade. Check the installed binary with `lazyclash --version`.

## Unreleased

## 0.2.0 — 2026-09-23

- Add Windows amd64/arm64 ZIP releases, PowerShell completion and verified Scoop installation/upgrade support. Upgrades exit into a private helper with visible progress and queryable final results; checks remain read-only and manager failures never trigger source fallback.
- Verify native Windows behavior in CI and refresh the canonical go-cli-tui development guidance.

- Homebrew-owned `upgrade` now refreshes taps even within Homebrew's
  auto-update interval, so a just-published formula is not reported as current;
  `HOMEBREW_NO_AUTO_UPDATE` is still honored. Releases also ask the tap to sync
  immediately when a dispatch token is configured.

## 0.1.12 — 2026-09-23

- Targets accept Windows source paths (`C:/...`) and owned native activation.
  Clone an active target into an independent Windows Verge or background Mihomo
  client with its resources, manual selections and saved connectivity checks,
  using user-logon tasks, guarded proxy handoff and resumable receipts over
  verified SFTP.
- Windows process exits are confirmed by a fresh PID lookup, and default
  lifecycle website probes get one bounded warmup retry with per-site evidence.
- Saved connectivity checks honor their full request budget.

## 0.1.11 — 2026-09-23

- Homebrew-owned `upgrade` now invokes the exact installed formula's owning
  `brew upgrade`, verifies the resulting stable executable and reports the
  actual version. Check mode previews without upgrading or requiring GitHub;
  pins, manager errors and unchanged formulas retain Homebrew's policy.

## 0.1.10 — 2026-09-22

- Added opt-in historical analytics with private SQLite, configurable retention
  and storage budgets, Mihomo/interface/access-log/user-stats collectors, vnStat
  import, day/week/month CLI/TUI reports, SSH queries and manual domain diagnosis.
  User service lifecycle requires reviewed actions and never elevates privileges.
  Host TX notifications retain threshold and delivery state without mixing client,
  server, interface or billing counters.

- Added offline YAML routing topology, terminal/Mermaid/JSON output, searchable
  CLI/TUI graph browsing and optional current-selection/provider overlays.
- Added searchable per-target proxy import wizards, per-target destination
  files and reviewed batch application with individual receipts and stop-on-failure
  behavior. URI imports accept `remarks` as a fallback display name.
- Added saved connectivity checks with HTTP expectations and observed routing,
  explicit existing-client service bindings, linked Oracle/Azure VPS usage and
  client-node/server provenance. Cloud billing and measured traffic remain separate.
- Added visible controller/mode state and explicit Rule/Global/Direct controls,
  offline cloud-CLI setup guides and agent handoffs, and narrow destination-IP repairs.
- Fixed Oracle/Lightsail CLI compatibility, live server status interpretation,
  and SSH setup time accounting in saved checks. Public module verification runs
  fixed-version and latest installs in disposable runner state.

## 0.1.9 — 2026-09-21

- Added Azure, AWS Lightsail and EC2 providers to VPS discovery, reviewed
  provisioning, recovery and lifecycle management through official CLIs.
  Previews pin architecture, Ubuntu image and availability zone; quotes separate
  compute, disk, static IPv4 and traffic costs. Lightsail estimates accept
  inbound usage, and stop previews distinguish retained resource charges.
- Added Tailscale Exit Node setup/selection and private Tailnet proxy management,
  with saved peer identity, scoped lifecycle, runtime Mihomo TUN handoff,
  recoverable operations, client exports and shared CLI/TUI actions. Handoff
  refreshes only Mihomo's volatile DNS answers after OS exit verification;
  validation errors identify the failed phase.
- Added separate VPS/server inventory and a shared CLI/TUI deployment workflow
  for existing SSH hosts/homelabs and Oracle, Vultr, Linode and DigitalOcean CLIs.
- Added native/Compose server recipes for VLESS/REALITY/Vision, Hysteria2 and
  VMess/WebSocket/TLS, immutable artifact verification, owned service lifecycle,
  recovery journals and isolated authenticated client verification.
- Added private client/admin bundles, URI/QR/starter exports and reviewed import
  into existing client sources, plus source-backed protocol and cost guidance.
- Added filtered source archives and Go module packaging guards; release
  publication verifies immutable assets before publishing or resuming a draft.

## 0.1.8 — 2026-09-21

- Publish checksummed macOS/Linux amd64/arm64 archives with shell completions.
- Upgrade standalone archive installs without Go while preserving source and package-manager ownership rules.

## 0.1.7 — 2026-09-21

- Added `proxy ssh HOST [-- COMMAND...]` and foreground `proxy tunnel share HOST`
  so remote shells and commands can use a local HTTP/SOCKS proxy through SSH.
  Dynamic/fixed remote ports, actual loopback-listener verification, isolated
  ownership and cleanup preserve existing SSH sessions.
- Remote shells retain their normal login setup; `--clean-shell` offers a
  predictable `/bin/sh` alternative. Single commands preserve input/output and
  exit status without reconnecting or retrying the command.
- Added `proxy env --consumer service` to reject known temporary SSH endpoints
  before they are handed to background services. Endpoint-bound origin metadata
  also identifies reverse forwards on a remote host.
- Proxy selection now distinguishes no configured local proxy (exit 4,
  `proxy-not-configured`) from a failed/ambiguous selection; service rejection
  reports `proxy-temporary`. Added completion, agent guidance and same-VPS
  website routing examples.

## 0.1.6 — 2026-09-21

- Added source-backed node/group editing, cross-target copies, private backups,
  guarded receipts and verification for native, Docker and Verge 2.5.2 owners.
  Common group fields retain raw advanced options and ordered membership.
- Import/export SS, VMess, VLESS, Trojan and Hysteria2 links; share complete
  Mihomo YAML/JSON, clipboard URLs and offline terminal/PNG QR codes. Unsupported
  URI fields are reported instead of silently discarded.
- Added standalone bash/zsh proxy-on/off integration, original environment
  restoration, selected-target command execution and independent persistent
  SSH forwards. Docker outputs distinguish containers, builds and daemon guidance.
- Added native/Docker client setup and owned-core lifecycle, version/digest
  verification, automatic target registration, offline cn-split/simple rule
  snapshots and explicit bootstrap routes.
- Added passive VPN/TUN/scoped-DNS diagnostics, platform-aware service and
  system-proxy configuration, reviewed bypass proposals and host-side network
  rollback guards. Full-tunnel VPN conflicts require choosing a routing owner.
- Added shared CLI/TUI wizards, mouse actions, source editing/share shortcuts,
  offline completion candidates and operating/agent documentation.

## 0.1.5 — 2026-09-20

- Password-only SSH login is now discoverable in the TUI: connection failures
  requiring SSH authentication offer Authenticate/Cancel and an A retry action.
  OpenSSH owns password/host-key entry; failed login or dialog cancellation preserves the
  dashboard without automatic prompt loops or interruption of other forms.
- Reuse user-configured ControlMaster/ControlPersist sessions across CLI/TUI
  invocations. Explicit authentication honors usable persistent SSH policy;
  private fallback sessions still close with their owning process. Cleanup
  cancels only lazyclash's forwards and never exits a configured SSH master.
- Updated operating guidance for SSH password/session lifetime and Docker
  controller ports versus host/container configuration paths.

## 0.1.4 — 2026-09-20

- Ctrl+S validates and saves target, YAML registration and rule-source settings
  directly from the current field, without stepping through every optional
  input. Added a matching mouse button and contextual shortcut hints; Review
  remains available.
- Invalid settings and failed saves retain the active field, entered values and
  editing focus. Quick save still uses normal validation/owner inspection,
  cancels stale connectivity tests and prevents duplicate pending saves.

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

[0.1.4]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.4

[0.1.5]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.5
[0.1.6]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.6
[0.1.7]: https://github.com/daviddwlee84/lazyclash/releases/tag/v0.1.7
