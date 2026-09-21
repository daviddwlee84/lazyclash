# References and evidence

Reviewed 2026-09-20 unless stated otherwise. Pinned source links support
version-specific claims. Living documentation is a discovery/usage reference;
recheck it when changing the dependency or supported owner version.

**Contract** means upstream documentation/source. **Observed** means a local
read-only observation or a repository test result. **Design** means lazyclash's
choice, not a promise made by an upstream project.

## Core API and routing

| Claim / use | Primary source | Version | Limit / resulting decision |
|---|---|---|---|
| External controller API and operations | [Mihomo API](https://wiki.metacubex.one/api/) | Living docs | Contract overview; check versioned implementation for edge cases |
| General runtime settings and PATCH semantics | [configs.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/configs.go), [executor](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/executor/executor.go) | 1.19.29 | GET is not full YAML; unknown PATCH fields/partial changes cannot be treated as full config synchronization |
| Reported version and endpoint registration | [server.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/server.go) | 1.19.29 | Reported version is not a binary checksum or installation provenance |
| Group selection and URL delay | [proxies.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/proxies.go), [adapter](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/adapter/adapter.go), [groups.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/groups.go) | 1.19.29 | Delay can update health and does not return HTTP status; copying automatic now can accidentally pin a group |
| Connection evidence lifetime | [connections.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/connections.go), [tracker](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/tunnel/statistic/tracker.go), [tunnel](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/tunnel/tunnel.go) | 1.19.29 | Active successful dials only; no request ID; absence is inconclusive |
| DNS query context | [dns.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/hub/route/dns.go), [DIRECT resolver](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/adapter/outbound/direct.go) | 1.19.29 | Native, query, DIRECT and fake-IP paths can differ |
| Rule ordering and syntax | [Rules](https://wiki.metacubex.one/config/rules/) | Living docs; 1.19.29 implementation reviewed | Design: exact DOMAIN suggestions only, with explicit policy and owner |
| Validation can access files/network | [main.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/main.go), [initialization](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/config/initial.go), [config parser](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/config/config.go), [cache](https://github.com/MetaCubeX/mihomo/blob/v1.19.29/component/profile/cachefile/cache.go) | 1.19.29 | Design: private resources and isolated validator; never validate against the live cache |

## Clash Verge ownership

| Claim / use | Primary source | Version | Limit / resulting decision |
|---|---|---|---|
| Existing profile and companion schema | [prfitem.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/config/prfitem.rs) | Rev 2.5.2 | Bind current UID and existing Rules companion; do not externally create manifest entries |
| Rules prepend/append/delete | [seq.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/seq.rs) | Rev 2.5.2 | Use Rules.prepend, not legacy-looking prepend-rules in Merge |
| Merge replaces arrays; generation order | [merge.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/merge.rs), [pipeline](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/mod.rs) | Rev 2.5.2 | Later merges/scripts may override rules; GUI control keys are restored |
| Manifest caching and companion reread | [config.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/config/config.rs), [chain.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/chain.rs) | Rev 2.5.2 | Saving an existing companion requires native reactivation |
| HTTP/scheme server is not a regenerate API | [server.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/utils/server.rs), [scheme.rs](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/utils/resolve/scheme.rs) | Rev 2.5.2 | Design: saved_pending_owner_reload rather than claiming an API reload regenerated the GUI profile |
| Native save/reactivate paths | [profile commands](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/cmd/profile.rs), [hotkeys](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/core/hotkey.rs) | Rev 2.5.2 | Private Tauri commands are not ordinary HTTP endpoints; user reactivates natively |

Observed during development: a local Rev 2.5.2 installation and a remote
Mihomo 1.19.29 controller. This establishes those inspected versions, not
compatibility with all future profiles or native clients. Production rule
files were not used for destructive fixture tests.

## Terminal, shell and distribution

| Claim / use | Source | Version / context | Limit / decision |
|---|---|---|---|
| Event/model/effect terminal architecture | [Bubble Tea](https://github.com/charmbracelet/bubbletea/tree/v2.0.9), [Bubbles](https://github.com/charmbracelet/bubbles/tree/v2.2.1), [Lip Gloss](https://github.com/charmbracelet/lipgloss/tree/v2.0.6) | Versions in go.mod | V1 examples are not interchangeable; rendering does not perform I/O |
| Dynamic completion providers and zsh bridge | [Cobra completion guide](https://github.com/spf13/cobra/blob/v1.10.2/site/content/completions/_index.md), [zsh generator](https://github.com/spf13/cobra/blob/v1.10.2/zsh_completions.go) | 1.10.2 | Zsh queries the invoked binary; current legacy Bash generation differs |
| fpath and compinit ordering | [zsh completion initialization](https://zsh.sourceforge.io/Doc/Release/Completion-System.html#Initialization) | Living manual | Install, activation and candidate lookup are separate |
| Version-qualified executable installation | [go install](https://go.dev/ref/mod#go-install), [version queries](https://go.dev/ref/mod#version-queries), [module publication](https://go.dev/doc/modules/publishing) | Go 1.25 minimum | /cmd package path, immutable tags, @latest versus @main |
| Executable identity and build metadata | [os.Executable](https://pkg.go.dev/os#Executable), [ReadBuildInfo](https://pkg.go.dev/runtime/debug#ReadBuildInfo), [toolchains](https://go.dev/doc/toolchain) | Go APIs | Provenance is not exact installer detection; preserve GOTOOLCHAIN policy |
| Agent-readable embedded guidance | [Go embed](https://pkg.go.dev/embed), [dev-cli skill](https://github.com/daviddwlee84/dev-cli/blob/689836cdea61d46ee86cdfa4a0df42ac324e6561/internal/skill/skill.go), [Herdr docs](https://herdr.dev/docs/) | dev-cli 689836c; Herdr inspiration | Design: offline skill matching the installed binary, help as syntax authority |
| Installation-aware update design | [dev-cli upgrade](https://github.com/daviddwlee84/dev-cli/blob/689836cdea61d46ee86cdfa4a0df42ac324e6561/internal/cli/upgrade.go), [source builder](https://github.com/daviddwlee84/dev-cli/blob/689836cdea61d46ee86cdfa4a0df42ac324e6561/internal/selfupdate/source.go) | dev-cli 689836c | Reference implementation; lazyclash owns its verification/replacement tests |
| Config/data/state locations | [XDG specification](https://specifications.freedesktop.org/basedir-spec/latest/) | Living specification | macOS os.UserConfigDir differs; lazyclash uses its explicit XDG policy |
| SSH forwarding and host checks | [OpenSSH ssh manual](https://man.openbsd.org/ssh), [ssh_config](https://man.openbsd.org/ssh_config) | Host OpenSSH | Controller and data forwards differ; configured masters follow user ControlPersist policy. Cleanup uses matching forward/cancel, never exit on a configured master; SSH alters source tuples |

## Host diagnostics

Docker namespace boundaries use [port publishing](https://docs.docker.com/engine/network/port-publishing/)
and [bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)
(living Docker documentation, reviewed 2026-09-20). Controller URLs use the
published host port; a host source_config path and a container reload path
have different owners/namespaces. Container-aware persistent rule repair
remains unimplemented.

| Claim / use | Source | Version / context | Limit / decision |
|---|---|---|---|
| curl proxy environment precedence | [curl proxy environment](https://everything.curl.dev/usingcurl/proxies/env.html), [curl manual](https://curl.se/docs/manpage.html) | Remote curl 8.5.0 observed | HTTP_PROXY ignored; newer writeout fields cannot be assumed |
| Native resolver behavior | [Python getaddrinfo](https://docs.python.org/3/library/socket.html#socket.getaddrinfo), [Go name resolution](https://pkg.go.dev/net#hdr-Name_Resolution) | Host implementations | Resolver contexts differ; bounded native lookup and explicit provenance |
| Linux resolver inspection | [resolvectl](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html) | Host capability detected | Availability and per-link scopes vary |
| Isolated Linux validation | [bubblewrap](https://github.com/containers/bubblewrap) | Host capability detected | Missing/denied namespace support blocks validation before writing |

macOS scutil/route/ifconfig and sandbox-exec behavior is checked through the
installed host tools; record capability failures instead of presenting an empty
result as a healthy system.

## Product inspiration and related knowledge

Reverse proxy sharing uses [OpenSSH remote forwarding](https://man.openbsd.org/ssh),
[GatewayPorts](https://man.openbsd.org/sshd_config#GatewayPorts), and the distinction
between [Bash startup files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
and [zsh startup files](https://zsh.sourceforge.io/Doc/Release/Files.html).
The [operating guide](ssh-proxy-sharing.md) records lifecycle and consumer limits;
isolated SSH tests verify the implementation rather than assuming `-R 127.0.0.1`
alone proves the actual bind address. Reviewed 2026-09-21.

| Reference | What we learned | Boundary |
|---|---|---|
| [MetaCubeXD](https://github.com/MetaCubeX/metacubexd) and [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Traffic, resource summaries, connection distributions and route presentation; user screenshots reviewed 2026-09-20 | Visual inspiration, not evidence for API semantics |
| [btop](https://github.com/aristocratos/btop) | Dense but navigable terminal resource display | Design reference; core RSS is not host RAM |
| [Lazygit](https://github.com/jesseduffield/lazygit) | Stable context, list/detail panes and explicit actions | Interaction inspiration; Lazygit does not use Bubble Tea |
| [go-cli-tui development skill](https://github.com/daviddwlee84/awesome-lazy-tools/tree/main/skills/go-cli-tui) | Shared services, input ownership, mouse semantics, real PTY verification | Contributor guidance; not required for end users |
| [clash-proxy-api knowledge](https://github.com/daviddwlee84/agent-skills/tree/main/skills/local/clash-proxy-api) | Controller discovery, host vantage and managed-client ownership | Operational research; this product's explicit source-binding workflow governs writes |
| [clash-rules](https://github.com/daviddwlee84/clash-rules), [wiring example](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml) | Category-to-policy mapping and published ruleset artifacts | v0.1.6 embeds an immutable snapshot; the example is a fragment and composition scripts remain environment-specific |

The initial ChatGPT/Mihomo TUI investigation under .specstory/references and
later user screenshots were discovery inputs. API conclusions above were
checked against primary sources. Conversation histories and private configs
are not republished as documentation.

## Source editing, setup and VPN coexistence

Reviewed 2026-09-21. These sources establish upstream behavior; supported owner
versions and automation/rollback choices are lazyclash design decisions.

| Claim / use | Primary source | Version / resulting decision |
|---|---|---|
| Runtime node serialization omits raw credentials | [adapter](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/adapter.go), [outbound base](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/base.go) | Mihomo 1.19.31; bind raw source for editing/export |
| Provider cache, inline payload and file watching differ | [provider parser](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/provider/parser.go), [fetcher](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/component/resource/fetcher.go) | Never treat an HTTP cache as a durable private-node owner |
| Verge node deletion alters group references | [sequence](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/seq.rs), [pipeline](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/mod.rs) | Rev 2.5.2; compensate memberships and disclose persistent group overrides |
| Share URI encodings are protocol-specific | [SS SIP002](https://shadowsocks.org/doc/sip002.html), [VMess/VLESS proposal](https://github.com/XTLS/Xray-core/discussions/716), [Hysteria2 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/) | Refuse lossy conversions; raw Mihomo YAML/JSON is the preserving format |
| QR is local encoding, not a hosted sharing service | [go-qrcode](https://github.com/skip2/go-qrcode/tree/da1b6568686e) | Pinned dependency in go.mod; same credential URI as URL export |
| Official native artifacts expose digests | [Mihomo release metadata](https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.31) | Pin version/platform/asset digest; do not treat locally retagged images as official |
| Client deployment example | [mihomo-docker](https://github.com/daviddwlee84/DockerCompose-V2Ray/tree/9e6f3b957edbbaf2bbcfd9deea8d871873069e56/clients/mihomo-docker) | Reference client only; use separate owned project, loopback publishing and generated secret |
| Offline rules and geo data provenance | [immutable manifest](https://github.com/daviddwlee84/clash-rules/blob/rules-27ae948beb8e304190344c28bf731fe3d1c7fbeb36e7485eb18975fcbdcb2e34/manifest.json), [third-party notice](https://github.com/daviddwlee84/clash-rules/blob/rules-27ae948beb8e304190344c28bf731fe3d1c7fbeb36e7485eb18975fcbdcb2e34/THIRD_PARTY.md) | Keep distinct data licenses, original notices and locks |
| Tailnet exclusions do not solve dual full-tunnel routing | [Tailscale other VPNs](https://tailscale.com/docs/reference/faq/other-vpns), [exit nodes](https://tailscale.com/docs/features/exit-nodes) | Split tailnet/subnet preset; competing defaults require owner selection |
| MagicDNS and core system resolver have different scopes | [Quad100](https://tailscale.com/docs/reference/quad100), [Mihomo POSIX system DNS](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/dns/system_posix.go) | Preserve scoped resolver evidence; regional rules do not establish unpoisoned DNS |
| TUN exclusions vary by platform | [Mihomo TUN](https://wiki.metacubex.one/config/inbound/tun/), [sing-tun Linux](https://github.com/metacubex/sing-tun/blob/v0.4.24/tun_linux.go) | Incoming-interface filtering is not universal outbound VPN bypass |
| Docker host networking and capabilities | [host driver](https://docs.docker.com/engine/network/drivers/host/), [runtime privileges](https://docs.docker.com/engine/containers/run/) | Native macOS/Linux or rootful Linux Docker for host TUN; Desktop L4 networking is not macOS TUN |
| Docker proxy consumers are distinct | [client](https://docs.docker.com/engine/cli/proxy/), [daemon](https://docs.docker.com/engine/daemon/proxy/), [build args](https://docs.docker.com/build/building/variables/) | Generate/test container/build configuration; daemon/Desktop changes remain explicit guidance |
| Native background SSH and control operations | [ssh](https://man.openbsd.org/ssh), [ssh_config](https://man.openbsd.org/ssh_config) | Private per-shell masters; fresh management verification disables multiplexing |

Fixture evidence is recorded in package tests and PTY harnesses. Passing a
simulated service/route test or cross-compilation does not establish a real
administrator service installation or host-TUN result on another platform.
