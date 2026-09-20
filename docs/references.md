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
| SSH forwarding and host checks | [OpenSSH ssh manual](https://man.openbsd.org/ssh), [ssh_config](https://man.openbsd.org/ssh_config) | Host OpenSSH | Controller tunnel and proxy tunnel differ; SSH alters observed source tuples |

## Host diagnostics

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

| Reference | What we learned | Boundary |
|---|---|---|
| [MetaCubeXD](https://github.com/MetaCubeX/metacubexd) and [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Traffic, resource summaries, connection distributions and route presentation; user screenshots reviewed 2026-09-20 | Visual inspiration, not evidence for API semantics |
| [btop](https://github.com/aristocratos/btop) | Dense but navigable terminal resource display | Design reference; core RSS is not host RAM |
| [Lazygit](https://github.com/jesseduffield/lazygit) | Stable context, list/detail panes and explicit actions | Interaction inspiration; Lazygit does not use Bubble Tea |
| [go-cli-tui development skill](https://github.com/daviddwlee84/agent-skills/tree/main/skills/local/go-cli-tui) | Shared services, input ownership, mouse semantics, real PTY verification | Contributor guidance; not required for end users |
| [clash-proxy-api knowledge](https://github.com/daviddwlee84/agent-skills/tree/main/skills/local/clash-proxy-api) | Controller discovery, host vantage and managed-client ownership | Operational research; this product's explicit source-binding workflow governs writes |
| [clash-rules](https://github.com/daviddwlee84/clash-rules), [wiring example](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml) | Category-to-policy mapping and published ruleset artifacts | Setup integration remains future work; composition scripts are environment-specific |

The initial ChatGPT/Mihomo TUI investigation under .specstory/references and
later user screenshots were discovery inputs. API conclusions above were
checked against primary sources. Conversation histories and private configs
are not republished as documentation.
