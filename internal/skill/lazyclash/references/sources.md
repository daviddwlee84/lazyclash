# Source-backed nodes and groups

The controller's `/proxies` response is not a credential-bearing node definition.
Keep runtime inspection separate from raw YAML/JSON and source ownership. Read
`configs source show --json`; bind with `configs source set` when the user has
authorized editing that source. `source_config` and `rules source` do not grant
node/group write ownership. Changing an endpoint/SSH host clears these bindings.

Use `proxies import --file FILE` or stdin for credential-bearing input. Import
supports five common protocols (SS, VMess, VLESS, Trojan, Hysteria2), Mihomo node
YAML/JSON and supported subscription bodies. Do not place private links in logs,
public files or copied command histories. Read per-item diagnostics; do not
silently ignore a failed import line.

Preview returns a digest and redacted field changes. Apply exactly that input
with `--yes --expect DIGEST`; read `configs verify RECEIPT --json` afterward.
`configs restore RECEIPT --yes` restores guarded private backups. Source save,
owner reload, runtime observation and network usability are separate outcomes.
Inspect a partial/unknown receipt before any retry.

Import/add forms offer searchable target and per-target group multi-selection. `--create-group NAME`
creates a select group containing the nodes in the same reviewed change; rules
and parent groups remain unchanged. `--adopt-existing` on import/server connect
reuses only a semantically identical node; conflicting credentials/options are
refused. A no-change adoption saves a receipt without reloading the client.
Preview checks protocol capabilities and validates with the bound actual core.
Classic Clash cannot import VLESS/REALITY; do not force the candidate into it.

For multiple targets, use `proxies import --file FILE --destinations FILE --json`.
The destinations file is an array of `{ "target": "ID", "groups": ["NAME"],
"create_groups": [] }`, without credentials. Apply with that batch's exact
`--yes --expect DIGEST`. All destinations are preflighted, then applied in target
ID order; failure or unverified results stop later targets. Inspect each returned
receipt; do not assume a batch is atomic or retry an unknown result. Each target
resolves its own credentials. URI `remarks` is a fallback name after `#fragment`;
legacy VMess JSON keeps `ps`. Unsupported parameters still require raw YAML.

`topology --file YAML --json` reads a local file offline without settings/core
access. `--target ID topology` reads the bound complete source; `--source-path`
selects a target-host file without granting write ownership. `--live` adds
timestamped group/provider observations, or a labeled API-only graph if no
complete source exists. Mermaid export is `--format mermaid`; relations support
`--view relations --focus NAME`. Graphs exclude credential values and do not
execute rules, download providers, probe traffic or claim a physical route.

`groups add/edit/duplicate` preserve ordered explicit members and provider `use`
separately. An API group's expanded `all` cannot reconstruct filters or provider
references. Names stay fixed during edit; duplicate under a new name. Check
group cycles, missing references, dialer dependencies and host-local files.

`proxies copy SOURCE DEST NAME` has independent source/destination transports and
credentials. The selected-target interactive form is `proxies copy NAME
--interactive`. A preview does not move or delete the source node.

Owner behavior:

- Native: validate with the bound actual core version in isolated storage, save
  and reload the complete source; runtime-only settings may be replaced.
- Docker: verify daemon/container/image and host bind mapping. Host source path
  and container reload path differ. A single-file bind can retain old content;
  don't claim activation before the container sees the new source.
  Use explicit `--docker-host unix:///...` for rootless daemons. A matching
  `targets service bind` enables reviewed owner restart and byte verification
  for single-file mounts, without recreating the container.
- Verge Rev 2.5.2: existing Proxies/Groups companions, manual native reactivation,
  then generated-config/runtime verification. Same-name subscription replacements
  may require group overrides that mask later subscription group updates.
  Dynamic provider members should be duplicated into private nodes; never edit
  downloaded caches. Missing companions require native repair/re-import.
- Managed privileged cores: use the managed owner adapter and native authorization;
  don't chmod a private root-owned profile or edit a local cached input instead.

`proxies export NAME --format yaml|json|url` is an intentional credential export;
`--clipboard`, `--qr`, and `--output` also disclose credentials to those destinations.
JSON means a Mihomo node mapping, not arbitrary third-party client JSON. QR
encodes the same supported share URI. Unsupported URI fields cause a refusal,
with YAML/JSON as the preserving alternative. Normal lists/previews stay redacted.
