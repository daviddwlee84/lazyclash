# Cross-target and persistent-rule workflows

## Compare before copying

Use `targets diff SOURCE DEST --json` with two saved IDs. Each target supplies
its own credentials. The report covers reported core versions, general runtime
settings and group membership/manual selections, not full YAML or binary hashes.
Secret-bearing fields are not compared.

`targets copy-settings SOURCE DEST --field mode --group GROUP --json` produces
a preview. Explicit choices are required; only mode, log-level and manual
Selector members can be copied. Do not copy URLTest/Fallback current choices as
if they were fixed user intent. Existing same-named nodes may differ internally.

Read the direction/steps, then use the same arguments with `--yes --expect DIGEST`
from that preview. Stale state fails. Partial receipts describe applied, failed,
unknown and unattempted steps; there is no automatic rollback or safe blind retry.
Restart or a native client can replace runtime choices.

## Compare rules, find declarations and inspect coverage

```sh
lazyclash rules diff desktop server --json
lazyclash rules diff desktop --all --scope runtime --json
lazyclash --target server rules find 'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT' --json
lazyclash rules find 'DOMAIN,api.enterprise.githubcopilot.com,DIRECT' --all --json
lazyclash --target server rules lookup api.enterprise.githubcopilot.com --json
lazyclash rules lookup 203.0.113.7 --all --scope source --json
```

All are read-only. Scope defaults to `both`; `runtime` and `source` are explicit
alternatives. Diff takes a baseline and destination, or baseline plus `--all`
for every other saved target. It rejects global target/transport/credential
overrides. Find/lookup use the selected/default target or `--all`, never both an
explicit `--target` and `--all`.

Diff compares ordered declarations, preserving duplicates and distinguishing
policy/options/enabled changes from relative reorder. Source canonical equality
is limited to understood rules; opaque expressions and delete directives use
literal text. Runtime exposes fewer fields, with known type-name aliases.
Different declarations do not establish which target is older. Identical
RULE-SET names do not prove identical provider data or policy implementations.

Find reports complete matches and same-selector alternatives. Disabled entries
remain present but are labeled. Runtime matches are reported-only; no-resolve
cannot be inferred from that API. Query parsing preserves existing unusual
domain literals and trailing dots. Delete directives are not active matches.
Known regex/logical outer syntax retains comma-bearing payloads before the final
policy. Unknown query grammar is literal-only, including runtime
`reported_literal` matches; do not infer selector alternatives from its commas.
Raw one-line `TYPE,...` queries keep `: ` and ` # ` literal. Explicit quoted
scalars or `- ` items are YAML; quote the full item to preserve such markers.

Lookup is a hypothetical coverage trace with match/miss/unknown steps, retaining
later matches after the first candidate. No DNS is requested: a hostname leaves
IP matchers unknown, and an IP leaves unspecified domain metadata unknown.
Providers/GEO/process/source-IP/complex rules can remain unknown. Earlier
unknown entries prevent a first candidate; disabled rules are skipped and
literal PASS/PASS-RULE continues. `first_candidate` is not an observed route:
groups, UDP fallback and incomplete Verge composition can change evaluation.
Use the existing URL diagnosis for request evidence.

Source reads prefer RuleSource, then may use existing ConfigSource strictly for
read access; no write binding is created. A complete YAML and a Verge Rules
companion are `incomparable` source shapes, while their runtime views can still
be compared. Companion sections keep their own provenance. Unavailable views
remain unavailable, not empty or not-found. Check `complete` and per-view
statuses: successful partial inspection, differences and absence return exit 0;
no usable requested data or malformed input returns nonzero. Never interpret
exit 0 alone as all targets equal or the rule present everywhere.

## Quick rules and healthchecks

For an authorized one-rule change, use a saved target and one raw scalar:

```sh
lazyclash --target server rules apply 'DOMAIN,api.enterprise.githubcopilot.com,DIRECT' --dry-run --json
lazyclash --target server rules apply 'DOMAIN,api.enterprise.githubcopilot.com,DIRECT' --yes --json
lazyclash rules apply 'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT' --all --yes --json
lazyclash rules healthcheck --all --json
```

Prefer DOMAIN for one hostname. DOMAIN-SUFFIX includes the base and every
subdomain; DOMAIN-KEYWORD matches a literal substring and can be much broader.
IP-CIDR/IP-CIDR6 require a prefix and apply across ports. Preserve optional
`no-resolve`; it suppresses DNS resolution initiated by that match and is not
automatically added. Quick apply does not accept new `src`, provider, GEO,
regex or logical rules. One YAML list item is accepted with a `--` terminator
before an argument beginning `- `.

An identical canonical rule in the bound source is skipped without moving it
or reloading, unless another occurrence conflicts with that requested selector.
Invalid source/candidate syntax, missing policy/provider references and policy
conflicts involving the requested selector block every write. Unrelated existing
selector conflicts are health warnings: first-match rules can still operate
normally. Quick apply summarizes these findings; use healthcheck for details.
JSON `findings` contains operation diagnostics; `existing_health` retains whole
source/runtime reports. Confirmed overlap/shadowing is WARNING; inspect the exact
rules and positions. Interactive confirmation
defaults to No. `--yes` accepts warnings and skips that prompt, without requiring
a digest or bypassing errors. `--expect DIGEST` is available with `--yes` to
pin a reviewed dry-run plan. JSON/noninteractive use without `--yes` returns a
preview; it never opens confirmation. Use `--dry-run` to request preview-only
behavior explicitly in either terminal mode.

`--all` and an explicit `--target` are mutually exclusive. All-target mode
skips unreachable/unbound saved targets, retaining each reason. Success plus
skips is `completed_with_skips` with exit 0; zero usable targets is nonzero.
Existing no-op rules count as usable. A later write failure stops the batch,
retains prior changes/receipts and returns nonzero. Never report skipped targets
as updated or blindly repeat an uncertain write.

Healthcheck is read-only and works without a source binding when runtime is
available. Source and runtime are separate evidence: drift is not a conflict
between entries in one list. A Verge source report covers its Rules companion,
not generated Merge/Script composition. Provider contents, GEO data and complex
matchers are opaque; runtime omits source options such as no-resolve. Report
these limits and supported/opaque counts, not total routing coverage or proof
that a URL used a rule. It refreshes no providers and generates no probe traffic.
Selector conflicts alone are warnings and do not make healthcheck fail. They
are not proof that a core cannot load the source. Runtime-only requested policy
drift is a warning for native/Docker full-source reload, but blocks Verge quick
apply because a conflicting base rule can survive its companion edit.
Existing unusual domain literals (including underscore labels or trailing dots)
remain opaque: the core only lowercases them, so do not treat them as a missing
or identical normalized hostname based on the stricter quick-input grammar.

## Bind an owner and use the existing repair workflow

`rules source show` reports an explicit owner binding. Credential discovery's
`source_config` does not establish a rule source.

- Standalone: `rules source set --kind mihomo --config-id ID --binary PATH --home PATH`.
  Use the real core-host binary/home and registered complete config.
- Docker: `rules source set --kind docker --container NAME --host-path HOST_FILE --core-path CORE_FILE --binary PATH --home PATH`.
  The host bind and container reload path are distinct. Existing owners can be
  explicitly reused with `rules source set --from-config-source`; node/group
  bindings never silently grant rule writes.
- Verge: `rules source set --kind verge --data-dir PATH --profile UID --owner-version 2.5.2`.
  Bind the current profile's existing Rules companion. Version is declared
  compatibility, not detected identity.

Within authorized scope, preview `rules add-domain HOST --via POLICY --json`.
Review exact hostname scope, file, owner, diff and digest before using
`--yes --expect DIGEST`. Never infer permission to edit a subscription or
generated YAML from the ability to read controller credentials.

The older `add-domain`/`add-ip` commands intentionally replace the same selector;
their reviewed `--yes --expect` requirement is unchanged. Prefer `rules apply`
when the user's intent is skip-existing and abort-on-conflict.

Standalone validation uses a private stage and required host isolation tools.
Missing validation resources/capabilities block before writing; do not bypass
that error or point the validator at the live cache.

Verge stores Rules.prepend, then reports `persisted_pending_owner_reload`.
Have the user reactivate the profile natively and run `rules verify RECEIPT`.
Native merges/scripts can override rules. Do not replace this step with a core
PUT and claim the GUI regenerated its configuration.

Receipts distinguish persistence and runtime verification. A runtime rule's
presence is still not evidence that this URL used it. Restore through
`rules restore RECEIPT --yes` only for an authorized recovery; concurrent file
changes are guarded. Backups/receipts use private storage.

## Shell completion

`completion install zsh` installs a user script and prints fpath instructions;
`completion status zsh --json` checks the file. Neither proves parent-shell
activation. Put the directory before the framework's compinit. Avoid rewriting
shell rc or using force on a foreign completion without the user's intent.
The zsh bridge queries the current binary; local candidate lookup performs no
controller/SSH calls. The legacy Bash generator must be refreshed separately.

Further rationale and sources:
[project knowledge guide](https://github.com/daviddwlee84/lazyclash/tree/main/docs).
