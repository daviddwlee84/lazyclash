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
or reloading. ERROR findings such as syntax, missing policy and same-selector
different-policy conflicts block every write. Confirmed overlap/shadowing is
WARNING; inspect the exact rules and positions. Interactive confirmation
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
