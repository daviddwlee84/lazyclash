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

## Persist an exact domain rule

`rules source show` reports an explicit owner binding. Credential discovery's
`source_config` does not establish a rule source.

- Standalone: `rules source set --kind mihomo --config-id ID --binary PATH --home PATH`.
  Use the real core-host binary/home and registered complete config.
- Verge: `rules source set --kind verge --data-dir PATH --profile UID --owner-version 2.5.2`.
  Bind the current profile's existing Rules companion. Version is declared
  compatibility, not detected identity.

Within authorized scope, preview `rules add-domain HOST --via POLICY --json`.
Review exact hostname scope, file, owner, diff and digest before using
`--yes --expect DIGEST`. Never infer permission to edit a subscription or
generated YAML from the ability to read controller credentials.

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
