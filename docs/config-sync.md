# Configuration comparison and selective sync

`configs diff` compares persistent declarations, including proxies, groups,
providers and ordered rules. `configs sync` selects complete objects, resolves
dependencies, and builds one candidate configuration per destination.
DNS, ports, TUN, controller settings and other host settings are comparison-only.

```sh
lazyclash configs diff desktop server
lazyclash configs diff desktop --all --format unified
lazyclash configs diff desktop server --format unified | delta
lazyclash configs diff desktop server --json
lazyclash configs sync desktop server --interactive
lazyclash configs sync desktop --all --interactive
```

Each positional target uses its own saved connection and source binding. Global
`--target`, controller, SSH and credential overrides cannot be combined with
these commands. Runtime API metadata does not contain transferable credentials:
an unavailable persistent source is reported explicitly.

Comparison ignores comments, formatting and mapping order. YAML types, missing
versus null fields, sequence order and duplicate rule occurrences still matter.
Credentials are compared privately before masking; a password-only change is
shown even when both displayed values are masked. Unified output is built from
sanitized data, so comments and credential-bearing URLs are not printed.

The interactive selector starts with nothing selected. It keeps separate
choices for each destination, shows the complete masked object difference, and
retains the draft when returning from review. Selecting a changed named object
means replacing that whole definition, including its fields and ordered members.
Destination-only objects are retained.

Use Space to select, arrows or `j/k` to navigate, `h/l` to switch destinations,
Tab to change focus, `g` to append a selected proxy to existing destination
groups, and `o` for rule-placement options. The dashboard Configs page also
opens the shared selector with `S`.

Missing transferable dependencies are included automatically. For a same-name
dependency with a different definition, explicitly choose either the existing
destination definition or replacement from the source. A group can depend on
nodes, other groups and proxy providers; rules can depend on policies and rule
providers. Missing definitions, ambiguous references and cycles block the plan.

Groups using `include-all` retain that declaration and show a warning that their
membership follows the destination inventory. Named definition order is shown
for comparison; replacements keep destination positions. Logical rules
(`AND`, `OR`, `NOT`, `SUB-RULE`) and unknown rule grammars remain blocked for
transfer until their dependencies can be resolved.

## Scripted selections

Copy object IDs from `configs diff --json`; rule IDs include occurrence identity.
For one destination, the selection file is a single object:

```json
{
  "objects": [
    {"id": "COPY_SOURCE_OBJECT_ID_FROM_DIFF", "replace": true}
  ],
  "dependencies": [
    {"id": "COPY_DEPENDENCY_ID_FROM_BLOCKER", "action": "reuse"}
  ],
  "rule_placement": "anchored"
}
```

`replace` is required for changing an existing definition. Dependency actions
are `reuse` or `replace`. The file contains IDs and decisions, never passwords or
raw YAML. Unknown fields, repeated JSON keys and duplicate destinations are
rejected. For `--all`, use per-target selections; omitted targets stay unselected:

```json
{
  "destinations": [
    {
      "target": "server",
      "selection": {
        "objects": [{"id": "COPY_SOURCE_OBJECT_ID_FROM_DIFF"}]
      }
    }
  ]
}
```

Optional group membership is expressed as
`"attach_groups":[{"proxy_id":"/proxies/NAME","groups":["PROXY"]}]`.
The proxy must be selected and the groups must already exist. Replacing a whole
group and attaching a proxy to that same group in one selection is a conflict;
choose the intended complete group definition instead.

```sh
# Preview and inspect the returned candidate digest.
lazyclash configs sync desktop server --selection selection.json

# Rechecks source, destination, resources and choices before writing.
lazyclash configs sync desktop server --selection selection.json \
  --yes --expect DIGEST
```

Preview is the default; `--dry-run` makes that intent explicit. `--json` is
noninteractive. The digest covers the actual private values, source bindings,
resource data and target decisions. If any relevant observation changes, obtain
a new preview.

## Rule order and persistent ownership

Selected rules keep their source order. Default `anchored` placement uses common
unchanged rules to locate the selected rules within the destination list. When
the location is ambiguous, the plan blocks; `"rule_placement":"prepend"` is an
explicit alternative. Existing destination rules are preserved unless an
individual selected replacement explicitly changes them.

Rules require a rule write binding. An existing configuration binding can be
copied explicitly:

```sh
lazyclash --target david-ubuntu rules source set --from-config-source
lazyclash --target david-ubuntu rules apply --dry-run \
  'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT'
lazyclash --target david-ubuntu rules apply --yes \
  'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT'
lazyclash --target david-ubuntu rules find \
  'DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT'
```

For combined object and rule writes, configuration and rule bindings must
identify the same owner. Read-only inspection never creates a write binding.

Verge uses existing active-profile companions. Positions expressible by its
Rules companion use that companion. Other placements need a complete
per-profile `Merge.rules` override. Set
`"allow_verge_rules_override":true` only after reviewing that consequence:
the override preserves the reviewed destination rules but masks future rule
updates from the subscription. Existing overrides remain disclosed. The tool
does not create profile-index entries, edit generated YAML or execute Scripts.
An owner composition that cannot be proven equivalent blocks the change.

## Providers, application and recovery

File providers transfer their authoritative data; HTTP providers transfer an
existing cache as an initial seed. Planning never downloads providers. Missing,
unreadable or unverifiable resource data blocks the selected transfer. Paths are
adapted to destination-owned resource files rather than reusing another host's
absolute path. Host-local certificate/key and interface dependencies need owner
support before they can be transferred.

Each destination's selected changes are validated together, saved once per file
and activated once. Multi-file and multi-target operations are not atomic.
With `--all`, unavailable selected targets are reported as skipped; configuration
and validation errors block before the first write. After writing starts, a
failure or unknown outcome stops later targets and retains completed changes.

```sh
lazyclash --target server configs verify RECEIPT
lazyclash --target server configs restore RECEIPT --yes
```

Receipts track the composite change and resource files. Restore checks for
intervening changes before replacing configuration files or removing unchanged
new resources. An HTTP provider may refresh its cache after activation; that
mutable cache is distinguished from authoritative file-provider data. Verge
may report persisted changes awaiting native profile reactivation; persistence
alone does not prove the running core loaded them.

Existing `rules diff/find/lookup`, `rules apply`, `proxies copy`, `configs apply`
and `targets diff/copy-settings` keep their original scopes. Use `rules find` for
one declaration and `configs sync` when transferring selected source objects and
their dependencies.
