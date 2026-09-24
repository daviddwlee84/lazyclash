# Upstream clash-rules publication and target refresh

Status: deferred; v1 quick rules edits the bound persistent owner (2026-09-24)
Priority: P?
Effort: L
Related: [TODO](../TODO.md), [managed clients](../docs/managed-cores.md),
[rule workflows](../docs/rules-and-ownership.md), `internal/managedcore/assets/rules`

## Why this is separate work

The motivating example was applying a Copilot API DIRECT exception to one or
all targets. Three possible paths were investigated: controller insertion,
editing each owner and reloading, or updating daviddwlee84/clash-rules and
refreshing consumers. The first version implements owner edits. It does not
commit, publish or mutate upstream repositories.

The reviewed Mihomo controller supports reading rules, disabling runtime rule
indices, reloading complete config and refreshing existing rule providers. It
does not expose ordinary insertion of one arbitrary rule. Provider refresh
updates a provider's content; it cannot create a missing provider, change the
consumer's RULE-SET policy or regenerate a GUI-owned profile.

## Upstream contract already inspected

`daviddwlee84/clash-rules` owns personal policy under `rules/`; byte-preserved
third-party inputs under `vendor/` move through fetch/review/promote with locked
hashes and licenses. Private nodes, subscriptions and device profiles are not
public rule data. Its repository contract prohibits ad hoc controller deployment
to a managed Pi; use that owner's managed rule-update transaction.

Offline build produces a canonical per-file hash manifest and deterministic
version. CI tests/builds source `main`, then publishes artifact contents to
`release` and an immutable `rules-<SHA-256>` tag. `release` is floating and CDN
caches can lag; an immutable tag is a recorded revision, not the newest data.
The consumer example points at `@release/clash/*.list`; `@main/dist/...` is not
the publication layout.

Classical provider content supplies match predicates such as
`DOMAIN-SUFFIX,example.com`. The action belongs to the consuming config, for
example `RULE-SET,direct,DIRECT`. Moving one predicate between public categories
can affect several consumers, but a target's policy names and RULE-SET order
remain local decisions. The original three-field rule cannot simply be appended
to a provider while assuming its trailing action will control every target.

## Distinguish the three update paths

| Consumer | Actual update mechanism | Work still needed |
| --- | --- | --- |
| Existing HTTP rule provider | `providers update rules NAME`, or its configured interval, fetches its configured URL. | Verify category/action mapping, URL revision, download success and current runtime content. |
| Complete profile / Verge-owned profile | The owner regenerates or refreshes its profile and activates it. | Respect profile identity, Merge/Script order, owner reload and verification. |
| lazyclash managed preset | `rules preset update` uses the immutable snapshot embedded in the installed lazyclash binary, with local file providers. | A separately downloaded bundle feature must be designed; provider refresh alone does not update the embedded snapshot. |

## Follow-up design

Keep policy editing, public publication, verified artifact acquisition and
target activation as separate operations with separate results. First discover
which saved targets actually consume which upstream categories and revisions;
never equate `--all` with every target being an HTTP subscriber.

An upstream edit should preview its category diff and affected consumers,
validate/build against the repository's own contract, then use an explicitly
requested publish workflow. Deployment should record artifact hash, consumer
policy mapping, before/after source, per-target receipts and rollback material.
Publication success does not prove CDN freshness or target reload success.

For independently downloaded lazyclash bundles, verify manifest and file hashes,
retain license/provenance files, stage all resources before switching active
state, and preserve the previous immutable bundle for recovery. Core version,
resource paths and provider behavior must be compatible before activation.

## Open decisions before implementation

- Should lazyclash author upstream repository changes, or consume a reviewed
  immutable artifact produced elsewhere?
- Which targets use floating HTTP URLs, pinned URLs, embedded file providers
  or complete owner-managed profiles?
- What constitutes observed refresh success when the API exposes metadata but
  not the full matching contents, and how should stale CDN data be reported?
- How are category changes reviewed when consumer policy names/order differ?

## Primary references

- [clash-rules release contract](https://github.com/daviddwlee84/clash-rules/blob/main/docs/release-pipeline.md)
- [clash-rules consumer wiring](https://github.com/daviddwlee84/clash-rules/blob/main/examples/clash.yaml)
- [clash-rules third-party data](https://github.com/daviddwlee84/clash-rules/blob/main/THIRD_PARTY.md)
- [Mihomo API](https://wiki.metacubex.one/api/)
- [Rule-provider formats](https://wiki.metacubex.one/en/config/rule-providers/)
- [Classical provider parsing](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/provider/classical_strategy.go)
