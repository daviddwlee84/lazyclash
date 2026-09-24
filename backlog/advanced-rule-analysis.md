# Advanced rule grammar and analysis

Status: deferred after the common-rule workbench (2026-09-24)
Priority: P?
Effort: L
Related: [TODO](../TODO.md), [rule workflows](../docs/rules-and-ownership.md),
`internal/rulecheck`, `internal/rulework`

## Current boundary

Quick apply accepts DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR and IP-CIDR6,
with optional no-resolve on destination CIDRs. It prepends absent rules, skips
identical persistent rules, blocks exact-selector different-policy conflicts,
and asks default No for warnings. Passive healthchecks use the same analyzer.

The analyzer checks common syntax, exact identities, domain/suffix containment,
provable keyword substring relations, CIDR containment and ordered MATCH
reachability. Existing source-IP rules stay distinct. Unknown kinds/modifiers
remain opaque; providers and GEO data are not expanded. Source and runtime
lists have separate provenance. Runtime does not expose every source option.
Pairwise overlap work is bounded, with the limit explicitly reported; exact
selector checks still cover the full list.

## Investigation worth retaining

- Mihomo parses IP-CIDR and IP-CIDR6 through the same constructor; normalize by
  actual prefix/address family. `src` changes the runtime type to SrcIPCIDR,
  and no-resolve changes DNS behavior. Never erase either distinction.
- DOMAIN-KEYWORD lowercases its payload and performs substring matching.
  Containment proves some overlaps, but failure to find containment does not
  prove disjoint sets. Unrelated keywords can still coexist in one hostname.
- `topology` parses outer rule structure to display policy/provider/sub-rule
  references. Its `Resolved` flag describes references, not semantic matcher
  validity or reachable traffic; do not reuse it as a routing proof.
- MATCH normally provides the final fallback. Generic overlap with that
  fallback is not actionable. Provider/logical expansion must account for
  order and action semantics rather than flagging every intersecting rule.
- Static order is not observed routing: DNS state, destination metadata and UDP
  fallback can change actual evaluation. Existing URL diagnosis remains the
  source of request-specific connection evidence.

## Follow-up choices

Extend the typed parser one matcher family at a time: source IP and modifiers,
process/port/network, regex, provider/GEO, then logical and sub-rules. Each needs
a declared syntax/version contract, canonical identity and a clear distinction
between invalid input and an unsupported but potentially valid existing rule.

Provider analysis needs an explicit snapshot with origin, revision/hash and
format. Decide how to read inline/file/http/mrs sources, whether any downloads
are requested, how stale data appears, and how bounded expansion behaves. A
metadata count from `/providers/rules` is not the provider's matching contents.
Never silently refresh it as a side effect of healthcheck.

For regex/logical relations, preserve unknown outcomes unless containment or
an overlap witness can be proved within bounds. Add representative golden
fixtures validated by the target core version and retain unknown data in
machine-readable coverage results. Provider changes can invalidate earlier
analysis; include the inspected revision in any later write guard.

## Open decisions before implementation

- Which new matcher family is needed by an actual rule-editing request?
- Which installed core versions define accepted syntax and modifiers?
- Does richer analysis remain strictly local, or gain an explicitly requested
  provider snapshot fetch step?
- Should a future request-route explainer accept hostname/IP/process/port
  metadata and show a bounded hypothetical trace beside observed evidence?

## Primary references

- [Mihomo rule grammar](https://wiki.metacubex.one/en/config/rules/)
- [Rule parser](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/parser.go)
- [IPCIDR matcher](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/common/ipcidr.go)
- [Keyword matcher](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/common/domain_keyword.go)
- [Controller rule representation](https://github.com/MetaCubeX/mihomo/blob/Meta/hub/route/rules.go)
