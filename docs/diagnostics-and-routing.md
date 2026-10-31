# Diagnostics and routing evidence

## Local passive doctor

```sh
lazyclash doctor
lazyclash doctor --json
lazyclash --target LOCAL doctor
lazyclash --controller http://127.0.0.1:9090 doctor --timeout 5s
```

`doctor` is a noninteractive, local-only overview, passive even without
`--read-only`. Its controller traffic is restricted to GET `/version` and
`/configs`; it reads local settings, process proxy variables, OS proxy settings,
and interface/default-route/DNS metadata. It never opens SSH, runs DNS/HTTP
outbound probes or URLTests/healthchecks, saves discovery, starts/repairs
services, or changes TUN, system proxy, selectors, or settings. **Egress
connectivity is not tested.** Controller failure does not establish data-path
failure, and controller success does not establish internet access.

Selection uses an explicit global `--target`/`--controller` first, then the
existing `LAZYCLASH_TARGET`/`LAZYCLASH_CONTROLLER`/`CLASH_CONTROLLER` environment
selection. Explicit remote/SSH selections are reported as unsupported without
local fallback. Otherwise it prefers a registered **local** default, then a sole
local registration, then local discovery. Multiple candidates require an
explicit choice. A remote `default_target` is not used. Discovery filters out
non-loopback/non-Unix candidates **before probing**, never persists candidates,
and does not interpret zero candidates as proof that no proxy exists.

Controller selection and data endpoint intent are separate. Without an explicit
target/controller, `LOCAL_PROXY_URL` (and `LOCAL_PROXY_SOCKS_URL`) takes precedence
for the reported data endpoint; otherwise a registered `probe_proxy` precedes
runtime listener ports. These endpoints are not contacted. The controller can
be unavailable while an explicit data endpoint remains useful. Endpoint
comparisons use only the same local scope and yield warnings, not ownership or
connectivity claims. Direct mode, TUN-only operation, and absent proxy variables
are not failures. Configured macOS Network services do not prove every service
is active; unsupported OS proxy backends or missing Python/host tools are
unknown, not disabled. PAC URLs, credentials and raw errors are withheld.

The overall timeout is **10 seconds**, adjustable with `--timeout`. Independent
collectors retain partial evidence on settings/auth/offline/timeout failures.
A missing default settings file is normal (no file is created); an explicitly
missing or malformed settings file is a report failure. Human and JSON output
represent the same checks. JSON is one report with `schema_version`, `scope`,
`selection`, typed evidence, `checks`, `summary`, and `suggestions`; no second
error envelope accompanies a successfully emitted diagnostic report.

| Exit | Meaning |
|---|---|
| 0 | Required checks completed with no failures; warnings and optional unknowns allowed |
| 1 | A failure or incomplete required check |
| 2 | CLI usage/flag error (ordinary CLI error, not a diagnostic report) |
| 130 | Canceled; partial report retained |

Checks use `pass`, `warn`, `fail`, `unknown`, and `skip`. A timeout confined to an
optional collector can still exit 0; `summary.timed_out` and the unknown check
retain that limitation. Output-write failures use the ordinary CLI error path.

Use `targets test` for a selected controller (including supported remote
transports), `diagnostics network` for detailed passive routing evidence, and
`proxy test` / `diagnostics url` for an explicitly requested active test.
Existing `proxy docker doctor` and `analytics doctor` remain scoped diagnostics,
not replacements for the local overview.

## Dashboard metrics

Overview keeps up to 15 minutes of per-target history in memory, displayed in
1/5/15-minute windows. Charts use sample timestamps, show disconnect gaps,
and retain visibly stale values. Each source has its own age; over five seconds
is stale. Core RSS is the core process's memory, not the host's RAM, and initial
zero RSS can be warmup. Cumulative counters may reset when the core restarts.

Connection distributions aggregate the full fetched snapshot; the browsing list
is capped at 2,000 rows. Observed route chains describe existing connections;
a group's current selection alone does not prove those connections used it.
Arrow/Vim navigation, Tab, mouse rows/buttons and `M` (mouse capture) work
together. Braille, block and ASCII graph modes offer terminal-compatible views.

## Reusable connectivity checks

Overview → **Saved connectivity checks** (or **C**) manages public HTTP(S) checks
for the selected target. Save website expectations once, then run one or all
manually. Transport, expected HTTP status, authentication limits and observed
rule/chain remain separate results. See [saved connectivity checks](connectivity-checks.md)
for the CLI commands and result semantics.

## Diagnose one URL

```sh
lazyclash --target server diagnostics url https://example.com --via PROXY
lazyclash --target server diagnostics url https://example.com --json
lazyclash --target server --read-only diagnostics url https://example.com --observe-only
```

`--via` names an existing policy to compare; it never changes a selector or
routing mode. A group is resolved to its currently observed leaf, which is
recorded in the result. Core URLTests may update health/history and automatic
selection can react to health changes.

The action menu provides the same URL workflow and an inspectable logical
topology. Host and explicit data-proxy probes use HEAD without redirects,
cookies or login state; core URLTests use the core's separate test API.
They can reach the named website: diagnosis is an explicit active operation,
not a background dashboard refresh. Each HTTP probe has a five-second limit;
the complete run has a sixty-second limit and retains partial evidence when
it expires. Request phases run sequentially to reduce correlation ambiguity.

| Evidence | What it establishes |
|---|---|
| Local process environment | Proxy variables available to this process; not all applications' settings |
| SSH session environment | Noninteractive SSH process state; not the remote browser or service environment |
| OS proxy/DNS/interfaces/routes | Host configuration and available route lookup evidence |
| No-application-proxy request | No curl application proxy; OS routing/TUN can still intercept it |
| Explicit data-proxy HTTP request | HTTP status/timing over the configured route; no fallback |
| Core DIRECT/leaf URLTest | A core-side response-time sample; no HTTP status or page-usability guarantee |
| Core DNS query | Core query resolver answers; not identical to native NSS, DIRECT resolver or fake-IP inbound processing |
| Connection metadata | Matched rule/chain for an observed active flow, with correlation confidence |

curl ignores uppercase HTTP_PROXY, has scheme-specific precedence, and supports
ALL_PROXY/NO_PROXY. Host requests use curl itself rather than pretending Go's
environment-proxy interpretation is identical. A curl socket peer can be a
proxy, not the destination website. Timing fields describe the particular
request engine's cumulative milestones since request start; they are not
additive phase durations. For explicit proxy requests these milestones can
describe the local connection to the proxy, rather than destination DNS.

Python 3 and relevant host tools are discovered, never installed by diagnosis.
Missing tools produce unavailable evidence. Passive DNS configuration and
interface inventory are also collected in observe-only mode. Linux includes
available policy-routing rules; destination route lookups use native DNS
answers during active diagnosis. Linux has no universal desktop proxy
configuration; an SSH process may not belong to a desktop session.

## Confidence and topology

The terminal topology is logical:

```text
client → environment / explicit proxy → SSH (when used)
       → core → matched rule → policy chain → outbound → destination
```

It is not traceroute or an ISP map. Unknown route sections stay unknown.
Raw core chain order is retained in JSON; the display may present outer policy
to leaf for readability.

- **Observed:** host and source address/port match during the request window.
- **Probable:** one new connection fits one request window, with no competing
  connection or request candidate, but no exact source tuple.
- **Unknown:** preexisting, ambiguous or missing evidence.

Mihomo connection tracking starts after a successful outbound dial and removes
closed connections. A failed DIRECT request may leave no active connection.
An absent record therefore does not prove bypass. SSH forwarding changes the
source tuple; matching a local forwarded socket directly to the core's socket
would be incorrect. Logs are supplemental and do not provide a request ID.

TUN enabled in config is not proof that this flow used it. A matching flow's
inbound metadata is stronger evidence. DNS answers that differ may reflect
fake-IP, split DNS, CDN/ECS, hosts, caches or filtering; lazyclash does not call
that difference confirmed poisoning.

Optional `--reference-doh https://resolver.example/dns-query` uses the explicit
data proxy. It is opt-in and cannot be combined with observe-only. The endpoint
must support the DNS-JSON GET interface (`name`/`type` parameters and
`application/dns-json` responses). Wire-format-only DoH endpoints are not
supported. Reference answers are separate evidence, not authoritative proof
that either native or core DNS is wrong.

## Recommendations and privacy

### A website hosted on the proxy VPS

Sharing a server/IP with a proxy node does not by itself select DIRECT. Rule
mode follows the first matching rule; global mode uses its selected outbound.
Avoiding a TUN loop for the node's transport connection is not evidence that
application requests to a website on that IP bypass proxy rules.

```text
DIRECT:       client → website VPS
Same node:    client → encrypted proxy → website on the same VPS
Other node:   client → another proxy VPS → website VPS
```

If the website really terminates on the same host, the proxy-to-website leg may
be host-local. This topology does not imply twice the public egress; a CDN,
another reverse-proxy backend or another selected node changes the path. Provider
billing requires its own evidence. DIRECT to an HTTPS website still uses the
website's TLS; proxy encapsulation is an additional layer.

Inspect an actual URL and the observed connection chain first:

```sh
lazyclash --target desktop diagnostics url https://site.example.com --via PROXY
# If direct reachability works and bypass is intended, preview an exact rule:
lazyclash --target desktop rules add-domain site.example.com --via DIRECT
```

Rule source binding, reviewed apply and owner activation still apply. Do not
automatically bypass a node's entire IP or shared hosting range. See
[Mihomo routing rules](https://wiki.metacubex.one/config/rules/) and
[operating modes](https://wiki.metacubex.one/config/general/).

### Recommendations and report privacy

DIRECT transport failure plus a chosen proxy's response sample can justify a
tentative exact DOMAIN recommendation, not a claim that the website functions.
HTTP error responses remain visible. NO_PROXY, missing application proxy or
non-rule mode may explain behavior that adding a rule cannot repair.
Automatic suggestions require known rule mode and a distinct non-DIRECT
alternative. An already observed proxied route suppresses the suggestion;
missing connection evidence alone does not. A NO_PROXY match is called out
because a core rule cannot change an application's proxy settings.

Recommendations open a separate [rule preview](rules-and-ownership.md).
They cover the whole hostname, not just the URL path; broad suffix/IP rules
are not generated automatically.

URLs containing userinfo or fragments are rejected. Internationalized hosts
must be supplied in ASCII/Punycode form. Query strings, proxy credentials and
raw controller logs are not included in the report. Reports are not saved
automatically. Treat an explicitly redirected report as network information.
`--observe-only` avoids active DNS, HTTP and URLTest requests; `--read-only`
requires this option for URL diagnosis.
