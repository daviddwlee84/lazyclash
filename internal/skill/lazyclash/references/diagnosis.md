# URL diagnosis and route evidence

Use `diagnostics url URL --via POLICY --json` for an explicit active test.
Choose POLICY from real target data; omitting it performs no guessed alternative
comparison. With `--read-only`, use `--observe-only` to avoid DNS/HTTP/URLTests.

Keep local process, SSH noninteractive session, core resolver/outbound, and
explicit data-proxy results separate. The SSH host may itself be a jump host,
not the controller's machine. Missing Python/curl/system tools mean unavailable
evidence, not a healthy or bypassed route.

HEAD requests do not follow redirects or reproduce browser sessions. Report
HTTP status separately from core delay samples: URLTest can return a delay for
an HTTP error and updates health/history. A chosen group's current leaf is
sampled without mode/selector writes; auto groups may respond to health changes.
No application proxy still allows OS TUN/routing interception.

Use observed/probable/unknown correlation as reported. Mihomo tracks successful
active dials and removes closed flows; missing connections do not prove bypass.
SSH forwarding changes the source tuple. Host/time alone is not exact evidence.
Logs are supplemental; no log-level mutation is needed to subscribe.

The topology is logical, not physical traceroute. Configured TUN is weaker
evidence than a matching flow's Tun inbound metadata. DNS differences can come
from fake-IP, CDN/ECS, split DNS, hosts or caches; do not call them confirmed
pollution. Optional reference DoH requires an explicitly configured proxy.

DIRECT failure plus a chosen policy's response can yield a tentative exact
DOMAIN recommendation. Check actual HTTP status, route evidence and mode.
NO_PROXY or an application bypass may need a different repair. A hostname
rule affects the whole host, not only the tested path.

Diagnosis does not apply recommendations. Use the separate
[preview/apply workflow](workflows.md). Userinfo URLs are rejected, query
strings/raw logs are omitted, and reports are not automatically saved.

## Reusable connectivity checks

Use a saved target and keep its check definitions separate from Mihomo YAML:

```sh
lazyclash --target TARGET diagnostics checks add claude --url https://claude.ai/
lazyclash --target TARGET diagnostics checks list --json
lazyclash --target TARGET diagnostics checks run --all --json
```

`add` only saves; `run ID` or `run --all` explicitly sends checks. Use
`--status 200,204` for exact expectations (default 200–399), `--replace` to
edit an existing ID, and `remove ID` to remove it. Dashboard Overview → Saved
connectivity checks (`C`) uses the same CLI workflow. Read-only mode permits
review/list only. Definitions reject credentials, query strings and fragments.

Each bounded HEAD request uses the selected target's explicit data proxy or a
local/SSH endpoint resolved from that same target's runtime ports in memory.
Do not select another controller or a process proxy variable as a fallback.
Separate transport reachability, expected HTTP status, application access
(not tested), and observed rule/chain. A possible SSH connection is a candidate,
not confirmation that this check followed that route. Optional `--via POLICY`
adds a separate core URLTest comparison; it does not reroute the HTTP request.
