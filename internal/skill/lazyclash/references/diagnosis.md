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
