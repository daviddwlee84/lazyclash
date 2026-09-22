# Historical analytics

Analytics is opt-in and independent of the dashboard. Read `analytics status`
and `analytics doctor --json` before enabling a source. `analytics setup` previews
by default; `--yes` saves configuration and `--enabled` opts a source into collection.
Saving configuration does not start a service. Restart a collector after edits.

Use source kinds `mihomo`, `interface`, `xray-access`, `xray-stats`, or `vnstat`.
Source IDs identify observation points, not people. Paths, target IDs and secrets
belong to the collecting host. An SSH target on a laptop is not a node-local
collector configuration. Missing access permissions or Stats policy is an
unavailable capability, not authority to elevate, change UUIDs or reconfigure a core.

`analytics collect --duration 10m` runs foreground; `analytics report --period
week --group-by domain --json` reads saved history. CLI/TUI share the report service.
`analytics --collector-host HOST report` invokes an existing remote lazyclash;
`--remote-binary` selects its executable. No public API port or live SQLite copy
is needed. `--analytics-config` and `--state-dir` address collector-host paths.

User services use `analytics service install|start|stop|status|remove`. Mutations
preview by default and require `--yes --expect DIGEST`. Install does not start;
remove preserves database and config. Linux user-session/linger and macOS login
limitations are reported; never infer uninterrupted collection from installation.

Defaults: 30 days detail, 90 days minute aggregates, 13 months daily aggregates,
1 GiB storage budget, Asia/Shanghai days and Monday weeks. They are configurable.
Capacity can shorten retention; preserve coverage, actual oldest times and gaps.
Read/report commands do not create or prune state. Queries use exclusive end dates
and complete available buckets; daily/native history cannot supply minute precision.

Client samples can miss short connections/final bytes. Access logs give accepted
connection events, not per-domain bytes. User Stats require configured labels;
shared UUIDs cannot establish people. Interface counts include non-proxy services.
Keep all scopes separate. Connection counts are not visits, byte-active minutes
are not human attention, unknown/gaps are not zero, and traffic is not a bill.

Only actual completed vnStat daily buckets can be imported with `import-vnstat`;
source timestamps/day timezone must match. Missing history cannot be reconstructed.
Notifications default off. Enabling alerts with a private webhook file/environment
reference authorizes collector delivery. Do not print secret values. Delivery timeouts
can be uncertain; retries may duplicate notifications. Verify new alerts before
retiring any old timer, keeping GiB/day/interface/timezone consistent.

Domain rankings are investigation candidates. Manual diagnosis requires choosing
the relevant client target. Never infer a DIRECT rule from high bytes alone;
use the existing URL diagnosis and fresh source-owned rule preview/apply workflow.
IP-only destinations must not become invented domains or suffix rules.
