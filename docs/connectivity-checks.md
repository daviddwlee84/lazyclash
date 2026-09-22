# Saved connectivity checks

Save public HTTP(S) checks on a target and run them again after changing a
profile, node or routing rule. The dashboard's Overview has a **Saved connectivity
checks** button; press **C** or find the same action in the action menu.

The shared terminal menu can review, add, edit, remove, run one, or run all saved
checks. Opening the menu, saving a definition and refreshing the dashboard send
no check requests. Escape cancels a menu or draft; a completed operation keeps
its result visible until you acknowledge it and return to the dashboard.

```sh
lazyclash --target desktop diagnostics checks add claude \
  --name 'Claude website' --url https://claude.ai/
lazyclash --target desktop diagnostics checks list
lazyclash --target desktop diagnostics checks run claude
lazyclash --target desktop diagnostics checks run --all --json
lazyclash --target desktop diagnostics checks --interactive
```

Active checks use the selected target's **Data proxy URL** (`probe_proxy`). If it
is absent, the existing proxy resolver can derive a local or SSH endpoint from
that same controller's runtime ports, keeping credential references in memory.
This does not edit the target or select an endpoint from process proxy variables
or another controller. A remote controller without SSH needs an explicit endpoint.

The controller supplies routing observations; requests use the selected data
proxy. If that proxy is explicitly configured, it can still be tested when the
controller is unavailable, with rule and chain evidence marked unknown.

## Definitions and expected responses

Checks are stored under the selected target in lazyclash's settings, independently
of the target's Mihomo YAML. Each definition has a stable ID, optional display
name, URL, optional expected HTTP statuses and optional comparison policy. IDs
are unique within a target; a target can have up to 64 checks.

The default expectation is any status from **200 through 399**. Use `--status`
for an explicit set and `--replace` to edit the definition with that ID:

```sh
lazyclash --target desktop diagnostics checks add health \
  --url https://example.com/health --status 200,204
lazyclash --target desktop diagnostics checks add health \
  --url https://example.com/status --status 200,204 --replace
lazyclash --target desktop diagnostics checks remove health
```

Choosing an expected error status can be useful for an unauthenticated endpoint.
It means that the received status matched the saved condition. It does not mean
that authentication succeeded or the application is usable.

URLs must use HTTP or HTTPS and contain no userinfo, query string or fragment.
No cookies, API keys or authorization headers are saved. Each check sends a HEAD
request without following redirects or reading a page as an authenticated user.
Definitions persist; results are only saved when you explicitly redirect output.

`--read-only` permits listing and reviewing definitions. It disables definition
changes and active requests. Temporary controller/SSH overrides cannot own saved
checks; register a target first.

## Reading the result

| Result | Meaning |
|---|---|
| Transport reachable | The explicit data-proxy request received an HTTP response, including an error response. |
| HTTP status matched / unexpected | The returned status was compared with the saved expectation. |
| Authentication / application access: not tested | A header request does not test browser login, account eligibility, an API key or a model call. |
| Observed rule and chain | One structured connection uniquely matched this request's host, time and local source tuple. |
| Rule / chain: unknown | No unique connection established the route. Fast requests and SSH forwarding can prevent exact correlation. |
| Possible connection | A candidate connection is shown separately with its rule and raw chain, explicitly unconfirmed for this check. |

For example, a Claude check can receive HTTP 403: transport was reachable, the
default HTTP expectation failed, and the check does not establish whether a
logged-in browser could use Claude. A successful status is also not a test of
an authenticated Claude conversation.

Checks run sequentially and have a bounded per-check timeout. An interrupted run
retains partial results and marks unstarted checks as `not-run`. Failed checks
produce a nonzero command result while preserving their individual observations.

The optional `--via POLICY` adds a separate core URLTest against that policy's
resolved leaf from the batch-start selector snapshot. Health-based selections
can change during the run. Its latency sample is separate from the HTTP result;
it does not route the HTTP request through that policy or change a selector.
Core URLTests can update the core's health history, which automatic groups may
react to. Saved checks do not set modes, selectors or routing rules.

For DNS, local environment, an alternative policy and fuller logical topology,
use [one-URL diagnosis](diagnostics-and-routing.md#diagnose-one-url). Persistent
routing changes remain a separate [reviewed rule workflow](rules-and-ownership.md).
