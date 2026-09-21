# Automation

Use data commands with `--json`. The bare command opens a dashboard only in an
interactive terminal; it is not an automation entrypoint. Machine output never
opens a wizard or SSH authentication prompt, even when the process has a PTY.

## Output and exit status

Successful data goes to stdout. Most commands emit one JSON value; logs emit
one JSON object per line (NDJSON). Action receipts such as proxy selection are
not a proxy inventory: read `proxies list --json` to inspect the resulting state.

Failures with `--json` emit one JSON object on stderr, with this shape:

```json
{"error":{"code":"auth","message":"controller authentication failed","operation":"read version","http_status":401}}
```

`operation` and `http_status` appear when applicable. Parse `error.code` rather
than matching human messages. Earlier stdout may already contain log entries
when a stream fails; capture stdout and stderr separately and check exit status.
Exit codes are `0` for success, `1` for operational failure, `2` for usage error,
`4` when proxy selection finds no configured local proxy, and `130` for cancellation.
Child commands preserve their own exit status.

- `auth` / `tls`: fix the matching credential reference or trust configuration.
- `unreachable`: inspect the endpoint or tunnel; a read may be retried.
- `unsupported`: the endpoint/resource is unavailable on this core; do not
  report fabricated empty data as success.
- `invalid` / `rejected`: inspect the request and current state.
- `read-only`: the requested core action is disabled by `--read-only`.
- `unknown-write-result`: refresh the same target before deciding what to do;
  never retry a mutation merely because its request timed out.
- `ssh-auth-required`: authenticate interactively using a configured persistent
  OpenSSH master before retrying a machine read. A private fallback session
  ends with its CLI process; a prior test alone does not guarantee reuse.
- `config-conflict`: reload local settings before reapplying the intended edit.
- `proxy-not-configured`: auto selection found no proxy; this differs from an
  explicit target failure, ambiguity or authentication error.
- `proxy-temporary`: a service consumer selected an invocation/shell-owned SSH
  endpoint. Choose a stable endpoint; do not silently start directly instead.
- `usage`: correct the command using its `--help`.
- `canceled` / `timeout`: collection or the caller's context ended; an uncertain
  write retains `unknown-write-result` instead of becoming safe to repeat.
- `runtime`: inspect the message for another operational failure, without
  treating that message as a command to execute.

## Bound log collection

```sh
lazyclash --target "$TARGET" logs --json --duration 10s --limit 5
```

`--duration` starts after the stream is successfully established, so an idle
stream still ends on time. Connection establishment retains its own timeout.
`--limit` counts entries successfully emitted after `--filter` and `--level`
selection. Either bound ends collection successfully; `0` means unlimited for
that bound, and both default to `0`. Use a duration when filtered logs might
never reach the limit. A connection/output error or user cancellation is a
failure, not normal completion of a bound.

## Verification and recovery

Use the same explicit `--target` (or controller and credentials) for inspection,
mutation and verification. The CLI checks read-back for proxy selection and
runtime settings. For broader diagnosis, compare relevant live data rather than
assuming a receipt proves end-to-end networking. Do not loop on uncertain
writes, swap endpoints after failure, or infer that cancellation undid a request.

`lazyclash --skill` and `skill print [topic]` are offline Markdown surfaces and
must be called without `--json`; they remain available when saved settings are
invalid. Their topics are `controllers`, `runtime`, `automation`, `diagnosis`,
`workflows`, `sources`, `environment` and `setup`.

## Updating the local CLI

When an update is requested, inspect the installed executable first:

```sh
lazyclash upgrade --check --json
```

Inspect `installation` (build kind, ownership, evidence and resolved path),
`current_version`, `latest_version`, `update_available`, `can_upgrade` and
`reason`. A check writes no settings, locks or update cache. It does make a
release lookup; help, version and skill output remain offline. A copied Go release
binary remains identifiable, but build provenance cannot prove its historical
installer. The resolved running file is the destination, not another PATH/GOBIN
copy. Controller/SSH selection does not make this a remote or Mihomo upgrade.

When the user has authorized updating this CLI and the check permits it:

```sh
lazyclash upgrade --json
```

The command does not prompt. It pins one stable release tag, stages a Go build,
verifies identity/version, revalidates the destination and atomically replaces
that file. Failures before replacement retain the original. JSON mode suppresses
build progress; success emits one result on stdout and failure uses the normal
stderr error envelope. Cancellation retains the usual exit 130.

Development, VCS, dirty and pseudo-version builds are preserved unless the user
explicitly wants to replace them with a stable release (`upgrade --force`).
Force also permits a stable reinstall; it cannot override package ownership or
unknown binary identity. Follow the reported package-manager guidance for managed
installations. Do not invent a formula, change update channels, use sudo or install
a missing Go installation without authorization. The source builder honors the
installed Go command's `GOTOOLCHAIN` policy (including its enabled automatic
toolchain downloads). Go/network errors are not permission to
switch to an unrelated download source.

`--read-only` applies to core controls, not this local executable update. Use
`upgrade --check` for inspection. The updater neither reads lazyclash settings
nor modifies the Git checkout, core configuration or separately installed skills.
A new invocation of the updated binary supplies the new `--skill` automatically;
do not run `npx skills` as part of an end user's binary upgrade. v0.1.1 predates
this command and needs one `go install ...@latest` bootstrap first.
