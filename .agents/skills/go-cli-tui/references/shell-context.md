# Shell context and consumer configuration

Read when a CLI changes the calling shell's environment, owns connections beyond
one invocation, or generates another application's configuration. An ordinary
one-shot command does not need a shell wrapper or persistent session registry.

## Parent-shell handoff

A child cannot update its parent's environment. When the product needs this,
provide a static `shell-init` emitter and narrow shell functions. Initialization
defines functions without contacting servers. Limit generated code to fixed
variable names with correctly quoted values; never eval ordinary diagnostics,
editable remote scripts, or arbitrary command output.

Separate interactive work from captured output: authenticate and prepare an owned
session in the foreground, then capture its fixed env fragment and apply it only
after success. Failed preparation retains the previous environment and session.
JSON/non-TTY calls return a structured authentication requirement without prompting.

Snapshot original values and unset-versus-empty state before the first switch;
later switches must not replace that snapshot. Restore only owned variables and
preserve unrelated exclusions. Keep existing functions and exit hooks, including
their exit status. Use a private namespace and make replacement of friendly public
names explicit. Test real Bash/zsh, nested shells, and failure paths.

A Go subprocess cannot invoke a function defined only in the parent shell. Retain
a shell subshell wrapper if an existing convenience command accepts functions and
builtins; a native `exec` command handles executable argv, stdio and child status.
Do not silently run directly on resolution failure or retry an arbitrary command
after a nonzero exit: the first attempt may already have performed a mutation.

## Connections that outlive the CLI

Do not print a usable-looking endpoint and immediately close its backing tunnel.
Choose the lifetime: one child command, a foreground session, or an explicitly
owned persistent session. In-memory authentication maps do not span invocations.
Reusing a connection does not require storing the user's password.

For an explicitly requested shell-lifetime SSH tunnel, a dedicated native master
can be appropriate when a shared user's idle policy cannot provide that lifetime.
A private `ssh -M -N -f` master with `ControlPersist=no` authenticates before
backgrounding and is stopped by its owner. This differs from short API requests
that can borrow a configured master. Preserve host/key/ProxyJump/trust policy;
never close a borrowed master or rewrite its timeout. Creating an independent
connection may prompt again. Listening forwards alone do not prevent a shared
`ControlPersist` timeout. See [ssh(1)](https://man.openbsd.org/ssh.1) and
[ssh_config(5)](https://man.openbsd.org/ssh_config.5).

A private registry stores opaque session IDs, process-generation identities,
captured control-socket identities and exact forwards, without password values.
Scope cleanup to those resources: a PID, port or path alone can be reused. Account
for Unix socket path limits, including OpenSSH's temporary creation suffix.

Prefer independent shell leases unless shared reference management is actually
needed. Nested shells must not release a parent's lease. Exit hooks cannot handle
SIGKILL; provide explicit and opportunistic stale-session cleanup. Report a dead
session as unavailable instead of silently changing routes or replaying commands.
A forwarding listener is not proof that the remote service or egress works.

## Existing owners and consumers

Build the standalone contract first; dotfile integration is a thin adapter. Do not
edit an rc file already owned by chezmoi or another manager. A missing/old binary
may keep legacy behavior, but a runtime resolver failure must not select different
guesses. Private legacy cache consumers need the same selected context as public
helpers. Consumers that print or persist raw URLs cannot implicitly receive new
credential values; use a native authenticated operation or explicit export.

Inspect existing writers before persisting generated settings. A template may
delete a section when its apply-time variable is absent. Prefer reviewable artifacts
or an explicit ownership transition over a competing configuration writer.

Endpoints belong to a consumer location. Host loopback, an SSH host, a container
and a remote builder differ. Require an explicitly reachable endpoint when evidence
cannot establish one; do not expose a loopback service on all interfaces implicitly.
An HTTPS proxy forwarded to localhost still needs its original TLS identity;
rewriting the hostname needs an appropriate bridge, not disabled verification.

Docker illustrates this: client proxy config affects new containers/builds;
registry pulls use daemon settings, and Desktop has its own proxy settings.
Runtime env files, Compose interpolation input and build arguments have different
escaping and activation semantics. See [Docker client proxy](https://docs.docker.com/engine/cli/proxy/),
[daemon proxy](https://docs.docker.com/engine/daemon/proxy/) and
[Compose interpolation](https://docs.docker.com/reference/compose-file/interpolation/).

Generate the selected artifact, with private non-overwriting output for credentials.
Test from the consumer when supported: an existing container or specified local
image with `--pull=never` avoids bootstrapping through a broken daemon network.
Container success does not prove a remote builder works.

## Verification focus

- Real Bash/zsh: snapshots, unset values, functions/traps, failure before apply,
  two shells, child exit status and no automatic replay.
- Isolated SSH daemon/keys: separate private sessions, pre-existing shared master
  survives cleanup, failed/canceled preparation and stale registry ownership.
- Structured consumer calls: no implicit pull or endpoint rewrite, correct format
  escaping, private artifacts and unchanged owner configuration.

Disposable local fixtures suffice; these checks need no production service restart.
