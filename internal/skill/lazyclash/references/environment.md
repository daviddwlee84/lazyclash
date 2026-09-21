# Proxy environments and consumer contexts

Use `proxy env --shell bash|zsh` for explicit shell output, `proxy exec -- CMD…`
for one executable, and `proxy shell-init bash|zsh` for current-shell functions.
A child executable cannot mutate its parent shell. `proxy-on` snapshots the
original values/unset state and `proxy-off` restores them; NO_PROXY is retained.
Do not promise every application honors environment variables.

Choose `--target` explicitly for automation. Without it, explicit LOCAL_PROXY_URL
is honored and local targets are preferred; ambiguity is an error in JSON mode.
The data proxy is independent of the controller URL. Do not infer the remote
proxy port from the external-controller port or fall back to another endpoint.

For SSH, shell integration creates a private persistent lease/master, completes
native authentication and forwarding before publishing env, and releases only
that shell's resources. Existing user masters stay alive. `proxy tunnel status`
and `cleanup` inspect/reap stale ownership after abnormal shell exit. JSON never
requests a password; a failed link is unavailable, not a reason to switch direct.
HTTP/SOCKS forwarding can publish loopback URLs; HTTPS proxy hostname validation
must not be disabled to make a rewritten localhost URL work.

For the reverse direction, select the locally reachable source with `--target`
or `--endpoint`, then use `proxy ssh HOST [-- COMMAND...]` or foreground
`proxy tunnel share HOST`. HOST is the consuming SSH host, not the source target.
The remote host needs no lazyclash installation. HTTP/SOCKS data endpoints without
credentials are supported; source SSH chaining and HTTPS proxy endpoints are not.
Source controller credentials remain usable and are not exported.

Remote listeners are checked for actual loopback binding before use. A server
with GatewayPorts=yes forces wildcard and will be rejected after allocation;
do not change sshd settings automatically. Fixed --remote-port and optional
--remote-socks-port are available; zero requests an allocated port. A ready
tunnel is not evidence of Internet reachability.

The default remote login shell can override proxy env through its startup files.
--clean-shell uses /bin/sh -i with ENV/BASH_ENV removed; no remote rc files are
edited. `-- COMMAND...` preserves argv/stdio/exit status without retry; proxy ssh
does not accept --json. Share --json emits one result and stays running until
canceled. Do not wait for a share process to exit before using its endpoint.
Status/stop/cleanup cover both directions. A reverse lease belongs to its local
invocation and cannot be consumed as a local proxy env session.

Before supplying an endpoint to a background service, use `proxy env --consumer
service`. It rejects known temporary SSH endpoints using local ownership records
and endpoint-bound LAZYCLASH_PROXY_ORIGIN metadata; preserve that non-secret
marker when using remote exports. It cannot identify arbitrary external tunnels
or guarantee uptime. Ordinary local endpoints remain allowed. Exit 4 /
proxy-not-configured means no local selection exists; proxy-temporary, ambiguity
and authentication failure must not silently become DIRECT or another proxy.

`proxy exec` preserves argv, stdio and exit code; it never retries the command.
The shell's `withproxy` wrapper also supports shell functions/builtins.
Status distinguishes selected configuration from reachability; `proxy test`
explicitly makes a bounded request. A response is not proof every website works.

Docker has separate consumers:

- `proxy docker render` emits env-file, Compose runtime/build mappings,
  build-args, or a client JSON snippet. It does not apply daemon changes.
- The container/builder's localhost is not the shell's host. Require the actual
  consumer endpoint, especially for remote contexts and SSH forwards.
- `proxy docker test` uses a selected existing container or already-local probe
  image. Do not pull an image just to test the daemon's currently broken proxy.
- Container success is not Buildx-node evidence. Daemon pulls and Docker Desktop
  proxy settings have their own configuration paths; follow doctor guidance.
- Custom proxy CAs/credentials require appropriate consumer configuration; don't
  assume the host's trust store or private refs exist in the container.

On the author's chezmoi setup, the shared shell adapter owns friendly proxy-*
functions and existing Docker client config remains chezmoi-owned. Legacy cache
consumers reject authenticated URLs to avoid printing/persisting credentials;
use native proxy-on/exec for such targets.
