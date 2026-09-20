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
