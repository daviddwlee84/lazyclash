# Deploy a client from an existing target

`setup --from-target` creates an independent, portable snapshot of an explicitly
bound target. It copies the active nodes, groups, rules, portable DNS settings,
required provider/geodata/certificate resources, compatible manual selections,
and saved connectivity checks. It does not establish ongoing synchronization.

For Verge, the source is its native-generated active YAML, guarded together with
the active profile index, companions and owner settings. Scripts are neither
executed by lazyclash nor copied to the destination. Necessary proxy credentials
travel privately; management credentials, operating-system paths, interface/TUN
bindings, GUI caches and system-proxy state do not. The destination gets a new
controller secret and private loopback listeners.

## Preview and deploy Windows Verge

The initial Windows desktop adapter supports the official Clash Verge Rev 2.5.2
x64 release with its bundled Mihomo. The SHA-256 and size of the artifact are
pinned. Installation requires an existing administrator SSH token; application
execution uses the same user's interactive desktop session with limited
privileges. Windows OpenSSH may use PowerShell as its default shell; Python is
not required.

The computer running lazyclash needs OpenSSH 9 or newer (`ssh` and `scp`). Helper
scripts, JSON requests and large private payloads use `scp`'s default SFTP
transport, with no legacy SCP fallback or helper/request data on stdin. The
Windows receiver stages each transfer in an ACL-private directory and checks its
expected SHA-256 and size before accepting it.

```sh
lazyclash setup windows-laptop \
  --from-target local-clash-verge-rev \
  --ssh local_david_windows_laptop \
  --client verge --client-version 2.5.2 \
  --controller-port 9097 --mixed-port 7897 \
  --system-proxy --boot --json
```

Review the preview, then repeat the same command with
`--yes --expect "$REVIEWED_DIGEST"`. `--from-target` cannot be combined with
`--input` or `--input-kind`. Source changes invalidate the reviewed digest.
`--artifact FILE` can supply the exact verified release for offline transfer;
`--bootstrap-target ID` explicitly selects an existing data proxy for downloads.

Cloning from a Windows target can take several minutes while its files are
verified over SSH. Changes to the source during verification invalidate the
snapshot and require a fresh preview.

The setup wizard, also available through the TUI setup action, includes **Copy
an existing target** and **Clash Verge Rev / Background Mihomo** choices. A bound
Windows source uses `host_os = "windows"`; local secret-file references continue
to refer to the computer running lazyclash.

The bundled core is staged independently in Rule mode with TUN off, while CFW
retains its system proxy. Native `profiles.yaml`, profile companions,
`config.yaml` and `verge.yaml` are created only for a fresh owned Verge
installation. Existing unowned Verge directories are not overwritten. After
controller and explicit-proxy verification, the guarded handoff stops the
inspected CFW owner and staged core, then launches Verge into the user's desktop.
Its native-generated profile and actual proxy are verified before acknowledging
the handoff. CFW files remain available for recovery.

Verge itself changes Windows proxy settings during startup, even when its proxy
toggle is off. A GUI deployment cannot silently coexist with a different active
system-proxy/PAC owner. The initial adapter also refuses native GUI activation
when RAS/VPN connection entries would require additional per-connection recovery.
Background Mihomo remains available for explicit-proxy deployments.

Both Windows clients use an owned InteractiveToken scheduled task. `--boot`
enables its user-logon trigger. The task stores no password, runs while that user
is logged on, permits battery operation and has no default execution-time limit.
Verge's separate auto-launch setting stays off to avoid duplicate startup owners.

## Background Mihomo

Use `--client mihomo` with the pinned Windows Mihomo v1.19.31 artifact. Its task
runs the foreground core through an owned hidden launcher; the executable is not
registered directly as a Windows Service. TUN and system service scope are not
supported by this initial Windows backend.

```sh
lazyclash setup windows-background \
  --from-target local-clash-verge-rev \
  --ssh local_david_windows_laptop --client mihomo \
  --controller-port 9098 --mixed-port 7898 --boot --json
```

Choose distinct unused ports when another client is present. Omit
`--system-proxy` for a parallel explicit-proxy instance; keep one system-proxy
owner on the machine.

## Verification and recovery

Successful setup registers the destination target without changing the existing
default target. Inspect it with `targets test`, `status`, `configs source show`
and its saved connectivity checks. Owned Windows node/group/rule edits use
guarded source writes and native owner activation, followed by verification.

```sh
lazyclash --target windows-laptop status
lazyclash --target windows-laptop diagnostics checks run --all
lazyclash cores status windows-laptop
lazyclash cores resume windows-laptop
```

An interrupted deployment keeps private receipts and snapshots. `resume` first
inspects ownership and the completed stage; it does not blindly rerun an
installer. Stop/restart/remove continue to use `cores` previews with reviewed
digests. Removal preserves configuration data. Configuration snapshots are
independent: ordinary lifecycle actions must not replay later changes from the
source target or replace destination users' current selections.

The initial Windows backend supports bound node/group/rule editing, but not
whole-instance `cores configure` changes to ports, network ownership or software
versions. Deploy a separate reviewed instance for those changes.

HTTP checks establish response connectivity and expected status only. They do
not establish an authenticated Claude conversation or API entitlement.
