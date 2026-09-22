# User-scoped analytics service protocol. Request data is JSON, never shell code.
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys

MAX_BINARY = 256 << 20
MAX_CONFIG = 4 << 20
OWNER_ENV = "LAZYCLASH_ANALYTICS_OWNER"


def fail(message):
    raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def absolute(value):
    if not isinstance(value, str) or not value.startswith("/") or any(ord(c) < 32 for c in value):
        fail("Analytics service paths must be absolute and contain no control characters")
    return pathlib.Path(os.path.normpath(value))


def safe_parents(path):
    # Require canonical paths, including when a caller chooses a macOS temp
    # directory through the system /var or /tmp aliases.
    for part in [path, *path.parents]:
        if part == pathlib.Path("/"):
            continue
        if os.path.lexists(part):
            info = os.lstat(part)
            if stat.S_ISLNK(info.st_mode):
                fail("Analytics managed path contains a symbolic link")
            if part != path and not stat.S_ISDIR(info.st_mode):
                fail("Analytics managed parent is not a directory")


def read_regular(path, limit, private=False):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        fail("Analytics service requires a bounded ordinary file")
    if private and (before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077):
        fail("Analytics configuration and ownership files must be private and owned by the current user")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
    fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_uid, stat.S_IMODE(s.st_mode))
    if len(data) > limit or fields(before) != fields(after):
        fail("Analytics service source changed while reading")
    return data


def private_dir(path, create=False):
    if not path.exists():
        if not create:
            return
        if not path.parent.exists():
            private_dir(path.parent, True)
        path.mkdir(mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        fail("Analytics state and service directories must already be private and owned by the current user")


def ensure_parent(path):
    # Existing normal user configuration directories need not be private; never
    # chmod them. Newly created ancestors are private.
    safe_parents(path)
    missing = []
    part = path
    while not part.exists():
        missing.append(part)
        part = part.parent
    for part in reversed(missing):
        part.mkdir(mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        fail("Analytics unit directory must be owned by the current user and not writable by others")


def exclusive(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def command(args, required=False):
    # Fixed, bounded service-manager queries; stderr is intentionally not echoed.
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        if required:
            fail("Analytics user service command is unavailable or timed out")
        return None
    if len(p.stdout) > 256 << 10:
        fail("Analytics user service command exceeded the output limit")
    if p.returncode != 0:
        if required:
            fail("Analytics user service command failed; inspect collector health and the user service manager")
        return None
    return p.stdout.decode("utf-8", "replace")


def platform_name():
    return {"Linux": "linux", "Darwin": "darwin"}.get(platform.system(), "unsupported")


def architecture():
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine(), "unsupported")


def binary_compatible(data, system):
    arch = architecture()
    if system == "linux" and len(data) >= 20 and data[:4] == b"\x7fELF":
        if data[4] != 2 or data[5] not in (1, 2):
            return False
        machine = struct.unpack(("<" if data[5] == 1 else ">") + "H", data[18:20])[0]
        return machine == {"amd64": 62, "arm64": 183}.get(arch)
    if system == "darwin" and len(data) >= 8:
        magic = data[:4]
        wanted = {"amd64": 0x01000007, "arm64": 0x0100000C}.get(arch)
        if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            return struct.unpack(("<" if magic[0] == 0xcf else ">") + "I", data[4:8])[0] == wanted
        if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            count = struct.unpack(">I", data[4:8])[0]
            stride = 32 if magic[-1] == 0xbf else 20
            if count > 16 or len(data) < 8 + count * stride:
                return False
            return any(struct.unpack(">I", data[8+i*stride:12+i*stride])[0] == wanted for i in range(count))
    return False


def context(request):
    state = absolute(request["state_dir"])
    safe_parents(state)
    private_dir(state)
    root = state / "service"
    safe_parents(root)
    private_dir(root)
    system = platform_name()
    identity = sha(str(state).encode())[:12]
    home = pathlib.Path(os.path.realpath(os.path.expanduser("~")))
    if system == "darwin":
        service = "io.lazyclash.analytics." + identity
        unit = home / "Library" / "LaunchAgents" / (service + ".plist")
    else:
        service = "lazyclash-analytics-" + identity + ".service"
        unit = home / ".config" / "systemd" / "user" / service
    safe_parents(unit)
    return {"state": state, "root": root, "system": system, "service": service, "unit": unit,
            "binary": root / "lazyclash", "manifest": root / "manifest.json", "owner": root / "owner-token"}


def manager_state(c):
    system, service = c["system"], c["service"]
    result = {"available": False, "loaded": False, "running": False, "enabled": False,
              "session_dependent": True, "live_guard": {}, "details": []}
    if os.geteuid() == 0:
        result["details"].append("User collector services are unavailable as root; select an ordinary user session")
        return result
    if system == "linux":
        if not shutil.which("systemctl"):
            result["details"].append("systemctl is unavailable; use foreground collect or an existing supported user service manager")
            return result
        prefix = ["systemctl", "--user", "--no-pager"]
        result["available"] = command(prefix + ["show-environment"]) is not None
        linger = command(["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"])
        result["session_dependent"] = (linger or "").strip() != "yes"
        if not result["available"]:
            result["details"].append("The systemd user manager is unavailable in this session; no linger or session settings will be changed")
            return result
        raw = command(prefix + ["show", service, "--property=LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,Environment"])
        props = dict(line.split("=", 1) for line in (raw or "").splitlines() if "=" in line)
        result["loaded"] = props.get("LoadState") == "loaded"
        result["running"] = props.get("ActiveState") in ("active", "activating", "reloading")
        result["enabled"] = props.get("UnitFileState") in ("enabled", "enabled-runtime")
        result["live_guard"] = {k: props.get(k, "") for k in ("FragmentPath", "DropInPaths", "NeedDaemonReload", "Environment")}
        if result["session_dependent"]:
            result["details"].append("Linux user collection depends on a live login session because linger is disabled or unknown")
    elif system == "darwin":
        domain = "gui/" + str(os.getuid())
        result["available"] = command(["launchctl", "print", domain]) is not None
        if not result["available"]:
            result["details"].append("The macOS GUI login session is unavailable; a LaunchAgent requires that user to be logged in")
            return result
        raw = command(["launchctl", "print", domain + "/" + service])
        result["loaded"] = raw is not None
        result["running"] = bool(raw and re.search(r"^\s*state = running\s*$", raw, re.M))
        result["enabled"] = os.path.lexists(c["unit"])
        # Keep only identity-related fields, not potentially sensitive launchd output.
        for key in ("path", "program"):
            match = re.search(r"^\s*" + key + r" = (.*?)\s*$", raw or "", re.M)
            result["live_guard"][key] = match.group(1) if match else ""
        match = re.search(r"^\s*" + OWNER_ENV + r" => ([a-f0-9]+)\s*$", raw or "", re.M)
        result["live_guard"]["owner"] = match.group(1) if match else ""
        result["details"].append("macOS LaunchAgent collection runs only during this user's GUI login session; sleep and logout create collection gaps")
    else:
        result["details"].append("Analytics user services support Linux systemd and macOS LaunchAgents")
    return result


def artifacts(c, config, token):
    argv = [str(c["binary"]), "analytics", "--analytics-config", config, "--state-dir", str(c["state"]), "collect"]
    if c["system"] == "darwin":
        return plistlib.dumps({"Label": c["service"], "ProgramArguments": argv, "RunAtLoad": True,
                              "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 10,
                              "Umask": 0o077, "EnvironmentVariables": {OWNER_ENV: token},
                              "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}, sort_keys=True)
    # systemd expands percent specifiers and dollar variables even inside quotes.
    def quote(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
    return ("# lazyclash analytics owner " + token + "\n[Unit]\nDescription=LazyClash analytics collector\n"
            "[Service]\nType=simple\nExecStart=" + " ".join(quote(v) for v in argv) +
            "\nEnvironment=" + OWNER_ENV + "=" + token + "\nUMask=0077\nRestart=on-failure\nRestartSec=10\n"
            "StandardOutput=null\nStandardError=null\nNoNewPrivileges=true\n"
            "[Install]\nWantedBy=default.target\n").encode()


def verify_owned(c, live):
    paths = [c["manifest"], c["owner"], c["binary"], c["unit"]]
    any_present = any(os.path.lexists(p) for p in paths)
    if not any_present:
        if live["loaded"]:
            fail("An unowned service already uses this analytics service name")
        return None
    if not all(os.path.lexists(p) for p in paths):
        fail("Analytics service ownership is incomplete; refusing to adopt or remove partial artifacts")
    info = json.loads(read_regular(c["manifest"], 64 << 10, True))
    token = read_regular(c["owner"], 128, True).decode().strip()
    if not re.fullmatch("[a-f0-9]{32}", token) or info.get("owner_token") != token or info.get("version") != 1:
        fail("Analytics service ownership token does not match")
    expected = {"state_dir": str(c["state"]), "executable": str(c["binary"]), "unit_path": str(c["unit"]), "service": c["service"]}
    if any(info.get(k) != v for k, v in expected.items()):
        fail("Analytics service ownership paths do not match")
    config = str(absolute(info.get("config_path")))
    binary = read_regular(c["binary"], MAX_BINARY, True)
    unit = read_regular(c["unit"], 64 << 10, True)
    if sha(binary) != info.get("binary_sha256") or sha(unit) != info.get("unit_sha256") or unit != artifacts(c, config, token):
        fail("Analytics service binary or definition has changed; refusing lifecycle changes")
    if not os.access(c["binary"], os.X_OK):
        fail("Analytics service binary is no longer executable")
    guard = live["live_guard"]
    if live["loaded"]:
        if c["system"] == "linux":
            if guard.get("FragmentPath") != str(c["unit"]) or guard.get("DropInPaths") or guard.get("NeedDaemonReload") == "yes" or (OWNER_ENV + "=" + token) not in guard.get("Environment", "").split():
                fail("Loaded analytics service identity differs from its owned definition")
        elif guard != {"path": str(c["unit"]), "program": str(c["binary"]), "owner": token}:
            fail("Loaded analytics LaunchAgent identity differs from its owned definition")
    return info


def inspect(request, c):
    live = manager_state(c)
    result = {"action": request["action"], "platform": c["system"],
              "manager": "launchd" if c["system"] == "darwin" else "systemd-user",
              "service": c["service"], "state_dir": str(c["state"]), "unit_path": str(c["unit"]),
              "executable": str(c["binary"]), "available": live["available"], "loaded": live["loaded"],
              "running": live["running"], "enabled": live["enabled"], "session_dependent": live["session_dependent"],
              "installed": False, "owned": False, "drifted": False, "changed": False,
              "preview": request["action"] != "status" and not request.get("apply"), "details": live["details"]}
    try:
        info = verify_owned(c, live)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        result["drifted"] = True
        result["details"].append(str(error) if isinstance(error, ValueError) else "Analytics ownership artifacts cannot be verified")
        info = None
    result["installed"] = info is not None
    result["owned"] = info is not None
    if info:
        result["config_path"] = info["config_path"]
        if request.get("config_path") and str(absolute(request["config_path"])) != info["config_path"]:
            fail("Requested config path differs from the installed analytics service")
    guard = {"action": request["action"], "uid": os.getuid(), "system": c["system"], "arch": architecture(),
             "state_dir": str(c["state"]), "service": c["service"], "unit_path": str(c["unit"]),
             "live": live, "manifest": info, "drifted": result["drifted"]}
    source = None
    if request["action"] == "install" and not info and not result["drifted"]:
        config = absolute(request["config_path"])
        safe_parents(config)
        config_raw = read_regular(config, MAX_CONFIG, True)
        executable = absolute(request["executable"])
        # Source executable aliases are accepted, but copied managed artifacts
        # and all private/config paths must be ordinary, non-symlink paths.
        executable = pathlib.Path(os.path.realpath(executable))
        binary = read_regular(executable, MAX_BINARY)
        st = os.stat(executable)
        if st.st_mode & 0o022 or not os.access(executable, os.X_OK):
            fail("Analytics source executable must be executable and not writable by other users")
        if not binary_compatible(binary, c["system"]):
            fail("Analytics executable does not match the selected host OS and architecture; select an already-installed host binary")
        help_text = command([str(executable), "analytics", "--help"])
        if not help_text or "collect" not in help_text or "--analytics-config" not in help_text:
            fail("Selected host executable does not expose the analytics collector command; install a compatible lazyclash build first")
        if config in (c["manifest"], c["owner"], c["binary"], c["unit"]):
            fail("Analytics configuration overlaps a managed service artifact")
        result["config_path"] = str(config)
        guard.update(source_path=str(executable), source_sha256=sha(binary), config_path=str(config), config_sha256=sha(config_raw))
        source = binary
    elif request["action"] == "start" and info:
        config = absolute(info["config_path"])
        safe_parents(config)
        guard["config_sha256"] = sha(read_regular(config, MAX_CONFIG, True))
    result["digest"] = sha(canonical(guard)) if request["action"] != "status" else ""
    if request["action"] == "install":
        result["details"].append("Install a private binary and user service definition; enable login autostart without starting now; keep using the caller's private config")
    elif request["action"] == "remove":
        result["details"].append("Stop and unregister only this owned collector; preserve configuration, analytics data, and collector health")
    elif request["action"] == "stop":
        result["details"].append("Stop this collector; its definition remains available for explicit start and future login autostart")
    result["details"].append("Service stdout/stderr are discarded to avoid unbounded logs; inspect persistent collector health for diagnostics")
    return result, info, source


def install(c, result, source):
    token = secrets.token_hex(16)
    unit = artifacts(c, result["config_path"], token)
    manifest = {"version": 1, "owner_token": token, "state_dir": str(c["state"]),
                "executable": str(c["binary"]), "config_path": result["config_path"],
                "unit_path": str(c["unit"]), "service": c["service"],
                "binary_sha256": sha(source), "unit_sha256": sha(unit)}
    private_dir(c["root"], True)
    ensure_parent(c["unit"].parent)
    # Exclusive creation will never replace a pre-existing service or artifact.
    # A failure retains the partial installation for explicit inspection.
    exclusive(c["owner"], (token + "\n").encode(), 0o600)
    exclusive(c["binary"], source, 0o700)
    exclusive(c["unit"], unit, 0o600)
    exclusive(c["manifest"], canonical(manifest), 0o600)
    if c["system"] == "linux":
        command(["systemctl", "--user", "daemon-reload"], True)
        command(["systemctl", "--user", "enable", c["service"]], True)


def mutate(request, c, result, info, source):
    action = request["action"]
    if action == "install":
        if info:
            return False
        install(c, result, source)
        return True
    if not info:
        if action in ("remove", "stop"):
            return False
        fail("Install this analytics user service before starting it")
    if c["system"] == "linux":
        prefix = ["systemctl", "--user"]
        if action == "start":
            if result["running"]:
                return False
            command(prefix + ["start", c["service"]], True)
        elif action == "stop":
            if not result["running"]:
                return False
            command(prefix + ["stop", c["service"]], True)
        else:
            command(prefix + ["stop", c["service"]], True)
            command(prefix + ["disable", c["service"]], True)
    else:
        domain = "gui/" + str(os.getuid())
        if action == "start":
            if result["running"]:
                return False
            if not result["loaded"]:
                command(["launchctl", "bootstrap", domain, str(c["unit"])], True)
            else:
                command(["launchctl", "kickstart", domain + "/" + c["service"]], True)
        elif result["loaded"]:
            command(["launchctl", "bootout", domain, str(c["unit"])], True)
        elif action == "stop":
            return False
    if action == "remove":
        # Never recursively delete: unknown files, config, SQLite and health stay.
        for path in (c["unit"], c["binary"], c["manifest"], c["owner"]):
            path.unlink()
        if c["system"] == "linux":
            command(["systemctl", "--user", "daemon-reload"], True)
        try:
            c["root"].rmdir()
        except OSError:
            pass
    return True


def main(request):
    if request.get("action") not in ("status", "install", "start", "stop", "remove"):
        fail("Unsupported analytics service action")
    c = context(request)
    result, info, source = inspect(request, c)
    if not request.get("apply"):
        return result
    if result["drifted"]:
        fail("Analytics service ownership drift prevents changes; inspect the existing artifacts")
    if not result["available"]:
        fail("A supported ordinary-user service session is required; no session or permission settings will be changed")
    if result["digest"] != request.get("expect"):
        fail("Analytics service state changed; review a fresh preview")
    private_dir(c["state"], True)
    lock = c["state"] / "service.lock"
    if os.path.lexists(lock):
        read_regular(lock, 128, True)
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Another analytics service lifecycle operation is running")
        result, info, source = inspect(request, c)
        if result["drifted"] or result["digest"] != request.get("expect"):
            fail("Analytics service state changed; review a fresh preview")
        changed = mutate(request, c, result, info, source)
        # Query resulting state with status semantics: removed sources need not
        # exist and installation input should not be reread after mutation.
        after_request = {"action": "status", "state_dir": str(c["state"])}
        after, _, _ = inspect(after_request, c)
        after.update(action=request["action"], preview=False, changed=changed, digest=result["digest"])
        return after
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        print(json.dumps(main(json.load(sys.stdin))))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        message = str(error) if isinstance(error, ValueError) else "Analytics service inspection or operation failed; no privileges or network settings were changed"
        print(json.dumps({"error": message}))
