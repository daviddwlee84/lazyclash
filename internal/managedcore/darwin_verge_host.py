# Fixed macOS Clash Verge Rev host protocol 1. Request data is JSON only; no
# user-supplied program is executed. YAML is rendered by the controller, so this
# helper never parses configuration and needs only the system python3.
import base64, hashlib, json, os, pathlib, platform, plistlib, pwd, re, shutil, socket, stat, subprocess, sys, tempfile, time

APP = "/Applications/Clash Verge.app"
BUNDLE_ID = "io.github.clash-verge-rev.clash-verge-rev"
SERVICE_LABEL = BUNDLE_ID + ".service"
SERVICE_PLIST = "/Library/LaunchDaemons/" + SERVICE_LABEL + ".plist"
STATE_BASE = "/Library/Application Support/lazyclash/verge"
CFW_APP = "/Applications/Clash for Windows.app"
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
NONCE = re.compile(r"^[a-f0-9]{32}$")
HEX = re.compile(r"^[a-f0-9]{64}$")
VERSION = "2.5.2"
MAX_DMG = 96 << 20
MAX_PAYLOAD = 192 << 20
DEFAULT_DEADLINE = 180


def fail(message):
    raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, timeout=30, ok=False, user=None, env=None, capture=True):
    """Run one fixed argv. As root, `user` executes inside that user's GUI
    bootstrap namespace so AppleScript/LaunchServices reach the console session."""
    if user is not None and os.geteuid() == 0:
        args = ["/bin/launchctl", "asuser", str(user.pw_uid), "/usr/bin/sudo", "-u", user.pw_name, "--"] + list(args)
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        if ok:
            return None
        fail("required host command is missing or timed out: " + os.path.basename(args[0]))
    if result.returncode != 0 and not ok:
        fail("host command failed: " + os.path.basename(args[0]))
    return result


def output(args, timeout=30, user=None):
    result = run(args, timeout=timeout, ok=True, user=user)
    if result is None or result.returncode != 0:
        return ""
    return result.stdout.decode("utf-8", "replace")


def atomic(path, data, mode=0o600, owner=None):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(os.lstat(path).st_mode)):
        fail("refusing to replace a non-regular file")
    fd, temporary = tempfile.mkstemp(prefix=".lazyclash-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, owner.pw_uid, owner.pw_gid)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_private(path, uid, limit):
    """Open a user-staged transfer without following links and hash the exact
    bytes that will be used; the path cannot be swapped after verification."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > limit or stat.S_IMODE(info.st_mode) & 0o077:
            fail("staged transfer ownership, mode or size is invalid")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                fail("staged transfer exceeds its limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def invoking_user():
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    return pwd.getpwuid(uid)


def console_user():
    try:
        info = os.stat("/dev/console")
        return pwd.getpwuid(info.st_uid).pw_name
    except (OSError, KeyError):
        return ""


def data_dir(user):
    return pathlib.Path(user.pw_dir) / "Library/Application Support" / BUNDLE_ID


def transfer_dir(user, request):
    if not ID.match(request.get("id", "")) or not NONCE.match(request.get("transfer_id", "")):
        fail("invalid transfer reference")
    return pathlib.Path(user.pw_dir) / ".cache/lazyclash/managed-transfers" / (request["id"] + "-" + request["transfer_id"])


def state_dir(request):
    if not ID.match(request.get("id", "")):
        fail("invalid managed ID")
    return pathlib.Path(STATE_BASE) / request["id"]


def port_busy(port):
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.3)
                if probe.connect_ex((address, port)) == 0:
                    return True
        except OSError:
            pass
    return False


def processes():
    rows = []
    for line in output(["/bin/ps", "-axo", "pid=,uid=,command="], timeout=10).splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            rows.append({"pid": int(parts[0]), "uid": int(parts[1]), "command": parts[2]})
    return rows


def verge_processes():
    prefix = APP + "/Contents/MacOS/"
    return [p for p in processes() if p["command"].startswith(prefix)]


def verge_gui_running():
    return any(p["command"].startswith(APP + "/Contents/MacOS/clash-verge") for p in processes())


def load_plist(path, raw):
    # launchd accepts some plists (e.g. CFW's helper) that expat rejects.
    try:
        return plistlib.loads(raw)
    except Exception:
        text = output(["/usr/bin/plutil", "-convert", "json", "-o", "-", str(path)], timeout=10)
        try:
            return json.loads(text) if text else None
        except ValueError:
            return None


def cfw_match(program):
    return program.startswith(CFW_APP + "/") or "/.config/clash/service/" in program


def cfw_facts():
    """Record CFW identities only: app processes, root jobs whose executable is
    CFW-owned, and the LaunchDaemon plists that define them. Nothing is changed."""
    apps = [p for p in processes() if p["command"].startswith(CFW_APP + "/Contents/MacOS/")]
    daemons = []
    base = pathlib.Path("/Library/LaunchDaemons")
    for plist in sorted(base.glob("*.plist")) if base.is_dir() else []:
        try:
            raw = plist.read_bytes()
        except OSError:
            continue
        document = load_plist(plist, raw)
        if document is None:
            continue
        label = str(document.get("Label", ""))
        program = str(document.get("Program") or (document.get("ProgramArguments") or [""])[0])
        if label.startswith("com.lbyczf.cfw") or cfw_match(program):
            daemons.append({"label": label, "plist": str(plist), "sha256": digest(raw), "program": program})
    jobs = []
    if os.geteuid() == 0:
        by_pid = {p["pid"]: p for p in processes()}
        for line in output(["/bin/launchctl", "list"], timeout=10).splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) == 3 and parts[0].strip().isdigit():
                proc = by_pid.get(int(parts[0]))
                if proc and cfw_match(proc["command"]) and not any(d["label"] == parts[2] for d in daemons):
                    jobs.append({"label": parts[2], "program": proc["command"].split(" ")[0]})
    return {"apps": apps, "daemons": daemons, "jobs": jobs, "running": bool(apps)}


def sudo_noninteractive():
    if os.geteuid() == 0:
        return True
    result = run(["/usr/bin/sudo", "-n", "/usr/bin/true"], timeout=10, ok=True)
    return result is not None and result.returncode == 0


def facts(request):
    user = invoking_user()
    ports = [int(p) for p in request.get("ports", [])]
    home = user.pw_dir
    result = {
        "os": platform.system().lower(), "arch": {"x86_64": "amd64", "arm64": "arm64"}.get(platform.machine(), platform.machine()),
        "home": home, "uid": user.pw_uid, "user": user.pw_name, "console_user": console_user(),
        "busy_ports": [p for p in ports if port_busy(p)], "launchd": os.path.exists("/bin/launchctl"),
        "app_existing": os.path.exists(APP), "service_existing": os.path.exists(SERVICE_PLIST),
        "data_dir": str(data_dir(user)), "data_dir_existing": data_dir(user).exists(),
        "existing": state_dir(request).exists(), "hdiutil": os.path.exists("/usr/bin/hdiutil"),
        "sudo_noninteractive": sudo_noninteractive(),
        "macos_version": platform.mac_ver()[0],
    }
    cfw = cfw_facts()
    result["cfw_running"] = cfw["running"]
    result["cfw_daemons"] = [d["label"] for d in cfw["daemons"]]
    public = dict(result)
    public["state_digest"] = digest(json.dumps({k: v for k, v in result.items() if k != "busy_ports"}, sort_keys=True).encode())
    return {"facts": public, "status": "ok"}


def prepare_transfer(request):
    user = invoking_user()
    directory = transfer_dir(user, request)
    parent = directory.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for item in (parent.parent, parent):
        info = os.lstat(item)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != user.pw_uid:
            fail("transfer directory ownership is unsafe")
    os.chmod(parent, 0o700)
    if directory.exists():
        fail("transfer directory already exists")
    directory.mkdir(mode=0o700)
    return {"status": "prepared", "transfer_path": str(directory)}


def cleanup_transfer(request):
    user = invoking_user()
    directory = transfer_dir(user, request)
    if directory.is_dir() and not directory.is_symlink() and os.lstat(directory).st_uid == user.pw_uid:
        shutil.rmtree(directory, ignore_errors=True)
    return {"status": "cleaned"}


# ---- privileged state ---------------------------------------------------

def load_manifest(request, owner=True):
    path = state_dir(request) / "instance.json"
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        fail("managed Verge manifest ownership is invalid")
    raw = path.read_bytes()
    manifest = json.loads(raw)
    if owner and manifest.get("owner_hash") != digest(request.get("owner_token", "").encode()):
        fail("managed Verge owner token differs")
    if request.get("expected") and digest(raw) != request["expected"]:
        fail("managed Verge state changed since review")
    return manifest


def save_manifest(request, manifest):
    directory = state_dir(request)
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(directory, 0o755)
    raw = json.dumps(manifest, sort_keys=True, indent=1).encode()
    atomic(directory / "instance.json", raw, 0o644)
    return digest(raw)


def require_root():
    if os.geteuid() != 0:
        fail("this operation requires administrator privileges")


def network_services():
    names = []
    for line in output(["/usr/sbin/networksetup", "-listallnetworkservices"], timeout=15).splitlines()[1:]:
        line = line.strip()
        if line and not line.startswith("*"):
            names.append(line)
    return names


def parse_proxy(text):
    values = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip().lower()] = value.strip()
    return {"enabled": values.get("enabled", "No") == "Yes", "server": values.get("server", ""), "port": values.get("port", "0")}


def proxy_snapshot():
    snapshot = {}
    for service in network_services():
        entry = {}
        for kind in ("webproxy", "securewebproxy", "socksfirewallproxy"):
            entry[kind] = parse_proxy(output(["/usr/sbin/networksetup", "-get" + kind, service], timeout=10))
        auto = output(["/usr/sbin/networksetup", "-getautoproxyurl", service], timeout=10)
        url = re.search(r"^URL:\s*(.*)$", auto, re.M)
        entry["autoproxy"] = {"url": url.group(1).strip() if url else "", "enabled": bool(re.search(r"^Enabled:\s*Yes", auto, re.M))}
        bypass = output(["/usr/sbin/networksetup", "-getproxybypassdomains", service], timeout=10).splitlines()
        entry["bypass"] = [] if bypass and bypass[0].startswith("There aren't") else [b.strip() for b in bypass if b.strip()]
        snapshot[service] = entry
    return snapshot


def restore_proxy(snapshot, errors):
    for service, entry in (snapshot or {}).items():
        for kind in ("webproxy", "securewebproxy", "socksfirewallproxy"):
            value = entry.get(kind) or {}
            if value.get("server"):
                run(["/usr/sbin/networksetup", "-set" + kind, service, value["server"], str(value.get("port") or "0")], timeout=15, ok=True)
            if run(["/usr/sbin/networksetup", "-set" + kind + "state", service, "on" if value.get("enabled") else "off"], timeout=15, ok=True) is None:
                errors.append("proxy:" + service)
        auto = entry.get("autoproxy") or {}
        if auto.get("url") and auto["url"] != "(null)":
            run(["/usr/sbin/networksetup", "-setautoproxyurl", service, auto["url"]], timeout=15, ok=True)
        run(["/usr/sbin/networksetup", "-setautoproxystate", service, "on" if auto.get("enabled") else "off"], timeout=15, ok=True)
        run(["/usr/sbin/networksetup", "-setproxybypassdomains", service] + (entry.get("bypass") or ["Empty"]), timeout=15, ok=True)


def terminate(match, grace=8):
    """SIGTERM matching processes, then SIGKILL survivors. AppleScript quit is
    not used: from an SSH session it can block on an unseen Automation prompt."""
    targets = [p["pid"] for p in processes() if match(p)]
    for pid in targets:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    deadline = time.time() + grace
    while time.time() < deadline and any(p["pid"] in targets for p in processes()):
        time.sleep(0.25)
    for proc in processes():
        if proc["pid"] in targets:
            try:
                os.kill(proc["pid"], 9)
            except OSError:
                pass
    time.sleep(0.5)
    return not any(match(p) for p in processes())


def quit_verge(user, errors=None):
    gui = lambda p: p["command"].startswith(APP + "/Contents/MacOS/clash-verge")
    stopped = terminate(gui)
    terminate(lambda p: p["command"].startswith(APP + "/Contents/MacOS/") and p["uid"] == user.pw_uid, grace=4)
    if not stopped and errors is not None:
        errors.append("verge-quit")


def launch_verge(user):
    run(["/usr/bin/open", "-g", "-a", APP], timeout=20, ok=True, user=user)
    for _ in range(80):
        if verge_gui_running():
            return True
        time.sleep(0.25)
    return False


def write_verge_settings(manifest, user, which):
    data = base64.b64decode(manifest["verge_" + which])
    atomic(pathlib.Path(manifest["data_dir"]) / "verge.yaml", data, 0o644, owner=user)


def stop_cfw(manifest, user, errors):
    cfw = manifest.get("cfw") or {}
    recorded = {p["pid"] for p in cfw.get("apps", [])}
    terminate(lambda p: p["command"].startswith(CFW_APP + "/Contents/MacOS/") and (p["pid"] in recorded or p["uid"] == user.pw_uid))
    for job in cfw.get("daemons", []) + cfw.get("jobs", []):
        run(["/bin/launchctl", "bootout", "system/" + job["label"]], timeout=20, ok=True)
        run(["/bin/launchctl", "disable", "system/" + job["label"]], timeout=10, ok=True)
    terminate(lambda p: p["uid"] == 0 and cfw_match(p["command"]))
    if cfw.get("login_item"):
        if run(["/usr/bin/osascript", "-e", 'tell application "System Events" to delete login item "Clash for Windows"'], timeout=8, ok=True, user=user) is None:
            errors.append("cfw-login-item")
    if any(cfw_match(p["command"]) for p in processes()):
        errors.append("cfw-still-running")
    manifest["cfw_stopped"] = True


def restore_cfw(manifest, user, errors):
    cfw = manifest.get("cfw") or {}
    if not manifest.get("cfw_stopped"):
        return
    for job in cfw.get("daemons", []):
        run(["/bin/launchctl", "enable", "system/" + job["label"]], timeout=10, ok=True)
        try:
            raw = pathlib.Path(job["plist"]).read_bytes()
        except OSError:
            errors.append("cfw-plist-missing:" + job["label"])
            continue
        if digest(raw) != job["sha256"]:
            errors.append("cfw-plist-changed:" + job["label"])
            continue
        run(["/bin/launchctl", "bootstrap", "system", job["plist"]], timeout=20, ok=True)
    for job in cfw.get("jobs", []):
        run(["/bin/launchctl", "enable", "system/" + job["label"]], timeout=10, ok=True)
    if cfw.get("running") and os.path.isdir(CFW_APP):
        run(["/usr/bin/open", "-g", "-a", CFW_APP], timeout=20, ok=True, user=user)
    if cfw.get("login_item"):
        run(["/usr/bin/osascript", "-e", 'tell application "System Events" to make login item at end with properties {path:"' + CFW_APP + '", hidden:true}'], timeout=15, ok=True, user=user)
    manifest["cfw_stopped"] = False


def watchdog_label(request):
    return "io.lazyclash.verge-rollback." + request["id"]


def watchdog_plist(request):
    return pathlib.Path("/Library/LaunchDaemons") / (watchdog_label(request) + ".plist")


def arm_watchdog(request, manifest, seconds):
    """A root launchd job survives SSH loss and reboot. Without an ACK before
    the deadline it returns TUN/system proxy and CFW to their recorded state."""
    directory = state_dir(request)
    token = base64.b32encode(os.urandom(20)).decode().rstrip("=").lower()
    deadline = int(time.time()) + int(seconds)
    helper = directory / "watchdog.py"
    atomic(helper, SELF.encode(), 0o644)
    atomic(directory / "guard.json", json.dumps({"deadline": deadline, "ack_hash": digest(token.encode()), "label": watchdog_label(request)}).encode(), 0o600)
    plist = plistlib.dumps({"Label": watchdog_label(request), "ProgramArguments": ["/usr/bin/python3", "-I", str(helper), "--watchdog", request["id"]], "StartInterval": 10, "RunAtLoad": True, "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"})
    path = watchdog_plist(request)
    run(["/bin/launchctl", "bootout", "system/" + watchdog_label(request)], timeout=15, ok=True)
    atomic(path, plist, 0o644)
    run(["/bin/launchctl", "bootstrap", "system", str(path)], timeout=20)
    manifest["rollback_deadline"] = deadline
    return token, deadline


def disarm_watchdog(request):
    path = watchdog_plist(request)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    guard = state_dir(request) / "guard.json"
    try:
        guard.unlink()
    except FileNotFoundError:
        pass
    run(["/bin/launchctl", "bootout", "system/" + watchdog_label(request)], timeout=15, ok=True)


def rollback(request, manifest):
    user = pwd.getpwnam(manifest["user"])
    errors = []
    quit_verge(user, errors)
    try:
        write_verge_settings(manifest, user, "staged")
    except Exception:
        errors.append("verge-settings")
    restore_proxy(manifest.get("proxy_snapshot"), errors)
    dns = pathlib.Path(APP) / "Contents/Resources/resources"
    if (dns / ".original_dns.txt").exists() and (dns / "unset_dns.sh").exists():
        run(["/bin/bash", str(dns / "unset_dns.sh")], timeout=30, ok=True)
    restore_cfw(manifest, user, errors)
    manifest["phase"] = "rolled_back"
    manifest["restore_incomplete"] = errors
    manifest.pop("rollback_deadline", None)
    return errors


def watchdog_tick(identifier):
    request = {"id": identifier}
    guard_path = state_dir(request) / "guard.json"
    if not guard_path.exists():
        disarm_watchdog(request)
        return
    guard = json.loads(guard_path.read_text())
    if time.time() < guard["deadline"]:
        return
    manifest = load_manifest(request, owner=False)
    rollback(request, manifest)
    save_manifest(request, manifest)
    disarm_watchdog(request)


# ---- operations -----------------------------------------------------------

def privilege_check(request):
    require_root()
    return {"status": "privileged"}


def install(request):
    require_root()
    user = invoking_user()
    if user.pw_uid == 0:
        fail("run setup as the desktop user, not root")
    if console_user() != user.pw_name:
        fail("the SSH user must own the active macOS console session")
    directory = state_dir(request)
    if directory.exists():
        fail("managed Verge state already exists; inspect it instead of reinstalling")
    if os.path.exists(APP) or os.path.exists(SERVICE_PLIST):
        fail("an existing Verge app or service is not owned by this instance")
    transfer = transfer_dir(user, request)
    dmg = read_private(str(transfer / "verge.dmg"), user.pw_uid, MAX_DMG)
    if digest(dmg) != request.get("dmg_sha256") or len(dmg) != request.get("dmg_size"):
        fail("Verge disk image differs from the reviewed release")
    payload_raw = read_private(str(transfer / "payload.json"), user.pw_uid, MAX_PAYLOAD)
    if digest(payload_raw) != request.get("payload_sha256"):
        fail("Verge payload differs from the reviewed plan")
    payload = json.loads(payload_raw)
    files = {name: base64.b64decode(value) for name, value in payload["files"].items()}
    for name in files:
        parts = pathlib.PurePosixPath(name).parts
        if not parts or name.startswith("/") or ".." in parts or any(p.startswith(".") for p in parts) or len(parts) > 2 or (len(parts) == 2 and parts[0] != "profiles"):
            fail("payload contains an unsafe data-directory path")
    snapshot = proxy_snapshot()
    cfw = cfw_facts()
    login = output(["/usr/bin/osascript", "-e", 'tell application "System Events" to get the name of every login item'], timeout=8, user=user)
    cfw["login_item"] = "Clash for Windows" in login
    manifest = {"id": request["id"], "owner_hash": digest(request["owner_token"].encode()), "phase": "installing", "user": user.pw_name, "uid": user.pw_uid, "app": APP, "data_dir": str(data_dir(user)), "cfw": cfw, "cfw_stopped": False, "proxy_snapshot": snapshot, "verge_staged": payload["verge_staged"], "verge_final": payload["verge_final"], "created": int(time.time()), "controller_port": request["controller_port"], "mixed_port": request["mixed_port"]}
    save_manifest(request, manifest)
    work = directory / "staging"
    work.mkdir(mode=0o700)
    image = work / "verge.dmg"
    atomic(image, dmg, 0o600)
    mount = work / "mnt"
    mount.mkdir(mode=0o700)
    nonce = request["transfer_id"][:12]
    temporary_app = pathlib.Path("/Applications/.Clash Verge.app.lazyclash-" + nonce)
    run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", str(mount), str(image)], timeout=120)
    try:
        source = mount / "Clash Verge.app"
        if not source.is_dir() or source.is_symlink():
            fail("disk image does not contain Clash Verge.app")
        run(["/usr/bin/ditto", str(source), str(temporary_app)], timeout=300)
    finally:
        run(["/usr/bin/hdiutil", "detach", str(mount), "-force"], timeout=60, ok=True)
    info = plistlib.loads((temporary_app / "Contents/Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != BUNDLE_ID or info.get("CFBundleShortVersionString") != VERSION:
        shutil.rmtree(temporary_app, ignore_errors=True)
        fail("installed bundle identity or version differs from the reviewed release")
    signed = run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(temporary_app)], timeout=180, ok=True)
    manifest["codesign_verified"] = bool(signed and signed.returncode == 0)
    run(["/usr/bin/xattr", "-dr", "com.apple.quarantine", str(temporary_app)], timeout=60, ok=True)
    os.rename(temporary_app, APP)
    manifest["phase"] = "app_installed"
    save_manifest(request, manifest)
    installer = pathlib.Path(APP) / "Contents/Resources/resources/clash-verge-service-install"
    run([str(installer)], timeout=120, ok=True)
    service = run(["/bin/launchctl", "print", "system/" + SERVICE_LABEL], timeout=15, ok=True)
    manifest["service_installed"] = bool(service and service.returncode == 0)
    target = pathlib.Path(manifest["data_dir"])
    if target.exists() or target.is_symlink():
        backup = target.with_name(target.name + ".lazyclash-backup-" + nonce)
        os.rename(target, backup)
        manifest["data_backup"] = str(backup)
    target.mkdir(mode=0o755)
    os.chown(target, user.pw_uid, user.pw_gid)
    profiles = target / "profiles"
    profiles.mkdir(mode=0o755)
    os.chown(profiles, user.pw_uid, user.pw_gid)
    for name, data in sorted(files.items()):
        atomic(target / name, data, 0o644, owner=user)
    write_verge_settings(manifest, user, "staged")
    core = output([APP + "/Contents/MacOS/verge-mihomo", "-v"], timeout=15)
    version = re.search(r"\b(v\d+\.\d+\.\d+)\b", core)
    manifest["core_version"] = version.group(1) if version else ""
    shutil.rmtree(work, ignore_errors=True)
    manifest["phase"] = "staged"
    result = {"status": "staged", "core_version": manifest["core_version"], "manifest": public_manifest(manifest)}
    result["digest"] = save_manifest(request, manifest)
    return result


def public_manifest(manifest):
    return {"phase": manifest.get("phase"), "gui_activated": verge_gui_running(), "service_installed": manifest.get("service_installed", False), "codesign_verified": manifest.get("codesign_verified", False), "data_backup": manifest.get("data_backup", ""), "cfw_stopped": manifest.get("cfw_stopped", False), "cfw_daemons": [d["label"] for d in (manifest.get("cfw") or {}).get("daemons", [])] + [j["label"] for j in (manifest.get("cfw") or {}).get("jobs", [])], "restore_incomplete": manifest.get("restore_incomplete", []), "takeover_warnings": manifest.get("takeover_warnings", []), "rollback_deadline": manifest.get("rollback_deadline", 0)}


def respond(request, manifest, status, extra=None):
    result = {"status": status, "core_version": manifest.get("core_version", ""), "manifest": public_manifest(manifest), "running": verge_gui_running()}
    result["digest"] = save_manifest(request, manifest)
    if extra:
        result.update(extra)
    return result


def launch_staged(request):
    require_root()
    manifest = load_manifest(request)
    user = pwd.getpwnam(manifest["user"])
    token, deadline = arm_watchdog(request, manifest, request.get("deadline_seconds") or DEFAULT_DEADLINE)
    write_verge_settings(manifest, user, "staged")
    launched = launch_verge(user)
    manifest["phase"] = "staged_running" if launched else "staged"
    return respond(request, manifest, manifest["phase"], {"ack_token": token, "deadline": deadline})


def listeners(ports):
    found = {}
    by_pid = {p["pid"]: p["command"] for p in processes()}
    for port in ports:
        text = output(["/usr/sbin/lsof", "-nP", "-iTCP:" + str(port), "-sTCP:LISTEN", "-Fpn"], timeout=15)
        pid, entries = None, []
        for line in text.splitlines():
            if line.startswith("p"):
                pid = int(line[1:])
            elif line.startswith("n") and pid is not None:
                entries.append((pid, line[1:]))
        found[port] = entries and all(address.startswith(("127.0.0.1:", "[::1]:", "localhost:")) and by_pid.get(owner, "").startswith(APP + "/Contents/MacOS/verge-mihomo") for owner, address in entries)
    return found


def verify_runtime(request):
    require_root()
    manifest = load_manifest(request)
    ports = [manifest["controller_port"], manifest["mixed_port"]]
    result = listeners(ports)
    generated = b""
    path = pathlib.Path(manifest["data_dir"]) / "clash-verge.yaml"
    if path.is_file() and not path.is_symlink():
        generated = path.read_bytes()[: 16 << 20]
    return {"status": "verified" if all(result.values()) else "unverified", "running": verge_gui_running(), "manifest": {"loopback_listeners_verified": all(result.values()), "gui_activated": verge_gui_running()}, "generated": base64.b64encode(generated).decode(), "digest": digest(json.dumps(manifest, sort_keys=True, indent=1).encode())}


def takeover(request):
    require_root()
    manifest = load_manifest(request)
    user = pwd.getpwnam(manifest["user"])
    token, deadline = arm_watchdog(request, manifest, request.get("deadline_seconds") or DEFAULT_DEADLINE)
    errors = []
    stop_cfw(manifest, user, errors)
    quit_verge(user)
    write_verge_settings(manifest, user, "final")
    launched = launch_verge(user)
    manifest["phase"] = "takeover" if launched else "takeover_unlaunched"
    manifest["takeover_warnings"] = errors
    return respond(request, manifest, manifest["phase"], {"ack_token": token, "deadline": deadline})


def verify_egress(request):
    manifest = load_manifest(request, owner=False) if os.path.exists(state_dir(request) / "instance.json") else {}
    port = int(request.get("mixed_port") or manifest.get("mixed_port") or 0)
    url = "https://www.google.com/generate_204"
    def probe(args):
        text = output(["/usr/bin/curl", "-sS", "-o", "/dev/null", "-m", "12", "-w", "%{http_code}"] + args + [url], timeout=20)
        return text.strip()
    result = {"via_proxy": probe(["-x", "http://127.0.0.1:%d" % port]) if port else "", "direct": probe(["--noproxy", "*"])}
    route = output(["/sbin/route", "-n", "get", "100.100.100.100"], timeout=10)
    iface = re.search(r"interface:\s*(\S+)", route)
    result["tailnet_interface"] = iface.group(1) if iface else ""
    return {"status": "checked", "manifest": result}


def ack(request):
    require_root()
    manifest = load_manifest(request)
    guard_path = state_dir(request) / "guard.json"
    if not guard_path.exists():
        fail("no armed rollback is awaiting acknowledgement")
    guard = json.loads(guard_path.read_text())
    if digest(request.get("ack_token", "").encode()) != guard["ack_hash"]:
        fail("rollback acknowledgement token differs")
    if time.time() >= guard["deadline"]:
        fail("rollback deadline already expired")
    disarm_watchdog(request)
    manifest.pop("rollback_deadline", None)
    manifest["phase"] = "active" if manifest.get("phase", "").startswith("takeover") else manifest.get("phase")
    return respond(request, manifest, "acknowledged")


def status(request):
    path = state_dir(request) / "instance.json"
    if not path.exists():
        return {"status": "missing", "running": False, "manifest": {}}
    manifest = json.loads(path.read_bytes())
    if manifest.get("owner_hash") != digest(request.get("owner_token", "").encode()):
        fail("managed Verge owner token differs")
    return {"status": manifest.get("phase", "unknown"), "running": verge_gui_running(), "core_version": manifest.get("core_version", ""), "manifest": public_manifest(manifest), "digest": digest(path.read_bytes())}


def stop(request):
    require_root()
    manifest = load_manifest(request)
    user = pwd.getpwnam(manifest["user"])
    errors = []
    disarm_watchdog(request)
    quit_verge(user, errors)
    restore_proxy(manifest.get("proxy_snapshot"), errors)
    restore_cfw(manifest, user, errors)
    manifest["phase"] = "stopped"
    manifest["restore_incomplete"] = errors
    return respond(request, manifest, "stopped")


def start(request):
    request = dict(request)
    return takeover(request)


def restart(request):
    require_root()
    manifest = load_manifest(request)
    user = pwd.getpwnam(manifest["user"])
    token, deadline = arm_watchdog(request, manifest, request.get("deadline_seconds") or DEFAULT_DEADLINE)
    quit_verge(user)
    launched = launch_verge(user)
    manifest["phase"] = "takeover" if launched else "takeover_unlaunched"
    manifest["takeover_warnings"] = []
    return respond(request, manifest, manifest["phase"], {"ack_token": token, "deadline": deadline})


def remove(request):
    result = stop(request)
    manifest = load_manifest(request, owner=False)
    uninstaller = pathlib.Path(APP) / "Contents/Resources/resources/clash-verge-service-uninstall"
    if uninstaller.exists():
        run([str(uninstaller)], timeout=120, ok=True)
    manifest["phase"] = "removed"
    result = respond(request, manifest, "removed")
    return result


def rollback_now(request):
    require_root()
    manifest = load_manifest(request)
    errors = rollback(request, manifest)
    disarm_watchdog(request)
    return respond(request, manifest, "rolled_back", {"error_list": errors})


def activate_source(request):
    user = invoking_user()
    quit_verge(user)
    launched = launch_verge(user)
    return {"status": "activated" if launched else "unlaunched", "running": launched, "manifest": {"gui_activated": launched}}


OPS = {"facts": facts, "prepare-transfer": prepare_transfer, "cleanup-transfer": cleanup_transfer, "privilege-check": privilege_check, "install": install, "launch-staged": launch_staged, "verify-runtime": verify_runtime, "takeover": takeover, "verify-egress": verify_egress, "ack": ack, "status": status, "stop": stop, "start": start, "restart": restart, "remove": remove, "rollback": rollback_now, "activate-source": activate_source}

SELF = ""

# DARWIN_VERGE_ENTRYPOINT
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--watchdog":
        try:
            watchdog_tick(sys.argv[2])
        except Exception:
            pass
        sys.exit(0)
    request = {}
    try:
        if len(sys.argv) == 3:
            path, expected = sys.argv[1:]
            before = os.lstat(path)
            uid = int(os.environ.get("SUDO_UID", os.getuid()))
            if before.st_uid != uid or stat.S_IMODE(before.st_mode) != 0o600:
                fail("privileged request ownership or mode is invalid")
            with open(path, "rb") as stream:
                raw = stream.read(32 << 20)
            if digest(raw) != expected:
                fail("privileged request changed after review")
            request = json.loads(raw)
        else:
            request = json.load(sys.stdin)
        SELF = request.pop("helper_source", "") or SELF
        operation = OPS.get(request.get("op"))
        if operation is None:
            fail("unsupported managed Verge operation")
        response = operation(request)
    except Exception as error:
        response = {"error": str(error) if isinstance(error, (RuntimeError, OSError, KeyError, ValueError)) else "managed Verge host operation failed"}
    print("LAZYCLASH_MANAGED_RESULT=" + base64.b64encode(json.dumps(response, separators=(",", ":")).encode()).decode())
