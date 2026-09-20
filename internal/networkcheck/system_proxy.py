# Fixed system proxy adapter. No request may specify commands or executables.
import ast, contextlib, fcntl, json, os, pathlib, platform, pwd, re, shutil, stat, subprocess, sys, time

def _proxy_lock_path(backend):
    if backend == "macos-networksetup":
        if os.geteuid() != 0: raise ValueError("macOS proxy transaction needs native administrator authorization")
        return pathlib.Path("/Library/Application Support/lazyclash/network/system-proxy.lock"), 0
    if backend == "gnome-gsettings":
        if os.geteuid() == 0 or not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
            raise ValueError("GNOME settings need the original unprivileged desktop session")
        return pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/state/lazyclash/network/system-proxy.lock", os.getuid()
    raise ValueError("unsupported system proxy backend")

@contextlib.contextmanager
def _proxy_lock(backend):
    path, owner = _proxy_lock_path(backend)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o711 if owner == 0 else 0o700)
    info = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise ValueError("system proxy lock directory ownership is unsafe")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lock = os.fdopen(fd, "wb")
    try:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
            raise ValueError("system proxy lock ownership is unsafe")
        deadline = time.monotonic() + 8
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline: raise RuntimeError("another system proxy transaction is still in progress")
                time.sleep(.05)
        yield
    finally:
        lock.close()

def command(argv):
    completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if completed.returncode != 0 or len(completed.stdout) > 65536:
        raise RuntimeError("system proxy command failed or requires native authorization")
    return completed.stdout.decode("utf-8", "replace")

def service_name(value):
    if not isinstance(value, str) or not value or value.startswith("-") or len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid network service")
    return value

def nw(*args):
    return command(["/usr/sbin/networksetup"] + list(args))

def fields(text):
    return dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)

def mac_listener(service, kind):
    values = fields(nw("-get" + kind, service))
    return {"enabled": values.get("Enabled") == "Yes", "host": values.get("Server", ""), "port": int(values.get("Port", "0")), "authenticated": values.get("Authenticated Proxy Enabled") in ("1", "Yes")}

def mac_state(service):
    service_name(service)
    pac = fields(nw("-getautoproxyurl", service))
    discovery = fields(nw("-getproxyautodiscovery", service))
    bypass = nw("-getproxybypassdomains", service).splitlines()
    if len(bypass) == 1 and bypass[0].startswith("There aren't any bypass domains"):
        bypass = []
    return {"service": service, "http": mac_listener(service, "webproxy"), "https": mac_listener(service, "securewebproxy"), "socks": mac_listener(service, "socksfirewallproxy"), "pac_enabled": pac.get("Enabled") == "Yes", "pac_url": "" if pac.get("URL") == "(null)" else pac.get("URL", ""), "discovery": discovery.get("Auto Proxy Discovery") in ("On", "Yes"), "exceptions": bypass, "mode": "manual"}

def gs_get(schema, key):
    raw = command([shutil.which("gsettings"), "get", schema, key]).strip()
    if raw == "true": return True
    if raw == "false": return False
    if raw.startswith("@as "): raw = raw[4:]
    if re.match(r"^(?:u?int\d+|byte) ", raw): raw = raw.split(" ", 1)[1]
    try:
        return ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        raise RuntimeError("unsupported GSettings value")

def gnome_state():
    schema = "org.gnome.system.proxy"
    mode = gs_get(schema, "mode")
    result = {"service": "gnome-session", "mode": mode, "pac_enabled": mode == "auto", "pac_url": gs_get(schema, "autoconfig-url"), "discovery": False, "exceptions": gs_get(schema, "ignore-hosts")}
    for key in ("http", "https", "socks"):
        child = schema + "." + key
        result[key] = {"enabled": mode == "manual" and bool(gs_get(child, "host")), "host": gs_get(child, "host"), "port": gs_get(child, "port"), "authenticated": gs_get(child, "use-authentication") if key == "http" else False}
    return result

def read_snapshot(services):
    result = {"protocol": 1, "os": platform.system(), "backend": "", "selection_explicit": bool(services), "services": []}
    if result["os"] == "Darwin" and os.path.exists("/usr/sbin/networksetup"):
        result["backend"] = "macos-networksetup"
        available = [line for line in nw("-listallnetworkservices").splitlines() if line and not line.startswith(("An asterisk", "*"))]
        chosen = services or available
        for service in chosen:
            service_name(service)
            if service not in available: raise ValueError("selected network service is absent or disabled")
        for service in chosen:
            result["services"].append(mac_state(service))
    elif result["os"] == "Linux" and os.environ.get("DBUS_SESSION_BUS_ADDRESS") and shutil.which("gsettings"):
        result["backend"] = "gnome-gsettings"
        if services and services != ["gnome-session"]: raise ValueError("choose the GNOME desktop session")
        result["services"] = [gnome_state()]
    else:
        result["unavailable"] = "No supported macOS Network service or active GNOME user session"
    return result

def validate_state(state):
    service_name(state["service"])
    for name in ("http", "https", "socks"):
        item = state[name]
        if not isinstance(item["enabled"], bool) or not isinstance(item["authenticated"], bool) or item["authenticated"]:
            raise ValueError("authenticated or invalid system proxy state")
        if not isinstance(item["host"], str) or len(item["host"]) > 253 or any(ord(c) < 33 for c in item["host"]):
            raise ValueError("invalid system proxy hostname")
        if not isinstance(item["port"], int) or isinstance(item["port"], bool) or not 0 <= item["port"] <= 65535:
            raise ValueError("invalid system proxy port")
        if item["enabled"] and (not item["host"] or item["port"] == 0): raise ValueError("enabled system proxy has no endpoint")
    if not isinstance(state["exceptions"], list) or len(state["exceptions"]) > 256:
        raise ValueError("invalid proxy exceptions")
    for value in state["exceptions"]:
        if not isinstance(value, str) or not value or len(value) > 253 or any(ord(c) < 32 for c in value): raise ValueError("invalid proxy exception")
    if not isinstance(state["pac_url"], str) or len(state["pac_url"]) > 4096 or any(ord(c) < 32 for c in state["pac_url"]): raise ValueError("invalid PAC URL")
    for key in ("pac_enabled", "discovery"):
        if not isinstance(state[key], bool): raise ValueError("invalid proxy toggle")

def write_mac(state):
    service = state["service"]
    for name, kind in (("http", "webproxy"), ("https", "securewebproxy"), ("socks", "socksfirewallproxy")):
        item = state[name]
        # Networksetup may retain a disabled listener address; preserve a known
        # prior address when possible, and verify disabled effective state below.
        if item["host"] and item["port"]:
            nw("-set" + kind, service, item["host"], str(item["port"]), "off")
        nw("-set" + kind + "state", service, "on" if item["enabled"] else "off")
    if state["pac_url"]:
        nw("-setautoproxyurl", service, state["pac_url"])
    nw("-setautoproxystate", service, "on" if state["pac_enabled"] else "off")
    nw("-setproxyautodiscovery", service, "on" if state["discovery"] else "off")
    nw("-setproxybypassdomains", service, *(state["exceptions"] or ["Empty"]))

def variant(value):
    if isinstance(value, bool): return "true" if value else "false"
    return repr(value)

def write_gnome(state):
    schema = "org.gnome.system.proxy"
    changes = []
    for name in ("http", "https", "socks"):
        item = state[name]
        changes.extend([(schema + "." + name, "host", item["host"]), (schema + "." + name, "port", item["port"])])
    changes.extend([(schema, "autoconfig-url", state["pac_url"]), (schema, "ignore-hosts", state["exceptions"]), (schema, "mode", state.get("mode", "manual"))])
    if state.get("mode", "manual") not in ("none", "auto", "manual"): raise ValueError("invalid GNOME proxy mode")
    for parent, key, value in changes:
        command([shutil.which("gsettings"), "set", parent, key, variant(value)])

def effective_equal(actual, expected):
    actual, expected = json.loads(json.dumps(actual)), json.loads(json.dumps(expected))
    for name in ("http", "https", "socks"):
        if not expected[name]["enabled"] and not expected[name]["host"]:
            actual[name]["host"], actual[name]["port"] = "", 0
    if not expected["pac_enabled"] and not expected["pac_url"]:
        actual["pac_url"] = ""
    return actual == expected

def apply_plan(plan, restore=False):
    # One host/backend lock covers CAS, every setter and read-back across all
    # managed instances, including rollback workers. Manual edits still require
    # the expected-state checks below; the lock never pretends to own other apps.
    with _proxy_lock(plan.get("backend")):
        return _apply_plan_unlocked(plan, restore)

def _apply_plan_unlocked(plan, restore=False):
    backend = plan.get("backend")
    if backend not in ("macos-networksetup", "gnome-gsettings") or plan.get("os") != platform.system(): raise ValueError("system proxy backend does not match host")
    if backend == "gnome-gsettings" and (os.geteuid() == 0 or not os.environ.get("DBUS_SESSION_BUS_ADDRESS")):
        raise ValueError("GNOME settings must run in the original unprivileged desktop session")
    changes = plan.get("changes", [])
    if not changes or len(changes) > 32: raise ValueError("invalid system proxy change count")
    for change in changes:
        validate_state(change["before"]); validate_state(change["after"])
        if change["service"] != change["before"]["service"] or change["service"] != change["after"]["service"]: raise ValueError("proxy service identity changed")
    result = {"status": "restored" if restore else "applied", "services": []}
    for change in changes:
        expected = change["after"] if restore else change["before"]
        intended = change["before"] if restore else change["after"]
        current = mac_state(change["service"]) if backend == "macos-networksetup" else gnome_state()
        if not effective_equal(current, expected):
            result["status"] = "partial" if result["services"] else "conflict"
            result["services"].append({"service": change["service"], "status": "conflict", "message": "system proxy changed since preview; no overwrite"})
            return result
        try:
            write_mac(intended) if backend == "macos-networksetup" else write_gnome(intended)
            after = mac_state(change["service"]) if backend == "macos-networksetup" else gnome_state()
            if not effective_equal(after, intended): raise RuntimeError("read-back did not match intended proxy state")
            result["services"].append({"service": change["service"], "status": "restored" if restore else "applied"})
        except Exception:
            result["status"] = "partial"
            result["services"].append({"service": change["service"], "status": "unknown", "message": "system proxy operation failed after submission; inspect before retrying"})
            return result
    return result

if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        if request.get("op") != "read": raise ValueError("readonly entry supports only read")
        snapshot = read_snapshot(request.get("services") or [])
        json.dump(snapshot, sys.stdout, ensure_ascii=True, separators=(",", ":"))
    except Exception:
        json.dump({"protocol": 1, "os": platform.system(), "backend": "", "selection_explicit": False, "services": [], "unavailable": "system proxy inspection failed or is not authorized"}, sys.stdout)
