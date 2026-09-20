# Network transactions survive loss of the initiating SSH/terminal session.
# These functions share only fixed host helper functions, never request code.
import secrets

def _guard_base(privileged):
    if privileged:
        return pathlib.Path("/Library/Application Support/lazyclash/network" if platform.system() == "Darwin" else "/var/lib/lazyclash/network")
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    return pathlib.Path(pwd.getpwuid(uid).pw_dir) / ".local/state/lazyclash/network"

def _guard_public(directory, state):
    atomic(directory / "status.json", json.dumps({"status": state["status"], "deadline": state["deadline"], "message": state.get("message", "")}, sort_keys=True).encode(), 0o644)

def _guard_save(directory, state):
    atomic(directory / "state.json", json.dumps(state, sort_keys=True).encode())
    _guard_public(directory, state)

def _guard_directory(request, ref):
    if not isinstance(ref, str) or not pathlib.Path(ref).is_absolute(): fail("invalid network guard reference")
    directory = pathlib.Path(ref)
    name = request["id"] + "-"
    if not directory.name.startswith(name) or not re.fullmatch(r"[a-f0-9]{32}", directory.name[len(name):]): fail("network guard identity mismatch")
    allowed = [_guard_base(True), _guard_base(False)]
    if request.get("fixture_root") and os.environ.get("LAZYCLASH_MANAGED_FIXTURE") == "1": allowed.append(pathlib.Path(request["fixture_root"]) / "network-guards")
    if not any(directory.parent.resolve() == base.resolve() for base in allowed): fail("network guard is outside its owned directory")
    if stat.S_ISLNK(os.lstat(directory).st_mode): fail("network guard must not be a symlink")
    return directory

def _guard_state(directory):
    state = json.loads(read_regular(directory / "state.json", 32 << 20))
    if state.get("protocol") != 1: fail("unsupported network guard format")
    return state

def _guard_lock(directory):
    fd = os.open(str(directory / "guard.lock"), os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lock = os.fdopen(fd, "wb")
    fcntl.flock(lock, fcntl.LOCK_EX)
    return lock

def _guard_instance_lock(state):
    # Normal install/configure/source operations use this same lock. The worker
    # already holds guard.lock, so never wait here: configure may need guard.lock
    # during cleanup while it holds the instance lock. Retry the tick instead.
    root = pathlib.Path(state["root"])
    path = root.parent / ("." + state["id"] + ".lock")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    lock = os.fdopen(fd, "wb")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock
    except BlockingIOError:
        lock.close()
        return None

def _guard_owned_core(root, request):
    if request.get("fixture_root") and os.environ.get("LAZYCLASH_MANAGED_FIXTURE") == "1": return
    if request.get("service_scope") != "system" or os.geteuid() != 0: fail("TUN rollback requires a system-owned core")
    if pathlib.Path(root) != checked_root(request): fail("TUN rollback root mismatch")
    for path in (root, root / "home", root / "instance.json"):
        info = os.lstat(path)
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode): fail("TUN rollback source is not root-owned")

def _guard_file(root, name):
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts or "\\" in name: fail("unsafe network backup path")
    path = root / "home" / relative
    if os.path.commonpath([str(path.resolve()), str((root / "home").resolve())]) != str((root / "home").resolve()):
        fail("network backup escapes managed home")
    return path

def _guard_spawn(directory):
    python = "/usr/bin/python3" if os.geteuid() == 0 else sys.executable
    if os.geteuid() == 0:
        executable = pathlib.Path(python).resolve()
        for path in [executable, *executable.parents]:
            info = path.stat()
            if info.st_uid != 0 or info.st_mode & 0o022: fail("rollback Python must be root-owned")
    with open(os.devnull, "rb") as source, open(os.devnull, "wb") as sink:
        subprocess.Popen([python, "-I", str(directory / "worker.py"), str(directory)], stdin=source, stdout=sink, stderr=sink, close_fds=True, start_new_session=True)

def arm_network_guard(root, request, info, previousProfile=None, previousManifest=None):
    tun = bool(request.get("network", {}).get("tun") or (previousManifest or {}).get("network", {}).get("tun"))
    proxy = request.get("system_proxy")
    if not tun and not proxy: return {}
    if tun: _guard_owned_core(root, request)
    privileged = os.geteuid() == 0
    base = _guard_base(privileged)
    if request.get("fixture_root") and os.environ.get("LAZYCLASH_MANAGED_FIXTURE") == "1": base = pathlib.Path(request["fixture_root"]) / "network-guards"
    base.mkdir(parents=True, exist_ok=True, mode=0o711 if privileged else 0o700)
    base = base.resolve()
    if base.stat().st_uid != os.getuid() or base.stat().st_mode & 0o022: fail("network guard directory ownership is unsafe")
    directory = base / (request["id"] + "-" + secrets.token_hex(16))
    directory.mkdir(mode=0o711 if privileged else 0o700)
    token = secrets.token_hex(24)
    uid = int(os.environ.get("SUDO_UID", os.getuid()))
    state = {"protocol": 1, "id": request["id"], "owner_token": request["owner_token"], "status": "armed", "deadline": int(time.time()) + 120, "ack_hash": digest(token.encode()), "uid": uid, "core": tun, "root": str(root), "request": {key: request[key] for key in ("id", "root", "backend", "version", "service_scope", "docker_endpoint", "image", "platform", "boot", "owner_token", "fixture_root") if key in request}, "after_hash": request.get("profile_sha256", info.get("profile_sha256", "")), "previous_profile": base64.b64encode(previousProfile).decode() if previousProfile is not None else None, "previous_manifest": previousManifest, "proxy_plan": proxy, "lifecycle_proxy_plan": proxy, "files": []}
    if tun:
        for name, encoded in request.get("resources", {}).items():
            path = _guard_file(root, name)
            before = read_regular(path) if path.exists() else None
            state["files"].append({"name": name, "before": base64.b64encode(before).decode() if before is not None else None, "after_hash": digest(base64.b64decode(encoded, validate=True))})
        compose = root / "compose.json"
        if request.get("backend") == "docker" and previousManifest is not None and compose.exists():
            state["compose_before"] = base64.b64encode(read_regular(compose)).decode()
            state["compose_after_hash"] = info.get("service_sha256", "")
    if len(json.dumps(state).encode()) > 32 << 20: fail("network recovery snapshot exceeds its size limit")
    previous_ref = (previousManifest or {}).get("network_guard") or request.get("previous_guard_ref")
    if previous_ref and proxy:
        previous_directory = _guard_directory(request, previous_ref)
        previous_state = _guard_state(previous_directory)
        if previous_state.get("owner_token") != request["owner_token"]: fail("previous network guard owner changed")
        if previous_state["status"] == "armed": fail("previous network transaction still awaits acknowledgement")
        old_plan = previous_state.get("lifecycle_proxy_plan") or {}
        lifecycle = json.loads(json.dumps(proxy))
        for change in lifecycle.get("changes", []):
            for prior in old_plan.get("changes", []):
                if change["service"] == prior["service"] and proxy_api["effective_equal"](change["before"], prior["after"]): change["before"] = prior["before"]
        state["lifecycle_proxy_plan"] = lifecycle
    ack = directory / "ack"
    fd = os.open(str(ack), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o200 if privileged else 0o600)
    os.close(fd)
    if privileged: os.chown(ack, uid, -1)
    atomic(directory / "worker.py", GUARD_WORKER_SOURCE.encode())
    _guard_save(directory, state)
    try:
        _guard_spawn(directory)
    except Exception:
        state["status"] = "arm_failed"; _guard_save(directory, state)
        raise
    info["network_guard"] = str(directory)
    return {"ack_token": token, "deadline": state["deadline"], "guard_ref": str(directory)}

def apply_network_proxy(request, plan=None, restore=False):
    plan = plan or request.get("system_proxy")
    if not plan: return {"status": "not_requested", "services": []}
    return proxy_api["apply_plan"](plan, restore)

def _guard_restore(directory, state, lifecycle=False):
    failures = []
    if state.get("core") and not lifecycle:
        try:
            root = pathlib.Path(state["root"]); request = state["request"]
            _guard_owned_core(root, request)
            info, _ = manifest(root, request)
            if info.get("network_guard") not in (None, str(directory)): fail("a newer network operation owns the core")
            current = read_regular(root / "home/config.yaml")
            before = base64.b64decode(state["previous_profile"], validate=True) if state.get("previous_profile") is not None else None
            if digest(current) != state["after_hash"] and (before is None or digest(current) != digest(before)): fail("core configuration changed after the network transaction")
            # Validate every backup before touching the service or any source.
            resources = []
            for saved in state["files"]:
                path = _guard_file(root, saved["name"])
                value = read_regular(path) if path.exists() else None
                original = base64.b64decode(saved["before"], validate=True) if saved["before"] is not None else None
                if value is not None and digest(value) != saved["after_hash"] and value != original: fail("managed resource changed after network apply")
                resources.append((path, original))
            compose = None
            if state.get("compose_before") is not None:
                compose = base64.b64decode(state["compose_before"], validate=True)
                current_compose = read_regular(root / "compose.json")
                if digest(current_compose) != state["compose_after_hash"] and current_compose != compose: fail("Compose definition changed after network apply")
            if request.get("backend") == "native" and not request.get("fixture_root"):
                _, service_path = unit_paths(root, request)
                if digest(read_regular(service_path)) != info.get("service_sha256"): fail("service definition changed after network apply")
            service_action(root, request, "stop", info)
            if before is not None:
                atomic(root / "home/config.yaml", before)
                for path, value in resources:
                    if value is None:
                        if path.exists(): path.unlink()
                    else: atomic(path, value)
                if compose is not None: atomic(root / "compose.json", compose, 0o644)
                info = state["previous_manifest"]
                request["network"] = info.get("network", {})
                if info.get("running"): service_action(root, request, "start", info)
                info["status"] = "network_rolled_back"
            else:
                # A newly installed, unacknowledged TUN must not reappear at boot.
                disable_boot(root, request, info)
                info["running"] = False; info["status"] = "network_rolled_back_stopped"
            atomic(root / "instance.json", json.dumps(info, sort_keys=True).encode(), 0o644)
        except Exception:
            failures.append("core rollback needs inspection; owned state changed or service restoration failed")
    plan = state.get("lifecycle_proxy_plan" if lifecycle else "proxy_plan")
    if plan:
        try:
            outcome = apply_network_proxy({}, plan, True)
            if outcome["status"] != "restored": failures.append("system proxy restoration was partial or conflicted with a later edit")
        except Exception:
            failures.append("system proxy restoration requires its original authorized host/session")
    state["status"] = "restore_incomplete" if failures else ("restored" if lifecycle else "rolled_back")
    state["message"] = "; ".join(failures) or "Owned network changes were restored; private core data was retained."
    _guard_save(directory, state)
    return {"status": state["status"], "message": state["message"]}

def _guard_tick(directory, now=None):
    with _guard_lock(directory):
        state = _guard_state(directory)
        if state["status"] != "armed": return True
        now = time.time() if now is None else now
        try: ack = read_regular(directory / "ack", 128)
        except Exception: ack = b""
        if now < state["deadline"] and digest(ack) == state["ack_hash"]:
            state["status"] = "acknowledged"; state["message"] = "Caller confirmed management connectivity; deadline disarmed."
            _guard_save(directory, state)
            return True
        if now >= state["deadline"]:
            if state.get("core"):
                instance_lock = _guard_instance_lock(state)
                if instance_lock is None: return False
                with instance_lock:
                    # Re-read under both locks; every CAS and mutation below
                    # now belongs to the same serialized instance transaction.
                    state = _guard_state(directory)
                    if state["status"] == "armed": _guard_restore(directory, state)
            else:
                _guard_restore(directory, state)
            return True
    return False

def network_guard_worker(reference):
    directory = pathlib.Path(reference)
    try:
        info = os.lstat(directory / "worker.py")
        if info.st_uid != os.getuid() or info.st_mode & 0o077: fail("network worker ownership changed")
        while not _guard_tick(directory): time.sleep(0.25)
    except Exception:
        # Keep the private snapshot for recovery; never execute a fallback
        # shell command or overwrite later configuration after an error.
        try:
            state = _guard_state(directory); state["status"] = "restore_incomplete"; state["message"] = "Rollback worker failed; inspect the retained private snapshot."
            _guard_save(directory, state)
        except Exception: pass

def ack_network_guard(root, request, info):
    reference = request.get("guard_ref") or info.get("network_guard")
    if not reference: return {"status": "not_requested"}
    directory = _guard_directory(request, reference)
    token = request.get("ack_token", "")
    if not re.fullmatch(r"[a-f0-9]{48}", token): fail("invalid network acknowledgement")
    ack = directory / "ack"
    before = os.lstat(ack)
    if not stat.S_ISREG(before.st_mode) or before.st_uid not in (os.getuid(), int(os.environ.get("SUDO_UID", os.getuid()))): fail("network acknowledgement belongs to another user")
    fd = os.open(str(ack), os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "wb") as output: output.write(token.encode()); output.flush(); os.fsync(output.fileno())
    for _ in range(24):
        status = json.loads(read_regular(directory / "status.json", 8192))
        if status["status"] != "armed": return status
        time.sleep(0.25)
    return {"status": "ack_pending", "message": "Acknowledgement was written but the worker has not confirmed it; inspect before retrying."}

def restore_network_guard(root, request, info):
    reference = request.get("guard_ref") or info.get("network_guard")
    if not reference: return {"status": "not_requested"}
    directory = _guard_directory(request, reference)
    with _guard_lock(directory):
        state = _guard_state(directory)
        if state.get("owner_token") != request.get("owner_token"): fail("network restoration owner mismatch")
        if state["status"] == "restored": return {"status": "restored"}
        return _guard_restore(directory, state, lifecycle=True)
