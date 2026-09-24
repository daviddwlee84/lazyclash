# Fixed managed-core host protocol 1. No user-supplied shell program is executed.
import base64, contextlib, fcntl, gzip, hashlib, json, os, pathlib, platform, plistlib, pwd, re, shutil, socket, stat, subprocess, sys, tempfile, time

MAX_FILE = 128 * 1024 * 1024
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

class SourceUnavailable(RuntimeError): pass

def fail(message):
    raise RuntimeError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read_regular(path, limit=MAX_FILE):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        fail("expected a bounded regular file")
    with open(path, "rb") as source:
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if len(data) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        fail("file changed while reading")
    return data

def atomic(path, data, mode=0o600):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and not stat.S_ISREG(os.lstat(path).st_mode):
        fail("refusing to replace a non-regular managed file")
    fd, temporary = tempfile.mkstemp(prefix=".managed-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def create_exclusive(path,data,mode=0o644):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),mode)
    with os.fdopen(fd,"wb") as output:output.write(data);output.flush();os.fsync(output.fileno())

def run(args, timeout=20, ok=False, env=None):
    if os.geteuid()==0:
        executable=pathlib.Path(args[0] if os.path.isabs(args[0]) else (shutil.which(args[0]) or "/missing")).resolve()
        try:
            for component in [executable,*executable.parents]:
                info=component.stat()
                if info.st_uid!=0 or info.st_mode&0o022:fail("privileged host commands must be root-owned and not writable by other users")
        except OSError:
            if ok:return None
            fail("required privileged host command is unavailable")
        args=[str(executable),*args[1:]]
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        if ok: return None
        fail("required host command is missing or timed out")
    if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
        if ok: return None
        fail("host command failed; inspect the managed service logs")
    return result.stdout.decode("utf-8", "replace")

def platform_info():
    system = platform.system()
    arch = {"x86_64":"amd64", "aarch64":"arm64", "arm64":"arm64"}.get(platform.machine(), "unsupported")
    return {"Darwin":"darwin", "Linux":"linux"}.get(system, "unsupported"), arch

def checked_root(request):
    identity = request["id"]
    if not ID.fullmatch(identity): fail("invalid managed core ID")
    system, _ = platform_info()
    scope = request.get("service_scope", "user")
    if scope not in ("user", "system"): fail("invalid service scope")
    if scope == "system":
        base = pathlib.Path("/Library/Application Support/lazyclash/cores" if system == "darwin" else "/var/lib/lazyclash/cores")
    else:
        base = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/lazyclash/cores"
    root = base / identity
    # Only fixture execution can replace the root, and only within a fresh
    # temporary directory supplied by the Go tests (the public CLI never sets it).
    fixture = request.get("fixture_root")
    if fixture:
        if os.environ.get("LAZYCLASH_MANAGED_FIXTURE") != "1": fail("fixture roots are disabled")
        root = pathlib.Path(fixture) / identity
    for parent in [root, *root.parents]:
        if parent.exists():
            info=os.lstat(parent)
            if stat.S_ISLNK(info.st_mode):fail("managed root contains a symbolic link")
            if scope=="system" and not fixture and (info.st_uid!=0 or info.st_mode&0o022):fail("system-owned managed paths must not be writable by non-root users")
    if request.get("root") and pathlib.Path(request["root"]) != root: fail("managed root does not match the chosen owner scope")
    return root

def docker_command(request):
    endpoint = request.get("docker_endpoint", "")
    if not endpoint.startswith("unix://") or not endpoint[7:].startswith("/"):
        fail("managed Docker requires an explicit local Unix daemon socket on the selected host")
    return ["docker", "--host", endpoint]

def archive_hash(path):
    if not isinstance(path,str) or not pathlib.Path(path).is_absolute():fail("Docker archive path must be absolute on the selected host")
    before=os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size>512<<20:fail("Docker archive must be a bounded regular file (512 MiB maximum)")
    h=hashlib.sha256()
    with open(path,"rb") as source:
        for chunk in iter(lambda:source.read(1<<20),b""):h.update(chunk)
        after=os.fstat(source.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):fail("Docker archive changed during inspection")
    return h.hexdigest(),before.st_size

def facts(request):
    system, arch = platform_info()
    root = checked_root(request)
    manifest_path = root / "instance.json"
    existing_digest = ""
    if manifest_path.exists(): existing_digest = digest(read_regular(manifest_path, 1<<20))
    busy = []
    for port in request.get("ports", []):
        if not isinstance(port, int) or not 1024 <= port <= 65535: fail("managed listeners need ports 1024..65535")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try: listener.bind(("127.0.0.1", port))
            except OSError: busy.append(port)
    result = dict(os=system, arch=arch, home=pwd.getpwuid(os.getuid()).pw_dir, uid=os.getuid(), systemd=bool(shutil.which("systemctl")), launchd=bool(shutil.which("launchctl")), docker=False, docker_rootless=False, busy_ports=busy, existing=root.exists(), existing_digest=existing_digest, is_root=os.geteuid()==0, sandbox=bool(shutil.which("sandbox-exec" if system=="darwin" else "bwrap")))
    if request.get("backend")=="native":
        if system=="linux" and result["systemd"]:
            args=["systemctl"]+(["--user"] if request.get("service_scope")=="user" else [])
            result["systemd"]=run(args+["show","--property=Version","--value"],ok=True) is not None
        if system=="darwin" and result["launchd"]:
            domain="system" if request.get("service_scope")=="system" else "gui/"+str(os.getuid())
            result["launchd"]=run(["launchctl","print",domain],ok=True) is not None
    if request.get("backend") == "docker" and shutil.which("docker"):
        args=["docker"]
        if request.get("docker_context"): args += ["--context", request["docker_context"]]
        context_name=request.get("docker_context") or (run(["docker", "context", "show"], ok=True) or "").strip()
        raw=run(["docker", "context", "inspect", context_name], ok=True) if context_name else None
        try:
            endpoint=json.loads(raw)[0]["Endpoints"]["docker"]["Host"]
        except (TypeError,ValueError,KeyError,IndexError): endpoint=""
        if not request.get("docker_context") and os.environ.get("DOCKER_HOST"): endpoint=os.environ["DOCKER_HOST"]
        raw=run(args+["info", "--format", "{{json .}}"], ok=True)
        try:
            info=json.loads(raw)
            result.update(docker=run(args+["compose","version","--short"],ok=True) is not None, docker_rootless=any("rootless" in str(v) for v in info.get("SecurityOptions",[])), docker_os=info.get("OSType",""), docker_arch={"x86_64":"amd64","aarch64":"arm64"}.get(info.get("Architecture"),info.get("Architecture","")), docker_endpoint=endpoint)
        except (TypeError,ValueError): pass
    if request.get("docker_archive"):
        result["archive_sha256"],result["archive_size"]=archive_hash(request["docker_archive"])
    return {"facts":result}

def manifest(root, request):
    path=root/"instance.json"
    data=read_regular(path,1<<20)
    info=json.loads(data)
    if info.get("id")!=request["id"] or info.get("owner_token")!=request.get("owner_token"):
        fail("managed ownership does not match this request")
    if request.get("expected") and digest(data)!=request["expected"]:
        fail("managed instance changed since preview")
    return info,data

def unit_paths(root, request):
    identity="lazyclash-mihomo-"+request["id"]
    if request.get("fixture_root"): return identity,root/(identity+".unit")
    if platform.system()=="Linux":
        directory=pathlib.Path("/etc/systemd/system") if request["service_scope"]=="system" else pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)/".config/systemd/user"
        return identity+".service",directory/(identity+".service")
    label="io.lazyclash.mihomo."+request["id"]
    if request.get("boot"):
        directory=pathlib.Path("/Library/LaunchDaemons") if request["service_scope"]=="system" else pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)/"Library/LaunchAgents"
    else: directory=root
    return label,directory/(label+".plist")

def command_quote(text):
    # systemd ExecStart quoting is not shell quoting; escape its percent specifiers.
    return '"'+str(text).replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"'

def service_data(root, request):
    label,path=unit_paths(root,request)
    binary=str(root/"bin/mihomo"); home=str(root/"home")
    if platform.system()=="Linux":
        data=("[Unit]\nDescription=lazyclash managed Mihomo "+request["id"]+"\nAfter=network.target\n[Service]\nType=simple\nExecStart="+command_quote(binary)+" -d "+command_quote(home)+" -f "+command_quote(root/"home/config.yaml")+"\nRestart=on-failure\nRestartSec=2\nKillMode=control-group\nUMask=0077\n[Install]\nWantedBy="+("multi-user.target" if request["service_scope"]=="system" else "default.target")+"\n").encode()
    else:
        data=plistlib.dumps({"Label":label,"ProgramArguments":[binary,"-d",home,"-f",str(root/"home/config.yaml")],"RunAtLoad":True,"KeepAlive":{"SuccessfulExit":False},"StandardOutPath":str(root/"service.stdout.log"),"StandardErrorPath":str(root/"service.stderr.log"),"WorkingDirectory":home,"Umask":0o077})
    return label,path,data

def service_action(root, request, action, info):
    if request.get("fixture_root"): return action!="stop"
    if request["backend"]=="docker":
        command=docker_command(request)+["compose","-p","lazyclash_"+request["id"],"-f",str(root/"compose.json")]
        if action=="start": run(command+["up","-d","--no-build","--pull","never"],timeout=90)
        elif action=="stop": run(command+["stop"],timeout=30)
        elif action=="restart": run(command+["restart"],timeout=40)
        elif action=="remove": run(command+["down","--remove-orphans"],timeout=40)
        return action not in ("stop","remove")
    label,path=unit_paths(root,request)
    if platform.system()=="Linux":
        args=["systemctl"]+(["--user"] if request["service_scope"]=="user" else [])
        if action=="remove":
            run(args+["disable","--now",label])
            if path.exists():
                if digest(read_regular(path))!=info["service_sha256"]: fail("service definition changed; refusing to remove it")
                path.unlink()
            run(args+["daemon-reload"])
        else: run(args+[action,label],timeout=30)
    else:
        domain="system" if request["service_scope"]=="system" else "gui/"+str(os.getuid())
        if action in ("stop","remove","restart"):
            run(["launchctl","bootout",domain+"/"+label],ok=True)
            if run(["launchctl","print",domain+"/"+label],ok=True) is not None:fail("owned launchd service did not stop")
        if action in ("start","restart"):
            run(["launchctl","enable",domain+"/"+label]);run(["launchctl","bootstrap",domain,str(path)],ok=False)
        if action=="remove" and path.exists():
            if digest(read_regular(path))!=info["service_sha256"]:fail("service definition changed; refusing to remove it")
            path.unlink()
    return action not in ("stop","remove")

def validate_profile(root, request, stage):
    home=stage/"home"; binary=stage/"bin/mihomo"
    if request.get("fixture_root"): return
    if request["backend"]=="docker":
        run(docker_command(request)+["run","--rm","--network","none","--cap-drop","ALL","--read-only","--tmpfs","/tmp:rw,noexec,nosuid,size=16m","--mount","type=bind,src="+str(home)+",dst=/root/.config/mihomo",request.get("runtime_image") or request["image"],"-t","-d","/root/.config/mihomo"],timeout=35)
    else:
        version=run([str(binary),"-v"],timeout=5)
        if ("Mihomo Meta "+request["version"]+" ") not in version: fail("Mihomo binary did not report the pinned version")
        system=platform.system(); sandbox=shutil.which("sandbox-exec" if system=="Darwin" else "bwrap")
        if not sandbox:fail("native validation requires sandbox-exec or bubblewrap; install the isolation tool before applying")
        if system=="Darwin":
            escaped=str(stage).replace('\\','\\\\').replace('"','\\"')
            profile='(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (subpath "'+escaped+'"))'
            command=[sandbox,"-p",profile]
        else: command=[sandbox,"--die-with-parent","--unshare-net","--unshare-pid","--ro-bind","/","/","--bind",str(stage),str(stage),"--dev","/dev","--proc","/proc","--"]
        run(command+[str(binary),"-t","-d",str(home),"-f",str(home/"config.yaml")],timeout=35)

def resource_path(home, name):
    relative=pathlib.PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts or "\\" in name or relative.parts[0] in ("config.yaml","instance.json","bin","compose.json"):
        fail("resource path conflicts with managed identity")
    path=home/relative
    for parent in [path,*path.parents]:
        if parent==home.parent:break
        if parent.exists() and stat.S_ISLNK(os.lstat(parent).st_mode):fail("resource contains a symbolic link")
    return path

def compose_data(root, request, boot=False):
    service={"image":request.get("runtime_image") or request["image"],"platform":request["platform"],"restart":"unless-stopped" if boot else "no","labels":{"io.lazyclash.owner":request["owner_token"],"io.lazyclash.instance":request["id"]},"volumes":[{"type":"bind","source":str(root/"home"),"target":"/root/.config/mihomo","bind":{"create_host_path":False}}]}
    if request.get("network",{}).get("tun"):
        service.update(network_mode="host",devices=["/dev/net/tun:/dev/net/tun"],cap_add=["NET_ADMIN"])
    else:
        ports=request["ports"];bind=request.get("proxy_listen") or "127.0.0.1"
        if ":" in bind:bind="["+bind+"]"
        service["ports"]=["127.0.0.1:%d:%d"%(ports[0],ports[0]),"%s:%d:%d"%(bind,ports[1],ports[1])]
        if request.get("proxy_udp"):service["ports"].append("%s:%d:%d/udp"%(bind,ports[1],ports[1]))
    return json.dumps({"services":{"mihomo":service}},sort_keys=True).encode()

def verify_owned_files(root,request,info):
    if info.get("removed"):fail("managed service was removed; preserved data is not a live service")
    for key in ("backend","version","service_scope","docker_endpoint","boot"):
        if request.get(key,False if key=="boot" else "")!=info.get(key,False if key=="boot" else ""):fail("managed service identity changed")
    if request["backend"]=="native":
        if digest(read_regular(root/"bin/mihomo"))!=info.get("binary_sha256"):fail("managed binary changed after installation")
        _,path=unit_paths(root,request)
    else:path=root/"compose.json"
    if digest(read_regular(path))!=info.get("service_sha256"):fail("managed service definition changed outside this tool")
    if request["backend"]=="docker" and not request.get("fixture_root"):
        text=run(docker_command(request)+["ps","-aq","--filter","label=com.docker.compose.project=lazyclash_"+request["id"]])
        for identity in text.split():
            raw=run(docker_command(request)+["inspect",identity,"--format","{{json .Config.Labels}}"])
            labels=json.loads(raw)
            if labels.get("io.lazyclash.owner")!=request["owner_token"] or labels.get("io.lazyclash.instance")!=request["id"]:fail("Docker project contains an unowned container")

def disable_boot(root,request,info):
    if request.get("fixture_root"):return
    if request["backend"]=="docker":
        # Compose definitions retain the reviewed setting, but stopped containers
        # must not autonomously revive an unacknowledged routing transaction.
        text=run(docker_command(request)+["ps","-aq","--filter","label=io.lazyclash.owner="+request["owner_token"]])
        for identity in text.split():run(docker_command(request)+["update","--restart=no",identity])
    elif platform.system()=="Linux":
        label,_=unit_paths(root,request);args=["systemctl"]+(["--user"] if request["service_scope"]=="user" else [])
        run(args+["disable",label],ok=True)
    else:
        label,_=unit_paths(root,request);domain="system" if request["service_scope"]=="system" else "gui/"+str(os.getuid())
        run(["launchctl","disable",domain+"/"+label],ok=True)

def finalize_boot(root,request,info):
    if not request.get("boot") or request.get("fixture_root"):return
    if request["backend"]=="docker":
        text=run(docker_command(request)+["ps","-aq","--filter","label=io.lazyclash.owner="+request["owner_token"]])
        for identity in text.split():run(docker_command(request)+["update","--restart=unless-stopped",identity])
    elif platform.system()=="Linux":
        label,_=unit_paths(root,request);args=["systemctl"]+(["--user"] if request["service_scope"]=="user" else [])
        run(args+["enable",label])
    else:
        label,_=unit_paths(root,request);domain="system" if request["service_scope"]=="system" else "gui/"+str(os.getuid())
        run(["launchctl","enable",domain+"/"+label])

def load_verified_archive(request,stage):
    import tarfile,io
    path=request["docker_archive"]
    actual,_=archive_hash(path)
    if actual!=request["docker_archive_sha256"]:fail("Docker archive changed after review")
    expected=request.get("config_sha256","")
    if not re.fullmatch(r"[a-f0-9]{64}",expected):fail("offline Docker image lacks verified platform config metadata")
    clean=stage/"verified-image.tar"
    with tarfile.open(path,"r:*") as archive:
        members=archive.getmembers();by_name={m.name:m for m in members}
        if len(by_name)!=len(members) or len(members)>2048:fail("Docker archive contains duplicate or excessive entries")
        def member(name,limit):
            rel=pathlib.PurePosixPath(name)
            if rel.is_absolute() or ".." in rel.parts or "\\" in name:fail("Docker archive member escapes its root")
            item=by_name.get(name)
            if item is None or not item.isfile() or item.size>limit:fail("Docker archive contains an invalid image member")
            return item
        def small(name,limit):return archive.extractfile(member(name,limit)).read(limit+1)
        manifests=json.loads(small("manifest.json",1<<20))
        if not isinstance(manifests,list) or len(manifests)!=1:fail("offline Docker archive must contain exactly one image")
        image=manifests[0];config=small(image["Config"],8<<20)
        if digest(config)!=expected:fail("Docker archive config is not the verified official platform image")
        definition=json.loads(config)
        if definition.get("os")!="linux" or definition.get("architecture")!=request["platform"].split("/")[1]:fail("Docker archive platform differs from the reviewed image")
        layers=image.get("Layers",[]);diffs=definition.get("rootfs",{}).get("diff_ids",[])
        if len(layers)!=len(diffs):fail("Docker archive layer inventory does not match the official image")
        # Strip tags before daemon load: importing this archive cannot move an
        # unrelated existing tag. The immutable config ID is the runtime image.
        image["RepoTags"]=[]
        with tarfile.open(clean,"w") as output:
            value=json.dumps([image]).encode();info=tarfile.TarInfo("manifest.json");info.size=len(value);output.addfile(info,io.BytesIO(value))
            item=member(image["Config"],8<<20);output.addfile(item,io.BytesIO(config))
            total=0
            for name,expected_layer in zip(layers,diffs):
                item=member(name,256<<20);total+=item.size
                if total>512<<20:fail("Docker archive layers exceed size limit")
                source=archive.extractfile(item);h=hashlib.sha256()
                for chunk in iter(lambda:source.read(1<<20),b""):h.update(chunk)
                if "sha256:"+h.hexdigest()!=expected_layer:fail("Docker archive layer hash does not match the official config")
                output.addfile(item,archive.extractfile(item))
    # Recheck after sanitizing, before the first daemon mutation.
    if archive_hash(path)[0]!=actual:fail("Docker archive changed while being verified")
    if not request.get("fixture_root"):run(docker_command(request)+["load","--input",str(clean)],timeout=180)
    clean.unlink()
    identity="sha256:"+expected
    if not request.get("fixture_root"):
        value=json.loads(run(docker_command(request)+["image","inspect",identity]))[0]
        if value.get("Id")!=identity or value.get("Architecture")!=request["platform"].split("/")[1]:fail("loaded Docker image identity differs from its verified archive")
    return identity

def install(request):
    root=checked_root(request)
    if root.exists(): fail("managed destination already exists; use configure for an owned instance")
    if request["service_scope"]=="system" and os.geteuid()!=0:fail("this installation needs native administrator authorization")
    root.parent.mkdir(parents=True,exist_ok=True,mode=0o755 if request["service_scope"]=="system" else 0o700)
    lock=open(root.parent/("."+request["id"]+".lock"),"a+b")
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if root.exists():fail("managed destination was concurrently created")
    with tempfile.TemporaryDirectory(prefix=".install-",dir=root.parent) as temporary:
        stage=pathlib.Path(temporary)
        (stage/"home").mkdir(mode=0o700);(stage/"bin").mkdir(mode=0o700)
        if request["backend"]=="native":
            archive=base64.b64decode(request["artifact"],validate=True)
            if digest(archive)!=request["artifact_sha256"]:fail("transferred artifact checksum mismatch")
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(archive)) as source: binary=source.read(MAX_FILE+1)
            if len(binary)>MAX_FILE:fail("decompressed binary exceeds size limit")
            atomic(stage/"bin/mihomo",binary,0o755)
        else:
            if not re.fullmatch(r"metacubex/mihomo@sha256:[a-f0-9]{64}",request["image"]):fail("Docker image must be pinned by official repository digest")
            if request.get("docker_archive"):request["runtime_image"]=load_verified_archive(request,stage)
            elif not request.get("fixture_root"):
                run(docker_command(request)+["pull","--platform",request["platform"],request["image"]],timeout=180)
        profile=base64.b64decode(request["profile"],validate=True)
        if digest(profile)!=request["profile_sha256"]:fail("transferred profile checksum mismatch")
        atomic(stage/"home/config.yaml",profile)
        for name,encoded in request.get("resources",{}).items():
            atomic(resource_path(stage/"home",name),base64.b64decode(encoded,validate=True))
        validate_profile(root,request,stage)
        info=dict(protocol=1,id=request["id"],owner_token=request["owner_token"],backend=request["backend"],version=request["version"],service_scope=request["service_scope"],root=str(root),profile_sha256=request["profile_sha256"],running=False,boot=bool(request.get("boot")),docker_endpoint=request.get("docker_endpoint",""),image=request.get("image",""),runtime_image=request.get("runtime_image",""),network=request.get("network",{}),binary_sha256=digest(binary) if request["backend"]=="native" else "")
        if request["backend"]=="docker":
            compose=compose_data(root,request,False);atomic(stage/"compose.json",compose,0o644);info["service_sha256"]=digest(compose)
        else:
            label,path,unit=service_data(root,request)
            if path.exists():fail("service definition already exists and is not owned by this installation")
            info["service_sha256"],info["service_path"]=digest(unit),str(path)
            atomic(stage/"service.definition",unit)
        root.mkdir(mode=0o700)
        os.rename(stage,root)
        if request["service_scope"]=="system": os.chmod(root,0o755);os.chmod(root/"bin",0o755)
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
        if request["backend"]=="native":
            if path.exists():fail("service definition changed during installation")
            create_exclusive(path,unit,0o644)
            if not request.get("fixture_root") and platform.system()=="Linux":
                args=["systemctl"]+(["--user"] if request["service_scope"]=="user" else [])
                run(args+["daemon-reload"])
        guard=arm_network_guard(root,request,info)
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
        try:
            info["running"]=service_action(root,request,"start",info)
            info["status"]="running_unverified"
        except RuntimeError:
            info["status"]="installed_start_failed"
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
        return dict({"manifest":info,"digest":digest(read_regular(root/"instance.json")),"status":info["status"]},**guard)

def configure(root,request,info):
    if request["service_scope"]=="system" and os.geteuid()!=0:fail("managed configuration requires native administrator authorization")
    before=read_regular(root/"home/config.yaml")
    if digest(before)!=info["profile_sha256"]:fail("configuration changed outside the managed workflow")
    candidate=base64.b64decode(request["profile"],validate=True)
    if digest(candidate)!=request["profile_sha256"]:fail("candidate configuration checksum mismatch")
    old=json.loads(json.dumps(info));backups={};compose_before=None
    with tempfile.TemporaryDirectory(prefix=".configure-",dir=root.parent) as temporary:
        stage=pathlib.Path(temporary);shutil.copytree(root/"home",stage/"home");(stage/"bin").mkdir()
        if request["backend"]=="native":shutil.copy2(root/"bin/mihomo",stage/"bin/mihomo")
        atomic(stage/"home/config.yaml",candidate)
        for name,encoded in request.get("resources",{}).items():
            path=resource_path(root/"home",name);backups[name]=read_regular(path) if path.exists() else None
            atomic(resource_path(stage/"home",name),base64.b64decode(encoded,validate=True))
        validate_profile(root,request,stage)
        info["profile_sha256"]=request["profile_sha256"];info["network"]=request["network"]
        if request["backend"]=="docker":
            compose_before=read_regular(root/"compose.json");compose=compose_data(root,request,False);info["service_sha256"]=digest(compose)
        guard=arm_network_guard(root,request,info,before,old)
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
        try:
            for name,encoded in request.get("resources",{}).items():atomic(resource_path(root/"home",name),base64.b64decode(encoded,validate=True))
            atomic(root/"home/config.yaml",candidate)
            if compose_before is not None:atomic(root/"compose.json",compose,0o644)
            info["running"]=service_action(root,request,"restart",info) if request["backend"]=="native" else service_action(root,request,"start",info)
            info["status"]="running_unverified"
        except Exception:
            atomic(root/"home/config.yaml",before)
            for name,data in backups.items():
                path=resource_path(root/"home",name)
                if data is None:
                    if path.exists():path.unlink()
                else:atomic(path,data)
            if compose_before is not None:atomic(root/"compose.json",compose_before,0o644)
            info=old;request["network"]=old.get("network",{})
            info["running"]=service_action(root,request,"restart",info) if old.get("running") else False
            info["status"]="configure_failed_restored"
            if guard:
                directory=_guard_directory(request,guard["guard_ref"])
                with _guard_lock(directory):
                    state=_guard_state(directory);state["status"]="rolled_back";_guard_save(directory,state)
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
        return dict({"manifest":info,"digest":digest(read_regular(root/"instance.json")),"status":info["status"]},**guard)

def operate(request):
    root=checked_root(request)
    op=request["op"]
    if op not in ("status","ack"):
        lock=open(root.parent/("."+request["id"]+".lock"),"a+b");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    info,raw=manifest(root,request)
    if op=="status" and info.get("removed"):return {"manifest":info,"digest":digest(raw),"running":False}
    if op=="ack":return ack_network_guard(root,request,info)
    if op=="restore-proxy":return restore_network_guard(root,request,info)
    verify_owned_files(root,request,info)
    request["runtime_image"]=info.get("runtime_image","")
    if op=="finalize":
        finalize_boot(root,request,info);return {"status":"finalized","digest":digest(raw)}
    if op=="configure":return configure(root,request,info)
    if op=="snapshot":
        resources={};total=0
        for directory,subdirs,files in os.walk(root/"home",followlinks=False):
            for subdir in subdirs:
                if (pathlib.Path(directory)/subdir).is_symlink():fail("owned resource directory is a symbolic link")
            for name in files:
                path=pathlib.Path(directory)/name;relative=str(path.relative_to(root/"home"))
                if relative=="config.yaml" or name in ("cache.db","cache.db-shm","cache.db-wal"):continue
                data=read_regular(resource_path(root/"home",relative),24<<20);total+=len(data)
                if total>16<<20:fail("owned resource snapshot exceeds 16 MiB")
                resources[relative]=base64.b64encode(data).decode()
        return {"profile":base64.b64encode(read_regular(root/"home/config.yaml",8<<20)).decode(),"resources":resources}

    if op=="status":
        running=info.get("running",False)
        if not request.get("fixture_root"):
            if request["backend"]=="docker":
                text=run(docker_command(request)+["compose","-p","lazyclash_"+request["id"],"-f",str(root/"compose.json"),"ps","--format","json"],ok=True)
                if text is None:fail("Docker service status is unavailable")
                running=bool(text and '"running"' in text)
            elif platform.system()=="Linux":
                label,_=unit_paths(root,request);args=["systemctl"]+(["--user"] if request["service_scope"]=="user" else [])
                state=run(args+["show",label,"--property=ActiveState","--value"],ok=True)
                if state is None:fail("systemd service status is unavailable")
                running=state.strip()=="active"
            else:
                label,_=unit_paths(root,request);domain="system" if request["service_scope"]=="system" else "gui/"+str(os.getuid())
                running=bool(re.search(r"\bpid = [1-9][0-9]*",run(["launchctl","print",domain+"/"+label],ok=True) or ""))
        return {"manifest":info,"digest":digest(raw),"running":running}
    if op not in ("start","stop","restart","remove"):fail("unsupported lifecycle operation")
    guard={}
    if op in ("start","restart"):
        guard=arm_network_guard(root,request,info,read_regular(root/"home/config.yaml"),json.loads(json.dumps(info)))
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
    info["running"]=service_action(root,request,op,info)
    if op in ("stop","remove"):disable_boot(root,request,info)
    info["status"]="removed_data_preserved" if op=="remove" else ("running_unverified" if info["running"] else "stopped")
    info["removed"]=op=="remove"
    atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
    return dict({"manifest":info,"digest":digest(read_regular(root/"instance.json")),"status":info["status"]},**guard)

def proxy_operation(request):
    # This operation never executes a user-owned core under administrator rights.
    root=pathlib.Path(request.get("root","/"));info={"network_guard":request.get("guard_ref")}
    if request["op"]=="ack-proxy":return ack_network_guard(root,request,info)
    if request["op"]=="restore-proxy":return restore_network_guard(root,request,info)
    request["network"]={"tun":False}
    guard=arm_network_guard(root,request,info)
    result=apply_network_proxy(request)
    return dict(result,**guard)

def source_operation(request):
    root=checked_root(request)
    lock=open(root.parent/("."+request["id"]+".lock"),"a+b");fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    info,raw=manifest(root,request);verify_owned_files(root,request,info)
    request["runtime_image"]=info.get("runtime_image","")
    source=request["source"];op=source["op"]
    def owned(path):
        path=pathlib.Path(path)
        if not path.is_absolute() or os.path.commonpath([str(path.resolve()),str((root/"home").resolve())])!=str((root/"home").resolve()):fail("configuration source is outside the owned home")
        for parent in [path,*path.parents]:
            if parent==root:break
            if parent.exists() and stat.S_ISLNK(os.lstat(parent).st_mode):fail("configuration source cannot traverse symbolic links")
    if source.get("path"):owned(source["path"])
    for guard in source.get("guards",[]):owned(guard["path"])
    result={}
    if op=="read":result["file"]=source_api["read"](source["path"])
    elif op=="check":source_api["guards_match"](source["guards"])
    elif op=="write":
        result["file"]=source_api["write"](source)
        if pathlib.Path(source["path"])==root/"home/config.yaml":info["profile_sha256"]=digest(read_regular(root/"home/config.yaml"))
        atomic(root/"instance.json",json.dumps(info,sort_keys=True).encode(),0o644)
    elif op in ("validate","docker-validate","docker-inspect"):
        if source.get("version") and source["version"]!=request["version"]:fail("validator version does not match owned artifact")
        if op in ("docker-inspect","docker-validate"):
            if request["backend"]!="docker":fail("Docker source is not owned by this backend")
            expected="lazyclash_"+request["id"]+"-mihomo-1"
            if source.get("container")!=expected:fail("Docker source container does not match managed instance")
            inspected=run(docker_command(request)+["inspect",expected],ok=True)
            if inspected is None:raise SourceUnavailable("managed Docker daemon or container is unavailable")
            items=json.loads(inspected);item=items[0]
            if item.get("Config",{}).get("Labels",{}).get("io.lazyclash.owner")!=request["owner_token"]:fail("Docker source owner label changed")
            if not item.get("State",{}).get("Running"):raise SourceUnavailable("managed Docker container is not running")
            output=run(docker_command(request)+["exec",item["Id"],"sha256sum","/root/.config/mihomo/config.yaml"],ok=True)
            if output is None:raise SourceUnavailable("managed Docker source is unavailable inside its container")
            visible=output.split()[0]
            if not re.fullmatch(r"[a-f0-9]{64}",visible):fail("managed container source hash is invalid")
            result.update(container_id=item["Id"],image=item["Image"],source_sha256=visible,single_file=False)
        if op!="docker-inspect":
            with tempfile.TemporaryDirectory(prefix=".source-check-",dir=root.parent) as temporary:
                stage=pathlib.Path(temporary);shutil.copytree(root/"home",stage/"home");(stage/"bin").mkdir()
                if request["backend"]=="native":shutil.copy2(root/"bin/mihomo",stage/"bin/mihomo")
                atomic(stage/"home/config.yaml",json.dumps(source["document"]).encode())
                validate_profile(root,request,stage)
    else:fail("unsupported managed source operation")
    return {"source":result,"manifest":info,"digest":digest(read_regular(root/"instance.json"))}

def main(request):
    op=request.get("op")
    if op=="source":return source_operation(request)
    if op=="facts":return facts(request)
    if op=="install":return install(request)
    if op in ("activate-proxy","ack-proxy","restore-proxy"):return proxy_operation(request)
    return operate(request)

# MANAGED_ENTRYPOINT
try:
    if len(sys.argv)==3:
        path,expected=sys.argv[1:]
        before=os.lstat(path)
        uid=int(os.environ.get("SUDO_UID",os.getuid()))
        if before.st_uid!=uid or stat.S_IMODE(before.st_mode)!=0o600:fail("privileged request ownership or mode is invalid")
        raw=read_regular(path,48<<20)
        if digest(raw)!=expected:fail("privileged request changed after review")
        request=json.loads(raw)
    else:request=json.load(sys.stdin)
    response=main(request)
    print("LAZYCLASH_MANAGED_RESULT="+base64.b64encode(json.dumps(response,separators=(",",":")).encode()).decode())
except Exception as error:
    message=str(error) if isinstance(error,RuntimeError) else "managed host operation failed; no untrusted process output is included"
    failure={"error":message}
    if isinstance(error,SourceUnavailable):failure["error_kind"]="unavailable"
    try:
        if request.get("op")=="install" and not checked_root(request).exists():failure["status"]="not_installed"
    except Exception:pass
    print("LAZYCLASH_MANAGED_RESULT="+base64.b64encode(json.dumps(failure).encode()).decode())
