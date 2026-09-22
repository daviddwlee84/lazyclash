import base64, contextlib, fcntl, hashlib, json, os, platform, re, shutil, stat, subprocess, sys, tempfile, urllib.parse, uuid

LIMIT = 8 * 1024 * 1024

def fail(message):
    raise ValueError(message)

def read(path):
    if not os.path.isabs(path): fail('source path must be absolute')
    resolved = os.path.realpath(path)
    with open(resolved, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode): fail('source is not a regular file')
        data = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    if len(data) > LIMIT: fail('source exceeds 8 MiB')
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(os.stat(resolved)) or resolved != os.path.realpath(path):
        fail('source changed while reading; prepare a new preview')
    digest = hashlib.sha256(data).hexdigest()
    fingerprint = hashlib.sha256(json.dumps([resolved, identity(before), digest]).encode()).hexdigest()
    return dict(path=path, resolved=resolved, data=base64.b64encode(data).decode(), fingerprint=fingerprint, sha256=digest, mode=stat.S_IMODE(before.st_mode))

def guards_match(guards):
    for guard in guards:
        if read(guard['path'])['fingerprint'] != guard['fingerprint']:
            fail('source or owner metadata changed; prepare a new preview')

def write(request):
    current = read(request['path'])
    path = current['resolved']
    lock_path = os.path.join(os.path.dirname(path), '.' + os.path.basename(path) + '.lazyclash-rules.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode): fail('source lock is not a regular file')
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: fail('another rule edit is in progress')
        guards_match(request['guards'])
        payload = base64.b64decode(request['data'], validate=True)
        if len(payload) > LIMIT: fail('candidate exceeds 8 MiB')
        temp_fd, temp_path = tempfile.mkstemp(prefix='.lazyclash-rule-', dir=os.path.dirname(path))
        try:
            with os.fdopen(temp_fd, 'wb') as stream:
                os.fchmod(stream.fileno(), current['mode'] & 0o777)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            guards_match(request['guards'])
            if os.path.realpath(request['path']) != path: fail('source symlink changed')
            os.replace(temp_path, path)
        finally:
            with contextlib.suppress(FileNotFoundError): os.unlink(temp_path)
        return read(request['path'])
    finally:
        os.close(fd)

def docker_validator(request, stage, env):
    endpoint = request.get('validation_docker_host', '')
    image = request.get('validation_image', '')
    parsed = urllib.parse.urlsplit(endpoint)
    if platform.system() != 'Linux': fail('native Docker validation requires a Linux core host')
    if parsed.scheme != 'unix' or parsed.netloc or parsed.query or parsed.fragment or not os.path.isabs(parsed.path) or parsed.path == '/' or urllib.parse.unquote(parsed.path) != parsed.path or any(ord(c) < 32 for c in endpoint):
        fail('native Docker validation requires an explicit local unix socket')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image): fail('native Docker validation requires a full sha256 ID of an existing image')
    docker = shutil.which('docker')
    if not docker: fail('native Docker validation requires Docker on the selected core host')
    binary = request['binary']
    if ',' in binary or ',' in stage: fail('native Docker validation paths cannot contain commas')
    binary_info = os.stat(binary)
    if not stat.S_ISREG(binary_info.st_mode) or not os.access(binary, os.X_OK): fail('bound validator binary is not an executable regular file')
    docker_env = {k:v for k,v in env.items() if not k.startswith('DOCKER_')}
    base = [docker, '--host', endpoint]
    def inspect(args):
        result = subprocess.run(base+args, capture_output=True, timeout=5, env=docker_env)
        if result.returncode: fail('native Docker sandbox is unavailable; check bound socket and existing local image')
        return json.loads(result.stdout)
    images = inspect(['image', 'inspect', image])
    if len(images) != 1 or images[0].get('Id') != image: fail('validation image identity changed')
    image_config = images[0].get('Config') or {}
    if image_config.get('Volumes'): fail('validation image declares writable volumes; select an image without VOLUME declarations')
    info = inspect(['info', '--format', '{{json .}}'])
    security = info.get('SecurityOptions') or []
    rootless = 'name=rootless' in security
    if not rootless and 'name=userns' in security:
        fail('native Docker validation does not support rootful user namespace remapping')
    # A rootless daemon maps namespace root to the invoking host user; passing
    # the host numeric UID again would map to an unrelated subordinate UID.
    user = '0:0' if rootless else str(os.getuid())+':'+str(os.getgid())
    # Copy only executable bytes: a live TUN binary may have file capabilities
    # that cannot execute under cap-drop=ALL. The copy has no inherited xattrs;
    # the original binary and its capabilities are never changed.
    binary_copy = os.path.join(stage, '.validator-binary')
    fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    digest = hashlib.sha256()
    with open(binary, 'rb') as source, open(binary_copy, 'xb') as destination:
        before = os.fstat(source.fileno())
        if before.st_size > 256*1024*1024: fail('validator binary exceeds 256 MiB')
        copied = 0
        while True:
            chunk = source.read(1024*1024)
            if not chunk: break
            copied += len(chunk)
            if copied > 256*1024*1024: fail('validator binary exceeds 256 MiB')
            digest.update(chunk)
            destination.write(chunk)
        if fingerprint(before) != fingerprint(os.fstat(source.fileno())) or fingerprint(before) != fingerprint(os.stat(binary)):
            fail('validator binary changed during isolation setup')
    copy_digest = hashlib.sha256()
    with open(binary_copy, 'rb') as copied_binary:
        for chunk in iter(lambda: copied_binary.read(1024*1024), b''): copy_digest.update(chunk)
    if copy_digest.digest() != digest.digest(): fail('validator binary copy verification failed')
    os.chmod(binary_copy, 0o500)
    args = ['run', '--rm', '--interactive', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=512m', '--user', user, '--workdir', stage,
            '--mount', 'type=bind,src='+binary_copy+',dst='+binary+',readonly',
            '--mount', 'type=bind,src='+stage+',dst='+stage]
    clear = {'CLASH_CONFIG_STRING', 'CLASH_CONFIG_FILE', 'CLASH_HOME_DIR', 'SAFE_PATHS', 'SKIP_SAFE_PATH_CHECK'}
    for value in image_config.get('Env') or []:
        key = value.split('=', 1)[0]
        if key.startswith('CLASH_') or key in ('SAFE_PATHS', 'SKIP_SAFE_PATH_CHECK'): clear.add(key)
    for key in sorted(clear): args += ['--env', key+'=']
    def run(command, timeout, input=None):
        name = 'lazyclash-validation-'+uuid.uuid4().hex
        try:
            return subprocess.run(base+args+['--name', name, '--entrypoint', command[0], image]+command[1:], input=input, capture_output=True, timeout=timeout, env=docker_env, cwd=stage)
        finally:
            # A killed Docker client does not stop its container. Remove only
            # this invocation's random name, including on validation timeout.
            cleanup = subprocess.run(base+['rm', '--force', name], capture_output=True, timeout=5, env=docker_env)
            if cleanup.returncode and b'No such container' not in cleanup.stderr:
                fail('could not confirm temporary validation container cleanup')
    return run

def validate(request):
    # The running core's home is never passed to -d. Mutable databases and
    # providers are copied, not linked, so validation cannot lock or repair them.
    source_home = request['home']
    if not os.path.isabs(source_home) or not os.path.isabs(request['binary']): fail('validator paths must be absolute')
    system = platform.system()
    docker = bool(request.get('validation_docker_host') or request.get('validation_image'))
    sandbox = shutil.which('sandbox-exec' if system == 'Darwin' else 'bwrap')
    if not docker and (system not in ('Darwin','Linux') or not sandbox):
        fail('isolated validation requires sandbox-exec on macOS or bubblewrap (bwrap) on Linux; source was not modified')
    env = {k:v for k,v in os.environ.items() if not k.startswith('CLASH_') and k not in ('SAFE_PATHS','SKIP_SAFE_PATH_CHECK')}
    try:
        with tempfile.TemporaryDirectory(prefix='lazyclash-rule-check-') as stage:
            os.chmod(stage, 0o700)
            if docker:
                execute = docker_validator(request, stage, env)
                check = '/bin/true'
            elif system == 'Darwin':
                escaped = stage.replace('\\','\\\\').replace('"','\\"')
                # Darwin reports /var/... aliases but sandbox paths are real.
                escaped = os.path.realpath(stage).replace('\\','\\\\').replace('"','\\"')
                profile = '(version 1)(allow default)(deny network*)(deny file-write* (require-not (subpath "' + escaped + '")))'
                prefix = [sandbox,'-p',profile]
                check = '/usr/bin/true'
            else:
                prefix = [sandbox,'--die-with-parent','--unshare-net','--unshare-pid','--ro-bind','/','/','--bind',stage,stage,'--dev','/dev','--proc','/proc','--']
                check = '/bin/true'
            if not docker:
                def execute(command, timeout, input=None):
                    return subprocess.run(prefix+command, input=input, capture_output=True, timeout=timeout, env=env, cwd=stage)
            probe = execute([check], timeout=5)
            if probe.returncode: fail('OS isolation is unavailable or denied; use an available native sandbox or explicitly bind an existing Docker validation image')
            version = execute([request['binary'], '-v'], timeout=5)
            if version.returncode or ('Mihomo Meta ' + request['version'] + ' ') not in version.stdout.decode(errors='replace'):
                fail('validator binary does not match the connected Mihomo version')
            copied = 0
            def copy_resource(source, destination, required=True):
                nonlocal copied
                if not os.path.exists(source):
                    if required: fail('validation resource is missing')
                    return
                info = os.stat(source)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 256*1024*1024: fail('validation resource is not a bounded regular file')
                copied += info.st_size
                if copied > 512*1024*1024: fail('validation resources exceed 512 MiB')
                os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
                shutil.copyfile(source, destination)
                os.chmod(destination, 0o600)
            for name in os.listdir(source_home):
                if not name.startswith('.') and name.lower().endswith(('.mmdb','.dat','.metadb')):
                    copy_resource(os.path.join(source_home,name), os.path.join(stage,name), False)
            document = request['document']
            index = 0
            def local_copy(value, required=True):
                nonlocal index
                source = value if os.path.isabs(value) else os.path.join(source_home,value)
                index += 1
                destination = os.path.join(stage,'resources',str(index),os.path.basename(source))
                copy_resource(source,destination,required)
                return destination
            # Rewrite resource-bearing paths in a JSON representation (valid
            # YAML), never by text substitution in the user's original YAML.
            for section in ('proxy-providers','rule-providers'):
                for provider in document.get(section,{}).values():
                    if isinstance(provider,dict) and isinstance(provider.get('path'),str):
                        provider['path'] = local_copy(provider['path'], provider.get('type') == 'file')
            def certificates(node):
                if isinstance(node,dict):
                    for key,value in list(node.items()):
                        is_file_key = key in ('certificate','ca','certificate-path','private-key-path') or (key == 'private-key' and 'certificate' in node)
                        if is_file_key and isinstance(value,str) and value and '\n' not in value and not value.startswith('-----') and (os.path.isabs(value) or os.path.exists(os.path.join(source_home,value))):
                            node[key] = local_copy(value)
                        else: certificates(value)
                elif isinstance(node,list):
                    for value in node: certificates(value)
            certificates(document)
            candidate = json.dumps(document).encode()
            process = execute([request['binary'],'-t','-d',stage,'-f','-'], input=candidate, timeout=30)
            if process.returncode: fail('isolated Mihomo validation failed; source was not modified')
    except subprocess.TimeoutExpired: fail('Mihomo validation timed out; source was not modified')
    return {}

try:
    request=json.load(sys.stdin)
    operation=request['op']
    if operation=='read': result=read(request['path'])
    elif operation=='write': result=write(request)
    elif operation=='check': guards_match(request['guards']); result={}
    elif operation=='validate': result=validate(request)
    else: fail('unknown rule host operation')
    print(json.dumps({'file':result}))
except ValueError as error:
    print(json.dumps({'error':str(error)}))
except Exception:
    # Files, configuration content and child stderr may contain credentials.
    print(json.dumps({'error':'host file operation failed; check permissions, Python and explicitly bound paths'}))
