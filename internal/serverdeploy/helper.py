# Fixed helper. Requests are data on stdin, never shell fragments.
import hashlib, io, json, os, pathlib, platform, re, shutil, socket, ssl, subprocess, sys, tempfile, time, urllib.request, zipfile

BASE = pathlib.Path('/var/lib/lazyclash/servers')
ALLOWED = {'config.json', 'config.yaml', 'nginx.conf', 'compose.yaml', 'service.unit', 'nginx.unit'}

class Failure(Exception): pass
def fail(message): raise Failure(message)
def run(args, check=True, timeout=120):
    p = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    if check and p.returncode: fail('host command failed during '+phase+'; correct prerequisites and resume')
    return p
def private_write(path, data, mode=0o600):
    path=pathlib.Path(path)
    if path.is_symlink(): fail('refusing a symlink in an owned path')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd,tmp=tempfile.mkstemp(prefix='.lazyclash-',dir=str(path.parent))
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f: f.write(data.encode() if isinstance(data,str) else data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
def save(): private_write(root/'manifest.json',json.dumps(manifest))
def unit(tls=False): return 'lazyclash-server-'+ident+('-tls' if tls else '')+'.service'
def compose(*args): return ['docker','compose','--project-name','lazyclash-'+ident,'--file',str(root/'compose.yaml'),*args]
def owned():
    if not manifest or manifest.get('token')!=req.get('token'): fail('owned deployment manifest does not match this operation')
def container_ownership():
    if r['backend']!='compose' or not shutil.which('docker'):return
    result=run(['docker','ps','-aq','--filter','label=com.docker.compose.project=lazyclash-'+ident],False)
    if result.returncode:fail('Docker daemon is not available')
    ids=result.stdout.decode().split()
    if ids and not manifest:fail('a Docker Compose project with this deployment name already exists')
    if ids:
        objects=json.loads(run(['docker','inspect',*ids]).stdout)
        for obj in objects:
            labels=obj.get('Config',{}).get('Labels',{}) or {}
            if labels.get('io.lazyclash.owner')!=req['token']:fail('Docker project contains a container owned by another operation')
def check_files():
    owned()
    for path,digest in manifest.get('file_hashes',{}).items():
        p=pathlib.Path(path)
        if p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:fail('an owned service file changed; restore it before a lifecycle action')
    container_ownership()
def record(path):
    p=pathlib.Path(path)
    manifest.setdefault('file_hashes',{})[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest();save()
def check_ports():
    sockets=[]
    ports=[(r['listen_port'],socket.SOCK_DGRAM if r['recipe']=='hysteria2' else socket.SOCK_STREAM)]
    if r['recipe']!='vless-reality': ports.append((80,socket.SOCK_STREAM))
    if r['recipe']=='legacy-vmess-ws-tls': ports.append((inner_port(),socket.SOCK_STREAM))
    try:
        for port,kind in ports:
            s=socket.socket(socket.AF_INET,kind);sockets.append(s)
            try:s.bind(('0.0.0.0',port))
            except OSError:fail('a required TCP/UDP port is already occupied')
            if socket.has_ipv6:
                s6=socket.socket(socket.AF_INET6,kind);sockets.append(s6)
                s6.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                try:s6.bind(('::',port))
                except OSError:fail('a required IPv6 TCP/UDP port is already occupied or unavailable')
    finally:
        for s in sockets:s.close()
def inner_port(): return 10000+int.from_bytes(hashlib.sha256(ident.encode()).digest()[:2],'big')%40000
def inspect():
    osr={}
    for line in pathlib.Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);osr[k]=v.strip('"')
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),'unsupported')
    if osr.get('ID')!='ubuntu' or osr.get('VERSION_ID')!='24.04':fail('server deployment currently requires Ubuntu 24.04 LTS')
    if arch=='unsupported':fail('server CPU architecture is not supported')
    if not shutil.which('systemctl'):fail('systemd is required')
    if r['backend']=='compose' and not req.get('allow_install'):
        if not shutil.which('docker') or run(['docker','compose','version'],False).returncode:fail('existing SSH hosts must install Docker and Compose before deployment')
    if root.is_symlink() or BASE.is_symlink() or BASE.parent.is_symlink():fail('owned server directories must not be symlinks')
    if root.exists() and not manifest:fail('deployment path exists without an owned manifest')
    if manifest:owned()
    container_ownership()
    if not manifest:
        check_ports()
        for u in [unit(),unit(True)]:
            if pathlib.Path('/etc/systemd/system',u).exists():fail('a service with this deployment name already exists')
    if r['recipe']=='vless-reality':
        try:
            host,port=r['reality_target'].rsplit(':',1)
            context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(['h2','http/1.1'])
            with socket.create_connection((host.strip('[]'),int(port)),timeout=8) as sock:
                with context.wrap_socket(sock,server_hostname=r['server_name']) as tls:
                    if tls.version()!='TLSv1.3' or tls.selected_alpn_protocol()!='h2':fail('REALITY target must support TLS 1.3 and HTTP/2')
        except (OSError,ValueError):fail('REALITY target TLS handshake failed from the server')
    if r['recipe']!='vless-reality':
        try:
            domain_ips={x[4][0] for x in socket.getaddrinfo(r['domain'],None)}
            endpoint_ips={x[4][0] for x in socket.getaddrinfo(r['public_host'],None)}
        except OSError:fail('cannot resolve certificate domain or public endpoint')
        if not domain_ips.intersection(endpoint_ips):fail('certificate domain DNS does not match the public endpoint')
        cert_dir=pathlib.Path('/etc/letsencrypt/live','lazyclash-'+ident)
        if cert_dir.exists() and not manifest:fail('certificate name is already in use')
    warnings=['Open the recipe port in cloud and host firewalls; TCP 80 must remain reachable for ACME renewal.'] if r['recipe']!='vless-reality' else ['Open the recipe TCP port in cloud and host firewalls.']
    if shutil.which('ufw') and b'Status: active' in run(['ufw','status'],False).stdout:warnings.append('UFW is active; explicitly allow '+str(r['listen_port'])+('/udp' if r['recipe']=='hysteria2' else '/tcp')+' before proxy verification.')
    return {'ok':True,'arch':arch,'os':'ubuntu-24.04','owned':bool(manifest),'warnings':warnings}
def completed(step,fn):
    global phase
    phase=step
    if step not in manifest['completed']:
        fn();manifest['completed'].append(step);save()
def packages():
    wanted=[]
    if r['backend']=='compose' and not shutil.which('docker'):wanted+=['docker.io','docker-compose-v2']
    elif r['backend']=='compose' and run(['docker','compose','version'],False).returncode:wanted+=['docker-compose-v2']
    if r['recipe']!='vless-reality' and not shutil.which('certbot'):wanted+=['certbot']
    add_nginx=r['recipe']=='legacy-vmess-ws-tls' and r['backend']=='native' and not pathlib.Path('/usr/sbin/nginx').exists()
    if add_nginx:wanted+=['nginx']
    if wanted:
        run(['apt-get','update'],timeout=600)
        run(['apt-get','install','-y','--no-install-recommends',*wanted],timeout=900)
    if add_nginx:run(['systemctl','disable','--now','nginx.service'])
    if r['backend']=='compose':run(['systemctl','enable','--now','docker.service'])
def acquire():
    if r['backend']=='compose':
        for image in [a.get('image'),a.get('nginx_image')]:
            if image:
                if not re.fullmatch(r'(ghcr\.io/xtls/xray-core|docker\.io/tobyxdd/hysteria|docker\.io/library/nginx)@sha256:[a-f0-9]{64}',image):fail('container image is not an approved pinned source')
                run(['docker','pull',image],timeout=900)
        return
    address=a.get('url','');digest=a.get('sha256','')
    official=re.fullmatch(r'https://github\.com/XTLS/Xray-core/releases/download/[^\s]+',address) or re.fullmatch(r'https://download\.hysteria\.network/app/v[0-9][A-Za-z0-9./-]+',address)
    if not official or not re.fullmatch('[a-f0-9]{64}',digest):fail('binary is not an approved pinned source')
    with urllib.request.urlopen(address,timeout=120) as response:
        data=response.read(150*1024*1024+1)
    if len(data)>150*1024*1024 or hashlib.sha256(data).hexdigest()!=digest:fail('binary download SHA256 verification failed')
    binary='hysteria' if r['recipe']=='hysteria2' else 'xray'
    if binary=='xray':
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            info=z.getinfo('xray')
            if info.file_size>150*1024*1024:fail('binary exceeds size limit')
            data=z.read(info)
    private_write(root/'bin'/binary,data,0o755)
    record(root/'bin'/binary)
def certificate():
    if r['recipe']=='vless-reality':return
    args=['certbot','certonly','--standalone','--preferred-challenges','http','--non-interactive','--agree-tos','--keep-until-expiring','--cert-name','lazyclash-'+ident,'-d',r['domain']]
    if r.get('email'):args+=['--email',r['email']]
    else:args+=['--register-unsafely-without-email']
    run(args,timeout=300)
    # Certbot renewals call the fixed, instance-owned service restart hook.
    hook='#!/bin/sh\nset -eu\n[ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/lazyclash-'+ident+'" ] || exit 0\n'
    if r['backend']=='compose':
        prefix='docker compose --project-name lazyclash-'+ident+' --file '+str(root/'compose.yaml')
        hook+='[ -n "$('+prefix+' ps --status running --quiet)" ] || exit 0\n'+prefix+' restart\n'
    else:
        hook+='systemctl try-restart '+unit()+'\n'
        if r['recipe']=='legacy-vmess-ws-tls':hook+='systemctl try-restart '+unit(True)+'\n'
    private_write('/etc/letsencrypt/renewal-hooks/deploy/lazyclash-'+ident,hook,0o700)
    record('/etc/letsencrypt/renewal-hooks/deploy/lazyclash-'+ident)
    run(['systemctl','enable','--now','certbot.timer'])
def configure():
    for name,data in req.get('files',{}).items():
        if name not in ALLOWED or not isinstance(data,str) or len(data)>1024*1024:fail('configuration file request is invalid')
        private_write(root/name,data)
        record(root/name)
    if r['backend']=='native':
        private_write('/etc/systemd/system/'+unit(),req['files']['service.unit'],0o644)
        record('/etc/systemd/system/'+unit())
        if r['recipe']=='legacy-vmess-ws-tls':
            private_write('/etc/systemd/system/'+unit(True),req['files']['nginx.unit'],0o644)
            record('/etc/systemd/system/'+unit(True))
        run(['systemctl','daemon-reload'])
def validate():
    if r['backend']=='native':
        if r['recipe']!='hysteria2':run([str(root/'bin/xray'),'run','-test','-config',str(root/'config.json')])
        if r['recipe']=='legacy-vmess-ws-tls':run(['/usr/sbin/nginx','-t','-c',str(root/'nginx.conf')])
    else:
        run(compose('config','--quiet'))
        if r['recipe']!='hysteria2':run(compose('run','--rm','--no-deps','core','run','-test','-config',str(root/'config.json')),timeout=180)
        if r['recipe']=='legacy-vmess-ws-tls':run(compose('run','--rm','--no-deps','tls','-t','-c',str(root/'nginx.conf')),timeout=180)
def lifecycle(action):
    owned()
    check_files()
    if action=='remove':
        tracked=set(manifest.get('file_hashes',{}))|{str(root/'manifest.json'),str(root/'nginx.pid')}
        for directory,dirs,names in os.walk(root):
            for name in names:
                p=pathlib.Path(directory,name)
                if p.is_symlink() or str(p) not in tracked:fail('deployment directory contains untracked files; preserve them before removal')
            for name in dirs:
                p=pathlib.Path(directory,name)
                if p.is_symlink() or str(p)!=str(root/'bin'):fail('deployment directory contains an untracked directory')
    if r['backend']=='compose':
        command={'start':['up','-d'],'stop':['stop'],'restart':['restart'],'remove':['down']}[action]
        run(compose(*command),timeout=180)
    else:
        units=[unit()]+([unit(True)] if r['recipe']=='legacy-vmess-ws-tls' else [])
        if action=='start':run(['systemctl','enable','--now',*units])
        elif action=='remove':run(['systemctl','disable','--now',*units],False)
        else:run(['systemctl',action,*units])
    if action=='remove':
        if r['backend']=='native':
            for u in [unit(),unit(True)]:
                p=pathlib.Path('/etc/systemd/system',u)
                if p.exists():p.unlink()
            run(['systemctl','daemon-reload'])
        if r['recipe']!='vless-reality':
            p=pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/lazyclash-'+ident)
            if p.exists():p.unlink()
            run(['certbot','delete','--non-interactive','--cert-name','lazyclash-'+ident])
        shutil.rmtree(root)
def status():
    if not manifest:return {'ok':True,'service':'absent'}
    owned()
    if r['backend']=='compose':
        result=run(compose('ps','--format','json'),False)
        if result.returncode:return {'ok':True,'service':'unknown','owned':True}
        states=[]
        try:
            raw=result.stdout.decode().strip()
            entries=json.loads(raw) if raw.startswith('[') else [json.loads(line) for line in raw.splitlines() if line]
            states=[entry.get('State') for entry in entries]
        except (ValueError,TypeError):pass
        needed=2 if r['recipe']=='legacy-vmess-ws-tls' else 1
        active=len(states)==needed and all(x=='running' for x in states)
    else:
        units=[unit()]+([unit(True)] if r['recipe']=='legacy-vmess-ws-tls' else [])
        active=all(run(['systemctl','is-active','--quiet',u],False).returncode==0 for u in units)
    return {'ok':True,'service':'running' if active else 'stopped','owned':True}

phase='preflight'
try:
    req=json.load(sys.stdin);ident=req.get('id','');r=req.get('request',{});a=req.get('artifact',{})
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,47}',ident):fail('invalid deployment ID')
    if req.get('op') not in {'inspect','deploy','status','start','stop','restart','remove','backup'}:fail('unsupported server operation')
    if r.get('id')!=ident or r.get('recipe') not in {'vless-reality','hysteria2','legacy-vmess-ws-tls'} or r.get('backend') not in {'native','compose'}:fail('invalid deployment request')
    if not re.fullmatch('[a-f0-9]{64}',req.get('token','')):fail('invalid operation ownership token')
    root=BASE/ident
    if root.is_symlink() or BASE.is_symlink() or BASE.parent.is_symlink():fail('server paths must not be symlinks')
    manifest_path=root/'manifest.json'
    if manifest_path.is_symlink():fail('manifest must not be a symlink')
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else None
    if manifest:owned()
    if req['op']=='inspect':out=inspect()
    elif req['op']=='status':out=status()
    elif req['op']=='backup':
        owned();certificates={}
        if r['recipe']!='vless-reality':
            for name in ['fullchain.pem','privkey.pem']:
                p=pathlib.Path('/etc/letsencrypt/live','lazyclash-'+ident,name)
                if not p.exists() or p.stat().st_size>65536:fail('issued TLS certificate is missing or invalid')
                expected=pathlib.Path('/etc/letsencrypt/archive','lazyclash-'+ident)
                if not p.resolve().is_relative_to(expected):fail('issued TLS path no longer belongs to this deployment')
                content=p.read_text()
                if not content.startswith('-----BEGIN '):fail('issued TLS file is not PEM data')
                certificates[name]=content
        out={'ok':True,'certificate_files':certificates}
    elif req['op']=='deploy':
        observation=inspect()
        if observation['arch']!=a.get('arch'):fail('host architecture changed since preview')
        fingerprint=hashlib.sha256(json.dumps({'request':r,'artifact':a,'files':req.get('files')},sort_keys=True).encode()).hexdigest()
        if manifest and manifest.get('fingerprint')!=fingerprint:fail('deployment inputs differ from the owned operation')
        if not manifest:
            BASE.mkdir(parents=True,exist_ok=True,mode=0o700);root.mkdir(mode=0o700)
            manifest={'token':req['token'],'fingerprint':fingerprint,'completed':[]};save()
        completed('packages',packages)
        completed('artifact',acquire)
        completed('certificate',certificate)
        completed('configuration',configure)
        completed('validation',validate)
        phase='start';lifecycle('start')
        if 'start' not in manifest['completed']:manifest['completed'].append('start');save()
        time.sleep(1)
        out=status()
        if out['service']!='running':fail('service did not remain running; correct the host prerequisites and resume')
    else:
        if req['op']=='remove' and not manifest:out={'ok':True,'service':'absent'}
        else:lifecycle(req['op']);out={'ok':True,'service':'absent'} if req['op']=='remove' else status()
    print(json.dumps(out))
except Failure as e:print(json.dumps({'ok':False,'error':str(e)}))
except Exception:print(json.dumps({'ok':False,'error':'host operation failed during '+phase+'; inspect prerequisites and resume'}))
