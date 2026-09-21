import base64,fcntl,hashlib,http.client,ipaddress,json,os,pathlib,platform,pwd,re,secrets,shutil,socket,stat,subprocess,sys,tempfile,time,urllib.parse

def fail(message): raise RuntimeError(message)
def digest(value): return hashlib.sha256(value).hexdigest()
def run(args, timeout=20):
    env={k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy')}
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env=env)
    if p.returncode: fail('command failed: '+pathlib.Path(args[0]).name+' '+('authorization may be required' if b'permission' in p.stderr.lower() or b'access denied' in p.stderr.lower() else 'operation was not confirmed'))
    if len(p.stdout)>2<<20:fail('command output exceeded limit')
    return p.stdout

def ts_path():
    path=shutil.which('tailscale')
    if not path:fail('Tailscale is not installed; join this device before managing it')
    if os.geteuid()==0:
        p=pathlib.Path(path).resolve()
        for v in [p,*p.parents]:
            s=v.stat()
            if s.st_uid!=0 or s.st_mode&0o022:fail('privileged Tailscale executable is not root-owned')
    return path

def ts(*args):return run([ts_path(),*args])
def pref(name):
    data=json.loads(ts('get','--json',name))
    if name not in data:fail('Tailscale does not support named preference reads; upgrade it')
    return data[name]

def peer(p):
    return {'id':p.get('ID',''),'hostname':p.get('HostName',''),'dns_name':p.get('DNSName',''),'os':p.get('OS',''),'ips':p.get('TailscaleIPs') or [],'online':bool(p.get('Online')),'exit_available':bool(p.get('ExitNodeOption')),'selected':bool(p.get('ExitNode')),'connection':'direct' if p.get('CurAddr') else ('relay' if p.get('Relay') else 'unknown')}

def controller_request(controller,secret,method='GET',path='/configs',body=None):
    u=urllib.parse.urlsplit(controller)
    if u.scheme=='unix':
        if not u.path.startswith('/') or u.netloc:fail('invalid local controller socket')
        class UnixConnection(http.client.HTTPConnection):
            def connect(self):
                self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(u.path)
        conn=UnixConnection('localhost',timeout=5)
    else:
        try:loopback=ipaddress.ip_address(u.hostname).is_loopback
        except ValueError:loopback=u.hostname=='localhost'
        if u.scheme not in ('http','https') or not loopback or u.username or u.password or u.path not in ('','/'):fail('controller must be a local loopback URL or Unix socket')
        conn=(http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection)(u.hostname,u.port,timeout=5)
    headers={'Content-Type':'application/json'}
    if secret:headers['Authorization']='Bearer '+secret
    try:
        conn.request(method,path,json.dumps(body) if body is not None else None,headers)
        r=conn.getresponse();data=r.read(1<<20)
        if r.status not in (200,204):fail('local controller rejected runtime TUN request')
        return json.loads(data) if data else {}
    finally:conn.close()

def core_snapshot(r):
    c=r.get('controller','')
    if not c:return {}
    v=controller_request(c,r.get('secret',''),path='/version')
    if not isinstance(v.get('version'),str) or not v['version']:fail('controller identity could not be established')
    config=controller_request(c,r.get('secret',''));tun=config.get('tun') or {}
    if not isinstance(tun,dict) or not isinstance(tun.get('enable'),bool):fail('controller did not report its TUN state')
    # Bind the receipt to the actual listener process. Socket inode alone may
    # survive a core restart and must never authorize restoring its TUN.
    u=urllib.parse.urlsplit(c);args=['lsof','-nP','-t']
    if u.scheme=='unix':args+=[u.path]
    else:args+=['-iTCP:'+str(u.port or (443 if u.scheme=='https' else 80)),'-sTCP:LISTEN']
    try:ids=sorted(set(run(args,5).decode().split()))
    except Exception:ids=[]
    socket_identity=''
    if not ids and u.scheme=='unix':
        # macOS hides root-owned listeners from unprivileged lsof. A unique
        # Mihomo process explicitly naming this exact Unix controller, plus
        # socket generation, provides independently readable process evidence.
        pattern=re.compile(r'(?:^|\s)-ext-ctl-unix\s+'+re.escape(u.path)+r'(?:\s|$)')
        candidates=[]
        for line in run(['ps','-axo','pid=,args='],5).decode().splitlines():
            parts=line.strip().split(None,1)
            if len(parts)==2 and parts[0].isdigit() and pattern.search(parts[1]):
                name=run(['ps','-p',parts[0],'-o','comm='],5).decode().strip()
                if pathlib.Path(name).name in ('mihomo','verge-mihomo','clash','clash-meta'):candidates.append(parts[0])
        ids=sorted(set(candidates))
        info=os.stat(u.path)
        if not stat.S_ISSOCK(info.st_mode):fail('controller path is not a Unix socket')
        socket_identity=':'+str(info.st_dev)+':'+str(info.st_ino)+':'+str(info.st_ctime_ns)
    if len(ids)!=1 or not ids[0].isdigit():fail('could not identify one local controller process for safe TUN restoration; use its Unix socket when the OS hides a privileged TCP listener')
    pid=ids[0];identity=run(['ps','-p',pid,'-o','lstart=','-o','comm='],5).decode().strip()+socket_identity
    if not identity:fail('local controller process disappeared')
    return {'enabled':tun['enable'],'device':tun.get('device',''),'identity':pid+':'+identity,'config_hash':digest(json.dumps(config,sort_keys=True,separators=(',',':')).encode()),'tun':tun,'config':config}

def inspect(r):
    status=json.loads(ts('status','--json'))
    if status.get('BackendState')!='Running':fail('Tailscale is not running and joined on this host')
    me=peer(status.get('Self') or {})
    if not me['id'] or not me['ips']:fail('Tailscale did not report a stable peer identity')
    prefs={'exit_node':pref('exit-node'),'allow_lan':pref('exit-node-allow-lan-access'),'advertise':pref('advertise-exit-node')}
    forwarding={}
    if platform.system()=='Linux':
        for k,p in [('ipv4','/proc/sys/net/ipv4/ip_forward'),('ipv6','/proc/sys/net/ipv6/conf/all/forwarding')]:
            try:forwarding[k]=pathlib.Path(p).read_text().strip()
            except OSError:forwarding[k]='unavailable'
    return {'self':me,'peers':sorted([peer(p) for p in (status.get('Peer') or {}).values()],key=lambda p:p['id']),'prefs':prefs,'forwarding':forwarding,'os':platform.system().lower(),'core':core_snapshot(r)}

def probe(r):
    base=['curl','-4','--fail','--silent','--show-error','--max-time','18','--connect-timeout','7']
    args=base+(['--proxy',r['probe_proxy']] if r.get('probe_proxy') else ['--noproxy','*'])
    body=run(args+['https://www.cloudflare.com/cdn-cgi/trace'],22).decode()
    fields=dict(line.split('=',1) for line in body.splitlines() if '=' in line)
    ip=fields.get('ip','')
    try:ipaddress.ip_address(ip)
    except ValueError:fail('HTTPS egress probe returned no valid public IP')
    code=run(args+['-o',os.devnull,'-w','%{http_code}','https://www.google.com/generate_204'],22).decode()
    if code!='204':fail('external HTTPS reachability probe did not return 204')
    # This exercises the host resolver independently from curl's HTTPS path.
    run([sys.executable,'-I','-c',"import socket;socket.getaddrinfo('www.cloudflare.com',443,type=socket.SOCK_STREAM)"],8)
    return {'ip':ip,'dns':True,'https':True}

def atomic(path,data,mode=0o600):
    path=pathlib.Path(path);fd,tmp=tempfile.mkstemp(prefix='.tailnet-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def read_regular(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size>2<<20:fail('unsafe private state')
    return path.read_bytes()

def root_for(r, privileged=False):
    scope=r.get('scope','');ident=r.get('id','selection')
    if not re.fullmatch('[a-f0-9]{24}',scope) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',ident):fail('invalid tailnet state identity')
    if privileged:base=pathlib.Path('/var/lib/lazyclash/tailnet')
    else:
        xdg=os.environ.get('XDG_STATE_HOME','')
        base=(pathlib.Path(xdg) if pathlib.Path(xdg).is_absolute() else pathlib.Path.home()/'.local/state')/'lazyclash/tailnet'
    # Fixtures are honored only when explicitly set by tests and never root.
    if r.get('fixture_root') and os.environ.get('LAZYCLASH_TAILNET_FIXTURE')=='1':base=pathlib.Path(r['fixture_root'])
    return base/scope/ident

def secure_dir(path, public=False):
    path.mkdir(parents=True,exist_ok=True,mode=0o711 if public else 0o700)
    if public:
        # Root-owned ancestors permit traversing only the per-transaction ack
        # and sanitized status; every private state file remains 0600.
        for ancestor in (path,path.parent):
            if ancestor.stat().st_uid==os.geteuid() and not ancestor.is_symlink():os.chmod(ancestor,0o711)
    for p in [path,path.parent]:
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o022:fail('unsafe tailnet state directory')

def lock(path):
    fd=os.open(str(path),os.O_CREAT|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600);f=os.fdopen(fd,'wb');fcntl.flock(f,fcntl.LOCK_EX);return f

def save(directory,state):
    atomic(directory/'state.json',json.dumps(state,sort_keys=True).encode())
    atomic(directory/'status.json',json.dumps({k:state.get(k) for k in ('status','deadline','message')}).encode(),0o644)

def owned(root,r,required=True):
    p=root/'owner.json'
    if not p.exists():
        if required:fail('no owned exit-node setup exists on this host')
        return None
    value=json.loads(read_regular(p))
    if value.get('token')!=r.get('owner_token') or value.get('peer_id')!=r.get('peer_id'):fail('exit-node ownership or peer identity changed')
    return value

def current_matches(r,expected):
    current=inspect(r)
    if current['self']['id']!=expected['self']['id'] or current['prefs']!=expected['prefs'] or current['forwarding']!=expected['forwarding'] or current['core']!=expected['core']:fail('network state changed since preview; refresh before applying')
    return current

def set_pref(name,value):ts('set','--'+name+'='+('true' if value is True else 'false' if value is False else str(value)))

def sysctl_file(r):return pathlib.Path('/etc/sysctl.d/lazyclash-tailnet-'+r['scope']+'-'+r['id']+'.conf')
def sysctl_data():return b'# Managed by lazyclash tailnet exit setup\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n'
def set_forwarding(values):
    for key,name in [('ipv4','net.ipv4.ip_forward'),('ipv6','net.ipv6.conf.all.forwarding')]:
        value=values.get(key)
        if value in ('0','1'):run(['/usr/sbin/sysctl','-w',name+'='+value])

def global_root(r,local):
    if r.get('fixture_root') and os.environ.get('LAZYCLASH_TAILNET_FIXTURE')=='1':return pathlib.Path(r['fixture_root'])/'global'
    return pathlib.Path.home()/'.local/state/lazyclash/tailnet-global' if local else pathlib.Path('/var/lib/lazyclash/tailnet-global')

def claim_path(r,local):return global_root(r,local)/'claim.json'
def check_claim(root,r,local):
    p=claim_path(r,local)
    if not p.exists():return
    claim=json.loads(read_regular(p))
    directory=pathlib.Path(claim['guard']);previous=json.loads(read_regular(directory/'state.json'))
    active=previous['status'] not in ('restored','rolled_back','released_tun_preserved')
    if previous['status']=='acknowledged' and previous['request']['action']=='remove':active=False
    if not active:return
    if str(root)!=claim.get('root'):fail('another inventory owns this host-wide Tailscale operation; release or remove it through its original inventory')
    if previous['status']=='armed':fail('a previous network transaction is still awaiting verification or rollback')
    if previous['status']=='restore_incomplete' and not (local and r['action']=='release'):fail('a previous network transaction requires recovery before another mutation')
    if local and r['action']!='release':fail('an exit selection is already owned; release it before selecting another exit')
    if not local and claim.get('owner_token')!=r.get('owner_token'):fail('host-wide exit ownership changed')

def save_claim(root,r,directory,local):
    atomic(claim_path(r,local),json.dumps({'root':str(root),'guard':str(directory),'owner_token':r.get('owner_token',''),'peer_id':r['peer_id']}).encode())

def restore(directory,state,explicit_release=False):
    r=state['request'];before=state['before'];after=state['after'];errors=[]
    try:
        claim=claim_path(r,state['kind']=='local')
        if claim.exists() and json.loads(read_regular(claim)).get('guard')!=str(directory):fail('a newer transaction owns these host-wide network preferences')
        core_unavailable=False
        try:live=inspect(r)
        except Exception:
            if not explicit_release or state['kind']!='local' or not r.get('controller'):raise
            without_core=dict(r);without_core.pop('controller',None);without_core.pop('secret',None)
            live=inspect(without_core);core_unavailable=True
        if live['self']['id']!=before['self']['id']:fail('Tailscale peer identity changed')
        if any(live['prefs'][k] not in (before['prefs'][k],after['prefs'][k]) for k in before['prefs']):fail('Tailscale preferences were edited after the transaction')
        if state['kind']=='local':
            # Preflight the core identity and complete config before changing any
            # routing. Later user edits are never overwritten during release.
            preserve_core=bool(after.get('core') and (core_unavailable or (live['core']!=after['core'] and live['core']!=before['core'])))
            if preserve_core and not explicit_release:fail('Mihomo restarted or its runtime configuration changed; explicitly release the exit to preserve the changed core, then revalidate its current TUN state')
            set_pref('exit-node',before['prefs']['exit_node'])
            set_pref('exit-node-allow-lan-access',before['prefs']['allow_lan'])
            if not preserve_core and before.get('core') and before['core']['enabled']!=live['core']['enabled']:
                controller_request(r['controller'],r.get('secret',''),'PATCH','/configs',{'tun':{'enable':before['core']['enabled']}})
        else:
            root=directory.parent.parent
            owned(root,r,required=state.get('owner_before') is not None)
            p=sysctl_file(r);current=read_regular(p) if p.exists() else None
            wanted=base64.b64decode(state['file_after']) if state.get('file_after') is not None else None
            original=base64.b64decode(state['file_before']) if state.get('file_before') is not None else None
            if current!=wanted and current!=original:fail('owned forwarding file changed after apply')
            set_pref('advertise-exit-node',before['prefs']['advertise'])
            if original is None:
                if p.exists():p.unlink()
            else:atomic(p,original,0o644)
            if any(live['forwarding'][k] not in (before['forwarding'][k],after['forwarding'][k]) for k in before['forwarding']):fail('forwarding values changed after apply')
            set_forwarding(before['forwarding'])
            if state.get('owner_before') is None:
                (root/'owner.json').unlink(missing_ok=True)
            else:atomic(root/'owner.json',base64.b64decode(state['owner_before']))
    except Exception as e:errors.append(str(e))
    state['status']='restore_incomplete' if errors else ('released_tun_preserved' if explicit_release and state['kind']=='local' and preserve_core else 'restored')
    state['message']='; '.join(errors) or ('Previous Tailscale exit preferences restored; changed or restarted Mihomo was preserved. Inspect its current TUN setting before selecting an exit again.' if state['status']=='released_tun_preserved' else 'Owned network preferences restored');save(directory,state)
    return {'status':state['status'],'message':state['message']}

def arm(root,r,before,kind):
    guards=root/'guards';secure_dir(guards,kind=='remote')
    directory=guards/secrets.token_hex(16);secure_dir(directory,kind=='remote')
    token=secrets.token_hex(24)
    state={'status':'armed','deadline':int(time.time())+120,'token_hash':digest(token.encode()),'kind':kind,'request':r,'before':before,'after':json.loads(json.dumps(before)),'message':''}
    if kind=='remote':
        p=sysctl_file(r);state['file_before']=base64.b64encode(read_regular(p)).decode() if p.exists() else None;state['file_after']=state['file_before']
        p=root/'owner.json';state['owner_before']=base64.b64encode(read_regular(p)).decode() if p.exists() else None
    save(directory,state);save_claim(root,r,directory,kind=='local');atomic(directory/'worker.py',WORKER_SOURCE.encode())
    ack=directory/'ack';atomic(ack,b'',0o600)
    if os.geteuid()==0:
        os.chown(ack,int(os.environ.get('SUDO_UID',0)),-1)
    try:
        with open(os.devnull,'rb') as src,open(os.devnull,'wb') as sink:
            subprocess.Popen([sys.executable,'-I',str(directory/'worker.py'),str(directory)],stdin=src,stdout=sink,stderr=sink,close_fds=True,start_new_session=True)
    except Exception:
        state['status']='restored';state['message']='Rollback worker failed to start; no network changes were applied';save(directory,state);raise
    return directory,state,token

def apply(r):
    local=r['action'] in ('use','release');root=root_for(r,not local);secure_dir(root,not local)
    global_base=global_root(r,local);secure_dir(global_base)
    with lock(global_base/'operation.lock'):
        check_claim(root,r,local)
        if r['action']=='release':return release(root,r)
        before=current_matches(r,r['expected'])
        if before['self']['id']!=r.get('self_id'):fail('unexpected Tailscale host identity')
        if not local:
            if os.geteuid()!=0:fail('exit-node setup requires administrator authorization')
            if before['os']!='linux':fail('managed exit-node setup currently supports Linux')
            owner=owned(root,r,required=r['action']!='setup')
            if r['action']=='setup' and before['prefs']['advertise'] and not owner:fail('this exit node is already advertised outside lazyclash; ownership was not adopted')
            if not owner and sysctl_file(r).exists():fail('forwarding file exists without a matching ownership receipt')
            if owner and sysctl_file(r).exists() and read_regular(sysctl_file(r))!=sysctl_data():fail('owned forwarding file was externally edited; refusing to overwrite it')
        else:
            selection=root/'selection.json'
            if selection.exists():
                old=json.loads(read_regular(selection));old_state=json.loads(read_regular(pathlib.Path(old['guard'])/'state.json'))
                if old_state['status'] not in ('restored','rolled_back','released_tun_preserved'):fail('an exit selection receipt already exists; release it before selecting another exit')
        directory,state,token=arm(root,r,before,'local' if local else 'remote')
        try:
            with lock(directory/'guard.lock'):
                if local:
                    if before.get('core') and before['core']['enabled']:
                        state['after']['core']['enabled']=False
                        state['after']['core']['tun']['enable']=False
                        state['after']['core']['config']['tun']['enable']=False
                        state['after']['core']['config_hash']=digest(json.dumps(state['after']['core']['config'],sort_keys=True,separators=(',',':')).encode());save(directory,state)
                        controller_request(r['controller'],r.get('secret',''),'PATCH','/configs',{'tun':{'enable':False}})
                        state['after']['core']=core_snapshot(r);save(directory,state)
                        if state['after']['core']['enabled']:fail('Mihomo TUN did not stop')
                    state['after']['prefs']['allow_lan']=r['allow_lan'];save(directory,state);set_pref('exit-node-allow-lan-access',r['allow_lan'])
                    state['after']['prefs']['exit_node']=r['exit_ip'];save(directory,state);set_pref('exit-node',r['exit_ip']);state['after']['prefs']['exit_node']=pref('exit-node');save(directory,state)
                    atomic(root/'selection.json',json.dumps({'guard':str(directory),'id':r['node_id'],'peer_id':r['peer_id']}).encode())
                else:
                    if not owned(root,r,False):atomic(root/'owner.json',json.dumps({'token':r['owner_token'],'peer_id':r['peer_id']}).encode())
                    if r['action']=='setup':
                        data=sysctl_data();state['file_after']=base64.b64encode(data).decode();save(directory,state);atomic(sysctl_file(r),data,0o644)
                        state['after']['forwarding']={'ipv4':'1','ipv6':'1'};save(directory,state);set_forwarding({'ipv4':'1','ipv6':'1'})
                    if r['action']=='enable' and (before['forwarding']!={'ipv4':'1','ipv6':'1'} or not sysctl_file(r).exists() or read_regular(sysctl_file(r))!=sysctl_data()):fail('owned forwarding configuration is missing or changed; run setup to restore it')
                    value=r['action'] in ('setup','enable');state['after']['prefs']['advertise']=value;save(directory,state);set_pref('advertise-exit-node',value)
                    if r['action']=='remove':
                        p=sysctl_file(r)
                        if p.exists():
                            if read_regular(p)!=sysctl_data():fail('forwarding file was externally edited; refusing removal')
                            state['file_after']=None;save(directory,state);p.unlink()
                        # Running forwarding may serve Docker or another router;
                        # removing the owned persistent file does not disable it.
                state['after']=inspect(r);save(directory,state)
        except Exception:
            # Avoid replacing a real failure with rollback diagnostics. The
            # private receipt preserves both outcomes for status inspection.
            restore(directory,state)
            raise
        return {'status':'verification_pending','guard':str(directory),'ack_token':token,'deadline':state['deadline']}

def validate_guard(r):
    p=pathlib.Path(r.get('guard',''));expected=root_for(r,r.get('remote',False))/'guards'
    if p.parent!=expected or not re.fullmatch('[a-f0-9]{32}',p.name):fail('invalid tailnet guard reference')
    if p.is_symlink():fail('tailnet guard cannot be a symlink')
    return p

def ack(r):
    directory=validate_guard(r);token=r.get('ack_token','')
    if not re.fullmatch('[a-f0-9]{48}',token):fail('invalid acknowledgement token')
    fd=os.open(str(directory/'ack'),os.O_WRONLY|os.O_TRUNC|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'wb') as f:f.write(token.encode());f.flush();os.fsync(f.fileno())
    for _ in range(30):
        state=json.loads(read_regular(directory/'status.json'))
        if state['status']!='armed':return state
        time.sleep(.2)
    return {'status':'ack_pending','message':'Rollback acknowledgement has not been confirmed'}

def release(root,r):
    p=root/'selection.json'
    if not p.exists():return {'status':'not_selected','message':'No lazyclash exit selection is active'}
    selected=json.loads(read_regular(p));directory=pathlib.Path(selected['guard'])
    if directory.parent!=root/'guards':fail('invalid saved selection reference')
    with lock(directory/'guard.lock'):
        state=json.loads(read_regular(directory/'state.json'))
        if state['status'] in ('restored','released_tun_preserved'):return {'status':state['status'],'message':state.get('message','')}
        if state['status']=='armed':fail('exit selection verification is still pending')
        result=restore(directory,state,explicit_release=True)
        return result

def selection_status(r):
    root=root_for(r);p=root/'selection.json'
    if not p.exists():return {'status':'not_selected'}
    selected=json.loads(read_regular(p));directory=pathlib.Path(selected['guard'])
    if directory.parent!=root/'guards':fail('invalid saved selection reference')
    state=json.loads(read_regular(directory/'state.json'));result={'status':state['status'],'node_id':selected['id'],'peer_id':selected['peer_id'],'message':state.get('message',''),'tun_paused':bool(state['before'].get('core',{}).get('enabled')) and state['status'] not in ('restored','released_tun_preserved'),'controller':state['request'].get('controller','')}
    if state.get('verified_at'):result['verified_at']=state['verified_at']
    if state['status']=='acknowledged':
        try:
            current=inspect(state['request'])
            if current['prefs']!=state['after']['prefs']:result.update(status='selection_changed',message='Tailscale preferences changed after selection; retained receipt was not overwritten')
            elif current.get('core')!=state['after'].get('core'):result.update(status='tun_handoff_stale',message='Mihomo restarted or changed; revalidate runtime TUN handoff before continuing')
        except Exception:result.update(status='inspection_failed',message='Cannot inspect the saved controller or Tailscale state')
    return result

def worker(reference):
    directory=pathlib.Path(reference)
    try:
        info=(directory/'worker.py').lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:fail('unsafe rollback worker')
        initial=json.loads(read_regular(directory/'state.json'))
        global_base=global_root(initial['request'],initial['kind']=='local')
        while True:
            with lock(global_base/'operation.lock'),lock(directory/'guard.lock'):
                state=json.loads(read_regular(directory/'state.json'))
                if state['status']!='armed':return
                raw=read_regular(directory/'ack')
                if time.time()<state['deadline'] and digest(raw)==state['token_hash']:
                    state['status']='acknowledged';state['verified_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());state['message']='Fresh management and required connectivity checks succeeded';save(directory,state);return
                if time.time()>=state['deadline']:restore(directory,state);return
            time.sleep(.25)
    except Exception:
        try:
            state=json.loads(read_regular(directory/'state.json'));state['status']='restore_incomplete';state['message']='Detached rollback failed; inspect the retained private receipt';save(directory,state)
        except Exception:pass

# TAILNET_ENTRYPOINT
try:
    request=json.load(sys.stdin)
    op=request.get('op')
    if op=='inspect':result=inspect(request)
    elif op=='probe':result=probe(request)
    elif op=='apply':result=apply(request)
    elif op=='ack':result=ack(request)
    elif op=='selection_status':result=selection_status(request)
    else:fail('unsupported tailnet helper operation')
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({'error':str(e)}))
