import hashlib, json, os, re, shlex, stat, subprocess, sys, tempfile

def fail(message): raise ValueError(message)
def hashed(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def run(args, data=None):
    env=dict(os.environ); env.pop('DOCKER_HOST',None); env.pop('DOCKER_CONTEXT',None)
    p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,env=env)
    if p.returncode: fail('Service command failed; inspect the bound owner and permissions before retrying')
    return p.stdout

def regular(path,limit=2<<20):
    st=os.lstat(path)
    if not stat.S_ISREG(st.st_mode): fail('Service source is not an ordinary file')
    with open(path,'rb') as f: data=f.read(limit+1)
    if len(data)>limit: fail('Service source exceeds the size limit')
    return data,st

def unix_host(value):
    return isinstance(value,str) and value.startswith('unix:///') and value!='unix:///' and not any(c in value for c in ('\n','\r','\x00','?','#','%'))

def compose_restart(raw,service,new=None):
    # Preserve original bytes/comments. Refuse complex YAML rather than flattening it.
    text=raw.decode('utf-8'); lines=text.splitlines(True)
    services=[i for i,line in enumerate(lines) if re.match(r'^services:\s*(?:#.*)?$',line.rstrip('\r\n'))]
    if len(services)!=1: return None,None
    start=services[0]+1; end=len(lines)
    for i in range(start,len(lines)):
        if lines[i].strip() and not lines[i].lstrip().startswith('#') and not lines[i][0].isspace(): end=i;break
    matches=[]
    for i in range(start,end):
        m=re.match(r'^( +)(?:'+re.escape(service)+r'|"'+re.escape(service)+r'"|\''+re.escape(service)+r'\'):\s*(?:#.*)?$',lines[i].rstrip('\r\n'))
        if m: matches.append((i,len(m.group(1))))
    if len(matches)!=1:return None,None
    first,indent=matches[0]; last=end
    for i in range(first+1,end):
        line=lines[i]
        if line.strip() and not line.lstrip().startswith('#') and len(line)-len(line.lstrip())<=indent:last=i;break
    candidates=[]
    for i in range(first+1,last):
        line=lines[i]
        if re.match(r'^ +(?:<<|extends|include):',line):return None,None
        m=re.match(r'^( +)restart:\s*([A-Za-z0-9:_-]+|"[A-Za-z0-9:_-]+"|\'[A-Za-z0-9:_-]+\')(\s*(?:#.*)?)(\r?\n)?$',line)
        if m and len(m.group(1))==indent+2:candidates.append((i,m))
    if len(candidates)>1:return None,None
    if candidates:
        i,m=candidates[0]; old=m.group(2).strip('"\'')
        if new is not None:lines[i]=m.group(1)+'restart: "'+new+'"'+m.group(3)+(m.group(4) or '')
    else:
        # Insertion is safe only for an ordinary block mapping.
        for line in lines[first+1:last]:
            if line.strip() and not line.lstrip().startswith('#') and len(line)-len(line.lstrip())<indent+2:return None,None
        old='no'
        if new is not None:lines.insert(first+1,' '*(indent+2)+'restart: "'+new+'"\n')
    return old,''.join(lines).encode()

r=json.load(sys.stdin); b=r['service']; op=r['op']; backup=''

def docker(*args,**kw):return run(['docker','--host',b['docker_host']]+list(args),kw.get('data'))

def inspect_docker():
    if not unix_host(b.get('docker_host')):fail('Docker service requires an explicit local unix socket')
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$',b.get('container','')):fail('Invalid Docker container identity')
    items=json.loads(docker('inspect',b['container']))
    if len(items)!=1:fail('Docker container identity is ambiguous')
    item=items[0]; labels=item.get('Config',{}).get('Labels') or {}
    mounts=sorted([{k:m.get(k) for k in ('Type','Source','Destination','RW','Propagation')} for m in item.get('Mounts',[])],key=lambda m:(str(m['Destination']),str(m['Source'])))
    binding={'kind':'docker','docker_host':b['docker_host'],'container':item['Id'],'image':item['Image'],'mounts_sha256':hashed(canonical(mounts))}
    compose=labels.get('com.docker.compose.project.config_files','')
    if compose:
        if ',' in compose or not os.path.isabs(compose):fail('Binding requires one explicit Compose source file')
        binding.update(compose_file=compose,compose_project=labels.get('com.docker.compose.project',''),compose_service=labels.get('com.docker.compose.service',''))
    status={'binding':binding,'running':bool(item['State'].get('Running')),'state':item['State'].get('Status','unknown'),'restart_policy':item['HostConfig'].get('RestartPolicy',{}).get('Name','no')}
    status['autostart']=status['restart_policy'] in ('always','unless-stopped')
    if compose:
        raw,_=regular(compose); old,_=compose_restart(raw,binding['compose_service'])
        status.update(compose_sha256=hashed(raw),compose_restart=old or '',compose_editable=old is not None)
    # Include port/network bindings without emitting credentials or command/env fields.
    guard=dict(status);guard['ports']=item['HostConfig'].get('PortBindings');guard['network']=item['HostConfig'].get('NetworkMode')
    status['state_digest']=hashed(canonical(guard))
    return status,item

def systemctl(*args):return run(['systemctl','--'+b['scope'],'--no-pager']+list(args))

def inspect_systemd():
    if b.get('scope') not in ('user','system') or not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.@-]*\.service$',b.get('unit','')):fail('Invalid systemd scope or service unit')
    names=['Id','LoadState','ActiveState','SubState','UnitFileState','FragmentPath','DropInPaths','NeedDaemonReload']
    raw=systemctl('show',b['unit'],'--property='+','.join(names)).decode()
    props=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
    if props.get('LoadState')!='loaded' or not props.get('FragmentPath'):fail('systemd service is not loaded from an inspected unit file')
    if props.get('NeedDaemonReload')=='yes':fail('Systemd unit files changed without daemon-reload; inspect the existing owner before binding')
    fragment=os.path.realpath(props['FragmentPath']); files=[]
    for path in [fragment]+shlex.split(props.get('DropInPaths','')):
        data,_=regular(path);files.append((path,hashed(data)))
    binding={'kind':'systemd','unit':props['Id'],'scope':b['scope'],'fragment_path':fragment,'unit_sha256':hashed(canonical(files))}
    status={'binding':binding,'running':props.get('ActiveState')=='active','state':props.get('ActiveState','unknown')+'/'+props.get('SubState','unknown'),'autostart':props.get('UnitFileState') in ('enabled','enabled-runtime'),'restart_policy':props.get('UnitFileState','unknown')}
    status['state_digest']=hashed(canonical(status));return status,None

def inspected():
    if b.get('kind')=='docker':return inspect_docker()
    if b.get('kind')=='systemd':return inspect_systemd()
    fail('Unknown existing service kind')

def pinned(status):
    if op!='bind' and status['binding']!={k:v for k,v in b.items() if v!=''}:fail('Existing service identity changed; rebind after inspection')

def check_expected(status):
    if not r.get('expected') or status['state_digest']!=r['expected']:fail('Service state changed since preview; no action taken')

def update_compose(status,policy):
    global backup
    path=status['binding'].get('compose_file')
    if not path:return
    raw,st=regular(path)
    if hashed(raw)!=status['compose_sha256']:fail('Compose source changed after preview')
    old,changed=compose_restart(raw,status['binding']['compose_service'],policy)
    if old is None:fail('Compose restart source requires manual inspection')
    if raw==changed:return
    root=os.path.join(os.path.expanduser('~'),'.local','state','lazyclash','service-backups')
    os.makedirs(root,mode=0o700,exist_ok=True)
    info=os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_mode&0o077:fail('Service backup directory must be private')
    fd,backup=tempfile.mkstemp(prefix='compose-',suffix='.yaml',dir=root)
    with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    fd,tmp=tempfile.mkstemp(prefix='.lazyclash-service-',dir=os.path.dirname(path))
    try:
        with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));f.write(changed);f.flush();os.fsync(f.fileno())
        current,now=regular(path)
        if hashed(current)!=status['compose_sha256'] or (st.st_dev,st.st_ino)!=(now.st_dev,now.st_ino):fail('Compose source changed before save')
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def source_status(status,item):
    host=r.get('source_path','');core=r.get('core_path','');expected=r.get('source_sha256','')
    if not os.path.isabs(host) or not os.path.isabs(core) or not re.match(r'^[a-f0-9]{64}$',expected):fail('Source verification requires absolute paths and the reviewed SHA256')
    if r.get('source_container'):
        other=json.loads(docker('inspect',r['source_container']))
        if len(other)!=1 or other[0]['Id']!=item['Id']:fail('Config source and service refer to different containers')
    matched=False; single=False
    for mount in item.get('Mounts',[]):
        rel=os.path.relpath(core,mount['Destination'])
        if mount.get('Type')=='bind' and rel!='..' and not rel.startswith('../') and os.path.realpath(os.path.join(mount['Source'],rel))==os.path.realpath(host):matched=True;single=rel=='.'
    if not matched:fail('Source path does not map to the bound container path')
    raw,_=regular(host,8<<20)
    if hashed(raw)!=expected:fail('Saved source changed before owner activation')
    inside=docker('exec',item['Id'],'cat',core)
    if len(inside)>8<<20:fail('Container configuration exceeds the size limit')
    status['source_matches']=hashed(inside)==expected;status['source_single_file']=single

try:
    status,item=inspected();pinned(status)
    if op in ('bind','status'):pass
    elif op=='source-status':
        if b['kind']!='docker':fail('Source verification requires Docker')
        source_status(status,item)
    elif op in ('start','stop','restart','enable','disable'):
        check_expected(status)
        if r.get('source_sha256'):
            if b['kind']!='docker':fail('Source activation requires Docker')
            source_status(status,item)
        if b['kind']=='docker':
            cid=status['binding']['container']
            if op in ('enable','disable') or r.get('disable_autostart'):
                policy='unless-stopped' if op=='enable' else 'no'
                update_compose(status,policy)
                docker('update','--restart='+policy,cid)
            if op in ('start','stop','restart'):
                args=[op]
                if op!='start':args+=['--time','10']
                docker(*(args+[cid]))
        else:
            if op=='stop' and r.get('disable_autostart'):systemctl('disable',b['unit'])
            systemctl(op,b['unit'])
        status,_=inspected();pinned(status)
        if op in ('start','restart') and not status['running']:fail('Service start was not observed')
        if op=='stop' and status['running']:fail('Service stop was not observed')
        if (op=='disable' or r.get('disable_autostart')) and (status['autostart'] or (b['kind']=='docker' and (status['restart_policy']!='no' or (status['binding'].get('compose_file') and status.get('compose_restart')!='no')))):fail('Service autostart disable was not observed')
        if op=='enable' and not status['autostart']:fail('Service autostart enable was not observed')
    else:fail('Unknown existing service action')
    if backup:status['backup_path']=backup
    print(json.dumps(status))
except ValueError as e:print(json.dumps({'error':str(e),'backup_path':backup}))
except Exception:print(json.dumps({'error':'Existing service inspection or action failed; inspect the saved receipt before retrying','backup_path':backup}))
