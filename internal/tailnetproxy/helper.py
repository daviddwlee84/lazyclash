# Fixed, scoped Tailscale Serve helper. No credentials appear in subprocess argv.
import fcntl, hashlib, ipaddress, json, os, pathlib, platform, re, shutil, socket, stat, subprocess, sys, tempfile

def fail(message): raise RuntimeError(message)
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def run(args):
    if os.geteuid()==0:
        binary=pathlib.Path(shutil.which(args[0]) or '/missing').resolve()
        for part in [binary,*binary.parents]:
            st=part.stat()
            if st.st_uid!=0 or st.st_mode&0o022:fail('privileged commands must be root-owned and not writable by other users')
        args=[str(binary),*args[1:]]
    try: p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25)
    except (OSError,subprocess.TimeoutExpired): fail('required host command is unavailable or timed out')
    if p.returncode or len(p.stdout)>2*1024*1024: fail('host command failed; check Tailscale permissions and installation')
    return p.stdout.decode()
def ts(*args): return run(['tailscale',*args])
def root():
    return pathlib.Path('/Library/Application Support/lazyclash/tailnet-proxies' if platform.system()=='Darwin' else '/var/lib/lazyclash/tailnet-proxies')
def private_root(path):
    path.mkdir(parents=True,exist_ok=True,mode=0o755)
    for p in [path,*path.parents]:
        st=p.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:fail('unsafe root-owned proxy ownership directory')
def record(path):
    if not path.exists():return None
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_size>8192:fail('unsafe proxy ownership marker')
    return json.loads(path.read_text())
def write_record(path,value):
    fd,tmp=tempfile.mkstemp(prefix='.tailnet-',dir=path.parent)
    try:
        os.fchmod(fd,0o644)
        with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
def mapping(config,port):
    key=str(port);tcp=(config.get('TCP') or {}).get(key)
    web={k:v for k,v in (config.get('Web') or {}).items() if k.rsplit(':',1)[-1]==key}
    funnel={k:v for k,v in (config.get('AllowFunnel') or {}).items() if v and k.rsplit(':',1)[-1]==key}
    foreground={k:mapping(v,port) for k,v in (config.get('Foreground') or {}).items() if mapping(v,port)}
    if tcp is None and not web and not funnel and not foreground:return ''
    return json.dumps({'TCP':tcp,'Web':web,'Funnel':funnel,'Foreground':foreground},sort_keys=True,separators=(',',':'))
def expected_mapping(port):
    return json.dumps({'TCP':{'TCPForward':'127.0.0.1:'+str(port)},'Web':{},'Funnel':{},'Foreground':{}},sort_keys=True,separators=(',',':'))
def listener_addresses(port,udp=False):
    if platform.system()=='Linux':
        output=run(['ss','-H','-lnu' if udp else '-lnt'])
        addresses=[]
        for line in output.splitlines():
            fields=line.split()
            if len(fields)<5:continue
            address=fields[3]
            host,sep,value=address.rpartition(':')
            if sep and value==str(port):addresses.append(host.strip('[]').split('%')[0])
        return addresses
    args=['lsof','-nP','-i'+('UDP' if udp else 'TCP')+':'+str(port)]
    if not udp:args+=['-sTCP:LISTEN']
    args+=['-Fn']
    try:p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    except OSError:fail('lsof is required to audit listener exposure')
    if p.returncode not in (0,1):fail('listener audit failed')
    return [v[1:].rsplit(':',1)[0].strip('[]') for v in p.stdout.decode().splitlines() if v.startswith('n')]
def authentication_required(host,port,protocol):
    try:
        if protocol in ('mixed','socks5'):
            with socket.create_connection((host,port),timeout=3) as s:
                s.settimeout(3);s.sendall(b'\x05\x01\x00');reply=s.recv(2)
                # Some SOCKS implementations select username/password even
                # when the probe offers only no-auth. Either response refuses
                # unauthenticated access; method 0 would accept it.
                if reply not in (b'\x05\xff',b'\x05\x02'):return False
        if protocol in ('mixed','http'):
            with socket.create_connection((host,port),timeout=3) as s:
                s.settimeout(3);s.sendall(b'CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n');reply=s.recv(2048)
                if len(reply.split())<2 or reply.split()[1]!=b'407':return False
        return protocol in ('mixed','socks5','http')
    except OSError:return False
def audit(r):
    expected=r['listen_ip'] if r['mode']=='direct' else '127.0.0.1'
    if r.get('backend')=='docker' and r.get('core_id'):
        endpoint=r.get('docker_endpoint','')
        if not endpoint.startswith('unix:///') or '\n' in endpoint:fail('gateway Docker endpoint must be the reviewed local Unix socket')
        docker=['docker','--host',endpoint]
        ids=run(docker+['ps','-q','--filter','label=io.lazyclash.instance='+r['core_id']]).split()
        if len(ids)!=1:return False,False
        value=json.loads(run(docker+['inspect',ids[0]]))[0]
        binds=value.get('HostConfig',{}).get('PortBindings') or {}
        proxy=binds.get(str(r['target_port'])+'/tcp') or []
        ctrl=binds.get(str(r['controller_port'])+'/tcp') or []
        safe=(len(proxy)==1 and proxy[0].get('HostIp')==expected and proxy[0].get('HostPort')==str(r['target_port']) and len(ctrl)==1 and ctrl[0].get('HostIp')=='127.0.0.1' and ctrl[0].get('HostPort')==str(r['controller_port']))
        udp=binds.get(str(r['target_port'])+'/udp') or []
        safe=safe and (len(udp)==1 and udp[0].get('HostIp')==expected and udp[0].get('HostPort')==str(r['target_port']) if r.get('udp') else not udp) and len(binds)==(3 if r.get('udp') else 2)
        safe=safe and authentication_required(expected,r['target_port'],r.get('protocol'))
        return bool(safe),bool(value.get('State',{}).get('Running'))
    data=listener_addresses(r['target_port'])
    safe=bool(data) and all(ip==expected for ip in data)
    if r.get('controller_port'):
        ctrl=listener_addresses(r['controller_port'])
        safe=safe and bool(ctrl) and all(ip=='127.0.0.1' for ip in ctrl)
    udp=listener_addresses(r['target_port'],True)
    safe=safe and (bool(udp) and all(ip==expected for ip in udp) if r.get('udp') else all(ip==expected for ip in udp))
    safe=safe and authentication_required(expected,r['target_port'],r.get('protocol'))
    return bool(safe),bool(data)
def main(r):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',r.get('id','')):fail('invalid proxy ID')
    if r.get('op') not in ('inspect','audit','start','stop','remove'):fail('unknown proxy helper operation')
    if r.get('mode') not in ('serve','direct'):fail('unknown proxy exposure mode')
    for key in ('port','target_port'):
        if not isinstance(r.get(key),int) or not 1<=r[key]<=65535:fail('invalid proxy port')
    state=json.loads(ts('status','--json'));self=state.get('Self') or {}
    if self.get('ID')!=r.get('peer_id'):fail('SSH host is a different Tailscale peer')
    ips=self.get('TailscaleIPs') or []
    active=state.get('BackendState')=='Running' and bool(self.get('Online',True))
    present=r.get('listen_ip') in ips
    if r.get('upstream_host') and r.get('upstream_port') in (r['port'],r['target_port'],r.get('controller_port')):
        try:resolved=[entry[4][0] for entry in socket.getaddrinfo(r['upstream_host'],r['upstream_port'],type=socket.SOCK_STREAM)]
        except OSError:fail('cannot resolve upstream to rule out a gateway loop')
        if any(ipaddress.ip_address(ip).is_loopback or ip in ips for ip in resolved):fail('upstream resolves back to this gateway or controller')
    address=ipaddress.ip_address(r['listen_ip'])
    if not (address in ipaddress.ip_network('100.64.0.0/10') if address.version==4 else address in ipaddress.ip_network('fd7a:115c:a1e0::/48')):fail('listener is not a Tailscale address')
    config=json.loads(ts('serve','status','--json')) if r['mode']=='serve' else {}
    current=mapping(config,r['port']);wanted=expected_mapping(r['target_port'])
    directory=root();path=directory/(r['id']+'.json');owner=record(path)
    identity={'token_hash':digest(r.get('token','')),'peer_id':r['peer_id'],'port':r['port'],'target_port':r['target_port'],'mode':r['mode'],'listen_ip':r['listen_ip']}
    owned=owner==identity
    out={'ok':True,'peer_id':self['ID'],'os':platform.system().lower(),'ips':ips,'running':active,'mapping':current,'owned':owned,'listener_safe':False,'listener_active':False}
    if r['op']=='inspect':return out
    if r['op']=='audit':
        out['listener_safe'],out['listener_active']=audit(r)
        return out
    if os.geteuid()!=0:fail('proxy mapping changes require native administrator authorization')
    if not re.fullmatch('[a-f0-9]{48}',r.get('token','')):fail('missing proxy ownership token')
    private_root(directory)
    lock=directory/'.lock'
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'w') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX)
        owner=record(path);owned=owner==identity
        if owner is not None and not owned:fail('proxy mapping ownership changed')
        current=mapping(json.loads(ts('serve','status','--json')),r['port']) if r['mode']=='serve' else ''
        if r.get('expected','')!=current:fail('Serve mapping changed since preview')
        if current and (not owned or current!=wanted):fail('Serve port belongs to another configuration')
        if r['op']=='start':
            if not active or not present:fail('Tailscale address is unavailable; refusing wildcard fallback')
            safe,listening=audit(r)
            if not safe or not listening:fail('proxy listener exposure audit failed')
            # Save before the command so an interrupted response is recoverable.
            write_record(path,identity)
            if r['mode']=='serve' and not current:ts('serve','--bg','--tcp',str(r['port']),'tcp://127.0.0.1:'+str(r['target_port']))
            out['owned']=True
        elif r['op'] in ('stop','remove'):
            if not owned and owner is not None:fail('cannot remove an unowned mapping')
            if r['mode']=='serve' and current:
                if not owned:fail('cannot stop an unowned Serve mapping')
                ts('serve','--tcp',str(r['port']),'off')
            if r['op']=='remove' and owned:path.unlink()
            out['owned']=r['op']!='remove' and owned
        out['mapping']=mapping(json.loads(ts('serve','status','--json')),r['port']) if r['mode']=='serve' else ''
        if r['op']=='start' and r['mode']=='serve' and out['mapping']!=wanted:fail('Serve did not retain the owned TCP mapping')
    return out

if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin))))
    except Exception as e:print(json.dumps({'ok':False,'error':str(e)}))
