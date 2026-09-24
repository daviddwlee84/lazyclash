import base64, hashlib, json, os, subprocess, sys, tempfile
class SourceUnavailable(Exception): pass
def unavailable(s): raise SourceUnavailable(s)
def fail(s): raise ValueError(s)
def run(args, **kwargs):
    env=kwargs.pop('env',dict(os.environ))
    env.pop('DOCKER_HOST',None); env.pop('DOCKER_CONTEXT',None)
    p=subprocess.run(['docker']+(['--host',endpoint] if endpoint else [])+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35,env=env,**kwargs)
    if p.returncode:
        diagnostic=p.stderr.decode(errors='replace').lower()
        if args[0] in ('context','inspect') or any(text in diagnostic for text in ('cannot connect to the docker daemon','is the docker daemon running','error during connect','is not running','no such container','permission denied while trying to connect')):
            unavailable('Docker daemon or bound container is unavailable; check daemon access and container state')
        fail('Docker source operation failed; check local daemon, bound container, mounts and offline validation resources')
    return p.stdout
try:
    r=json.load(sys.stdin)
    endpoint=r.get('docker_host') or os.environ.get('DOCKER_HOST','')
    if not endpoint:
        contexts=json.loads(run(['context','inspect']))
        endpoint=contexts[0].get('Endpoints',{}).get('docker',{}).get('Host','') if len(contexts)==1 else ''
    if not endpoint.startswith('unix://'): fail('Docker source requires a daemon on the selected host; remote Docker contexts are unsupported')
    inspect=json.loads(run(['inspect',r['container']]))
    if len(inspect)!=1: fail('Docker container identity is ambiguous')
    item=inspect[0]; cid=item['Id']; image=item['Image']
    matched=False; single_file=False
    for mount in item.get('Mounts',[]):
        dest=mount.get('Destination','')
        rel=os.path.relpath(r['core_path'],dest)
        if mount.get('Type')=='bind' and rel!='..' and not rel.startswith('../'):
            candidate=os.path.normpath(os.path.join(mount['Source'],rel))
            if os.path.realpath(candidate)==os.path.realpath(r['host_path']): matched=True; single_file=(rel=='.')
    if not matched: fail('host_path does not map to core_path through a container bind mount')
    if not item.get('State',{}).get('Running'): unavailable('bound Docker container is not running')
    resource_data=None;resource_sha='';resource_home=''
    if r['op']=='resource-home':
        home=os.path.normpath(r['home']);dedicated=os.path.join(home,'lazyclash-resources');covering=[]
        for mount in item.get('Mounts',[]):
            dest=os.path.normpath(mount.get('Destination',''));rel=os.path.relpath(home,dest)
            if dest==dedicated or dest.startswith(dedicated+'/'):fail('Docker resource directory has an overlapping mount; explicit migration is required')
            if rel!='..' and not rel.startswith('../'):covering.append((len(dest),mount,rel))
        covering.sort(key=lambda entry:entry[0],reverse=True)
        if len(covering)>1 and covering[0][0]==covering[1][0]:fail('Docker resource home has ambiguous mounts')
        if covering:
            _,mount,rel=covering[0]
            if mount.get('Type')=='bind' and mount.get('RW',True) and os.path.isdir(mount['Source']):
                candidate=os.path.normpath(os.path.join(mount['Source'],rel))
                if os.path.isdir(candidate):resource_home=candidate
        if not resource_home:fail('Docker resource migration requires a writable directory bind covering the core home')
    if r['op']=='read-resource':
        p=r.get('resource_path','')
        if not os.path.isabs(p) or os.path.commonpath([os.path.normpath(p),os.path.normpath(r['home'])])!=os.path.normpath(r['home']):fail('source resource escapes Docker owner home')
        home=run(['exec',cid,'readlink','-f',r['home']]).decode().strip()
        resolved=run(['exec',cid,'readlink','-f',p]).decode().strip()
        if not home or not resolved or os.path.commonpath([home,resolved])!=home or home==resolved:fail('source resource resolves outside Docker owner home')
        run(['exec',cid,'test','-f',resolved])
        data=run(['exec',cid,'head','-c',str(8*1024*1024+1),resolved])
        repeated=run(['exec',cid,'head','-c',str(8*1024*1024+1),resolved])
        if len(data)>8*1024*1024 or repeated!=data or run(['exec',cid,'readlink','-f',p]).decode().strip()!=resolved:fail('Docker source resource changed or exceeds 8 MiB')
        resource_data=base64.b64encode(data).decode();resource_sha=hashlib.sha256(data).hexdigest()
    if r['op']=='validate':
        with tempfile.TemporaryDirectory(prefix='lazyclash-config-check-') as stage:
            os.chmod(stage,0o700);doc=r['document']; copies=[]
            def resource(value,required=True):
                src=value if os.path.isabs(value) else os.path.join(r['home'],value)
                dst='/lazyclash-validation/resources/'+str(len(copies))
                supplied=r.get('resources',{}).get(src)
                if supplied is not None:
                    payload=base64.b64decode(supplied,validate=True)
                    if len(payload)>8*1024*1024:fail('staged Docker resource exceeds 8 MiB')
                    target=os.path.join(stage,'resources',str(len(copies)))
                    os.makedirs(os.path.dirname(target),mode=0o700,exist_ok=True)
                    with open(target,'xb') as stream:stream.write(payload)
                    os.chmod(target,0o600)
                    copies.append((dst,dst,False))
                else:copies.append((src,dst,required))
                return dst
            for section in ('proxy-providers','rule-providers'):
                for p in doc.get(section,{}).values():
                    if isinstance(p,dict) and isinstance(p.get('path'),str):
                        p['path']=resource(p['path'],p.get('type')=='file')
            def certificates(n):
                if isinstance(n,dict):
                    for key,value in list(n.items()):
                        if key in ('certificate','certificate-path','ca','private-key-path') and isinstance(value,str) and value and '\n' not in value and not value.startswith('-----'):
                            n[key]=resource(value)
                        elif key=='private-key' and 'certificate' in n and isinstance(value,str) and '\n' not in value and not value.startswith('-----'):
                            n[key]=resource(value)
                        else: certificates(value)
                elif isinstance(n,list):
                    for v in n: certificates(v)
            certificates(doc)
            candidate=os.path.join(stage,'candidate.json')
            with open(candidate,'w') as f: json.dump(doc,f)
            os.chmod(candidate,0o600)
            # Fixed shell code; filenames are positional arguments, never shell code.
            script="""set -eu
binary=$1; home=$2; expected=$3; shift 3
mkdir -p /lazyclash-validation/resources
for p in "$home"/*.dat "$home"/*.mmdb "$home"/*.metadb; do
  [ ! -f "$p" ] || cp "$p" /lazyclash-validation/
done
while [ "$#" -ge 3 ]; do
  src=$1; dst=$2; required=$3; shift 3
  if [ "$src" = "$dst" ]; then [ -f "$dst" ]; elif [ -f "$src" ]; then cp "$src" "$dst"; elif [ "$required" = yes ]; then exit 72; fi
done
actual=$("$binary" -v)
case "$actual" in *"Mihomo Meta $expected "*) ;; *) exit 73;; esac
exec "$binary" -t -d /lazyclash-validation -f /lazyclash-validation/candidate.json
"""
            args=['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=64','--memory=512m','--volumes-from',cid+':ro','--mount','type=bind,src='+stage+',dst=/lazyclash-validation']
            # Image ENV can otherwise override -f (notably CONFIG_STRING).
            clear={'CLASH_CONFIG_STRING','CLASH_CONFIG_FILE','CLASH_HOME_DIR','SAFE_PATHS','SKIP_SAFE_PATH_CHECK'}
            for value in item.get('Config',{}).get('Env',[]) or []:
                key=value.split('=',1)[0]
                if key.startswith('CLASH_') or key in ('SAFE_PATHS','SKIP_SAFE_PATH_CHECK'): clear.add(key)
            for key in sorted(clear): args += ['--env',key+'=']
            args += ['--entrypoint','/bin/sh',image,'-c',script,'--',r['binary'],r['home'],r['version']]
            for src,dst,required in copies: args += [src,dst,'yes' if required else 'no']
            run(args,env={k:v for k,v in os.environ.items() if not k.startswith('CLASH_') and k not in ('SAFE_PATHS','SKIP_SAFE_PATH_CHECK')})
    elif r['op'] not in ('inspect','read-resource','resource-home'): fail('invalid Docker operation')
    visible=run(['exec',cid,'cat',r['core_path']])
    if len(visible)>8*1024*1024: fail('Container configuration exceeds the size limit')
    result={'container_id':cid,'image':image,'source_sha256':hashlib.sha256(visible).hexdigest(),'single_file':single_file,'resource_home_host':resource_home,'resource_sha256':resource_sha}
    if resource_data is not None:result['resource_data']=resource_data
    print(json.dumps(result))
except SourceUnavailable as e: print(json.dumps({'error':str(e),'error_kind':'unavailable'}))
except (FileNotFoundError,PermissionError,ConnectionError,subprocess.TimeoutExpired): print(json.dumps({'error':'Docker source host or daemon is unavailable','error_kind':'unavailable'}))
except ValueError as e: print(json.dumps({'error':str(e)}))
except Exception: print(json.dumps({'error':'Docker source inspection or isolated validation failed; no credentials are shown'}))
