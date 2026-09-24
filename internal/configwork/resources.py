import base64,hashlib,json,os,pathlib,stat,sys,tempfile

def resource_fail(message): raise ValueError(message)
def resource_operation(r):
    raw_root=pathlib.Path(r.get('resource_root',''))
    raw_path=pathlib.Path(r.get('path',''))
    if r['op']=='source-resource-read':
        if not raw_root.is_absolute() or not raw_path.is_absolute():resource_fail('source resource requires absolute owner paths')
        root=os.path.realpath(raw_root);resolved=os.path.realpath(raw_path)
        if os.path.commonpath([root,resolved])!=root or resolved==root:resource_fail('source resource escapes its owner home')
        initial=os.stat(resolved)
        if not stat.S_ISREG(initial.st_mode):resource_fail('source resource is not a bounded regular file')
        fd=os.open(resolved,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):resource_fail('source resource is not a bounded regular file')
            data=stream.read(8*1024*1024+1);after=os.fstat(stream.fileno())
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
        if not stat.S_ISREG(before.st_mode) or len(data)>8*1024*1024 or identity(before)!=identity(after) or identity(before)!=identity(os.stat(resolved)) or resolved!=os.path.realpath(raw_path):resource_fail('source resource is not a stable bounded regular file')
        digest=hashlib.sha256(data).hexdigest()
        return {'file':{'path':str(raw_path),'resolved':resolved,'data':base64.b64encode(data).decode(),'sha256':digest,'fingerprint':hashlib.sha256(json.dumps([resolved,identity(after),digest]).encode()).hexdigest(),'mode':stat.S_IMODE(after.st_mode)},'exists':True}
    if not raw_root.is_absolute() or not raw_path.is_absolute() or raw_root.name!='lazyclash-resources':resource_fail('resource root is not an explicit dedicated directory')
    if raw_path.parent!=raw_root or raw_path.name in ('','.','..'):resource_fail('resource path escapes its dedicated directory')
    if raw_root.is_symlink() or raw_path.is_symlink():resource_fail('resource paths cannot be symbolic links')
    root=pathlib.Path(os.path.realpath(raw_root));path=root/raw_path.name
    def read_existing():
        if not path.exists():return None
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size>8*1024*1024:resource_fail('resource is not a bounded regular file')
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):resource_fail('resource is not a bounded regular file')
            data=stream.read(8*1024*1024+1);after=os.fstat(stream.fileno())
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
        if len(data)>8*1024*1024 or identity(before)!=identity(after) or identity(before)!=identity(path.stat()):resource_fail('resource changed while reading')
        digest=hashlib.sha256(data).hexdigest()
        return {'path':str(raw_path),'resolved':str(path),'data':base64.b64encode(data).decode(),'sha256':digest,'fingerprint':hashlib.sha256(json.dumps([str(path),identity(after),digest]).encode()).hexdigest(),'mode':stat.S_IMODE(after.st_mode)}
    before=read_existing()
    if r['op']=='resource-inspect':return {'file':before or {},'exists':before is not None}
    if r['op']=='resource-write':
        data=base64.b64decode(r['data'],validate=True)
        if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=r['expected_sha256']:resource_fail('resource bytes do not match the reviewed digest')
        if before:
            if before['sha256']!=r['expected_sha256']:resource_fail('resource path already contains different data')
            return {'file':before,'exists':True,'created':False}
        root.mkdir(mode=0o700,parents=False,exist_ok=True)
        if root.is_symlink() or not root.is_dir():resource_fail('resource root is unsafe')
        fd,temp=tempfile.mkstemp(prefix='.resource-',dir=root)
        try:
            with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.link(temp,path,follow_symlinks=False)
        finally:os.unlink(temp)
        return {'file':read_existing(),'exists':True,'created':True}
    if r['op']=='resource-remove':
        if before is None:return {'exists':False}
        if before['sha256']!=r['expected_sha256']:resource_fail('resource changed; removal refused')
        path.unlink();return {'exists':False}
    resource_fail('unsupported resource operation')

# RESOURCE_ENTRYPOINT
try:print(json.dumps(resource_operation(json.load(sys.stdin))))
except ValueError as e:print(json.dumps({'error':str(e)}))
except Exception:print(json.dumps({'error':'resource operation failed; inspect permissions and bound paths'}))
