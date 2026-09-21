package tailnet

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestPythonRollbackPreservesSnapshotsAndLaterEdits(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	defs, _, _ := strings.Cut(hostScript, "\n# TAILNET_ENTRYPOINT\n")
	test := `
import copy
class NoWorker:
    def __init__(self,*a,**k):pass
subprocess.Popen=NoWorker
WORKER_SOURCE='pass'
os.environ['LAZYCLASH_TAILNET_FIXTURE']='1'
base=tempfile.TemporaryDirectory();fixture=pathlib.Path(base.name)
config={'tun':{'enable':True,'device':'utun0'},'mode':'direct','mixed-port':7897}
core={'enabled':True,'device':'utun0','identity':'123:old-core','tun':copy.deepcopy(config['tun']),'config':copy.deepcopy(config),'config_hash':digest(json.dumps(config,sort_keys=True,separators=(',',':')).encode())}
initial={'self':{'id':'local'},'prefs':{'exit_node':'','allow_lan':True,'advertise':False},'forwarding':{},'os':'darwin','core':core}
current=copy.deepcopy(initial)
inspect=lambda r:copy.deepcopy(current)
core_snapshot=lambda r:copy.deepcopy(current['core'])
def change_pref(k,v):current['prefs'][{'exit-node':'exit_node','exit-node-allow-lan-access':'allow_lan','advertise-exit-node':'advertise'}[k]]=v
set_pref=change_pref
pref=lambda k:current['prefs'][{'exit-node':'exit_node','exit-node-allow-lan-access':'allow_lan','advertise-exit-node':'advertise'}[k]]
dns_requests=[]
def change_core(c,s,method='GET',path='/configs',body=None):
    if method=='POST':dns_requests.append((c,path))
    if body:
        v=body['tun']['enable'];current['core']['enabled']=v;current['core']['tun']['enable']=v;current['core']['config']['tun']['enable']=v;current['core']['config_hash']=digest(json.dumps(current['core']['config'],sort_keys=True,separators=(',',':')).encode())
controller_request=change_core
r={'action':'use','scope':'a'*24,'id':'selection','fixture_root':str(fixture),'expected':copy.deepcopy(initial),'self_id':'local','peer_id':'rpi','node_id':'rpi','allow_lan':False,'exit_ip':'100.72.151.78','controller':'unix:///tmp/example.sock','secret':'private'}
result=apply(r);directory=pathlib.Path(result['guard']);state=json.loads((directory/'state.json').read_text())
assert state['before']==initial, 'before snapshot was mutated by after changes'
assert current['prefs']['exit_node']=='100.72.151.78' and not current['core']['enabled']
assert state['after']==current
refresh={'scope':r['scope'],'id':'selection','fixture_root':str(fixture),'guard':result['guard'],'ack_token':result['ack_token']}
assert refresh_dns(refresh)['status']=='dns_cache_refreshed'
assert dns_requests==[(r['controller'],'/cache/dns/flush')]
assert current==state['after'], 'DNS cache refresh changed runtime settings'
bad=dict(refresh);bad['ack_token']='0'*48
try:refresh_dns(bad);assert False,'accepted a different ownership token'
except RuntimeError:pass
current['core']['identity']='foreign-core'
try:refresh_dns(refresh);assert False,'refreshed DNS on a different core'
except RuntimeError:pass
current=copy.deepcopy(state['after'])
assert len(dns_requests)==1, 'failed ownership checks reached the controller'
restored=restore(directory,state)
assert restored['status']=='restored',restored
assert current==initial, (current,initial)
# A restart is not the process that accepted the runtime TUN pause.
result=apply(r);directory=pathlib.Path(result['guard']);state=json.loads((directory/'state.json').read_text())
current['core']['identity']='456:new-core'
changed=copy.deepcopy(current);restored=restore(directory,state)
assert restored['status']=='restore_incomplete'
assert current==changed, 'restoration overwrote later core state'
# Explicit release restores only unchanged Tailscale preferences and preserves
# a replaced core. Its retired claim permits a newly reviewed selection.
root=directory.parent.parent
result=release(root,r)
assert result['status']=='released_tun_preserved',result
assert current['prefs']==initial['prefs'] and current['core']==changed['core']
new_request=copy.deepcopy(r);new_request['expected']=copy.deepcopy(current)
new_request['action']='use';new_result=apply(new_request)
new_dir=pathlib.Path(new_result['guard']);new_state=json.loads((new_dir/'state.json').read_text())
assert new_state['before']['core']['identity']=='456:new-core'
assert restore(new_dir,new_state)['status']=='restored'
# Interrupted command groups can contain independently before/after prefs.
current=copy.deepcopy(initial);r['scope']='b'*24;result=apply(r);directory=pathlib.Path(result['guard']);state=json.loads((directory/'state.json').read_text())
current['prefs']['exit_node']='' # exit command never ran; LAN and TUN did
restored=restore(directory,state)
assert restored['status']=='restored' and current==initial
# Unknown selected exits are never cleared by recovery.
current=copy.deepcopy(initial);r['scope']='c'*24;result=apply(r);directory=pathlib.Path(result['guard']);state=json.loads((directory/'state.json').read_text())
current['prefs']['exit_node']='100.99.99.99';changed=copy.deepcopy(current)
restored=restore(directory,state)
assert restored['status']=='restore_incomplete' and current==changed
print('ok')
`
	cmd := exec.Command(python, "-I", "-c", defs+test)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rollback Python: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatal(string(out))
	}
}

func TestHelperIncludesOnlyNamedTailscaleMutations(t *testing.T) {
	for _, bad := range []string{"ts('up'", "ts('down'", "serve reset", "--accept-dns", "--accept-routes"} {
		if strings.Contains(hostScript, bad) {
			t.Fatalf("unsafe whole-daemon/policy mutation: %s", bad)
		}
	}
	if !strings.Contains(hostScript, "ts('set','--'+name") {
		t.Fatal("missing scoped set")
	}
}

func TestPythonRemoteMutationRecoveryAndOwnership(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	defs, _, _ := strings.Cut(hostScript, "\n# TAILNET_ENTRYPOINT\n")
	test := `
import copy
class NoWorker:
    def __init__(self,*a,**k):pass
subprocess.Popen=NoWorker
WORKER_SOURCE='pass'
os.environ['LAZYCLASH_TAILNET_FIXTURE']='1'
base=tempfile.TemporaryDirectory();fixture=pathlib.Path(base.name)
# This fixture replaces only privileged OS facilities. Mutation/ownership,
# private receipts and restoration execute the actual fixed helper functions.
secure_dir=lambda p,public=False:p.mkdir(parents=True,exist_ok=True,mode=0o700)
os.geteuid=lambda:0
os.chown=lambda *a:None
sysctl_file=lambda r:fixture/('sysctl-'+r['id']+'.conf')
initial={'self':{'id':'remote'},'prefs':{'exit_node':'','allow_lan':False,'advertise':False},'forwarding':{'ipv4':'0','ipv6':'0'},'os':'linux','core':{}}
current=copy.deepcopy(initial)
inspect=lambda r:copy.deepcopy(current)
set_pref=lambda k,v:current['prefs'].update({{'advertise-exit-node':'advertise'}[k]:v})
set_forwarding=lambda values:current['forwarding'].update(values)
r={'action':'setup','scope':'d'*24,'id':'rpi','fixture_root':str(fixture),'expected':copy.deepcopy(initial),'self_id':'remote','peer_id':'remote','owner_token':'private-owner'}
result=apply(r);directory=pathlib.Path(result['guard']);state=json.loads((directory/'state.json').read_text());root=directory.parent.parent
assert current['prefs']['advertise'] and current['forwarding']=={'ipv4':'1','ipv6':'1'}
assert state['before']==initial and state['after']==current
assert sysctl_file(r).read_bytes()==sysctl_data()
restored=restore(directory,state)
assert restored['status']=='restored', restored
assert current==initial and not sysctl_file(r).exists() and not (root/'owner.json').exists()
# Another owner cannot turn off or remove this exit.
result=apply(r);directory=pathlib.Path(result['guard']);state=json.loads((directory/'state.json').read_text())
# A pending transaction blocks concurrent operations, even from its owner.
competing=copy.deepcopy(r);competing.update(scope='f'*24,expected=copy.deepcopy(current))
try:apply(competing);assert False,'concurrent inventory was accepted'
except RuntimeError as e:assert 'another inventory' in str(e)
state['status']='acknowledged';save(directory,state)
wrong=copy.deepcopy(r);wrong.update(action='disable',expected=copy.deepcopy(current),owner_token='other')
try:apply(wrong);assert False,'foreign owner accepted'
except RuntimeError as e:assert 'ownership' in str(e)
# Owned persistent configuration was later edited; all network mutation is
# rejected before disable/removal and rollback does not overwrite that file.
sysctl_file(r).write_bytes(b'# user edited\n');changed=copy.deepcopy(current)
changed_request=copy.deepcopy(r);changed_request.update(action='remove',expected=copy.deepcopy(current))
try:apply(changed_request);assert False,'edited file accepted'
except RuntimeError as e:assert 'externally edited' in str(e)
assert current==changed
restored=restore(directory,state)
assert restored['status']=='restore_incomplete' and sysctl_file(r).read_bytes()==b'# user edited\n'
# Recreate a clean fixture and interrupt halfway through sysctl writes.
claim_path(r,False).unlink();current=copy.deepcopy(initial);r['scope']='e'*24;sysctl_file(r).unlink()
normal_forwarding=set_forwarding
calls=[]
def interrupted_forwarding(v):
    calls.append(v.copy())
    if len(calls)==1:
        current['forwarding']['ipv4']=v['ipv4'];raise RuntimeError('injected IPv6 write failure')
    normal_forwarding(v)
set_forwarding=interrupted_forwarding
try:apply(r);assert False,'injected failure did not surface'
except RuntimeError as e:assert 'injected' in str(e)
assert current==initial and not sysctl_file(r).exists(),current
print('ok')
`
	cmd := exec.Command(python, "-I", "-c", defs+test)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("remote Python recovery: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatal(string(out))
	}
}

func TestPythonDetachedWorkerAcknowledgementAndTimeout(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	defs, _, _ := strings.Cut(hostScript, "\n# TAILNET_ENTRYPOINT\n")
	test := `
import copy
os.environ['LAZYCLASH_TAILNET_FIXTURE']='1'
base=tempfile.TemporaryDirectory();fixture=pathlib.Path(base.name)
r={'scope':'9'*24,'id':'selection','fixture_root':str(fixture),'peer_id':'peer','action':'use'}
root=root_for(r);secure_dir(root);secure_dir(global_root(r,True))
snap={'self':{'id':'local'},'prefs':{'exit_node':'','allow_lan':True,'advertise':False},'core':{},'forwarding':{}}
# The real detached worker only acknowledges here; this does not run any
# Tailscale or controller command on the developer machine.
WORKER_SOURCE=SOURCE+'\nworker(sys.argv[1])\n'
directory,state,token=arm(root,r,copy.deepcopy(snap),'local')
reply=ack(dict(r,guard=str(directory),ack_token=token,remote=False))
assert reply['status']=='acknowledged',reply
assert json.loads((directory/'state.json').read_text())['before']==snap
# Exercise actual detached timeout in a private fixture with all networking
# effects replaced by writes to a test-only JSON file.
claim_path(r,True).unlink();r['scope']='8'*24;root=root_for(r);secure_dir(root)
live=copy.deepcopy(snap);live['prefs']['exit_node']='100.72.151.78';live['prefs']['allow_lan']=False
live_path=fixture/'live.json';live_path.write_text(json.dumps(live))
override="\nLIVE=pathlib.Path("+repr(str(live_path))+")\ndef inspect(r):return json.loads(LIVE.read_text())\ndef set_pref(k,v):\n data=json.loads(LIVE.read_text());data['prefs'][{'exit-node':'exit_node','exit-node-allow-lan-access':'allow_lan'}[k]]=v;LIVE.write_text(json.dumps(data))\n"
WORKER_SOURCE=SOURCE+override+'\nworker(sys.argv[1])\n'
directory,state,token=arm(root,r,copy.deepcopy(snap),'local')
with lock(directory/'guard.lock'):
 state['after']=live;state['deadline']=int(time.time())-1;save(directory,state)
for _ in range(60):
 result=json.loads((directory/'status.json').read_text())
 if result['status']!='armed':break
 time.sleep(.1)
assert result['status']=='restored',result
assert json.loads(live_path.read_text())==snap
print('ok')
`
	cmd := exec.Command(python, "-I", "-c", "SOURCE="+strconv.Quote(defs)+"\n"+defs+test)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("detached recovery worker: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatal(string(out))
	}
}

func TestPythonProbeFailuresIdentifyPhaseWithoutCredentials(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	defs, _, _ := strings.Cut(hostScript, "\n# TAILNET_ENTRYPOINT\n")
	test := `
class Reply:
    def __init__(self,code,out=b''):self.returncode=code;self.stdout=out;self.stderr=b'private-token http://user:password@127.0.0.1:7897'
cases=[
 ('proxy-https-trace',28,[Reply(28)]),
 ('proxy-https-reachability',35,[Reply(0,b'ip=42.73.172.97\n'),Reply(35)]),
 ('host-dns-resolution',1,[Reply(0,b'ip=42.73.172.97\n'),Reply(0,b'204'),Reply(1)]),
 ('proxy-https-trace',0,[Reply(0,b'not a trace')]),
 ('proxy-https-reachability',0,[Reply(0,b'ip=42.73.172.97\n'),Reply(0,b'200')]),
]
for phase,code,replies in cases:
    observed=[]
    def fake_run(args,**kwargs):
        observed.append((args,kwargs));return replies.pop(0)
    subprocess.run=fake_run
    try:probe({'probe_proxy':'http://user:password@127.0.0.1:7897'});assert False,'probe failure was accepted'
    except ProbeFailure as e:
        assert e.phase==phase and e.exit_code==code,(e.phase,e.exit_code)
        assert 'private-token' not in str(e) and 'password' not in str(e) and '127.0.0.1' not in str(e),str(e)
    assert all(not any(k.lower() in ('http_proxy','https_proxy','all_proxy','no_proxy') for k in opts['env']) for args,opts in observed)
def timeout(*args,**kwargs):raise subprocess.TimeoutExpired('private-command',22,stderr=b'private-token')
subprocess.run=timeout
try:probe({});assert False,'timeout accepted'
except ProbeFailure as e:assert e.phase=='direct-ipv4-trace' and e.exit_code==124 and 'private' not in str(e)
print('ok')
`
	cmd := exec.Command(python, "-I", "-c", defs+test)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("probe diagnostics: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatal(string(out))
	}
}
