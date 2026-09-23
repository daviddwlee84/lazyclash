package tailnetproxy

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func runHelperFixture(t *testing.T, body string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	defs, _, ok := strings.Cut(helper, "\nif __name__=='__main__':")
	if !ok {
		t.Fatal("helper entry changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, python, "-c", defs+"\n"+body).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("helper fixture: %s %v", out, err)
	}
}

func TestServeHelperOwnsOnlyOneMappingAndPreservesForeignChange(t *testing.T) {
	base, _ := json.Marshal(t.TempDir())
	runHelperFixture(t, `directory=pathlib.Path(`+string(base)+`)
root=lambda:directory
private_root=lambda p:p.mkdir(parents=True,exist_ok=True)
record=lambda p:json.loads(p.read_text()) if p.exists() else None
os.geteuid=lambda:0
config={'TCP':{'8443':{'TCPForward':'127.0.0.1:8080'}},'Web':{'other:443':{'Handlers':{'/':{'Text':'foreign'}}}}}
calls=[]
def fake_ts(*args):
 calls.append(args)
 if args==('status','--json'):return json.dumps({'BackendState':'Running','Self':{'ID':'peer','Online':True,'TailscaleIPs':['100.72.151.78']}})
 if args==('serve','status','--json'):return json.dumps(config)
 if args[:3]==('serve','--bg','--tcp'):
  config['TCP'][args[3]]={'TCPForward':args[4].removeprefix('tcp://')};return ''
 if args[:2]==('serve','--tcp') and args[-1]=='off':
  config['TCP'].pop(args[2]);return ''
 raise AssertionError(args)
ts=fake_ts
audit=lambda r:(True,True)
r={'id':'gateway','op':'start','peer_id':'peer','token':'a'*48,'port':7898,'target_port':17898,'listen_ip':'100.72.151.78','mode':'serve','expected':''}
out=main(r);assert out['owned'] and out['mapping']==expected_mapping(17898)
foreign=json.loads(json.dumps(config));foreign['TCP'].pop('7898')
r.update(op='stop',expected=out['mapping']);out=main(r)
assert config==foreign and not out['mapping']
r.update(op='start',expected='');out=main(r)
config['TCP']['7898']={'TCPForward':'127.0.0.1:9999'}
r.update(op='stop',expected=out['mapping'])
try:main(r);raise AssertionError('foreign edit overwritten')
except RuntimeError as e:assert 'changed' in str(e)
assert config['TCP']['7898']['TCPForward']=='127.0.0.1:9999'
r.update(id='other',op='start',expected=mapping(config,7898))
try:main(r);raise AssertionError('other ID stole mapping')
except RuntimeError as e:assert 'another' in str(e)
assert all('reset' not in c and 'down' not in c and 'funnel' not in c for c in calls)
print('ok')`)
}
func TestServeHelperRejectsForegroundAndPublicFunnel(t *testing.T) {
	runHelperFixture(t, `plain={'TCP':{'7898':{'TCPForward':'127.0.0.1:17898'}}}
assert mapping(plain,7898)==expected_mapping(17898)
plain['AllowFunnel']={'node:7898':True}
assert mapping(plain,7898)!=expected_mapping(17898)
plain.pop('AllowFunnel');plain['Foreground']={'session':{'TCP':{'7898':{'TCPForward':'127.0.0.1:17898'}}}}
assert mapping(plain,7898)!=expected_mapping(17898)
assert mapping({'Foreground':plain['Foreground']},7898)
print('ok')`)
}
func TestListenerAuditRejectsWildcardAndLostUDPBinding(t *testing.T) {
	runHelperFixture(t, `platform.system=lambda:'Linux'
authentication_required=lambda *args:True
def output(args):
 if '-lnu' in args:return 'UNCONN 0 0 100.72.151.78:7898 0.0.0.0:*\n'
 return 'LISTEN 0 4096 100.72.151.78:7898 0.0.0.0:*\nLISTEN 0 4096 127.0.0.1:19098 0.0.0.0:*\n'
run=output
r={'mode':'direct','listen_ip':'100.72.151.78','target_port':7898,'controller_port':19098,'udp':True,'protocol':'mixed'}
assert audit(r)==(True,True)
run=lambda args:output(args).replace('100.72.151.78:7898','0.0.0.0:7898')
assert audit(r)==(False,True)
run=lambda args:'' if '-lnu' in args else output(args)
assert audit(r)==(False,True)
run=output;authentication_required=lambda *args:False
assert audit(r)==(False,True)
print('ok')`)
}
func TestHelperAddressLossNeverCallsServeMutation(t *testing.T) {
	runHelperFixture(t, `root=lambda:pathlib.Path('/missing-tailnet-fixture')
record=lambda path:None
os.geteuid=lambda:0
calls=[]
def fake_ts(*args):
 calls.append(args)
 if args==('status','--json'):return json.dumps({'BackendState':'Running','Self':{'ID':'peer','Online':True,'TailscaleIPs':[]}})
 if args==('serve','status','--json'):return '{}'
 raise AssertionError('unexpected mutation')
ts=fake_ts
r={'id':'gateway','op':'inspect','peer_id':'peer','port':7898,'target_port':17898,'listen_ip':'100.72.151.78','mode':'serve'}
assert main(r)['ips']==[]
assert len(calls)==2
print('ok')`)
}

func TestDockerAuditUsesPinnedSocketAndExactUDPPort(t *testing.T) {
	runHelperFixture(t, `authentication_required=lambda *args:True
endpoint='unix:///run/user/1000/docker.sock'
value={'HostConfig':{'PortBindings':{'7898/tcp':[{'HostIp':'100.72.151.78','HostPort':'7898'}],'7898/udp':[{'HostIp':'100.72.151.78','HostPort':'7898'}],'19098/tcp':[{'HostIp':'127.0.0.1','HostPort':'19098'}]}},'State':{'Running':True}}
def fake_run(args):
 assert args[:3]==['docker','--host',endpoint],args
 return 'container\n' if args[3]=='ps' else json.dumps([value])
run=fake_run
r={'mode':'direct','listen_ip':'100.72.151.78','target_port':7898,'controller_port':19098,'udp':True,'protocol':'mixed','backend':'docker','core_id':'gateway','docker_endpoint':endpoint}
assert audit(r)==(True,True)
value['HostConfig']['PortBindings']['7898/udp'][0]['HostPort']='9999'
assert audit(r)==(False,True)
r['docker_endpoint']='tcp://other:2375'
try:audit(r);raise AssertionError('remote daemon accepted')
except RuntimeError as e:assert 'Unix socket' in str(e)
print('ok')`)
}
