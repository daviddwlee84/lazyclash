package networkcheck

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

func TestSystemProxyTransactionsSerializeAcrossInstances(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	encoded, _ := json.Marshal(SystemProxyScript)
	script := "import json\nns={'__name__':'lazyclash_system_proxy'}\nexec(json.loads(" + strconvQuote(string(encoded)) + "),ns)\n" + `
import copy,os,pathlib,tempfile,threading,time
fixture=tempfile.TemporaryDirectory()
ns['_proxy_lock_path']=lambda backend:(pathlib.Path(fixture.name)/'shared.lock',os.getuid())
ns['platform'].system=lambda:'Darwin'
base={'service':'Wi-Fi','http':{'enabled':False,'host':'','port':0,'authenticated':False},'https':{'enabled':False,'host':'','port':0,'authenticated':False},'socks':{'enabled':False,'host':'','port':0,'authenticated':False},'pac_enabled':False,'pac_url':'','discovery':False,'exceptions':[],'mode':'manual'}
after=copy.deepcopy(base);after['http'].update({'enabled':True,'host':'127.0.0.1','port':7890})
state=copy.deepcopy(base);writes=[]
def read(service):
 snapshot=copy.deepcopy(state)
 time.sleep(.04) # force overlap of otherwise unprotected read-before-write
 return snapshot
def write(value):
 state.clear();state.update(copy.deepcopy(value));writes.append(True)
ns['mac_state']=read;ns['write_mac']=write
plan={'backend':'macos-networksetup','os':'Darwin','changes':[{'service':'Wi-Fi','before':base,'after':after}]}
start=threading.Barrier(3);outcomes=[]
def actor():
 start.wait();outcomes.append(ns['apply_plan'](plan)['status'])
threads=[threading.Thread(target=actor) for _ in range(2)]
for thread in threads:thread.start()
start.wait()
for thread in threads:thread.join(4)
assert sorted(outcomes)==['applied','conflict'],outcomes
assert len(writes)==1,writes
fixture.cleanup()
print('ok')
`
	output, err := connection.ExecutePython(context.Background(), "", script, []byte("{}"), 4096)
	if err != nil || strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("concurrent proxy fixture %s %v", output, err)
	}
}
