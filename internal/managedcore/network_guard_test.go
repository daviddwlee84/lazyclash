package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

func runGuardFixture(t *testing.T, body string) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	t.Helper()
	definitions, _, ok := strings.Cut(hostScript, "\n# MANAGED_ENTRYPOINT\n")
	if !ok {
		t.Fatal("missing host entrypoint")
	}
	script := networkGuardPrelude(hostScript) + definitions + "\n" + body
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := connection.ExecutePython(ctx, "", compactHostScript(script), []byte("{}"), 8192)
	if errors.Is(err, connection.ErrPythonUnavailable) {
		t.Skip("Python3 unavailable")
	}
	if err != nil || strings.TrimSpace(string(output)) != "ok" {
		t.Fatalf("network guard fixture: %s %v", output, err)
	}
}

func TestNetworkGuardDeadlineRestoresOwnedCoreAndProtectsLaterEdit(t *testing.T) {
	root, _ := json.Marshal(t.TempDir())
	runGuardFixture(t, `os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(root)+`)
root=fixture/"fixture"; (root/"home").mkdir(parents=True)
request={"id":"fixture","root":str(root),"backend":"native","service_scope":"system","version":"v1.19.31","owner_token":"fixture-owner","fixture_root":str(fixture),"network":{"tun":True},"profile_sha256":digest(b"after"),"resources":{"rules/a.list":base64.b64encode(b"new-rules").decode()}}
before={"id":"fixture","owner_token":"fixture-owner","running":True,"profile_sha256":digest(b"before"),"network":{"tun":False}}
after=dict(before);after["profile_sha256"]=digest(b"after");after["network"]={"tun":True}
atomic(root/"home/config.yaml",b"before");atomic(root/"home/rules/a.list",b"old-rules")
atomic(root/"instance.json",json.dumps(before).encode(),0o644)
_guard_spawn=lambda directory:None
guard=arm_network_guard(root,request,after,b"before",before)
directory=pathlib.Path(guard["guard_ref"])
atomic(root/"home/config.yaml",b"after");atomic(root/"home/rules/a.list",b"new-rules")
atomic(root/"instance.json",json.dumps(after).encode(),0o644)
with open(root.parent/".fixture.lock","a+b") as instance_lock:
 fcntl.flock(instance_lock,fcntl.LOCK_EX)
 assert _guard_tick(directory,guard["deadline"]+1) is False
 assert (root/"home/config.yaml").read_bytes()==b"after"
 assert _guard_state(directory)["status"]=="armed"
assert _guard_tick(directory,guard["deadline"]+1)
assert (root/"home/config.yaml").read_bytes()==b"before"
assert (root/"home/rules/a.list").read_bytes()==b"old-rules"
assert _guard_state(directory)["status"]=="rolled_back"
guard=arm_network_guard(root,request,after,b"before",before)
directory=pathlib.Path(guard["guard_ref"])
atomic(root/"instance.json",json.dumps(after).encode(),0o644)
atomic(root/"home/config.yaml",b"newer external change")
assert _guard_tick(directory,guard["deadline"]+1)
assert (root/"home/config.yaml").read_bytes()==b"newer external change"
assert _guard_state(directory)["status"]=="restore_incomplete"
print("ok")
`)
}

func TestNetworkGuardAcknowledgementAndDetachedWorker(t *testing.T) {
	root, _ := json.Marshal(t.TempDir())
	runGuardFixture(t, `os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(root)+`)
root=fixture/"fixture"; (root/"home").mkdir(parents=True)
request={"id":"fixture","root":str(root),"backend":"native","service_scope":"system","version":"v1.19.31","owner_token":"fixture-owner","fixture_root":str(fixture),"network":{"tun":True},"profile_sha256":digest(b"after")}
info={"id":"fixture","owner_token":"fixture-owner","running":True,"profile_sha256":digest(b"after"),"network":{"tun":True}}
atomic(root/"home/config.yaml",b"after");atomic(root/"instance.json",json.dumps(info).encode(),0o644)
guard=arm_network_guard(root,request,info,None,None)
atomic(root/"instance.json",json.dumps(info).encode(),0o644)
request.update(guard)
outcome=ack_network_guard(root,request,info)
assert outcome["status"]=="acknowledged",outcome
directory=pathlib.Path(guard["guard_ref"])
assert _guard_tick(directory,guard["deadline"]+1)
assert (root/"home/config.yaml").read_bytes()==b"after"
assert _guard_state(directory)["status"]=="acknowledged"
guard=arm_network_guard(root,request,info,None,None)
directory=pathlib.Path(guard["guard_ref"])
atomic(root/"instance.json",json.dumps(info).encode(),0o644)
with _guard_lock(directory):
 state=_guard_state(directory);state["deadline"]=int(time.time())-1;_guard_save(directory,state)
for _ in range(30):
 if _guard_state(directory)["status"]!="armed":break
 time.sleep(.1)
assert _guard_state(directory)["status"]=="rolled_back"
assert json.loads((root/"instance.json").read_bytes())["running"] is False
print("ok")
`)
}

func TestNetworkGuardUserProxyNeverExecutesUserCoreAsRoot(t *testing.T) {
	root, _ := json.Marshal(t.TempDir())
	runGuardFixture(t, `os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(root)+`);root=fixture/"fixture"
request={"id":"fixture","backend":"native","service_scope":"user","owner_token":"fixture-owner","fixture_root":str(fixture),"network":{"tun":False},"system_proxy":{"backend":"fixture","changes":[]}}
info={"id":"fixture","owner_token":"fixture-owner"}
calls=[]
proxy_api["apply_plan"]=lambda plan,restore: calls.append(restore) or {"status":"restored"}
def forbidden(*args): raise AssertionError("user core was accessed")
service_action=forbidden;manifest=forbidden
_guard_spawn=lambda directory:None
guard=arm_network_guard(root,request,info)
directory=pathlib.Path(guard["guard_ref"])
assert _guard_tick(directory,guard["deadline"]+1)
assert calls==[True]
assert not root.exists()
print("ok")
`)
}
