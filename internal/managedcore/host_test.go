package managedcore

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagedHostInstallConfigureOwnershipAndRemoval(t *testing.T) {
	base, _ := json.Marshal(t.TempDir())
	runHostFixture(t, `os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(base)+`).resolve()
request={"op":"install","id":"demo","fixture_root":str(fixture),"backend":"native","version":"v1.19.31","service_scope":"user","owner_token":"owned","network":{"tun":False},"ports":[19090,17890],"boot":False,"artifact":base64.b64encode(gzip.compress(b"fixture binary")).decode(),"resources":{"rules/test.list":base64.b64encode(b"DOMAIN,example.test").decode()}}
request["artifact_sha256"]=digest(base64.b64decode(request["artifact"]))
request["profile"]=base64.b64encode(b"mode: rule\n").decode();request["profile_sha256"]=digest(b"mode: rule\n")
out=main(request);assert out["status"]=="running_unverified",out
root=fixture/"demo";assert (root/"home/config.yaml").read_bytes()==b"mode: rule\n"
request.update(op="status",expected=out["digest"])
assert main(request)["running"]
request["owner_token"]="someone-else"
try:main(request);raise AssertionError("owner accepted")
except RuntimeError as e:assert "ownership" in str(e)
request["owner_token"]="owned";request.update(op="configure",profile=base64.b64encode(b"mode: direct\n").decode(),profile_sha256=digest(b"mode: direct\n"))
out=main(request);assert out["status"]=="running_unverified"
assert (root/"home/config.yaml").read_bytes()==b"mode: direct\n"
try:main(request);raise AssertionError("stale digest accepted")
except RuntimeError as e:assert "changed" in str(e)
request.update(op="remove",expected=out["digest"])
out=main(request);assert out["status"]=="removed_data_preserved"
assert (root/"home/config.yaml").exists() and (root/"bin/mihomo").exists()
print("ok")`)
}

func TestManagedHostResourceIdentityAndArtifactTampering(t *testing.T) {
	base, _ := json.Marshal(t.TempDir())
	runHostFixture(t, `os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(base)+`).resolve()
for value in ("../instance.json","config.yaml","/etc/passwd","bin/other","nested/../../evil","a\\evil"):
 try:resource_path(fixture/"home",value);raise AssertionError("unsafe resource accepted")
 except RuntimeError:pass
request={"op":"install","id":"demo","fixture_root":str(fixture),"backend":"native","version":"v1.19.31","service_scope":"user","owner_token":"owned","network":{},"ports":[19090,17890],"boot":False,"artifact":base64.b64encode(gzip.compress(b"fixture")).decode(),"artifact_sha256":"bad","profile":base64.b64encode(b"mode: rule").decode(),"profile_sha256":digest(b"mode: rule")}
try:main(request);raise AssertionError("checksum accepted")
except RuntimeError as e:assert "checksum" in str(e)
assert not (fixture/"demo").exists()
request["artifact_sha256"]=digest(base64.b64decode(request["artifact"]))
out=main(request);request.update(op="restart",expected=out["digest"])
root=fixture/"demo";atomic(root/"bin/mihomo",b"changed",0o755)
try:main(request);raise AssertionError("changed binary accepted")
except RuntimeError as e:assert "binary changed" in str(e)
print("ok")`)
}

func TestManagedHostConfigureFailureRestoresAllSources(t *testing.T) {
	base, _ := json.Marshal(t.TempDir())
	runHostFixture(t, `os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(base)+`).resolve()
request={"op":"install","id":"demo","fixture_root":str(fixture),"backend":"native","version":"v1.19.31","service_scope":"user","owner_token":"owned","network":{},"ports":[19090,17890],"boot":False,"artifact":base64.b64encode(gzip.compress(b"fixture")).decode(),"profile":base64.b64encode(b"before").decode(),"profile_sha256":digest(b"before"),"resources":{"rules/a.list":base64.b64encode(b"before-rule").decode()}}
request["artifact_sha256"]=digest(base64.b64decode(request["artifact"]))
out=main(request);request.update(op="configure",expected=out["digest"],profile=base64.b64encode(b"after").decode(),profile_sha256=digest(b"after"),resources={"rules/a.list":base64.b64encode(b"after-rule").decode()})
original=service_action;calls=[]
def fail_once(root,req,op,info):
 calls.append(op)
 if len(calls)==1:fail("fixture service failed")
 return original(root,req,op,info)
service_action=fail_once
out=main(request);assert out["status"]=="configure_failed_restored",out
assert (fixture/"demo/home/config.yaml").read_bytes()==b"before"
assert (fixture/"demo/home/rules/a.list").read_bytes()==b"before-rule"
print("ok")`)
}

func TestDockerComposeHasExplicitOwnershipAndLoopback(t *testing.T) {
	runHostFixture(t, `request={"id":"demo","owner_token":"owned","image":"metacubex/mihomo@sha256:"+"1"*64,"platform":"linux/arm64","ports":[19090,17890],"network":{"tun":False}}
value=json.loads(compose_data(pathlib.Path("/owned/demo"),request));service=value["services"]["mihomo"]
assert service["ports"]==["127.0.0.1:19090:19090","127.0.0.1:17890:17890"]
assert service["restart"]=="no" and service["labels"]["io.lazyclash.owner"]=="owned"
assert service["volumes"][0]["bind"]["create_host_path"]==False
request["network"]["tun"]=True
service=json.loads(compose_data(pathlib.Path("/owned/demo"),request))["services"]["mihomo"]
assert service["network_mode"]=="host" and "ports" not in service
assert service["cap_add"]==["NET_ADMIN"] and service["devices"]==["/dev/net/tun:/dev/net/tun"]
print("ok")`)
}

func runHostFixture(t *testing.T, body string) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python3 unavailable")
	}
	defs, _, _ := strings.Cut(hostScript, "\n# MANAGED_ENTRYPOINT\n")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-c", compactHostScript(networkGuardPrelude(hostScript)+defs+"\n"+body))
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("fixture: %s %v", out, err)
	}
}

func TestOfflineDockerArchiveVerifiesLayersAndDoesNotMoveTags(t *testing.T) {
	base, _ := json.Marshal(t.TempDir())
	runHostFixture(t, `import tarfile,io
os.environ["LAZYCLASH_MANAGED_FIXTURE"]="1"
fixture=pathlib.Path(`+string(base)+`).resolve();stage=fixture/"stage";stage.mkdir()
layer=b"fixture uncompressed layer tar bytes"
config=json.dumps({"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:"+digest(layer)]}}).encode()
archive=fixture/"image.tar"
def make_archive(data):
 with tarfile.open(archive,"w") as output:
  values={"manifest.json":json.dumps([{"Config":"config.json","RepoTags":["other/existing:tag"],"Layers":["layer.tar"]}]).encode(),"config.json":config,"layer.tar":data}
  for name,value in values.items():
   info=tarfile.TarInfo(name);info.size=len(value);output.addfile(info,io.BytesIO(value))
make_archive(layer)
request={"fixture_root":str(fixture),"docker_archive":str(archive),"docker_archive_sha256":archive_hash(str(archive))[0],"config_sha256":digest(config),"platform":"linux/arm64"}
assert load_verified_archive(request,stage)=="sha256:"+digest(config)
assert not (stage/"verified-image.tar").exists()
make_archive(b"tampered layer");request["docker_archive_sha256"]=archive_hash(str(archive))[0]
try:load_verified_archive(request,stage);raise AssertionError("tampered official layer accepted")
except RuntimeError as e:assert "layer hash" in str(e)
print("ok")`)
}

func TestFixedHostHelperStaysBelowPortableArgumentLimit(t *testing.T) {
	if size := len(fullHostScript()); size > 60<<10 {
		t.Fatalf("helper argument too large: %d", size)
	}
}
