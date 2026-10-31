package serverdeploy

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNativeArtifactIdentifiesClientAndRetainsDigestVerification(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX server helper runs on the Ubuntu deployment host")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	defs := helper[:strings.Index(helper, "phase='preflight'")]
	script := defs + `
with tempfile.TemporaryDirectory() as directory:
    root=pathlib.Path(directory);ident='test';phase='artifact'
    r={'backend':'native','recipe':'hysteria2'}
    manifest={'file_hashes':{}}
    payload=b'fixture binary, not executable'
    address='https://download.hysteria.network/app/v2.13.0/hysteria-linux-amd64'
    a={'url':address,'sha256':hashlib.sha256(payload).hexdigest()}
    def fake_open(request,timeout):
        assert isinstance(request,urllib.request.Request)
        assert request.full_url==address
        assert request.get_header('User-agent')=='lazyclash-server-deploy'
        assert timeout==120
        return io.BytesIO(payload)
    urllib.request.urlopen=fake_open
    acquire()
    assert (root/'bin'/'hysteria').read_bytes()==payload
    assert manifest['file_hashes'][str(root/'bin'/'hysteria')]==a['sha256']
    a['sha256']='0'*64
    try:
        acquire()
        raise AssertionError('invalid artifact digest accepted')
    except Failure as error:
        assert 'SHA256' in str(error)
    assert (root/'bin'/'hysteria').read_bytes()==payload
print('ok')
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, python, "-I", "-c", script).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("artifact helper: %v %s", err, out)
	}
}
