package rulework

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplicitDockerSandboxUsesPinnedImageAndPrivateResources(t *testing.T) {
	for _, rootless := range []bool{false, true} {
		t.Run(map[bool]string{false: "rootful", true: "rootless"}[rootless], func(t *testing.T) {
			dir := t.TempDir()
			home := filepath.Join(dir, "home")
			if err := os.Mkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			provider := filepath.Join(home, "provider.yaml")
			os.WriteFile(provider, []byte("original provider"), 0600)
			os.WriteFile(filepath.Join(home, "Country.mmdb"), []byte("original geodata"), 0600)
			binary := filepath.Join(dir, "mihomo")
			os.WriteFile(binary, []byte("fixture executable"), 0700)
			capture := filepath.Join(dir, "capture.jsonl")
			image := "sha256:" + strings.Repeat("a", 64)
			script := `#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
assert args[:2]==['--host','unix:///run/fixture/docker.sock']
assert not any(k.startswith('DOCKER_') for k in os.environ)
args=args[2:]
with open(os.environ['FIXTURE_CAPTURE'],'a') as f: f.write(json.dumps(args)+'\n')
if args[:2]==['image','inspect']:
 print(json.dumps([{'Id':os.environ['FIXTURE_IMAGE'],'Config':{'Env':['CLASH_TEST=secret','SAFE_PATHS=bad','SKIP_SAFE_PATH_CHECK=true']}}]))
elif args[0]=='info':
 print(json.dumps({'SecurityOptions':['name=rootless'] if os.environ['FIXTURE_ROOTLESS']=='1' else []}))
elif args[0]=='run':
 assert '--pull=never' in args and '--network=none' in args and '--read-only' in args and '--interactive' in args
 assert '--cap-drop=ALL' in args and '--security-opt=no-new-privileges' in args
 assert '--pids-limit=64' in args and '--memory=512m' in args
 assert args[args.index('--user')+1]==('0:0' if os.environ['FIXTURE_ROOTLESS']=='1' else str(os.getuid())+':'+str(os.getgid()))
 for k in ['CLASH_TEST=','CLASH_CONFIG_STRING=','SAFE_PATHS=','SKIP_SAFE_PATH_CHECK=']: assert k in args
 stage=args[args.index('--workdir')+1]
 assert os.stat(stage).st_mode&0o777==0o700
 mounts=[args[i+1] for i,v in enumerate(args) if v=='--mount']
 assert len(mounts)==2 and mounts[0].endswith(',readonly')
 assert mounts[0].startswith('type=bind,src='+stage+'/.validator-binary,dst=')
 assert open(os.path.join(stage,'.validator-binary')).read()=='fixture executable'
 assert os.stat(os.path.join(stage,'.validator-binary')).st_mode&0o777==0o500
 assert mounts[1]=='type=bind,src='+stage+',dst='+stage
 if '-v' in args:
  print('Mihomo Meta '+os.environ.get('FIXTURE_VERSION','v1.19.29')+' fixture fixture')
 elif '-t' in args:
  doc=json.load(sys.stdin)
  resource=doc['rule-providers']['fixture']['path']
  assert resource.startswith(stage+os.sep) and not os.path.islink(resource)
  assert open(resource).read()=='original provider'
  assert open(os.path.join(stage,'Country.mmdb')).read()=='original geodata'
  assert os.stat(resource).st_mode&0o777==0o600
  open(resource,'w').write('isolated change')
elif args[:2]!=['rm','--force']: sys.exit(1)
`
			os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("DOCKER_CONTEXT", "must-not-use")
			t.Setenv("DOCKER_HOST", "tcp://must-not-use")
			t.Setenv("FIXTURE_CAPTURE", capture)
			t.Setenv("FIXTURE_IMAGE", image)
			t.Setenv("FIXTURE_ROOTLESS", map[bool]string{false: "0", true: "1"}[rootless])
			req := hostRequest{Op: "validate", Binary: binary, Home: home, Version: "v1.19.29", ValidationDockerHost: "unix:///run/fixture/docker.sock", ValidationImage: image, Document: map[string]any{"rule-providers": map[string]any{"fixture": map[string]any{"type": "file", "path": provider}}}}
			if err := dockerHostScriptTest(t, req); err != "" {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(provider)
			if string(data) != "original provider" {
				t.Fatal("live provider modified")
			}
			calls, _ := os.ReadFile(capture)
			if strings.Contains(string(calls), "original provider") || strings.Contains(string(calls), "CLASH_TEST=secret") {
				t.Fatal("private data leaked into arguments")
			}
			t.Setenv("FIXTURE_VERSION", "v9.0.0")
			if err := dockerHostScriptTest(t, req); !strings.Contains(err, "does not match") {
				t.Fatalf("different core version accepted: %s", err)
			}
			req.ValidationDockerHost = "tcp://127.0.0.1:2375"
			if err := dockerHostScriptTest(t, req); !strings.Contains(err, "explicit local unix socket") {
				t.Fatalf("nonlocal daemon accepted: %s", err)
			}
			req.ValidationDockerHost = ""
			if err := dockerHostScriptTest(t, req); !strings.Contains(err, "explicit local unix socket") {
				t.Fatalf("ambient daemon accepted: %s", err)
			}
			req.ValidationDockerHost = "unix:///run/fixture/docker.sock"
			req.ValidationImage = "alpine:latest"
			if err := dockerHostScriptTest(t, req); !strings.Contains(err, "full sha256") {
				t.Fatalf("mutable image accepted: %s", err)
			}
		})
	}
}

func dockerHostScriptTest(t *testing.T, req hostRequest) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	// The fake Docker executable checks arguments and private resources on all
	// supported developer OSes; actual Linux sandbox validation is an E2E check.
	script := strings.Replace(hostScript, "\ntry:\n    request=json.load(sys.stdin)", "\nplatform.system=lambda: 'Linux'\ntry:\n    request=json.load(sys.stdin)", 1)
	cmd := exec.Command(python, "-c", script)
	data, _ := json.Marshal(req)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ Error string }
	if err = json.Unmarshal(out, &result); err != nil {
		t.Fatalf("invalid response: %s", out)
	}
	return result.Error
}
