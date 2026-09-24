package sourceowner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDockerProtocolSeparatesUnavailableOwnerFromMountMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper fixture")
	}
	dir := t.TempDir()
	host := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(host, []byte("rules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env python3
import json,os,sys
args=sys.argv[3:]
mode=os.environ['FIXTURE_DOCKER_MODE']
if args[0]=='inspect':
 if mode=='daemon':
  sys.stderr.write('Cannot connect to the Docker daemon');sys.exit(1)
 source=os.environ['FIXTURE_DOCKER_HOME']
 if mode=='mismatch':source += '/other'
 print(json.dumps([{'Id':'bound-id','Image':'bound-image','State':{'Running':mode!='stopped'},'Mounts':[{'Type':'bind','Source':source,'Destination':'/core'}]}]))
elif args[0]=='exec':print('rules: []')
else:sys.exit(1)
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FIXTURE_DOCKER_HOME", dir)
	req := DockerRequest{DockerSource: DockerSource{DockerHost: "unix:///fixture", Container: "bound", HostPath: host, CorePath: "/core/config.yaml", Binary: "/mihomo", Home: "/core"}, Op: "inspect"}
	for _, mode := range []string{"stopped", "daemon", "mismatch", "running"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("FIXTURE_DOCKER_MODE", mode)
			_, err := DockerOperation(context.Background(), "", req)
			if mode == "running" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || errors.Is(err, ErrUnavailable) != (mode != "mismatch") {
				t.Fatal(mode, err)
			}
		})
	}
}
