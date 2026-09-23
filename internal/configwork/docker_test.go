package configwork

import (
	"context"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerMountProofAndIsolatedValidationArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.Mkdir(home, 0700)
	configPath := filepath.Join(home, "config.yaml")
	os.WriteFile(configPath, []byte(sourceFixture), 0600)
	manifest := []map[string]any{{"Id": "fixed-container-id", "Image": "sha256:fixed-image", "State": map[string]any{"Running": true}, "Mounts": []map[string]any{{"Type": "bind", "Source": home, "Destination": "/etc/mihomo"}}}}
	raw, _ := json.Marshal(manifest)
	capture := filepath.Join(dir, "calls.json")
	script := "#!/usr/bin/env python3\nimport json,os,sys\nargs=sys.argv[1:]\nif args[:2] != ['--host','unix:///fixture']: sys.exit(2)\nargs=args[2:]\nif args[0]=='inspect':\n print(os.environ['FIXTURE_INSPECT'])\nelif args[0]=='exec':\n sys.stdout.write(os.environ['FIXTURE_SOURCE'])\nelif args[0]=='run':\n open(os.environ['FIXTURE_CAPTURE'],'w').write(json.dumps(args))\nelse: sys.exit(1)\n"
	os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FIXTURE_INSPECT", string(raw))
	t.Setenv("FIXTURE_CAPTURE", capture)
	t.Setenv("FIXTURE_SOURCE", sourceFixture)
	t.Setenv("DOCKER_HOST", "unix:///fixture")
	target := config.Target{ID: "fixture", Controller: "http://127.0.0.1:9090", ConfigSource: &config.ConfigSource{Kind: "docker", Container: "running", HostPath: configPath, CorePath: "/etc/mihomo/config.yaml", Binary: "/mihomo", Home: "/etc/mihomo"}}
	result, e := dockerCall(context.Background(), target, "inspect", nil, "")
	if e != nil || result.ContainerID != "fixed-container-id" {
		t.Fatal(result, e)
	}
	if _, e = dockerCall(context.Background(), target, "validate", []byte(sourceFixture), "version"); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(capture)
	if e != nil {
		t.Fatal(e)
	}
	text := string(data)
	for _, arg := range []string{"--network=none", "--read-only", "--pull=never", "--cap-drop=ALL", "fixed-container-id:ro", "sha256:fixed-image"} {
		if !strings.Contains(text, arg) {
			t.Fatal("missing isolated validator argument", arg)
		}
	}
	if strings.Contains(text, "original-secret") {
		t.Fatal("credentials leaked into process arguments")
	}
	target.ConfigSource.CorePath = "/different/config.yaml"
	if _, e = dockerCall(context.Background(), target, "inspect", nil, ""); e == nil {
		t.Fatal("unproved mount accepted")
	}
}
