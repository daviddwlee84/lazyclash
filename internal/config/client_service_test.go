package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientServiceAndDockerHostRoundTripPreservesUnrelatedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	raw := "# keep\n[[targets]]\nid='core'\ncontroller='http://127.0.0.1:9090'\nunknown='keep'\n"
	os.WriteFile(path, []byte(raw), 0600)
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].Service = &ClientService{Kind: "docker", DockerHost: "unix:///run/user/123/docker.sock", Container: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), MountsSHA256: strings.Repeat("c", 64)}
	cfg.Targets[0].ConfigSource = &ConfigSource{Kind: "docker", DockerHost: "unix:///run/user/123/docker.sock", Container: "core", HostPath: "/host/config.yaml", CorePath: "/core/config.yaml", Binary: "/core/mihomo", Home: "/core"}
	if err = Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	next, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if next.Targets[0].Service.DockerHost != cfg.Targets[0].Service.DockerHost || next.Targets[0].ConfigSource.DockerHost != cfg.Targets[0].Service.DockerHost {
		t.Fatal("endpoint binding lost")
	}
	next.Targets[0].Service = nil
	if err = Save(path, next); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "[targets.service]") || !strings.Contains(string(data), "unknown='keep'") || !strings.Contains(string(data), "# keep") || !strings.Contains(string(data), "docker_host") {
		t.Fatal(string(data))
	}
}
func TestDockerHostRejectsRemoteAndAmbiguousEndpoints(t *testing.T) {
	for _, host := range []string{"tcp://127.0.0.1:2375", "ssh://host", "unix://remote/path", "unix:///", "unix:///socket?x=1", "unix:///socket#fragment", "unix:///bad\npath"} {
		if ValidDockerHost(host) {
			t.Fatal("unsafe endpoint", host)
		}
	}
	if !ValidDockerHost("unix:///run/user/8091/docker.sock") {
		t.Fatal("rootless endpoint rejected")
	}
}
