package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeValidationDockerBindingValidationAndPreservation(t *testing.T) {
	image := "sha256:" + strings.Repeat("b", 64)
	base := ConfigSource{Kind: "native", ConfigID: "main", Binary: "/opt/mihomo", Home: "/home/user/mihomo", ValidationDockerHost: "unix:///run/user/1000/docker.sock", ValidationImage: image}
	for _, tc := range []struct {
		name   string
		mutate func(*ConfigSource)
	}{
		{"missing socket", func(s *ConfigSource) { s.ValidationDockerHost = "" }},
		{"missing image", func(s *ConfigSource) { s.ValidationImage = "" }},
		{"remote socket", func(s *ConfigSource) { s.ValidationDockerHost = "tcp://localhost:2375" }},
		{"mutable image", func(s *ConfigSource) { s.ValidationImage = "alpine:latest" }},
		{"short image", func(s *ConfigSource) { s.ValidationImage = "sha256:abc" }},
		{"docker source", func(s *ConfigSource) { s.Kind = "docker" }},
		{"verge source", func(s *ConfigSource) { s.Kind = "verge" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mutate(&s)
			if err := ValidateConfigSource(Target{ConfigSource: &s, Configs: []CoreConfig{{ID: "main", Path: "/home/user/mihomo/config.yaml"}}}); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte("# keep\n[[targets]]\nid='fixture'\ncontroller='http://127.0.0.1:9090'\nunknown='keep'\n[[targets.configs]]\nid='main'\npath='/home/user/mihomo/config.yaml'\n"), 0600)
	cfg, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets[0].ConfigSource = &base
	if err = Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	next, err := Load(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if *next.Targets[0].ConfigSource != base {
		t.Fatal("sandbox binding lost")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "# keep") || !strings.Contains(string(data), "unknown='keep'") {
		t.Fatal("unrelated configuration lost")
	}
}
