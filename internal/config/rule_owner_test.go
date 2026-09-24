package config

import (
	"strings"
	"testing"
)

func TestCopyRuleOwnerIsIndependentAndKeepsValidationSandbox(t *testing.T) {
	target := Target{Configs: []CoreConfig{{ID: "main", Path: "/core/config.yaml"}}, ConfigSource: &ConfigSource{Kind: "native", ConfigID: "main", Binary: "/core/mihomo", Home: "/core", ValidationDockerHost: "unix:///run/docker.sock", ValidationImage: "sha256:" + strings.Repeat("a", 64)}}
	source, err := RuleSourceFromConfigSource(target)
	if err != nil || source.Kind != "mihomo" || source.ValidationImage != target.ConfigSource.ValidationImage || target.RuleSource != nil {
		t.Fatal(source, err)
	}
	target.ConfigSource.Home = "/changed"
	if source.Home != "/core" {
		t.Fatal("rule owner aliased config source")
	}
}

func TestDockerRuleOwnerValidationAndPersistence(t *testing.T) {
	target := Target{RuleSource: &RuleSource{Kind: "docker", HostPath: "/host/config.yaml", CorePath: "/core/config.yaml", Container: "mihomo", DockerHost: "unix:///run/docker.sock", Binary: "/mihomo", Home: "/core"}}
	if err := ValidateRuleSource(target); err != nil {
		t.Fatal(err)
	}
	raw, err := patchRuleSource([]byte("[[targets]]\nid='x'\n"), target.RuleSource)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"host_path", "core_path", "container", "docker_host"} {
		if !strings.Contains(string(raw), field) {
			t.Fatal("missing", field)
		}
	}
	target.RuleSource.Kind = "mihomo"
	if ValidateRuleSource(target) == nil {
		t.Fatal("Docker fields accepted for native owner")
	}
	target.RuleSource.Kind = "docker"
	target.RuleSource.CorePath = ""
	if ValidateRuleSource(target) == nil {
		t.Fatal("missing container reload path accepted")
	}
}
