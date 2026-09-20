package proxyenv

import (
	"context"
	"go.yaml.in/yaml/v3"
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestDockerFormatsAndNoImplicitMutations(t *testing.T) {
	p := Plan{HTTP: "http://host.docker.internal:7897", All: "socks5h://host.docker.internal:7897"}
	for _, format := range []string{"env-file", "build-args", "compose", "client-json"} {
		text, err := RenderDocker(p, DockerRenderOptions{Format: format, Services: []string{"web"}, Scope: "both", NoProxy: "localhost,127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "host.docker.internal:7897") {
			t.Fatal(text)
		}
		if format == "compose" {
			var got map[string]any
			if yaml.Unmarshal([]byte(text), &got) != nil || got["services"] == nil {
				t.Fatal(text)
			}
		}
	}
	if _, err := RenderDocker(p, DockerRenderOptions{Format: "compose"}); err == nil {
		t.Fatal("missing service accepted")
	}
	p.PasswordEnv = "PW"
	if _, err := RenderDocker(p, DockerRenderOptions{}); err == nil {
		t.Fatal("credential artifact silently allowed")
	}
}

func TestDockerConsumerProbeNoPullNoCredentialArgv(t *testing.T) {
	p := Plan{HTTP: "http://host.docker.internal:7897", All: "http://host.docker.internal:7897", Username: "user", PasswordEnv: "DOCKER_PROXY_FIXTURE_SECRET"}
	t.Setenv("DOCKER_PROXY_FIXTURE_SECRET", "PRIVATE&$value")
	run := func(cmd *exec.Cmd) error {
		args := strings.Join(cmd.Args, " ")
		if !strings.Contains(args, "--pull=never") || !strings.Contains(args, "--rm") || strings.Contains(args, "PRIVATE") || strings.Contains(args, "7897") {
			t.Fatalf("unsafe docker argv: %s", args)
		}
		input, _ := io.ReadAll(cmd.Stdin)
		if !strings.Contains(string(input), "proxy = ") || !strings.Contains(string(input), `noproxy = ""`) {
			t.Fatal(string(input))
		}
		_, err := io.WriteString(cmd.Stdout, "204")
		return err
	}
	result, err := DockerTest(context.Background(), p, DockerTestOptions{Image: "fixture/curl:local", Run: run})
	if err != nil || result.HTTPStatus != 204 {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err := DockerTest(context.Background(), p, DockerTestOptions{Image: "fixture", Container: "fixture", Run: run}); err == nil {
		t.Fatal("ambiguous consumer")
	}
}
