package proxyenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go.yaml.in/yaml/v3"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type DockerRenderOptions struct {
	Format             string
	Services           []string
	Scope              string
	NoProxy            string
	IncludeCredentials bool
}

func RenderDocker(p Plan, opts DockerRenderOptions) (string, error) {
	if p.SSHHost != "" {
		return "", errors.New("Docker needs an explicit endpoint reachable from its container/builder; an SSH target or local shell tunnel is not sufficient")
	}
	if !opts.IncludeCredentials && (p.Username != "" || p.PasswordEnv != "" || p.PasswordFile != "") {
		return "", errors.New("generated Docker files expose proxy credentials; use --include-credentials explicitly or an unauthenticated reachable endpoint")
	}
	if strings.ContainsAny(opts.NoProxy, "\x00\r\n") {
		return "", errors.New("invalid NO_PROXY value")
	}
	values, err := Values(p)
	if err != nil {
		return "", err
	}
	keys := append([]string{}, Variables...)
	if opts.NoProxy != "" {
		values["no_proxy"], values["NO_PROXY"] = opts.NoProxy, opts.NoProxy
		keys = append(keys, "no_proxy", "NO_PROXY")
	}
	format := opts.Format
	if format == "" {
		format = "env-file"
	}
	switch format {
	case "env-file":
		var out strings.Builder
		for _, key := range keys {
			if strings.ContainsAny(values[key], "\x00\r\n") {
				return "", errors.New("invalid environment value")
			}
			fmt.Fprintf(&out, "%s=%s\n", key, values[key])
		}
		return out.String(), nil
	case "build-args":
		var parts []string
		for _, key := range keys {
			parts = append(parts, "--build-arg "+Quote(key+"="+values[key]))
		}
		return strings.Join(parts, " ") + "\n", nil
	case "compose":
		if len(opts.Services) == 0 {
			return "", errors.New("Compose output requires --service NAME; select only services with build configuration for build scope")
		}
		scope := opts.Scope
		if scope == "" {
			scope = "runtime"
		}
		if scope != "runtime" && scope != "build" && scope != "both" {
			return "", errors.New("Compose scope must be runtime, build or both")
		}
		services := map[string]any{}
		for _, service := range opts.Services {
			if !dockerName.MatchString(service) {
				return "", errors.New("invalid Compose service name")
			}
			env := map[string]string{}
			for key, value := range values {
				env[key] = strings.ReplaceAll(value, "$", "$$")
			}
			entry := map[string]any{}
			if scope != "build" {
				entry["environment"] = env
			}
			if scope != "runtime" {
				entry["build"] = map[string]any{"args": env}
			}
			services[service] = entry
		}
		data, e := yaml.Marshal(map[string]any{"services": services})
		return string(data), e
	case "client-json":
		entry := map[string]string{"httpProxy": values["http_proxy"], "httpsProxy": values["https_proxy"], "allProxy": values["all_proxy"]}
		if opts.NoProxy != "" {
			entry["noProxy"] = opts.NoProxy
		}
		data, e := json.MarshalIndent(map[string]any{"proxies": map[string]any{"default": entry}}, "", "  ")
		return string(data) + "\n", e
	default:
		return "", errors.New("Docker format must be env-file, compose, build-args or client-json")
	}
}
func WriteArtifact(path, text string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create artifact; choose a new file in an existing directory")
	}
	_, err = f.WriteString(text)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return closeErr
}

var dockerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

type DockerTestOptions struct {
	Container, Image, Network, URL string
	Run                            Runner
}

func DockerTest(ctx context.Context, p Plan, opts DockerTestOptions) (TestResult, error) {
	if (opts.Container == "") == (opts.Image == "") {
		return TestResult{}, errors.New("choose one existing --container NAME or already-local --image REF")
	}
	if opts.Container != "" && !dockerName.MatchString(opts.Container) {
		return TestResult{}, errors.New("invalid container name or ID")
	}
	if opts.Network != "" && !dockerName.MatchString(opts.Network) {
		return TestResult{}, errors.New("invalid Docker network name")
	}
	if opts.Container != "" && opts.Network != "" {
		return TestResult{}, errors.New("an existing container already owns its network; omit --network")
	}
	if strings.HasPrefix(opts.Image, "-") || strings.ContainsAny(opts.Image, "\x00\r\n ") {
		return TestResult{}, errors.New("invalid image reference")
	}
	values, err := Values(p)
	if err != nil {
		return TestResult{}, err
	}
	u := opts.URL
	if u == "" {
		u = DefaultTestURL
	}
	parsed, e := url.Parse(u)
	if e != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return TestResult{}, errors.New("Docker test URL must be HTTP(S) without credentials or fragment")
	}
	if strings.ContainsAny(u, "\r\n\x00") {
		return TestResult{}, errors.New("invalid Docker test URL")
	}
	quote := func(value string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"` }
	input := "proxy = " + quote(values["https_proxy"]) + "\nurl = " + quote(u) + "\nnoproxy = \"\"\nhead\nsilent\nshow-error\nconnect-timeout = 5\nmax-time = 10\noutput = \"/dev/null\"\nwrite-out = \"%{http_code}\"\n"
	var args []string
	if opts.Container != "" {
		args = []string{"exec", "-i", opts.Container, "curl", "--config", "-"}
	} else {
		args = []string{"run", "--rm", "--pull=never", "-i"}
		if opts.Network != "" {
			args = append(args, "--network", opts.Network)
		}
		args = append(args, "--entrypoint", "curl", opts.Image, "--config", "-")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(input)
	var out, diagnostic cappedBuffer
	out.limit, diagnostic.limit = 1024, 8192
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	cmd.WaitDelay = time.Second
	start := time.Now()
	run := opts.Run
	if run == nil {
		run = func(c *exec.Cmd) error { return c.Run() }
	}
	err = run(cmd)
	result := TestResult{Endpoint: p.HTTP, URL: safeTestURL(u), Scope: "Docker container; builder not verified", Milliseconds: time.Since(start).Milliseconds()}
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, errors.New("container proxy test failed; ensure the container/image exists, contains curl, and can reach the endpoint (no image was pulled)")
	}
	result.HTTPStatus, err = strconv.Atoi(strings.TrimSpace(out.String()))
	if err != nil || result.HTTPStatus < 100 || result.HTTPStatus > 599 {
		return result, errors.New("container returned an invalid HTTP result")
	}
	if result.HTTPStatus == 407 {
		return result, errors.New("proxy authentication rejected")
	}
	return result, nil
}

func DockerDoctor(ctx context.Context) map[string]any {
	result := map[string]any{"scope": "read-only Docker metadata", "daemon_modified": false, "builder": "not verified; Buildx may run on another host", "guidance": []string{"Container/build proxy settings do not configure docker pull.", "Docker Desktop uses its proxy settings UI; daemon.json proxies are ignored.", "Linux daemon proxy changes require an explicit owner-aware daemon restart; lazyclash does not perform it.", "Loopback belongs to the consumer namespace; use an explicitly reachable endpoint and docker test.", "Generated files do not modify ~/.docker/config.json; preserve its existing owner (including chezmoi)."}}
	query := func(args ...string) string {
		q, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(q, "docker", args...)
		var out cappedBuffer
		out.limit = 8192
		cmd.Stdout = &out
		cmd.WaitDelay = time.Second
		if cmd.Run() != nil {
			return ""
		}
		return strings.TrimSpace(out.String())
	}
	if name := query("context", "show"); name != "" {
		result["context"] = name
	} else {
		result["error"] = "Docker context unavailable"
		return result
	}
	if host := query("context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"); host != "" {
		var endpoint string
		if json.Unmarshal([]byte(host), &endpoint) == nil {
			result["context_endpoint"] = safeEndpoint(endpoint)
		}
	}
	result["docker_host_override_set"] = os.Getenv("DOCKER_HOST") != ""
	result["docker_context_override_set"] = os.Getenv("DOCKER_CONTEXT") != ""
	if info := query("info", "--format", `{"version":{{json .ServerVersion}},"os":{{json .OperatingSystem}},"http_proxy":{{json .HTTPProxy}},"https_proxy":{{json .HTTPSProxy}}}`); info != "" {
		var values map[string]string
		if json.Unmarshal([]byte(info), &values) == nil {
			for _, key := range []string{"http_proxy", "https_proxy"} {
				if values[key] != "" {
					values[key] = safeEndpoint(values[key])
				}
			}
			result["daemon"] = values
		}
	} else {
		result["daemon"] = "unavailable"
	}
	return result
}

func safeTestURL(value string) string {
	if i := strings.Index(value, "?"); i >= 0 {
		return value[:i]
	}
	return value
}
