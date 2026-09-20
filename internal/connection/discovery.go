package connection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"go.yaml.in/yaml/v3"
)

const maxConfigBytes = 8 << 20

type runtimeConfig struct {
	Controller     string    `yaml:"external-controller"`
	TLSController  string    `yaml:"external-controller-tls"`
	UnixController string    `yaml:"external-controller-unix"`
	Secret         string    `yaml:"secret"`
	Proxies        yaml.Node `yaml:"proxies"`
	ProxyProviders yaml.Node `yaml:"proxy-providers"`
	Rules          yaml.Node `yaml:"rules"`
	RuleProviders  yaml.Node `yaml:"rule-providers"`
}

func parseRuntime(data []byte) (runtimeConfig, error) {
	var runtime runtimeConfig
	if len(data) > maxConfigBytes {
		return runtime, errors.New("configuration exceeds size limit")
	}
	if err := yaml.Unmarshal(data, &runtime); err != nil {
		return runtime, errors.New("invalid controller configuration YAML")
	}
	if _, err := cleanSecret(runtime.Secret); err != nil {
		return runtime, err
	}
	return runtime, nil
}

func (r runtimeConfig) complete() bool {
	return (r.Proxies.Kind != 0 || r.ProxyProviders.Kind != 0) && (r.Rules.Kind != 0 || r.RuleProviders.Kind != 0)
}

func (r runtimeConfig) controllers() []string {
	var endpoints []string
	for _, entry := range []struct{ value, scheme string }{{r.Controller, "http"}, {r.TLSController, "https"}, {r.UnixController, "unix"}} {
		if entry.value == "" {
			continue
		}
		e, err := normalizeController(entry.value, entry.scheme)
		if err == nil {
			endpoints = append(endpoints, e)
		}
	}
	return endpoints
}
func (r runtimeConfig) matches(controller string) bool {
	for _, endpoint := range r.controllers() {
		if endpoint == strings.TrimSuffix(controller, "/") {
			return true
		}
	}
	return false
}

func normalizeController(value, scheme string) (string, error) {
	value = strings.TrimSpace(value)
	if scheme == "unix" {
		if !strings.HasPrefix(value, "unix://") {
			value = "unix://" + value
		}
	} else if !strings.Contains(value, "://") {
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return "", err
		}
		if host == "" || host == "0.0.0.0" || host == "*" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		value = scheme + "://" + net.JoinHostPort(host, port)
	}
	if err := config.ValidateController(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(value, "/"), nil
}

// Discover only reads runtime configuration and probes GET /version. It never
// falls back during Open of an explicitly chosen target. A 401 is exposed as an
// authentication-needed candidate, not mistaken for a usable controller.
func Discover(ctx context.Context, sshHost string) ([]config.Target, error) {
	if sshHost != "" {
		return discoverRemote(ctx, sshHost)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("cannot locate home directory for local discovery")
	}
	paths := knownPaths(home, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("XDG_DATA_HOME"))
	psCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	ps, _ := commandContext(psCtx, "ps", "-axo", "pid=,command=").Output()
	cancel()
	paths = uniquePaths(append(processConfigPaths(string(ps)), paths...))
	var candidates []config.Target
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readLimitedFile(path, maxConfigBytes)
		if err != nil {
			continue
		}
		runtime, err := parseRuntime(data)
		if err != nil {
			continue
		}
		for _, endpoint := range runtime.controllers() {
			t := candidate(endpoint, path, "", runtime)
			if runtime.complete() {
				t.Configs = append(t.Configs, config.CoreConfig{ID: "runtime", Name: "Runtime YAML", Path: path})
			}
			t.Configs = append(t.Configs, localProfiles(filepath.Dir(path))...)
			candidates = append(candidates, t)
		}
	}
	for _, endpoint := range processListeners(ctx, "", string(ps)) {
		candidates = append(candidates, candidate(endpoint, "", "", runtimeConfig{}))
	}
	return probeCandidates(ctx, candidates, ""), ctx.Err()
}

func candidate(endpoint, path, sshHost string, runtime runtimeConfig) config.Target {
	hash := sha256.Sum256([]byte(sshHost + "\x00" + endpoint))
	name := endpoint
	if path != "" {
		name = filepath.Base(filepath.Dir(path)) + " · " + endpoint
	}
	if sshHost != "" {
		name = sshHost + " · " + name
	}
	return config.Target{ID: "core-" + hex.EncodeToString(hash[:4]), Name: name, Controller: endpoint, SSHHost: sshHost, SourceConfig: path, Secret: runtime.Secret}
}

func probeCandidates(ctx context.Context, candidates []config.Target, sshHost string) []config.Target {
	// Source-backed and process-owned endpoints retain priority. The two known
	// defaults get independent empty credentials and never borrow another core's.
	seen := map[string]bool{}
	for _, t := range candidates {
		seen[t.Controller] = true
	}
	for _, port := range []string{"9090", "9097"} {
		endpoint := "http://127.0.0.1:" + port
		if !seen[endpoint] {
			candidates = append(candidates, candidate(endpoint, "", sshHost, runtimeConfig{}))
		}
	}
	return probeBatch(ctx, candidates)
}

func probeBatch(ctx context.Context, candidates []config.Target) []config.Target {
	// Keep deterministic configuration order even when probes finish out of order.
	results := make([]*config.Target, len(candidates))
	limit := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, t := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int, t config.Target) {
			defer wg.Done()
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limit }()
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			// Discovery already read the candidate's source. Open's ordinary path
			// re-reads it later so saved targets never retain stale credentials.
			probeTarget := t
			probeTarget.SourceConfig = ""
			_, closer, err := Open(probeCtx, probeTarget, true)
			if err != nil {
				var coreErr *core.Error
				if errors.As(err, &coreErr) && coreErr.Kind == core.KindAuth {
					t.AuthRequired = true
					results[i] = &t
				}
				return
			}
			defer closer.Close()
			results[i] = &t
		}(i, t)
	}
	wg.Wait()
	byEndpoint := map[string]int{}
	var found []config.Target
	for _, result := range results {
		if result == nil {
			continue
		}
		t := *result
		key := t.SSHHost + "\x00" + t.Controller
		if prior, ok := byEndpoint[key]; ok {
			if found[prior].AuthRequired && !t.AuthRequired {
				found[prior] = t
			}
			continue
		}
		byEndpoint[key] = len(found)
		found = append(found, t)
	}
	return found
}

func knownPaths(home, xdgConfig, xdgData string) []string {
	if !filepath.IsAbs(xdgConfig) {
		xdgConfig = filepath.Join(home, ".config")
	}
	if !filepath.IsAbs(xdgData) {
		xdgData = filepath.Join(home, ".local", "share")
	}
	var dirs []string
	for _, name := range []string{"mihomo", "clash", "clash-verge", "clash-verge-rev"} {
		dirs = append(dirs, filepath.Join(xdgConfig, name))
	}
	for _, name := range []string{"io.github.clash-verge-rev.clash-verge-rev", "io.github.clash-verge-rev.clash-verge", "com.github.zzzgydi.clashverge", "io.github.zzzgydi.clash-verge"} {
		dirs = append(dirs, filepath.Join(home, "Library", "Application Support", name), filepath.Join(xdgData, name))
	}
	for _, name := range []string{"mihomo", "clash", "ClashX", "ClashMetaX"} {
		dirs = append(dirs, filepath.Join(home, "Library", "Application Support", name))
	}
	dirs = append(dirs, "/etc/mihomo", "/etc/clash")
	var paths []string
	for _, dir := range dirs {
		for _, name := range []string{"clash-verge.yaml", "config.yaml", "config.yml"} {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	return paths
}

func processConfigPaths(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		_, command, ok := coreProcess(line)
		if !ok {
			continue
		}
		line = command
		// Append a sentinel to let the regexp inspect adjacent flags separately.
		for _, flag := range []string{"-f", "-d", "--config", "--home"} {
			re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(flag) + `(?:=|\s+)(.*?)(?:\s+-[A-Za-z]|$)`)
			match := re.FindStringSubmatch(line)
			if len(match) < 2 {
				continue
			}
			path := strings.Trim(strings.TrimSpace(match[1]), "'\"")
			if !filepath.IsAbs(path) {
				continue
			}
			if flag == "-d" || flag == "--home" {
				path = filepath.Join(path, "config.yaml")
			}
			paths = append(paths, path)
		}
	}
	return uniquePaths(paths)
}

func uniquePaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		if !seen[p] && filepath.IsAbs(p) {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Verge index types distinguish complete subscription/local profiles from
// Merge and Script fragments; fragments are never proposed for PUT /configs.
func localProfiles(dir string) []config.CoreConfig {
	data, err := readLimitedFile(filepath.Join(dir, "profiles.yaml"), maxConfigBytes)
	if err != nil {
		return nil
	}
	return indexedProfiles(data, dir, func(path string) ([]byte, error) { return readLimitedFile(path, maxConfigBytes) })
}

func indexedProfiles(data []byte, dir string, read func(string) ([]byte, error)) []config.CoreConfig {
	var index struct {
		Items []struct {
			UID  string `yaml:"uid"`
			Type string `yaml:"type"`
			Name string `yaml:"name"`
			File string `yaml:"file"`
		} `yaml:"items"`
	}
	if yaml.Unmarshal(data, &index) != nil {
		return nil
	}
	var result []config.CoreConfig
	seen := map[string]bool{}
	for _, item := range index.Items {
		if item.Type != "local" && item.Type != "remote" {
			continue
		}
		if item.File == "" || filepath.Base(item.File) != item.File {
			continue
		}
		path := filepath.Join(dir, "profiles", item.File)
		content, err := read(path)
		if err != nil {
			continue
		}
		runtime, err := parseRuntime(content)
		if err != nil || !runtime.complete() {
			continue
		}
		hash := sha256.Sum256([]byte(path))
		id := "profile-" + hex.EncodeToString(hash[:4])
		if seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, config.CoreConfig{ID: id, Name: item.Name, Path: path})
	}
	return result
}

func discoverRemote(ctx context.Context, host string) ([]config.Target, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	inventory, err := remoteCommand(ctx, host, `printf '%s\000%s\000%s\000' "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME"; ps -axo pid=,command= 2>/dev/null`, 1<<20)
	if err != nil {
		return nil, err
	}
	parts := bytes.SplitN(inventory, []byte{0}, 4)
	if len(parts) != 4 || !filepath.IsAbs(string(parts[0])) {
		return nil, errors.New("cannot determine remote home directory")
	}
	paths := knownPaths(string(parts[0]), string(parts[1]), string(parts[2]))
	paths = uniquePaths(append(processConfigPaths(string(parts[3])), paths...))
	// One SSH round trip reads only the enumerated known paths; there is no port
	// scan, privilege escalation, recursive filesystem walk or shell evaluation.
	files, err := remoteCommand(ctx, host, remoteFileScript(paths), 32<<20)
	if err != nil {
		return nil, err
	}
	segments := bytes.Split(files, []byte{0})
	allowed := map[string]bool{}
	for _, path := range paths {
		allowed[path] = true
	}
	var candidates []config.Target
	for i := 0; i+1 < len(segments); i += 2 {
		path := string(segments[i])
		if !allowed[path] {
			continue
		}
		runtime, err := parseRuntime(segments[i+1])
		if err != nil {
			continue
		}
		for _, endpoint := range runtime.controllers() {
			if strings.HasPrefix(endpoint, "unix://") {
				continue
			}
			t := candidate(endpoint, path, host, runtime)
			if runtime.complete() {
				t.Configs = []config.CoreConfig{{ID: "runtime", Name: "Runtime YAML", Path: path}}
			}
			candidates = append(candidates, t)
		}
	}
	for _, endpoint := range processListeners(ctx, host, string(parts[3])) {
		candidates = append(candidates, candidate(endpoint, "", host, runtimeConfig{}))
	}
	found := probeCandidates(ctx, candidates, host)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return found, nil
}

func remoteFileScript(paths []string) string {
	var script strings.Builder
	script.WriteString("for f in")
	for _, path := range paths {
		script.WriteString(" " + shellQuote(path))
	}
	script.WriteString(`; do if test -f "$f" && test -r "$f"; then printf '%s\000' "$f"; head -c 8388609 < "$f"; printf '\000'; fi; done`)
	return script.String()
}

// ControllerAddress returns the remote host and effective port without changing
// the original URL used for HTTP Host and TLS verification.
func ControllerAddress(endpoint string) (string, error) {
	if err := config.ValidateController(endpoint); err != nil {
		return "", err
	}
	u, _ := url.Parse(endpoint)
	if u.Scheme == "unix" {
		return "", fmt.Errorf("Unix socket has no TCP address")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}
