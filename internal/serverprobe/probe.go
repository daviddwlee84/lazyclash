// Package serverprobe verifies a newly deployed proxy through an isolated
// authenticated Mihomo client, without changing a user's active client.
package serverprobe

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"go.yaml.in/yaml/v3"
)

type Options struct {
	// Binary explicitly selects a local Mihomo binary; empty prefers PATH and
	// otherwise downloads the same verified release as managed client setup.
	Binary        string
	InterfaceName string
	Endpoint      string
	RootCAs       *x509.CertPool
	ResolveBinary func(context.Context, string) (string, error)
	// Start and Validate allow deterministic lifecycle tests without services.
	Start    func(context.Context, string, string) (func(), <-chan struct{}, error)
	Validate func(context.Context, string, string) error
}

// ValidateInterface checks an explicit caller choice. Verification never
// silently selects a physical interface or changes an existing VPN/TUN.
func ValidateInterface(name string) error {
	if name == "" {
		return nil
	}
	if _, err := net.InterfaceByName(name); err != nil {
		return fmt.Errorf("local verification interface %q is unavailable", name)
	}
	return nil
}

func Probe(ctx context.Context, nodeYAML []byte) (string, error) {
	return ProbeWithOptions(ctx, nodeYAML, Options{})
}

func ProbeWithOptions(parent context.Context, nodeYAML []byte, opts Options) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	if err := ValidateInterface(opts.InterfaceName); err != nil {
		return "", err
	}
	nodes, diagnostics, err := configwork.ParseImport(nodeYAML)
	if err != nil || len(diagnostics) > 0 || len(nodes) != 1 {
		return "", errors.New("proxy verification requires exactly one valid node")
	}
	node := nodes[0].Map()
	node["name"] = "LAZYCLASH-VERIFY"
	stage, err := os.MkdirTemp("", "lazyclash-server-probe-")
	if err != nil {
		return "", errors.New("cannot prepare private verification directory")
	}
	defer os.RemoveAll(stage)
	if err = os.Chmod(stage, 0700); err != nil {
		return "", err
	}
	binary := opts.Binary
	if binary == "" {
		resolve := opts.ResolveBinary
		if resolve == nil {
			resolve = resolveBinary
		}
		binary, err = resolve(ctx, stage)
		if err != nil {
			return "", err
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", errors.New("cannot reserve verification listener")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	secret := make([]byte, 24)
	if _, err = rand.Read(secret); err != nil {
		listener.Close()
		return "", err
	}
	password := hex.EncodeToString(secret)
	profile := map[string]any{"mixed-port": port, "bind-address": "127.0.0.1", "allow-lan": false, "authentication": []string{"verify:" + password}, "mode": "rule", "log-level": "silent", "ipv6": true, "proxies": []any{node}, "rules": []string{"MATCH,LAZYCLASH-VERIFY"}, "profile": map[string]any{"store-selected": false, "store-fake-ip": false}, "dns": map[string]any{"enable": false}}
	if opts.InterfaceName != "" {
		profile["interface-name"] = opts.InterfaceName
	}
	data, err := yaml.Marshal(profile)
	if err != nil {
		listener.Close()
		return "", errors.New("cannot encode verification profile")
	}
	configPath := filepath.Join(stage, "config.yaml")
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		listener.Close()
		return "", err
	}
	validate := opts.Validate
	if validate == nil {
		validate = validateCore
	}
	if err = validate(ctx, binary, configPath); err != nil {
		listener.Close()
		return "", err
	}
	listener.Close()
	start := opts.Start
	if start == nil {
		start = startCore
	}
	stop, exited, err := start(ctx, binary, configPath)
	if err != nil {
		return "", err
	}
	defer stop()
	probeCtx, cancelProbe := context.WithCancel(ctx)
	defer cancelProbe()
	ctx = probeCtx
	ownedExit := func() bool {
		select {
		case <-exited:
			return true
		default:
			return false
		}
	}
	if exited != nil {
		go func() {
			select {
			case <-exited:
				cancelProbe()
			case <-probeCtx.Done():
			}
		}()
	}
	endpoints := []string{opts.Endpoint}
	if opts.Endpoint == "" {
		endpoints = []string{"https://api.ip.sb/geoip", "https://www.cloudflare.com/cdn-cgi/trace"}
	}
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return "", errors.New("verification endpoint must be an HTTPS URL without credentials")
		}
	}
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), User: url.UserPassword("verify", password)}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10}
	if opts.RootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || req.URL.Scheme != "https" {
			return errors.New("verification redirect refused")
		}
		return nil
	}}
	// Endpoint redundancy uses the same authenticated proxy transport throughout.
	// Neither failed readiness nor an endpoint failure permits direct traffic.
	ready, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readyCancel()
	for {
		if ownedExit() {
			return "", errors.New("temporary verification client exited before verification completed")
		}
		conn, e := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ready, "tcp", proxyURL.Host)
		if e == nil {
			conn.Close()
			break
		}
		select {
		case <-ready.Done():
			if ownedExit() {
				return "", errors.New("temporary verification client exited before verification completed")
			}
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", errors.New("temporary verification client did not become ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	for _, endpoint := range endpoints {
		ip, err := probeEndpoint(ctx, client, endpoint)
		if ownedExit() {
			return "", errors.New("temporary verification client exited before verification completed")
		}
		if err == nil {
			return ip, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", errors.New("authenticated proxy HTTPS verification failed at the configured endpoints; server remains installed but unverified")
}

func probeEndpoint(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", errors.New("cannot build verification request")
	}
	req.Header.Set("User-Agent", "lazyclash-server-verification")
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("authenticated proxy HTTPS request failed; server remains installed but unverified")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy verification endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return "", errors.New("invalid proxy verification response")
	}
	return exitIP(body)
}

func exitIP(body []byte) (string, error) {
	var result struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(body, &result) != nil {
		// Cloudflare trace is a newline-delimited diagnostic response. Require
		// one exact ip= entry, not an IP-looking substring in arbitrary HTML.
		count := 0
		for _, line := range strings.Split(string(body), "\n") {
			if ip, ok := strings.CutPrefix(line, "ip="); ok {
				result.IP = ip
				count++
			}
		}
		if count != 1 {
			return "", errors.New("proxy verification endpoint returned an invalid response")
		}
	}
	ip := net.ParseIP(strings.TrimSpace(result.IP))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return "", errors.New("proxy verification endpoint did not return a usable exit IP")
	}
	return ip.String(), nil
}

func resolveBinary(ctx context.Context, stage string) (string, error) {
	if path, err := exec.LookPath("mihomo"); err == nil {
		return path, nil
	}
	// Reuse the installed client executable, never its live configuration,
	// controller or process. The new instance still owns only its temp directory.
	if runtime.GOOS == "darwin" {
		candidates := []string{"/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo"}
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, "Applications/Clash Verge.app/Contents/MacOS/verge-mihomo"))
		}
		for _, path := range candidates {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				return path, nil
			}
		}
	}
	_, archive, err := managedcore.DownloadProbeArtifact(ctx, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", errors.New("cannot acquire verified temporary Mihomo client; install mihomo on PATH and retry verification")
	}
	r, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return "", errors.New("invalid verified client archive")
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, (128<<20)+1))
	if err != nil || len(data) > 128<<20 {
		return "", errors.New("temporary client archive exceeds limit")
	}
	p := filepath.Join(stage, "mihomo")
	if err = os.WriteFile(p, data, 0700); err != nil {
		return "", err
	}
	return p, nil
}

func validateCore(parent context.Context, binary, path string) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-t", "-d", filepath.Dir(path), "-f", path)
	cmd.Dir = filepath.Dir(path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("temporary Mihomo rejected the generated proxy configuration")
	}
	return nil
}

func startCore(ctx context.Context, binary, path string) (func(), <-chan struct{}, error) {
	child, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(child, binary, "-d", filepath.Dir(path), "-f", path)
	cmd.Dir = filepath.Dir(path)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, errors.New("cannot start temporary verification client")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	return func() { cancel(); <-done }, done, nil
}
