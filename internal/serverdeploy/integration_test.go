package serverdeploy

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverprobe"
	"go.yaml.in/yaml/v3"
)

// Run with LAZYCLASH_SERVER_INTEGRATION=1. Only disposable Docker containers
// and test temporary directories are changed; no SSH or host services are used.
func TestIntegrationOfficialLinuxCores(t *testing.T) {
	if os.Getenv("LAZYCLASH_SERVER_INTEGRATION") != "1" {
		t.Skip("set LAZYCLASH_SERVER_INTEGRATION=1 for disposable-container integration")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v %s", args[0], err, out)
		}
		return out
	}
	arch := "arm64"
	architecture := strings.TrimSpace(string(run("info", "--format", "{{.Architecture}}")))
	if architecture == "x86_64" {
		arch = "amd64"
	}
	dir := t.TempDir()
	for _, recipe := range []string{"vless-reality", "hysteria2"} {
		a, err := resolveArtifact(ctx, Request{Recipe: recipe, Backend: "native"}, arch)
		if err != nil {
			t.Fatal(err)
		}
		if recipe == "vless-reality" {
			image, err := resolveImage(ctx, "ghcr.io", "xtls/xray-core", strings.TrimPrefix(a.Version, "v"))
			if err != nil {
				t.Fatal(err)
			}
			run("pull", image)
			container := strings.TrimSpace(string(run("create", image)))
			run("cp", container+":/usr/local/bin/xray", filepath.Join(dir, "xray"))
			run("rm", container)
			t.Logf("verified official Xray container %s", image)
			continue
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("artifact download status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 150<<20))
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != a.SHA256 {
			t.Fatal("artifact SHA256 mismatch")
		}
		name := "hysteria"
		if recipe == "vless-reality" {
			name = "xray"
			reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
			if err != nil {
				t.Fatal(err)
			}
			f, err := reader.Open("xray")
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(f)
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if err = os.WriteFile(filepath.Join(dir, name), body, 0755); err != nil {
			t.Fatal(err)
		}
		t.Logf("verified %s %s %s", name, a.Version, a.SHA256)
	}
	cert, key := integrationCertificate(t)
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), key, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := generateCredentials()
	if err != nil {
		t.Fatal(err)
	}
	for _, recipe := range Recipes() {
		for _, backend := range []string{"native", "compose"} {
			t.Run(recipe.ID+"/"+backend, func(t *testing.T) {
				r := Request{ID: "integration", Recipe: recipe.ID, Backend: backend, PublicHost: "127.0.0.1", PublicPort: 443, ListenPort: 443, Domain: "proxy.example.com", RealityTarget: "www.microsoft.com:443", ServerName: "www.microsoft.com"}
				a := Artifact{Image: "ghcr.io/xtls/xray-core@sha256:" + strings.Repeat("a", 64), NginxImage: "docker.io/library/nginx@sha256:" + strings.Repeat("b", 64)}
				files, err := render(r, c, a)
				if err != nil {
					t.Fatal(err)
				}
				if backend == "compose" {
					p := filepath.Join(dir, "compose.yaml")
					if err = os.WriteFile(p, []byte(files["compose.yaml"]), 0600); err != nil {
						t.Fatal(err)
					}
					run("compose", "--file", p, "config", "--quiet")
				}
				name := "config.json"
				if recipe.ID == "hysteria2" {
					name = "config.yaml"
				}
				body := strings.ReplaceAll(files[name], "/etc/letsencrypt/live/lazyclash-integration", "/fixture")
				if err = os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				if recipe.ID != "hysteria2" {
					run("run", "--rm", "--volume", dir+":/fixture:ro", "ubuntu:24.04", "/fixture/xray", "run", "-test", "-config", "/fixture/config.json")
					return
				}
				container := "lazyclash-test-" + strings.ToLower(strings.ReplaceAll(filepath.Base(dir), "_", "-")) + "-" + backend
				run("run", "--detach", "--name", container, "--volume", dir+":/fixture:ro", "ubuntu:24.04", "/fixture/hysteria", "server", "--config", "/fixture/config.yaml")
				defer exec.Command("docker", "rm", "-f", container).Run()
				time.Sleep(time.Second)
				if strings.TrimSpace(string(run("inspect", "--format", "{{.State.Running}}", container))) != "true" {
					logs := run("logs", container)
					t.Fatalf("Hysteria exited: %s", logs)
				}
			})
		}
	}
}

func TestIntegrationRealityTunnel(t *testing.T) {
	if os.Getenv("LAZYCLASH_SERVER_E2E") != "1" {
		t.Skip("set LAZYCLASH_SERVER_E2E=1 for an authenticated REALITY tunnel in disposable containers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v %s", args[0], err, out)
		}
		return out
	}
	a, err := resolveArtifact(ctx, Request{Recipe: "vless-reality", Backend: "compose"}, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	c, err := generateCredentials()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	suffix := strings.ToLower(strings.ReplaceAll(filepath.Base(dir), "_", "-"))
	network := "lazyclash-network-" + suffix
	server := "lazyclash-reality-" + suffix
	client := "lazyclash-client-" + suffix
	run("network", "create", network)
	defer exec.Command("docker", "network", "rm", network).Run()
	r := Request{ID: "reality-test", Recipe: "vless-reality", Backend: "native", PublicHost: "127.0.0.1", ListenPort: 443, PublicPort: 443, RealityTarget: "www.cloudflare.com:443", ServerName: "www.cloudflare.com"}
	files, err := render(r, c, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "server.json"), []byte(files["config.json"]), 0644); err != nil {
		t.Fatal(err)
	}
	clientConfig := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "0.0.0.0", "port": 1080, "protocol": "http", "settings": map[string]any{"accounts": []any{map[string]any{"user": "test", "pass": c.Password}}}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": server, "port": 443, "users": []any{map[string]any{"id": c.UUID, "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"serverName": r.ServerName, "fingerprint": "chrome", "password": c.PublicKey, "shortId": c.ShortID}}}}}
	body, err := json.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "client.json"), body, 0644); err != nil {
		t.Fatal(err)
	}
	run("run", "--detach", "--name", server, "--network", network, "--publish", "127.0.0.1::443", "--user", "0:0", "--volume", dir+":/fixture:ro", a.Image, "run", "-config", "/fixture/server.json")
	defer exec.Command("docker", "rm", "-f", server).Run()
	run("run", "--detach", "--name", client, "--network", network, "--publish", "127.0.0.1::1080", "--user", "0:0", "--volume", dir+":/fixture:ro", a.Image, "run", "-config", "/fixture/client.json")
	defer exec.Command("docker", "rm", "-f", client).Run()
	port := strings.TrimSpace(string(run("inspect", "--format", `{{(index (index .NetworkSettings.Ports "1080/tcp") 0).HostPort}}`, client)))
	proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", port), User: url.UserPassword("test", c.Password)}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	var observed string
	for attempt := 0; attempt < 4; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
		response, e := httpClient.Do(req)
		if e != nil {
			t.Logf("HTTP probe: %v", e)
		}
		if e == nil {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			response.Body.Close()
			if response.StatusCode == 200 && readErr == nil {
				for _, line := range strings.Split(string(data), "\n") {
					if value, ok := strings.CutPrefix(line, "ip="); ok && net.ParseIP(value) != nil {
						observed = value
						break
					}
				}
				if observed != "" {
					break
				}
			}
		}
		time.Sleep(time.Second)
	}
	if observed == "" {
		t.Fatalf("authenticated REALITY HTTPS tunnel failed; server %s; client %s", run("logs", server), run("logs", client))
	}
	t.Logf("authenticated HTTPS request through REALITY succeeded; observed exit %s", observed)
	serverPort := strings.TrimSpace(string(run("inspect", "--format", `{{(index (index .NetworkSettings.Ports "443/tcp") 0).HostPort}}`, server)))
	r.PublicPort, err = strconv.Atoi(serverPort)
	if err != nil {
		t.Fatal(err)
	}
	node, err := yaml.Marshal(clientMap(journal{Plan: Plan{Request: r}, Credentials: c}))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := serverprobe.Probe(ctx, node)
	if err != nil {
		t.Fatalf("exported Mihomo node failed actual isolated client verification: %v", err)
	}
	t.Logf("exported Mihomo node verified by serverprobe; observed exit %s", ip)
}

func TestIntegrationNginxRestrictedStartup(t *testing.T) {
	if os.Getenv("LAZYCLASH_SERVER_NGINX") != "1" {
		t.Skip("set LAZYCLASH_SERVER_NGINX=1 for disposable native nginx startup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v %s", args[0], err, out)
		}
		return out
	}
	dir := t.TempDir()
	cert, key := integrationCertificate(t)
	for name, data := range map[string][]byte{"fullchain.pem": cert, "privkey.pem": key} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := generateCredentials()
	if err != nil {
		t.Fatal(err)
	}
	r := Request{ID: "nginx-test", Recipe: "legacy-vmess-ws-tls", Backend: "native", ListenPort: 443, Domain: "proxy.example.com"}
	files, err := render(r, c, Artifact{})
	if err != nil {
		t.Fatal(err)
	}
	config := strings.ReplaceAll(files["nginx.conf"], "/etc/letsencrypt/live/lazyclash-nginx-test", "/fixture")
	if err = os.WriteFile(filepath.Join(dir, "nginx.conf"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	container := "lazyclash-nginx-test-" + strings.ToLower(filepath.Base(dir))
	// The production helper writes root-owned private configuration. Copy the
	// runner-owned bind mount before dropping DAC capabilities so the fixture
	// has the same ownership, without chmod/chown on any host path.
	run("run", "--detach", "--name", container, "--publish", "127.0.0.1::443", "--volume", dir+":/input:ro", "ubuntu:24.04", "sleep", "300")
	defer exec.Command("docker", "rm", "-f", container).Run()
	run("exec", container, "sh", "-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends nginx")
	run("exec", container, "sh", "-c", "cp -R /input /fixture && chown -R root:root /fixture")
	run("exec", container, "nginx", "-t", "-c", "/fixture/nginx.conf")
	run("exec", container, "sh", "-c", "rm -rf /tmp/lazyclash-client /tmp/lazyclash-proxy /tmp/lazyclash-fastcgi /tmp/lazyclash-uwsgi /tmp/lazyclash-scgi")
	run("exec", "--detach", container, "setpriv", "--bounding-set=-all,+net_bind_service,+setuid,+setgid,+chown", "--no-new-privs", "nginx", "-c", "/fixture/nginx.conf", "-g", "daemon off;")
	port := strings.TrimSpace(string(run("inspect", "--format", `{{(index (index .NetworkSettings.Ports "443/tcp") 0).HostPort}}`, container)))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "proxy.example.com", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	address := "https://127.0.0.1:" + port
	for attempt := 0; attempt < 5; attempt++ {
		resp, e := client.Get(address)
		if e == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			if resp.StatusCode == 200 && string(body) == "Service ready" {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("nginx did not serve trusted HTTPS under the systemd unit capability bound")
}

func integrationCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy.example.com"}, DNSNames: []string{"proxy.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
