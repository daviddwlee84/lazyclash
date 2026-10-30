package serverdeploy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverprobe"
	"go.yaml.in/yaml/v3"
)

// All endpoints are local fixtures; no cloud resources or live profiles are used.
func TestIntegrationHysteriaTunnel(t *testing.T) {
	if os.Getenv("LAZYCLASH_SERVER_E2E") != "1" {
		t.Skip("set LAZYCLASH_SERVER_E2E=1 for authenticated HY2 HTTPS and UDP tunnels")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	binaryPath := integrationMihomo(t, ctx, managedcore.DefaultVersion)
	arch := strings.TrimSpace(string(integrationDocker(t, ctx, "info", "--format", "{{.Architecture}}")))
	if arch == "aarch64" {
		arch = "arm64"
	}
	if arch == "x86_64" {
		arch = "amd64"
	}
	native, err := resolveArtifact(ctx, Request{Recipe: "hysteria2", Backend: "native"}, arch)
	if err != nil {
		t.Fatal(err)
	}
	data, err := integrationDownload(ctx, native.URL, native.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != native.SHA256 {
		t.Fatal("HY2 binary digest mismatch")
	}
	composeArtifact, err := resolveArtifact(ctx, Request{Recipe: "hysteria2", Backend: "compose"}, arch)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Hysteria %s; Mihomo %s; native SHA256 %s; Compose %s", native.Version, managedcore.DefaultVersion, native.SHA256, composeArtifact.Image)
	cert, key := integrationCertificate(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ip=198.51.100.20") }))
	endpoint.Listener.Close()
	endpoint.Listener, err = net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	endpoint.StartTLS()
	defer endpoint.Close()
	endpointURL := "https://host.docker.internal:" + strconv.Itoa(endpoint.Listener.Addr().(*net.TCPAddr).Port)
	echo, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], addr)
		}
	}()
	for _, backend := range []string{"native", "compose"} {
		for _, mode := range []string{"none", "salamander"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				for name, body := range map[string][]byte{"fullchain.pem": cert, "privkey.pem": key, "hysteria": data} {
					if err := os.WriteFile(filepath.Join(dir, name), body, 0755); err != nil {
						t.Fatal(err)
					}
				}
				c, err := generateCredentials()
				if err != nil {
					t.Fatal(err)
				}
				c.ObfsPassword = "independent-test-obfs-secret"
				r := Request{ID: "hy2-test", Recipe: "hysteria2", Backend: backend, ListenPort: 443, PublicPort: 443, PublicHost: "127.0.0.1", Domain: "proxy.example.com"}
				if mode == "salamander" {
					r.Obfs = mode
				}
				files, err := render(r, c, composeArtifact)
				if err != nil {
					t.Fatal(err)
				}
				config := strings.ReplaceAll(files["config.yaml"], "/etc/letsencrypt/live/lazyclash-hy2-test", "/fixture")
				if err = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				name := "lazyclash-hy2-" + strings.ToLower(filepath.Base(dir)) + "-" + backend + "-" + mode
				if backend == "native" {
					integrationDocker(t, ctx, "run", "-d", "--name", name, "--add-host", "host.docker.internal:host-gateway", "-p", "127.0.0.1::443/udp", "-v", dir+":/fixture:ro", "ubuntu:24.04", "/fixture/hysteria", "server", "--config", "/fixture/config.yaml")
					t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
				} else {
					var cfg map[string]any
					if err = yaml.Unmarshal([]byte(files["compose.yaml"]), &cfg); err != nil {
						t.Fatal(err)
					}
					service := cfg["services"].(map[string]any)["core"].(map[string]any)
					// Fixture-only networking/mount overlay; retain the production image,
					// read-only filesystem, capability bounds and process configuration.
					delete(service, "network_mode")
					service["container_name"] = name
					service["ports"] = []string{"127.0.0.1::443/udp"}
					service["extra_hosts"] = []string{"host.docker.internal:host-gateway"}
					service["volumes"] = []string{dir + ":/fixture:ro"}
					service["command"] = []string{"server", "--config", "/fixture/config.yaml"}
					body, _ := yaml.Marshal(cfg)
					path := filepath.Join(dir, "compose.yaml")
					if err = os.WriteFile(path, body, 0600); err != nil {
						t.Fatal(err)
					}
					project := "hy2-" + strings.ToLower(filepath.Base(dir))
					integrationDocker(t, ctx, "compose", "-p", project, "-f", path, "up", "-d")
					t.Cleanup(func() { _ = exec.Command("docker", "compose", "-p", project, "-f", path, "down").Run() })
				}
				port := strings.TrimSpace(string(integrationDocker(t, ctx, "inspect", "--format", `{{(index (index .NetworkSettings.Ports "443/udp") 0).HostPort}}`, name)))
				r.PublicPort, err = strconv.Atoi(port)
				if err != nil {
					t.Fatal(err)
				}
				var gateway string
				for _, line := range strings.Split(string(integrationDocker(t, ctx, "exec", name, "cat", "/etc/hosts")), "\n") {
					fields := strings.Fields(line)
					if len(fields) > 1 && fields[1] == "host.docker.internal" && net.ParseIP(fields[0]).To4() != nil {
						gateway = fields[0]
						break
					}
				}
				if gateway == "" {
					t.Fatal("missing IPv4 host gateway for fixture")
				}
				node := clientMap(journal{Plan: Plan{Request: r}, Credentials: c})
				block, _ := pem.Decode(cert)
				pin := sha256.Sum256(block.Bytes)
				node["fingerprint"] = hex.EncodeToString(pin[:])
				probe := func(t *testing.T, m map[string]any, positive bool) {
					t.Helper()
					body, _ := yaml.Marshal(m)
					timeout := 6 * time.Second
					if positive {
						timeout = 35 * time.Second
					}
					probeCtx, stop := context.WithTimeout(ctx, timeout)
					defer stop()
					opts := serverprobe.Options{Binary: binaryPath, Endpoint: endpointURL, RootCAs: roots, Validate: func(ctx context.Context, binary, config string) error {
						output, err := exec.CommandContext(ctx, binary, "-t", "-d", filepath.Dir(config), "-f", config).CombinedOutput()
						if err != nil {
							return fmt.Errorf("fixture client config: %w: %s", err, output)
						}
						return nil
					}}
					if positive {
						opts.Start = func(ctx context.Context, binary, config string) (func(), <-chan struct{}, error) {
							cmd := exec.CommandContext(ctx, binary, "-d", filepath.Dir(config), "-f", config)
							var clientLog bytes.Buffer
							cmd.Stdout = &clientLog
							cmd.Stderr = &clientLog
							if err := cmd.Start(); err != nil {
								return nil, nil, err
							}
							done := make(chan struct{})
							go func() { _ = cmd.Wait(); close(done) }()
							cleanup := func() { _ = cmd.Process.Kill(); <-done }
							profile, _ := os.ReadFile(config)
							var cfg struct {
								Port int      `yaml:"mixed-port"`
								Auth []string `yaml:"authentication"`
							}
							_ = yaml.Unmarshal(profile, &cfg)
							if err := integrationUDP(cfg.Port, cfg.Auth[0], gateway, echo.LocalAddr().(*net.UDPAddr).Port); err != nil {
								cleanup()
								return nil, nil, fmt.Errorf("%w; fixture client: %s", err, clientLog.String())
							}
							return cleanup, done, nil
						}
					}
					ip, err := serverprobe.ProbeWithOptions(probeCtx, body, opts)
					if positive && (err != nil || ip != "198.51.100.20") {
						t.Fatalf("real HY2 HTTPS/UDP verification: %v", err)
					}
					if !positive && err == nil {
						t.Fatal("invalid node bypassed authentication or used direct traffic")
					}
				}
				probe(t, node, true)
				for _, bad := range []string{"password", "sni", "certificate", "udp-unreachable", "obfs-password"} {
					if bad == "obfs-password" && mode == "none" {
						continue
					}
					t.Run(bad, func(t *testing.T) {
						altered := map[string]any{}
						for k, v := range node {
							altered[k] = v
						}
						switch bad {
						case "password", "obfs-password":
							altered[bad] = "wrong-secret"
						case "sni":
							altered[bad] = "wrong.example.com"
						case "certificate":
							delete(altered, "fingerprint")
						case "udp-unreachable":
							blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
							if err != nil {
								t.Fatal(err)
							}
							defer blackhole.Close()
							altered["port"] = blackhole.LocalAddr().(*net.UDPAddr).Port
						}
						probe(t, altered, false)
					})
				}
			})
		}
	}
}

func integrationDocker(t *testing.T, ctx context.Context, args ...string) []byte {
	t.Helper()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v %s", args[0], err, out)
	}
	return out
}

// Verify release metadata, compressed bytes and executable before use. Never
// pick a user-installed executable for a reproducible compatibility matrix.
func integrationMihomo(t *testing.T, ctx context.Context, version string) string {
	t.Helper()
	platform := runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOARCH == "amd64" {
		platform += "-compatible"
	}
	name := "mihomo-" + platform + "-" + version + ".gz"
	body, _, err := getArtifact(ctx, "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/"+version, nil, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name   string
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		}
	}
	if json.Unmarshal(body, &release) != nil || release.Tag != version {
		t.Fatal("invalid Mihomo release")
	}
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		if !strings.HasPrefix(asset.URL, "https://github.com/MetaCubeX/mihomo/releases/download/"+version+"/") {
			t.Fatal("untrusted client source")
		}
		compressed, err := integrationDownload(ctx, asset.URL, strings.TrimPrefix(asset.Digest, "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(compressed)
		if asset.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatal("client digest mismatch")
		}
		reader, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		executable, err := io.ReadAll(io.LimitReader(reader, 128<<20))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "mihomo")
		if err = os.WriteFile(path, executable, 0700); err != nil {
			t.Fatal(err)
		}
		t.Logf("verified Mihomo %s SHA256 %x", version, sum)
		return path
	}
	t.Fatal("missing official Mihomo artifact", name)
	return ""
}

func integrationUDP(port int, auth string, targetHost string, targetPort int) error {
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	user, pass, _ := strings.Cut(auth, ":")
	if _, err = conn.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{5, 2} {
		return fmt.Errorf("unexpected SOCKS authentication")
	}
	packet := append([]byte{1, byte(len(user))}, []byte(user)...)
	packet = append(packet, byte(len(pass)))
	packet = append(packet, []byte(pass)...)
	if _, err = conn.Write(packet); err != nil {
		return err
	}
	if _, err = io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[1] != 0 {
		return fmt.Errorf("SOCKS authentication failed")
	}
	if _, err = conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	var head [4]byte
	if _, err = io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("UDP associate failed")
	}
	size := 4
	if head[3] == 4 {
		size = 16
	}
	if head[3] != 1 && head[3] != 4 {
		return fmt.Errorf("unexpected UDP relay address")
	}
	address := make([]byte, size+2)
	if _, err = io.ReadFull(conn, address); err != nil {
		return err
	}
	relayPort := binary.BigEndian.Uint16(address[size:])
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)})
	if err != nil {
		return err
	}
	defer udp.Close()
	_ = udp.SetDeadline(deadline)
	host := targetHost
	payload := []byte("hy2-udp-verified")
	packet = append([]byte{0, 0, 0, 3, byte(len(host))}, []byte(host)...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(targetPort))
	packet = append(packet, payload...)
	if _, err = udp.Write(packet); err != nil {
		return err
	}
	buf := make([]byte, 2048)
	n, err := udp.Read(buf)
	if err != nil {
		return err
	}
	if n < 3 || buf[2] != 0 || !bytes.HasSuffix(buf[:n], payload) {
		return fmt.Errorf("invalid UDP echo")
	}
	return nil
}

// Public archives are cached only by their independently verified SHA-256.
func integrationDownload(ctx context.Context, address, digest string) ([]byte, error) {
	if !shaPattern.MatchString(digest) {
		return nil, fmt.Errorf("invalid fixture digest")
	}
	path := filepath.Join(os.TempDir(), "lazyclash-integration-"+digest)
	if body, err := os.ReadFile(path); err == nil {
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) == digest {
			return body, nil
		}
	}
	body, _, err := getArtifact(ctx, address, nil, 150<<20)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("fixture artifact SHA256 mismatch")
	}
	file, err := os.CreateTemp(os.TempDir(), "lazyclash-integration-download-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(body); err != nil {
		file.Close()
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return nil, err
	}
	return body, nil
}
