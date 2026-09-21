package managedcore

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// This opt-in check starts only a disposable loopback core. It does not change
// host routing, Tailscale, installed services or the user's running controller.
func TestTailnetGatewayRealCoreAuthenticationAndUDP(t *testing.T) {
	binaryPath := os.Getenv("LAZYCLASH_TEST_MIHOMO")
	if binaryPath == "" {
		t.Skip("set LAZYCLASH_TEST_MIHOMO to an existing verified core")
	}
	port := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	mixed, controller := port(), port()
	if mixed == controller {
		t.Skip("ephemeral ports collided")
	}
	r := Request{ID: "gateway", Backend: "native", ProxyGateway: true, ProxyUDP: true, InputKind: "yaml", Preset: "preserve", MixedPort: mixed, ControllerPort: controller, Input: []byte("proxy-groups: []\nrules: ['MATCH,DIRECT']\nauthentication: [user:password]\nskip-auth-prefixes: [127.0.0.0/8]\ndns: {enable: false}\n")}
	body, _, _, _, err := buildProfile(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(configPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "-d", dir, "-f", configPath)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(output.String())
		}
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(mixed))
	for deadline := time.Now().Add(5 * time.Second); ; {
		c, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway failed to start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	conn.Close()
	if err != nil || (!bytes.Equal(reply, []byte{5, 255}) && !bytes.Equal(reply, []byte{5, 2})) {
		t.Fatal("SOCKS accepted unauthenticated loopback", reply, err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "gateway-verified") }))
	defer origin.Close()
	proxyURL, _ := url.Parse("http://" + address)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 407 {
		t.Fatal("HTTP accepted unauthenticated loopback", resp.StatusCode)
	}
	proxyURL.User = url.UserPassword("user", "password")
	transport.CloseIdleConnections()
	resp, err = client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(data) != "gateway-verified" {
		t.Fatal("authenticated HTTP failed", resp.StatusCode, string(data))
	}
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 1024)
		n, a, e := echo.ReadFrom(buffer)
		if e == nil {
			echo.WriteTo(buffer[:n], a)
		}
	}()
	udp, err := net.Dial("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(3 * time.Second))
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], uint16(echo.LocalAddr().(*net.UDPAddr).Port))
	packet = append(packet, []byte("tailnet-udp")...)
	if _, err = udp.Write(packet); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := udp.Read(buffer)
	if err != nil || n < 10 || string(buffer[10:n]) != "tailnet-udp" {
		t.Fatal("UDP forwarding failed", err)
	}
}
