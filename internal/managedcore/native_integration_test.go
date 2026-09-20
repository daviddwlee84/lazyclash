//go:build linux

package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// This is deliberately unavailable on ordinary developer machines. It uses a
// real privileged service and TUN on a disposable GitHub-hosted Ubuntu runner,
// with DIRECT-only routing and an in-process HTTP destination. It never enables
// system proxy, changes resolv.conf, installs packages or uses fixture_root.
func TestNativeLinuxManagedAcceptance(t *testing.T) {
	if os.Getenv("LAZYCLASH_NATIVE_INTEGRATION") != "1" {
		t.Skip("opt-in disposable Linux runner acceptance")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("native integration is restricted to disposable GitHub-hosted runners")
	}
	for _, command := range []string{"sudo", "systemctl", "python3", "bwrap", "ip"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("native integration blocked: %s unavailable", command)
		}
	}
	if output, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Fatalf("native integration blocked: noninteractive fixture sudo unavailable: %v %s", err, output)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("native integration blocked: systemd is not running")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Fatal("native integration blocked: /dev/net/tun unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	idSuffix, err := randomHex(6)
	if err != nil {
		t.Fatal(err)
	}
	id := "ci-native-" + idSuffix
	unit := "lazyclash-mihomo-" + id + ".service"
	root := filepath.Join("/var/lib/lazyclash/cores", id)
	unitPath := filepath.Join("/etc/systemd/system", unit)
	for _, path := range []string{root, unitPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture destination already exists or cannot be inspected: %s", path)
		}
	}
	beforeRoutes := nativeRoutes(t)
	beforeRules := nativeRules(t)
	controllerPort, mixedPort := nativePorts(t)
	settingsPath := filepath.Join(t.TempDir(), "settings.toml")
	opts := Options{StateDir: filepath.Join(t.TempDir(), "managed"), Foreground: func(cmd *exec.Cmd) error {
		// Do not replace Stdout: runPrivileged owns its bounded result capture.
		if filepath.Base(cmd.Path) == "sudo" {
			cmd.Args = append([]string{cmd.Args[0], "-n"}, cmd.Args[1:]...)
		}
		cmd.Stdin = nil
		cmd.Stderr = io.Discard
		return cmd.Run()
	}}
	opts.Register = func(target config.Target) error {
		saved, err := config.Load(settingsPath, false)
		if err != nil {
			return err
		}
		saved.DefaultTarget = id
		saved.Targets = []config.Target{target}
		return config.Save(settingsPath, saved)
	}
	opts.Unregister = func(targetID string) error {
		if targetID != id {
			return errors.New("fixture attempted another registration")
		}
		saved, err := config.Load(settingsPath, true)
		if err != nil {
			return err
		}
		saved.Targets = nil
		saved.DefaultTarget = ""
		return config.Save(settingsPath, saved)
	}
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Lazyclash-Fixture", "native")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()
	opts.Probe = func(ctx context.Context, target config.Target) error {
		proxy, err := url.Parse(target.ProbeProxy)
		if err != nil {
			return err
		}
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, destination.URL, nil)
		if err != nil {
			return err
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 204 || response.Header.Get("X-Lazyclash-Fixture") != "native" {
			return errors.New("mixed proxy did not reach the local HTTP fixture")
		}
		return nil
	}
	// Always stop/remove only this unique unit, even when an assertion interrupts
	// the public lifecycle. Core data intentionally remains for inspection.
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 45*time.Second)
		defer done()
		if plan, e := PreviewAction(cleanupCtx, id, "remove", opts); e == nil {
			_, _ = ApplyAction(cleanupCtx, id, "remove", plan.Digest, opts)
		}
		_ = exec.CommandContext(cleanupCtx, "sudo", "-n", "systemctl", "disable", "--now", unit).Run()
		_ = exec.CommandContext(cleanupCtx, "sudo", "-n", "rm", "-f", "--", unitPath).Run()
		_ = exec.CommandContext(cleanupCtx, "sudo", "-n", "systemctl", "daemon-reload").Run()
	})
	request := Request{ID: id, Name: "Disposable native acceptance", Backend: "native", Version: DefaultVersion, InputKind: "yaml", Preset: "preserve", Input: []byte("mode: rule\nlog-level: warning\nipv6: false\ndns:\n  enable: false\nproxies: []\nproxy-groups:\n- name: PROXY\n  type: select\n  proxies: [DIRECT]\nrules: ['MATCH,DIRECT']\n"), ServiceScope: "system", ControllerPort: controllerPort, MixedPort: mixedPort}
	artifact, err := resolveOfficialArtifact(ctx, request, HostFacts{OS: "linux", Arch: runtime.GOARCH})
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := fetchOfficialArtifact(ctx, artifact)
	if err != nil {
		t.Fatalf("pinned official fixture download failed: %v", err)
	}
	request.ArtifactFile = filepath.Join(t.TempDir(), artifact.Name)
	request.ArtifactSHA256 = artifact.SHA256
	if err = os.WriteFile(request.ArtifactFile, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := Preview(ctx, request, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Blockers) > 0 {
		t.Fatalf("native integration blocked: %v", plan.Blockers)
	}
	receipt, err := Apply(ctx, request, plan.Digest, opts)
	if err != nil {
		t.Fatalf("native install: status=%s %v", receipt.Status, err)
	}
	if receipt.Status != "running_verified" || !receipt.ProxyHealthy {
		t.Fatalf("native health not verified: %+v", receipt)
	}
	status, err := GetStatus(ctx, id, opts)
	if err != nil || !status.Running || !status.ControllerHealthy {
		t.Fatalf("actual service/API status: %+v %v", status, err)
	}
	if output, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output(); err != nil || strings.TrimSpace(string(output)) != "active" {
		t.Fatalf("systemd unit is not active: %s %v", output, err)
	}
	stored, err := config.Load(settingsPath, true)
	if err != nil || len(stored.Targets) != 1 || stored.Targets[0].ManagedCoreID != id {
		t.Fatalf("registration missing: %v", err)
	}
	privateCheck := exec.CommandContext(ctx, "sudo", "-n", "/usr/bin/python3", "-I", "-c", `import os,stat,sys
for name in ('home','home/config.yaml'):
 s=os.lstat(os.path.join(sys.argv[1],name))
 assert s.st_uid==0 and not(s.st_mode&0o077) and not stat.S_ISLNK(s.st_mode)
print('private')`, root)
	if output, err := privateCheck.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "private" {
		t.Fatalf("system source permissions: %v %s", err, output)
	}
	secretInfo, err := os.Stat(stored.Targets[0].SecretFile)
	if err != nil || secretInfo.Mode().Perm() != 0600 {
		t.Fatalf("private controller secret: %v", err)
	}

	request.Network.TUN = true
	plan, err = PreviewConfigure(ctx, id, request, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Blockers) > 0 {
		t.Fatalf("TUN integration blocked: %v", plan.Blockers)
	}
	receipt, err = Configure(ctx, id, request, plan.Digest, opts)
	if err != nil {
		t.Fatalf("real TUN activation: status=%s %v", receipt.Status, err)
	}
	if receipt.Status != "running_verified" || receipt.NeedsACK {
		t.Fatalf("TUN activation not verified: %+v", receipt)
	}
	instance, err := GetInstance(id, opts)
	if err != nil {
		t.Fatal(err)
	}
	client, closer, err := connection.Open(ctx, instance.Target, true)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := client.Config(ctx)
	client.Close()
	closer.Close()
	if err != nil {
		t.Fatal(err)
	}
	tun, _ := settings["tun"].(map[string]any)
	enabled, _ := tun["enable"].(bool)
	device, _ := tun["device"].(string)
	if !enabled || device == "" {
		t.Fatalf("core did not report active TUN/device: %v", tun)
	}
	if _, err = exec.CommandContext(ctx, "ip", "-j", "link", "show", "dev", device).Output(); err != nil {
		t.Fatalf("core TUN has no kernel device %q: %v", device, err)
	}
	if reflect.DeepEqual(beforeRules, nativeRules(t)) {
		t.Fatal("TUN created no observable IPv4 routing policy")
	}
	if err = opts.Probe(ctx, instance.Target); err != nil {
		t.Fatal("mixed proxy failed after TUN:", err)
	}

	for _, operation := range []string{"stop", "remove"} {
		action, err := PreviewAction(ctx, id, operation, opts)
		if err != nil {
			t.Fatal(err)
		}
		result, err := ApplyAction(ctx, id, operation, action.Digest, opts)
		if err != nil {
			t.Fatalf("%s: %s %v", operation, result.Status, err)
		}
	}
	if _, err = os.Lstat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed unit retained: %v", err)
	}
	if _, err = os.Stat(root); err != nil {
		t.Fatal("remove deleted private instance data:", err)
	}
	for deadline := time.Now().Add(8 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		_, linkErr := exec.Command("ip", "-j", "link", "show", "dev", device).Output()
		if linkErr != nil && reflect.DeepEqual(beforeRoutes, nativeRoutes(t)) && reflect.DeepEqual(beforeRules, nativeRules(t)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cleanup left a TUN device or changed baseline routes/rules")
		}
	}
	stored, err = config.Load(settingsPath, true)
	if err != nil || len(stored.Targets) != 0 {
		t.Fatal("remove did not unregister fixture target")
	}
	t.Log("real native systemd install, verified mixed proxy, TUN kernel device/routing, stop/remove, private data retention and route restoration passed")
}

func nativePorts(t *testing.T) (int, int) {
	t.Helper()
	a, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	return a.Addr().(*net.TCPAddr).Port, b.Addr().(*net.TCPAddr).Port
}
func nativeRoutes(t *testing.T) []string {
	return nativeNetworkRows(t, "route", "show", "table", "main")
}
func nativeRules(t *testing.T) []string { return nativeNetworkRows(t, "rule", "show") }
func nativeNetworkRows(t *testing.T, args ...string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ip", append([]string{"-j"}, args...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(output, &rows); err != nil {
		t.Fatal(err)
	}
	var normalized []string
	for _, row := range rows {
		delete(row, "expires")
		value, _ := json.Marshal(row)
		normalized = append(normalized, string(value))
	}
	sort.Strings(normalized)
	return normalized
}
