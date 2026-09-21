package vps

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"go.yaml.in/yaml/v3"
)

type cloudInitFile struct {
	Path        string `yaml:"path"`
	Owner       string `yaml:"owner"`
	Permissions string `yaml:"permissions"`
	Content     string `yaml:"content"`
}

func initializerFiles(t *testing.T) (map[string]cloudInitFile, [][]string) {
	t.Helper()
	var config struct {
		WriteFiles []cloudInitFile `yaml:"write_files"`
		RunCmd     [][]string      `yaml:"runcmd"`
	}
	if !bytes.HasPrefix(oracleCloudInit, []byte("#cloud-config\n")) {
		t.Fatal("initializer is not cloud-config")
	}
	if err := yaml.Unmarshal(oracleCloudInit, &config); err != nil {
		t.Fatal(err)
	}
	files := map[string]cloudInitFile{}
	for _, f := range config.WriteFiles {
		files[f.Path] = f
	}
	return files, config.RunCmd
}

func TestOracleInitializerLaunchMetadataIsReviewedAndPersisted(t *testing.T) {
	s, f, req := testService(t, "oracle")
	preview, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Request.InitializerVersion != oracleInitializerVersion || preview.Request.InitializerSHA256 != oracleInitializerSHA256() {
		t.Fatalf("initializer missing from review: %#v", preview.Request)
	}
	if !strings.Contains(strings.Join(preview.Warnings, " "), "host INPUT TCP 80/443 and UDP 443") {
		t.Fatal("host firewall mutation missing from review")
	}
	host, err := s.Create(context.Background(), req, preview.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]string
	for _, args := range f.requests {
		if !strings.Contains(strings.Join(args, " "), "instance launch") {
			continue
		}
		for i, arg := range args {
			if arg == "--metadata" {
				if err = json.Unmarshal([]byte(args[i+1]), &metadata); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	data, err := base64.StdEncoding.DecodeString(metadata["user_data"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, oracleCloudInit) {
		t.Fatal("launch did not send the reviewed initializer")
	}
	if !strings.HasPrefix(metadata["ssh_authorized_keys"], "ssh-ed25519 ") {
		t.Fatal("initializer dropped reviewed SSH key")
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Request.InitializerSHA256 != preview.Request.InitializerSHA256 || op.Request.InitializerVersion != oracleInitializerVersion {
		t.Fatal("initializer binding was not persisted")
	}
	bad := op.Request
	bad.InitializerSHA256 = strings.Repeat("0", 64)
	before := len(f.requests)
	if _, err = s.createRemote(context.Background(), bad, op.ID); err == nil {
		t.Fatal("changed initializer hash was accepted")
	}
	if len(f.requests) != before {
		t.Fatal("changed initializer reached provider")
	}
}

func TestOracleInitializerPreservesRulesAndRunsAtBoot(t *testing.T) {
	files, commands := initializerFiles(t)
	script, ok := files["/usr/local/libexec/lazyclash-oci-ingress"]
	if !ok || script.Owner != "root:root" || script.Permissions != "0700" {
		t.Fatalf("unsafe initializer script installation: %#v", script)
	}
	unit, ok := files["/etc/systemd/system/lazyclash-oci-ingress.service"]
	if !ok || unit.Owner != "root:root" || unit.Permissions != "0644" {
		t.Fatalf("unsafe unit installation: %#v", unit)
	}
	for _, required := range []string{"After=network-pre.target netfilter-persistent.service ufw.service firewalld.service", "Type=oneshot", "ExecStart=/usr/local/libexec/lazyclash-oci-ingress", "TimeoutStartSec=90", "WantedBy=multi-user.target"} {
		if !strings.Contains(unit.Content, required) {
			t.Fatalf("missing persistent initializer unit setting %q", required)
		}
	}
	if len(commands) != 2 || strings.Join(commands[0], " ") != "systemctl daemon-reload" || strings.Join(commands[1], " ") != "systemctl enable --now lazyclash-oci-ingress.service" {
		t.Fatalf("initializer is not enabled now and at boot: %#v", commands)
	}
	syntax := exec.Command("sh", "-n", "-")
	syntax.Stdin = strings.NewReader(script.Content)
	if output, err := syntax.CombinedOutput(); err != nil {
		t.Fatalf("invalid shell: %v %s", err, output)
	}
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules")
	callsPath := filepath.Join(dir, "calls")
	fakePath := filepath.Join(dir, "iptables")
	original := "INPUT -p tcp --dport 22 -j ACCEPT\nINPUT -j REJECT\nOUTPUT -d 169.254.0.0/16 -j ACCEPT\n"
	if err := os.WriteFile(rulesPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$LAZYCLASH_TEST_CALLS_FILE"
[ "$1" = --wait ] && [ "$2" = 10 ]
shift 2
action="$1"
shift
case "$action" in
  --check) grep -Fqx -- "$*" "$LAZYCLASH_TEST_RULES_FILE" ;;
  --insert)
    [ "$1" = INPUT ] && [ "$2" = 1 ]
    shift 2
    printf 'INPUT %s\n' "$*" >> "$LAZYCLASH_TEST_RULES_FILE"
    ;;
  *) exit 70 ;;
esac
`
	if err := os.WriteFile(fakePath, []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	// Only the fixed executable location is redirected. The real initializer
	// otherwise runs unchanged against a disposable, observable rule store.
	runnable := strings.ReplaceAll(script.Content, "/usr/sbin/iptables", `"`+fakePath+`"`)
	run := func() {
		t.Helper()
		cmd := exec.Command("sh", "-eu", "-")
		cmd.Stdin = strings.NewReader(runnable)
		cmd.Env = append(os.Environ(), "LAZYCLASH_TEST_RULES_FILE="+rulesPath, "LAZYCLASH_TEST_CALLS_FILE="+callsPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("initializer failed: %v %s", err, output)
		}
	}
	run()
	first, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(first), original) {
		t.Fatal("existing firewall rules were changed")
	}
	if len(strings.Split(strings.TrimSpace(string(first)), "\n")) != 6 {
		t.Fatalf("expected exactly three added ingress rules: %s", first)
	}
	for _, rule := range []string{"-p tcp --dport 80", "-p tcp --dport 443", "-p udp --dport 443"} {
		if !strings.Contains(string(first), rule) {
			t.Fatalf("missing port rule %q", rule)
		}
	}
	run()
	second, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("repeated initializer duplicated or changed rules")
	}
	calls, _ := os.ReadFile(callsPath)
	if strings.Count(string(calls), "--insert INPUT 1") != 3 {
		t.Fatalf("unexpected mutations: %s", calls)
	}
}

func TestOracleInitializerDoesNotApplyToOtherProvidersOrRegisteredHosts(t *testing.T) {
	s, f, req := testService(t, "digitalocean")
	req.InitializerSHA256 = "untrusted"
	req.InitializerVersion = "untrusted"
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.InitializerSHA256 != "" || p.Request.InitializerVersion != "" {
		t.Fatal("Oracle initializer leaked to another provider")
	}
	if _, err = s.Create(context.Background(), req, p.Digest); err != nil {
		t.Fatal(err)
	}
	for _, args := range f.requests {
		if strings.Contains(strings.Join(args, " "), "user_data") {
			t.Fatal("initializer sent to another provider")
		}
	}
	s, f, _ = testService(t, "oracle")
	if _, err = s.Register(serverstate.Host{ID: "byo", Provider: "oracle", SSHHost: "existing", PublicHost: "existing.example"}); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 0 {
		t.Fatal("registering an existing host contacted or initialized it")
	}
}
