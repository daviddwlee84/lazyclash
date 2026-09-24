package clientservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func fixtureBinding() config.ClientService {
	return config.ClientService{Kind: "docker", DockerHost: "unix:///fixture", Container: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), MountsSHA256: strings.Repeat("c", 64)}
}
func TestReviewedActionRecordsBeforeMutationAndRejectsDrift(t *testing.T) {
	b := fixtureBinding()
	target := config.Target{ID: "fixture", Controller: "http://127.0.0.1:9090", Service: &b}
	root := filepath.Join(t.TempDir(), "receipts")
	mutations := 0
	state := "initial"
	opts := Options{StateDir: root, Host: func(_ context.Context, _ config.Target, r Request) (Status, error) {
		s := Status{Binding: b, StateDigest: state, Running: true, State: "running"}
		if r.Op != "status" {
			mutations++
			files, err := os.ReadDir(root)
			if err != nil || len(files) != 1 {
				t.Fatal("receipt missing before mutation", err)
			}
			info, _ := files[0].Info()
			if !info.Mode().IsRegular() || !privatefs.Private(filepath.Join(root, files[0].Name())) {
				t.Fatal("receipt permissions", info.Mode())
			}
			raw, _ := os.ReadFile(filepath.Join(root, files[0].Name()))
			var receipt Receipt
			json.Unmarshal(raw, &receipt)
			if receipt.Status != "pending" || receipt.Before.Binding.Container != b.Container {
				t.Fatal("unreviewed receipt", receipt)
			}
			if r.Expected != state {
				t.Fatal("missing remote guard")
			}
			s.Running = false
			s.State = "exited"
		}
		return s, nil
	}}
	p, err := Preview(context.Background(), target, "stop", true, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("preview wrote receipts")
	}
	if _, err = Apply(context.Background(), target, "stop", true, strings.Repeat("0", 64), opts); err == nil || mutations != 0 {
		t.Fatal("unreviewed mutation")
	}
	state = "changed"
	if _, err = Apply(context.Background(), target, "stop", true, p.Digest, opts); err == nil || mutations != 0 {
		t.Fatal("stale mutation")
	}
	state = "initial"
	receipt, err := Apply(context.Background(), target, "stop", true, p.Digest, opts)
	if err != nil || receipt.Status != "observed" || mutations != 1 {
		t.Fatal(receipt, err, mutations)
	}
	opts.ReadOnly = true
	if _, err = Apply(context.Background(), target, "stop", true, p.Digest, opts); err == nil || mutations != 1 {
		t.Fatal("read-only mutation")
	}
}

func dockerFixture(t *testing.T) (config.Target, Options, string, string) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	t.Helper()
	dir := t.TempDir()
	compose := filepath.Join(dir, "compose.yaml")
	manifest := filepath.Join(dir, "inspect.json")
	log := filepath.Join(dir, "calls.jsonl")
	host := filepath.Join(dir, "config.yaml")
	inside := filepath.Join(dir, "container.yaml")
	os.WriteFile(compose, []byte("# keep comment\nservices:\n  fixture:\n    image: fixture\n    restart: unless-stopped # preserve\n  unrelated:\n    image: fixture\n    restart: always\n"), 0600)
	os.WriteFile(host, []byte("new-config"), 0600)
	os.WriteFile(inside, []byte("old-config"), 0600)
	item := map[string]any{"Id": strings.Repeat("a", 64), "Image": "sha256:" + strings.Repeat("b", 64), "State": map[string]any{"Running": true, "Status": "running"}, "HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "unless-stopped"}, "PortBindings": map[string]any{"9090/tcp": []any{map[string]any{"HostPort": "9090"}}}, "NetworkMode": "bridge"}, "Config": map[string]any{"Labels": map[string]any{"com.docker.compose.project.config_files": compose, "com.docker.compose.project": "fixture", "com.docker.compose.service": "fixture"}}, "Mounts": []any{map[string]any{"Type": "bind", "Source": host, "Destination": "/core/config.yaml", "RW": false, "Propagation": "rprivate"}}}
	raw, _ := json.Marshal(item)
	os.WriteFile(manifest, raw, 0600)
	script := `#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
if args[:2]!=['--host','unix:///fixture']:sys.exit(42)
if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):sys.exit(43)
args=args[2:]
with open(os.environ['FIXTURE_LOG'],'a') as f:f.write(json.dumps(args)+'\n')
p=os.environ['FIXTURE_MANIFEST'];item=json.load(open(p))
if args[0]=='inspect':print(json.dumps([item]))
elif args[0]=='update':
 item['HostConfig']['RestartPolicy']['Name']=args[1].split('=',1)[1];json.dump(item,open(p,'w'))
elif args[0] in ('start','restart','stop'):
 item['State']={'Running':args[0]!='stop','Status':'exited' if args[0]=='stop' else 'running'};json.dump(item,open(p,'w'))
 if args[0]=='restart':open(os.environ['FIXTURE_INSIDE'],'wb').write(open(os.environ['FIXTURE_HOST'],'rb').read())
elif args[0]=='exec':sys.stdout.buffer.write(open(os.environ['FIXTURE_INSIDE'],'rb').read())
else:sys.exit(44)
`
	os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FIXTURE_LOG", log)
	t.Setenv("FIXTURE_MANIFEST", manifest)
	t.Setenv("FIXTURE_INSIDE", inside)
	t.Setenv("FIXTURE_HOST", host)
	t.Setenv("DOCKER_HOST", "unix:///wrong")
	t.Setenv("DOCKER_CONTEXT", "wrong")
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	target := config.Target{ID: "fixture", Controller: "http://127.0.0.1:9090"}
	opts := Options{StateDir: filepath.Join(dir, "receipts")}
	plan, err := PrepareBind(context.Background(), target, config.ClientService{Kind: "docker", DockerHost: "unix:///fixture", Container: "fixture"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	target.Service = &plan.Before.Binding
	target.ConfigSource = &config.ConfigSource{Kind: "docker", DockerHost: "unix:///fixture", Container: "fixture", HostPath: host, CorePath: "/core/config.yaml", Binary: "/core/mihomo", Home: "/core"}
	return target, opts, compose, manifest
}
func TestDockerDisableUpdatesOnlyBoundComposeServiceAndKeepsPrivateBackup(t *testing.T) {
	target, opts, compose, _ := dockerFixture(t)
	p, err := Preview(context.Background(), target, "stop", true, opts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := Apply(context.Background(), target, "stop", true, p.Digest, opts)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.After.Running || receipt.After.Autostart || receipt.After.RestartPolicy != "no" || receipt.After.ComposeRestart != "no" {
		t.Fatal(receipt.After)
	}
	data, _ := os.ReadFile(compose)
	if !strings.Contains(string(data), "restart: \"no\" # preserve") || !strings.Contains(string(data), "restart: always") {
		t.Fatal("lost source fields", string(data))
	}
	backup, err := os.Stat(receipt.After.BackupPath)
	if err != nil || backup.Mode().Perm() != 0600 {
		t.Fatal("private backup missing", err)
	}
	original, _ := os.ReadFile(receipt.After.BackupPath)
	if !strings.Contains(string(original), "unless-stopped") {
		t.Fatal("backup not original")
	}
}
func TestDockerIdentityAndComposeChangesRefuseAction(t *testing.T) {
	target, opts, compose, manifest := dockerFixture(t)
	p, err := Preview(context.Background(), target, "stop", true, opts)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(compose, os.O_APPEND|os.O_WRONLY, 0600)
	f.WriteString("# concurrent edit\n")
	f.Close()
	if _, err = Apply(context.Background(), target, "stop", true, p.Digest, opts); err == nil {
		t.Fatal("changed Compose accepted")
	}
	raw, _ := os.ReadFile(manifest)
	var item map[string]any
	json.Unmarshal(raw, &item)
	item["Image"] = "sha256:" + strings.Repeat("f", 64)
	raw, _ = json.Marshal(item)
	os.WriteFile(manifest, raw, 0600)
	if _, err = Inspect(context.Background(), target, opts); err == nil {
		t.Fatal("changed owner image accepted")
	}
}
func TestSingleFileOwnerRestartRefreshesMountWithoutRecreating(t *testing.T) {
	target, opts, _, _ := dockerFixture(t)
	sum := hashedBytes([]byte("new-config"))
	s, err := VerifySource(context.Background(), target, sum, opts)
	if err != nil || s.SourceMatches || !s.SourceSingleFile {
		t.Fatal(s, err)
	}
	receipt, err := RestartForSource(context.Background(), target, sum, opts)
	if err != nil || receipt.Status != "observed" {
		t.Fatal(receipt, err)
	}
	s, err = VerifySource(context.Background(), target, sum, opts)
	if err != nil || !s.SourceMatches {
		t.Fatal(s, err)
	}
	log, _ := os.ReadFile(os.Getenv("FIXTURE_LOG"))
	for _, forbidden := range []string{`"rm"`, `"run"`, `"create"`, `"compose"`} {
		if strings.Contains(string(log), forbidden) {
			t.Fatal("unexpected lifecycle action", string(log))
		}
	}
	if _, err = VerifySource(context.Background(), target, strings.Repeat("f", 64), opts); err == nil {
		t.Fatal("source hash drift accepted")
	}
}

func TestExplicitRuleSourceActivationDoesNotRequireNodeOwner(t *testing.T) {
	target, opts, _, _ := dockerFixture(t)
	source := target.ConfigSource
	descriptor := DockerSource{DockerHost: source.DockerHost, Container: source.Container, HostPath: source.HostPath, CorePath: source.CorePath, Binary: source.Binary, Home: source.Home}
	target.ConfigSource = nil
	sum := hashedBytes([]byte("new-config"))
	if s, err := VerifyBoundSource(context.Background(), target, descriptor, sum, opts); err != nil || s.SourceMatches {
		t.Fatal(s, err)
	}
	if r, err := RestartForBoundSource(context.Background(), target, descriptor, sum, opts); err != nil || r.Status != "observed" {
		t.Fatal(r, err)
	}
	if s, err := VerifyBoundSource(context.Background(), target, descriptor, sum, opts); err != nil || !s.SourceMatches {
		t.Fatal(s, err)
	}
	descriptor.DockerHost = "unix:///other"
	if _, err := VerifyBoundSource(context.Background(), target, descriptor, sum, opts); err == nil {
		t.Fatal("different daemon accepted")
	}
}
func hashedBytes(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }

func TestSystemdIdentityAndCombinedDisableStop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper/session execution is covered on native Unix; Windows retains explicit refusal")
	}
	dir := t.TempDir()
	unit := filepath.Join(dir, "mihomo.service")
	state := filepath.Join(dir, "state.json")
	log := filepath.Join(dir, "calls.jsonl")
	os.WriteFile(unit, []byte("[Service]\nExecStart=/bin/mihomo\n[Install]\nWantedBy=default.target\n"), 0600)
	os.WriteFile(state, []byte(`{"active":"active","enabled":"enabled"}`), 0600)
	script := `#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
if args[:2]!=['--user','--no-pager']:sys.exit(42)
args=args[2:]
with open(os.environ['FIXTURE_LOG'],'a') as f:f.write(json.dumps(args)+'\n')
p=os.environ['FIXTURE_STATE'];s=json.load(open(p))
if args[0]=='show':
 for k,v in {'Id':'mihomo.service','LoadState':'loaded','ActiveState':s['active'],'SubState':'running' if s['active']=='active' else 'dead','UnitFileState':s['enabled'],'FragmentPath':os.environ['FIXTURE_UNIT'],'DropInPaths':'','NeedDaemonReload':'no'}.items():print(k+'='+v)
elif args[0] in ('start','restart','stop','enable','disable'):
 if args[0]=='disable':s['enabled']='disabled'
 elif args[0]=='enable':s['enabled']='enabled'
 else:s['active']='inactive' if args[0]=='stop' else 'active'
 json.dump(s,open(p,'w'))
else:sys.exit(43)
`
	os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FIXTURE_UNIT", unit)
	t.Setenv("FIXTURE_STATE", state)
	t.Setenv("FIXTURE_LOG", log)
	target := config.Target{ID: "fixture", Controller: "http://127.0.0.1:9090"}
	opts := Options{StateDir: filepath.Join(dir, "receipts")}
	p, err := PrepareBind(context.Background(), target, config.ClientService{Kind: "systemd", Unit: "mihomo.service", Scope: "user"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	target.Service = &p.Before.Binding
	p, err = Preview(context.Background(), target, "stop", true, opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(context.Background(), target, "stop", true, p.Digest, opts)
	if err != nil || r.After.Running || r.After.Autostart {
		t.Fatal(r, err)
	}
	raw, _ := os.ReadFile(log)
	calls := string(raw)
	if !strings.Contains(calls, `["disable", "mihomo.service"]`) || !strings.Contains(calls, `["stop", "mihomo.service"]`) || strings.Contains(calls, "daemon-reload") {
		t.Fatal(calls)
	}
	os.WriteFile(unit, []byte("[Service]\nExecStart=/different/core\n"), 0600)
	if _, err = Inspect(context.Background(), target, opts); err == nil {
		t.Fatal("replaced systemd unit accepted")
	}
}
