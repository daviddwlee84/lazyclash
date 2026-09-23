package rulework

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestNativeValidatorIsolationAndCopiedResources(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	sandbox := "bwrap"
	if runtime.GOOS == "darwin" {
		sandbox = "sandbox-exec"
	}
	if _, err := exec.LookPath(sandbox); err != nil {
		if os.Getenv("LAZYCLASH_REQUIRE_NATIVE_ISOLATION") == "1" {
			t.Fatal("required native validation isolation is not installed")
		}
		t.Skip("native validation isolation is not installed")
	}
	f := newFixture(t, false)
	home := f.target.RuleSource.Home
	provider := filepath.Join(home, "rules.list")
	os.WriteFile(provider, []byte("original provider"), 0600)
	geo := filepath.Join(home, "Country.mmdb")
	os.WriteFile(geo, []byte("original geodata"), 0600)
	cache := filepath.Join(home, "cache.db")
	os.WriteFile(cache, []byte("live cache"), 0600)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	script := fmt.Sprintf(`#!/usr/bin/env python3
import json,os,socket,sys
if '-v' in sys.argv:
 print('Mihomo Meta v1.19.29 fixture fixture')
 sys.exit(0)
document=json.load(sys.stdin)
stage=sys.argv[sys.argv.index('-d')+1]
assert os.path.realpath(stage)!=os.path.realpath(%s)
resource=document['rule-providers']['fixture']['path']
assert os.path.realpath(resource).startswith(os.path.realpath(stage)+os.sep)
assert not os.path.islink(resource)
assert open(resource).read()=='original provider'
assert open(os.path.join(stage,'Country.mmdb')).read()=='original geodata'
open(os.path.join(stage,'cache.db'),'w').write('isolated cache')
for path in [%s,%s]:
 try:
  open(path,'a').write('must not write')
  raise AssertionError('live write was allowed')
 except OSError: pass
try:
 socket.create_connection(('127.0.0.1',%d),timeout=.2)
 raise AssertionError('network was allowed')
except (PermissionError,OSError): pass
`, strconv.Quote(home), strconv.Quote(provider), strconv.Quote(cache), listener.Addr().(*net.TCPAddr).Port)
	os.WriteFile(f.target.RuleSource.Binary, []byte(script), 0700)
	data := []byte(fmt.Sprintf("rule-providers:\n  fixture:\n    type: file\n    behavior: classical\n    path: %s\nrules:\n  - MATCH,DIRECT\n", strconv.Quote(provider)))
	err = validateCandidate(context.Background(), f.target, data, "v1.19.29", Options{})
	if err != nil && strings.Contains(err.Error(), "OS isolation is unavailable or denied") {
		if os.Getenv("LAZYCLASH_REQUIRE_NATIVE_ISOLATION") == "1" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{provider: "original provider", geo: "original geodata", cache: "live cache"} {
		got, _ := os.ReadFile(path)
		if string(got) != want {
			t.Fatalf("live resource modified: %s", path)
		}
	}
}

func TestMissingSandboxFailsBeforeSourceWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	f := newFixture(t, false)
	directory := t.TempDir()
	if err = os.Symlink(python, filepath.Join(directory, "python3")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	err = validateCandidate(context.Background(), f.target, f.source, "v1.19.29", Options{})
	if err == nil || !strings.Contains(err.Error(), "sandbox-exec on macOS or bubblewrap") {
		t.Fatalf("missing isolation was not actionable: %v", err)
	}
	got, _ := os.ReadFile(f.target.Configs[0].Path)
	if string(got) != string(f.source) {
		t.Fatal("failed validation modified source")
	}
}
