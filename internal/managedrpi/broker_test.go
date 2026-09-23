package managedrpi

import (
	"context"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileRejectsSymlinkHardlinkModeAndDigest(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Mkdir(filepath.Join(root, "private"), 0700)
	p := filepath.Join(root, "private", "source.yaml")
	raw := []byte("proxies: []\n")
	os.WriteFile(p, raw, 0600)
	target := config.Target{Controller: "https://192.0.2.1:9090", ManagedRPi: &config.ManagedRPi{ProjectDir: root}}
	response := Response{ProfilePath: p, Controller: target.Controller, Identity: Identity{ProfileSHA256: Digest(raw), NetworkBundleSHA256: strings.Repeat("a", 64), BootID: "boot", CoreIdentity: "core"}}
	if _, e = ReadProfile(target, response); e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0644)
	if _, e = ReadProfile(target, response); e == nil {
		t.Fatal("public file accepted")
	}
	os.Chmod(p, 0600)
	link := filepath.Join(root, "private", "link.yaml")
	os.Link(p, link)
	if _, e = ReadProfile(target, response); e == nil {
		t.Fatal("hardlinked file accepted")
	}
	os.Remove(link)
	os.Symlink(p, link)
	response.ProfilePath = link
	if _, e = ReadProfile(target, response); e == nil {
		t.Fatal("symlink accepted")
	}
	response.ProfilePath = p
	response.Identity.ProfileSHA256 = strings.Repeat("b", 64)
	if _, e = ReadProfile(target, response); e == nil {
		t.Fatal("wrong digest accepted")
	}
}

func TestTransportAndReceiptStayBoundToOwner(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(filepath.Join(root, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	target := config.Target{Controller: "https://192.0.2.1:9090", CAFile: "/private/ca.pem", ManagedRPi: &config.ManagedRPi{ProjectDir: root, ConnectionFile: filepath.Join(root, "private", "connection.json")}}
	identity := Identity{ProfileSHA256: strings.Repeat("a", 64), NetworkBundleSHA256: strings.Repeat("b", 64), BootID: "boot", CoreIdentity: "core"}
	observed := Response{Schema: 1, Controller: target.Controller, CACert: target.CAFile, Identity: identity}
	runner := func(context.Context, config.Target, Request) (Response, error) { return observed, nil }
	if err = ValidateTransport(context.Background(), target, runner); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []Response{
		{Schema: 1, Controller: "https://other.test:9090", CACert: target.CAFile, Identity: identity},
		{Schema: 1, Controller: target.Controller, CACert: "/other/ca.pem", Identity: identity},
		{Schema: 1, Controller: target.Controller, CACert: target.CAFile, SSHJump: "other-host", Identity: identity},
	} {
		observed = changed
		if err = ValidateTransport(context.Background(), target, runner); err == nil {
			t.Fatal("owner transport drift accepted")
		}
	}
	p := filepath.Join(root, "private", "receipt.json")
	if err = os.WriteFile(p, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	runner = func(context.Context, config.Target, Request) (Response, error) {
		calls++
		return Response{Schema: 1}, nil
	}
	if _, err = Call(context.Background(), target, Request{Operation: "restore", ReceiptPath: p}, runner); err == nil || calls != 0 {
		t.Fatal("unsafe receipt reached broker")
	}
	if err = os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(p, p+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err = Call(context.Background(), target, Request{Operation: "restore", ReceiptPath: p}, runner); err == nil || calls != 0 {
		t.Fatal("hardlinked receipt reached broker")
	}
}
