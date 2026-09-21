package serverstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventoryPreservesCommentsUnknownFieldsAndResources(t *testing.T) {
	p := filepath.Join(t.TempDir(), "servers.toml")
	raw := `# my inventory
version = 1 # schema
custom = 'kept'

[[hosts]]
id = 'home'
provider = 'ssh'
ssh_host = 'admin@private-alias' # management
public_host = 'proxy.example'
owner_note = 'my homelab'

[[hosts.resources]]
id = 'net-1'
kind = 'network'
owned = false # do not delete
annotation = 'shared'

[[deployments]]
id = 'main'
host_id = 'home'
recipe = 'vless-reality'
backend = 'native'
public_host = 'proxy.example'
public_port = 443
listen_port = 8443
status = 'pending'
custom_option = 'keep me'

[personal]
note = 'unrelated'
`
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: p}
	err := s.Update(func(i *Inventory) error {
		h, e := i.Host("home")
		if e != nil {
			return e
		}
		h.Status = "running"
		h.Resources = append(h.Resources, Resource{Kind: "vm", ID: "vm-2", Owned: true})
		if e = i.UpsertHost(h); e != nil {
			return e
		}
		d, e := i.Deployment("main")
		if e != nil {
			return e
		}
		d.Status = "ready"
		return i.UpsertDeployment(d)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# my inventory", "# schema", "custom = 'kept'", "# management", "owner_note = 'my homelab'", "# do not delete", "annotation = 'shared'", "custom_option = 'keep me'", "[personal]", "note = 'unrelated'"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing preserved content %q\n%s", want, got)
		}
	}
	inv, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := inv.Host("home")
	d, _ := inv.Deployment("main")
	if h.Status != "running" || len(h.Resources) != 2 || d.Status != "ready" || h.SSHHost == h.PublicHost {
		t.Fatalf("wrong inventory: %+v", inv)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %o", info.Mode().Perm())
	}
}

func TestReadDoesNotCreateAndStateIsNamespaced(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "missing", "servers.toml")}
	inv, err := s.Load()
	if err != nil || len(inv.Hosts) != 0 {
		t.Fatalf("read: %+v %v", inv, err)
	}
	if _, err = os.Stat(filepath.Dir(s.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read created a directory")
	}
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	a, _ := s.StateRoot()
	b, _ := (Store{Path: filepath.Join(dir, "other", "servers.toml")}).StateRoot()
	if a == b {
		t.Fatal("different inventories share private state")
	}
}

func TestExternalEditConflict(t *testing.T) {
	p := filepath.Join(t.TempDir(), "servers.toml")
	s := Store{Path: p}
	err := s.Update(func(i *Inventory) error {
		if err := os.WriteFile(p, []byte("version = 1\n# concurrent editor\n"), 0600); err != nil {
			return err
		}
		return i.UpsertHost(Host{ID: "home", Provider: "ssh"})
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict: %v", err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "concurrent editor") {
		t.Fatal("overwrote editor")
	}
}

func TestRejectSymlinkWriteAndInvalidInventory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(link, []byte("replacement")); err == nil {
		t.Fatal("followed symlink")
	}
	if err := Validate(Inventory{Version: 1, Hosts: []Host{{ID: "../escape"}}}); err == nil {
		t.Fatal("accepted path traversal")
	}
	if err := Validate(Inventory{Version: 1, Deployments: []Deployment{{ID: "test", HostID: "missing"}}}); err == nil {
		t.Fatal("accepted dangling deployment")
	}
}

func TestLockExcludesSecondWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "op.lock")
	unlock, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if unlock2, err := Lock(p); err == nil {
		unlock2()
		t.Fatal("allowed concurrent lock")
	}
}

func TestSameResourceIDAcrossKindsPreservesSeparateAnnotations(t *testing.T) {
	p := filepath.Join(t.TempDir(), "servers.toml")
	raw := `version=1
[[hosts]]
id='cloud'
provider='linode'
[[hosts.resources]]
id='123'
kind='instance'
owned=true
annotation='machine annotation'
[[hosts.resources]]
id='123'
kind='firewall'
owned=true
annotation='firewall annotation'
`
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: p}
	if err := s.Update(func(i *Inventory) error { i.Hosts[0].Status = "running"; return nil }); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if strings.Count(string(data), "machine annotation") != 1 || strings.Count(string(data), "firewall annotation") != 1 {
		t.Fatalf("resource annotations collided:\n%s", data)
	}
}
