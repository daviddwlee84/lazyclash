package serverstate

import (
	"errors"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
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
		h.SubscriptionID, h.Architecture, h.AvailabilityZone = "subscription-fixture", "arm64", "1"
		h.DiskGB, h.MonthlyUSD = 32, 12.182
		h.ComputeMonthlyUSD, h.DiskMonthlyUSD, h.IPv4MonthlyUSD = 6.132, 2.4, 3.65
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
	if h.SubscriptionID != "subscription-fixture" || h.Architecture != "arm64" || h.AvailabilityZone != "1" || h.DiskGB != 32 || h.MonthlyUSD != 12.182 || h.ComputeMonthlyUSD != 6.132 || h.DiskMonthlyUSD != 2.4 || h.IPv4MonthlyUSD != 3.65 {
		t.Fatalf("cloud ownership and pricing metadata did not survive update: %+v", h)
	}
	info, _ := os.Stat(p)
	if !info.Mode().IsRegular() || !privatefs.Private(p) {
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

func TestTailnetArrayPreservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.toml")
	source := "version = 1\n# peer comment\n[[tailnet]]\nid = 'rpi'\npeer_id = 'peer1'\nssh_host = 'rpi'\nips = [\n  '100.72.151.78', # address comment\n  'fd7a:115c:a1e0::1',\n]\nfuture = 'keep' # future comment\n"
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: path}
	for i := 0; i < 2; i++ {
		if err := s.Update(func(inv *Inventory) error {
			n, e := inv.TailnetNode("rpi")
			if e != nil {
				return e
			}
			n.ExitManaged = true
			n.IPs = []string{"100.72.151.79"}
			return inv.UpsertTailnetNode(n)
		}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# peer comment", "future = 'keep' # future comment", "100.72.151.79"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("lost preserved content %q: %s", want, b)
		}
	}
	inv, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.TailnetNodes) != 1 || !inv.TailnetNodes[0].ExitManaged {
		t.Fatalf("bad saved peer: %+v", inv)
	}
}

func TestTailnetPreservesUnknownMultilineArrays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "servers.toml")
	unknown := `future = [
  """A single " quote before ] and # is content.
A pair "" also stays inside this string, plus [ and =.
An escaped quote \" is still content, ending with a literal quote"""",
  '''A single ' quote before ] and # is literal content.
A pair '' does not end the multiline literal, nor do [ or =.
Finish with two literal quotes''''',
  { name = "brackets [ ] # =", nested = ["escaped \\\" ]", '''nested ' ] # literal'''] },
] # keep the array comment
`
	from, to, err := arrayValueRange([]byte(unknown), 0)
	if err != nil {
		t.Fatal(err)
	}
	if from != strings.Index(unknown, "[") || to != strings.LastIndex(unknown, "] # keep the array comment")+1 {
		t.Fatalf("array scanner stopped inside a multiline string: range %d:%d", from, to)
	}
	source := "version = 1\n# leading comment\n[[tailnet]]\nid = 'rpi'\npeer_id = 'peer1'\nssh_host = 'rpi'\nips = ['100.72.151.78'] # keep IP comment\n" + unknown + "after_unknown = 'keep this too' # final comment\n"
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: path}
	if _, err := s.Load(); err != nil {
		t.Fatalf("fixture is not valid TOML: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.Update(func(inv *Inventory) error {
			n, err := inv.TailnetNode("rpi")
			if err != nil {
				return err
			}
			n.ExitStatus = "available"
			n.ExitManaged = true
			return inv.UpsertTailnetNode(n)
		}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), unknown) {
		t.Fatalf("unknown multiline array was changed:\n%s", data)
	}
	for _, comment := range []string{"# leading comment", "# keep IP comment", "after_unknown = 'keep this too' # final comment"} {
		if !strings.Contains(string(data), comment) {
			t.Fatalf("surrounding content lost %q:\n%s", comment, data)
		}
	}
	inv, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	n, err := inv.TailnetNode("rpi")
	if err != nil || n.ExitStatus != "available" || !n.ExitManaged {
		t.Fatalf("tailnet update failed: %+v %v", n, err)
	}
}
