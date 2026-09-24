package managedcore

import (
	"context"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/configwork"
)

func TestWindowsSourceStagesResourcesWithoutGrantingForeignPaths(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	installWindowsFixture(t, r, o)
	instance, err := loadInstance(r.ID, o)
	if err != nil {
		t.Fatal(err)
	}
	root := winJoin(instance.Target.ConfigSource.Home, "lazyclash-resources")
	path := winJoin(root, "provider.yaml")
	data := []byte("payload: [example.test]\n")
	document := map[string]any{"rule-providers": map[string]any{"new": map[string]any{"type": "file", "path": path}}}
	before := len(f.ops)
	if _, err = WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "validate", Document: document}, o); err == nil {
		t.Fatal("unstaged unowned resource accepted")
	}
	if len(f.ops) != before {
		t.Fatal("invalid resource reached host validator")
	}
	if _, err = WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "validate", Document: document, Resources: map[string][]byte{path: data}}, o); err != nil {
		t.Fatal(err)
	}
	staged, _ := loadInstance(r.ID, o)
	if len(staged.ResourceInventory) != len(instance.ResourceInventory) {
		t.Fatal("preview changed inventory")
	}
	request := configwork.HostRequest{Op: "resource-write", Path: path, ResourceRoot: root, Data: data, ExpectedSHA256: hashBytes(data)}
	readOnly := o
	readOnly.ReadOnly = true
	before = len(f.ops)
	if _, err = WindowsSourceOperation(context.Background(), instance.Target, request, readOnly); err == nil || len(f.ops) != before {
		t.Fatal("read-only resource write reached host")
	}
	if _, err = WindowsSourceOperation(context.Background(), instance.Target, request, o); err != nil {
		t.Fatal(err)
	}
	saved, _ := loadInstance(r.ID, o)
	if !strings.Contains(strings.Join(saved.ResourceInventory, "\n"), "lazyclash-resources/provider.yaml") {
		t.Fatal("resource inventory not updated")
	}
	request.Op = "resource-remove"
	if _, err = WindowsSourceOperation(context.Background(), instance.Target, request, o); err != nil {
		t.Fatal(err)
	}
	saved, _ = loadInstance(r.ID, o)
	if strings.Contains(strings.Join(saved.ResourceInventory, "\n"), "lazyclash-resources/provider.yaml") {
		t.Fatal("removed resource retained")
	}
	before = len(f.ops)
	request.Path = winJoin(instance.Target.ConfigSource.Home, "config.yaml")
	if _, err = WindowsSourceOperation(context.Background(), instance.Target, request, o); err == nil || len(f.ops) != before {
		t.Fatal("resource operation escaped its owned directory")
	}
}

func TestWindowsSourceMergeAllowsRoutingOnly(t *testing.T) {
	r, o, f := newWindowsFixture(t)
	r.Client = "verge"
	f.facts.WindowsProxy.Enabled = 0
	f.facts.WindowsProxy.AutoConfigURL = ""
	installWindowsFixture(t, r, o)
	instance, _ := loadInstance(r.ID, o)
	f.generated = []byte("{}\n")
	path := winJoin(instance.Target.ConfigSource.Home, "profiles", instance.ProfileUID+"_merge.yaml")
	if _, err := WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "write", Path: path, Data: []byte("rules: ['MATCH,DIRECT']\n")}, o); err != nil {
		t.Fatal(err)
	}
	if _, err := WindowsSourceOperation(context.Background(), instance.Target, configwork.HostRequest{Op: "write", Path: path, Data: []byte("mixed-port: 8888\n")}, o); err == nil {
		t.Fatal("Merge changed host settings")
	}
}
