package serverstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObservationPreservesHostResourcesAndUnknownFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "servers.toml")
	raw := "version = 1\n# inventory comment\n[[hosts]]\nid = 'vm'\nprovider = 'oracle'\nowned = false\ncustom_note = 'keep'\n[[hosts.resources]]\nkind = 'subnet'\nid = 'subnet-id'\nowned = false\n[[hosts]]\nid = 'other'\nprovider = 'ssh'\nowned = false\n"
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	store := Store{Path: p}
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	for _, region := range []string{"ap-singapore-1", "ap-tokyo-1"} {
		if err := store.Update(func(i *Inventory) error {
			h, e := i.Host("vm")
			if e != nil {
				return e
			}
			h.Observation = &CloudObservationBinding{Provider: "oracle", Region: region, ResourceID: "instance", AccountID: "account", VerifiedAt: now}
			return i.UpsertHost(h)
		}); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := inv.Host("vm")
	other, _ := inv.Host("other")
	if h.Owned || h.Observation == nil || h.Observation.Region != "ap-tokyo-1" || len(h.Resources) != 1 || h.Resources[0].ID != "subnet-id" || other.Observation != nil {
		t.Fatalf("observation leaked into ownership/another host: %+v", inv)
	}
	data, _ := os.ReadFile(p)
	for _, text := range []string{"# inventory comment", "custom_note = 'keep'"} {
		if !strings.Contains(string(data), text) {
			t.Fatalf("lost preserved field %q: %s", text, data)
		}
	}
	if strings.Count(string(data), "[hosts.observation]") != 1 {
		t.Fatalf("duplicate observation table: %s", data)
	}
}
