package vps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func firewallFixture(t *testing.T, provider string) (*Service, *operation) {
	t.Helper()
	dir := t.TempDir()
	s := New(serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}, Options{})
	op := &operation{Version: 1, ID: "lc-firewall-fixture", State: "intent", Request: CreateRequest{ID: "test", Provider: provider, SSHCIDR: "192.0.2.0/24"}, Host: serverstate.Host{ID: "test", Provider: provider, Owned: true, OperationID: "lc-firewall-fixture"}}
	if err := s.persistFirewall(op); err != nil {
		t.Fatal(err)
	}
	return s, op
}

func TestFirewallPrepareRecordsResourceAndProtectsNewInstances(t *testing.T) {
	for _, provider := range []string{"digitalocean", "vultr", "linode"} {
		t.Run(provider, func(t *testing.T) {
			s, op := firewallFixture(t, provider)
			creates, ruleCreates := 0, 0
			s.options.Run = func(_ context.Context, executable string, args []string) ([]byte, error) {
				joined := strings.Join(args, " ")
				durable, err := s.readOperation(op.ID)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(joined, "tag create") {
					if durable.PendingResourceKind != "firewall-tag" {
						t.Fatal("tag intent was not durable")
					}
					return json.Marshal([]any{map[string]any{"name": op.ID}})
				}
				if strings.Contains(joined, "rule list") {
					return []byte(`{"firewall_rules":[],"meta":{"links":{"next":""}}}`), nil
				}
				if strings.Contains(joined, "rule create") {
					if !firewallOwned(durable.Host, "fw-1") {
						t.Fatal("firewall ID not saved before rules")
					}
					ruleCreates++
					if !strings.Contains(joined, "--size ") || strings.Contains(joined, "--subnet-size") {
						t.Fatal("incorrect Vultr CLI flag", joined)
					}
					return []byte(`{"firewall_rule":{"id":1}}`), nil
				}
				if !strings.Contains(joined, "create") || durable.PendingResourceKind != "firewall" {
					t.Fatal("unexpected or unrecorded create", joined, durable)
				}
				creates++
				switch provider {
				case "digitalocean":
					if !strings.Contains(joined, "--tag-names "+op.ID) || !strings.Contains(joined, "ports:22,address:192.0.2.0/24") || !strings.Contains(joined, "protocol:udp,ports:443") {
						t.Fatal("firewall lost security rules/tag association", joined)
					}
					return []byte(`[{"id":"fw-1"}]`), nil
				case "vultr":
					return []byte(`{"firewall_group":{"id":"fw-1"}}`), nil
				default:
					if !strings.Contains(joined, "--rules.inbound_policy DROP") || !strings.Contains(joined, `"ipv4":["192.0.2.0/24"]`) || !strings.Contains(joined, `"protocol":"UDP"`) {
						t.Fatal("Linode policy missing", joined)
					}
					return []byte(`[{"id":"fw-1"}]`), nil
				}
			}
			if err := s.prepareFirewall(context.Background(), op); err != nil {
				t.Fatal(err)
			}
			if creates != 1 || op.Request.FirewallID != "fw-1" || op.PendingResourceKind != "" {
				t.Fatal("firewall not durable", creates, op)
			}
			if provider == "vultr" && ruleCreates != 7 {
				t.Fatal("IPv4/IPv6 rules missing", ruleCreates)
			}
			if provider == "digitalocean" {
				if len(op.Host.Resources) != 2 {
					t.Fatal("tag ownership not recorded")
				}
				if err := s.attachFirewall(context.Background(), op); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestFirewallUnknownCreateOnlyReconcilesExactOperation(t *testing.T) {
	s, op := firewallFixture(t, "linode")
	creates := 0
	s.options.Run = func(context.Context, string, []string) ([]byte, error) {
		creates++
		return nil, context.DeadlineExceeded
	}
	if err := s.prepareFirewall(context.Background(), op); err == nil {
		t.Fatal("unknown create accepted")
	}
	if err := s.prepareFirewall(context.Background(), op); err == nil || creates != 1 {
		t.Fatal("unknown create retried")
	}
	for _, rows := range []string{`[]`, `[{"id":"wrong","label":"other-operation"}]`, `[{"id":"one","label":"lc-firewall-fixture"},{"id":"two","label":"lc-firewall-fixture"}]`} {
		s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
			if !strings.Contains(strings.Join(args, " "), "firewalls list") {
				t.Fatal("resume performed a write")
			}
			return []byte(rows), nil
		}
		if err := s.resumeFirewall(context.Background(), op); err == nil {
			t.Fatal("ambiguous/absent firewall reconciled", rows)
		}
	}
	s.options.Run = func(context.Context, string, []string) ([]byte, error) {
		return []byte(`[{"id":"fw-found","label":"lc-firewall-fixture"}]`), nil
	}
	if err := s.resumeFirewall(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if op.PendingResourceKind != "" || op.Request.FirewallID != "fw-found" || !firewallOwned(op.Host, "fw-found") {
		t.Fatal("recovery did not save ID", op)
	}
}

func TestVultrRulesResumeUsesObservedRules(t *testing.T) {
	s, op := firewallFixture(t, "vultr")
	op.Request.FirewallID = "fw-owned"
	addFirewallResource(&op.Host, "firewall", "fw-owned", true)
	wanted, _ := desiredVultrFirewallRules(op.Request.SSHCIDR)
	rows := []any{}
	for _, r := range wanted {
		rows = append(rows, map[string]any{"protocol": r.Protocol, "port": r.Port, "subnet": r.Subnet, "subnet_size": r.Size, "ip_type": r.Family})
	}
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "rule list") {
			t.Fatal("existing firewall rule was duplicated", args)
		}
		return json.Marshal(map[string]any{"firewall_rules": rows, "meta": map[string]any{"links": map[string]any{"next": ""}}})
	}
	if err := s.prepareFirewall(context.Background(), op); err != nil {
		t.Fatal(err)
	}
}

func TestReusedFirewallIsAttachedButNeverDeleted(t *testing.T) {
	s, op := firewallFixture(t, "digitalocean")
	op.Request.FirewallID = "shared-firewall"
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "firewall add-droplets shared-firewall --droplet-ids 123") {
			t.Fatal("touched shared firewall rules or deleted shared firewall", joined)
		}
		return nil, nil
	}
	if err := s.prepareFirewall(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	op.Host.ResourceID = "123"
	if err := s.attachFirewall(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := s.cleanupFirewall(context.Background(), op.Host); err != nil {
		t.Fatal(err)
	}
	if len(op.Host.Resources) != 1 || op.Host.Resources[0].Owned {
		t.Fatal("reused firewall was claimed")
	}
}

func TestFirewallCleanupRefusesSharedDevicesAndRetainsUnconfirmedDeletes(t *testing.T) {
	s, op := firewallFixture(t, "linode")
	op.Request.FirewallID = "42"
	addFirewallResource(&op.Host, "firewall", "42", true)
	if err := s.persistFirewall(op); err != nil {
		t.Fatal(err)
	}
	attached := true
	deletes := 0
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "firewalls list"):
			return []byte(`[{"id":42,"label":"lc-firewall-fixture"}]`), nil
		case strings.Contains(joined, "devices-list"):
			if attached {
				return []byte(`[{"id":9,"entity":{"id":999}}]`), nil
			}
			return []byte(`[]`), nil
		case strings.Contains(joined, "firewalls delete"):
			deletes++
			return nil, errors.New("timeout")
		}
		return nil, fmt.Errorf("unexpected %s", joined)
	}
	if err := s.cleanupFirewall(context.Background(), op.Host); err == nil || deletes != 0 {
		t.Fatal("deleted firewall attached elsewhere")
	}
	attached = false
	if err := s.cleanupFirewall(context.Background(), op.Host); err == nil || deletes != 1 {
		t.Fatal("unconfirmed delete accepted")
	}
	durable, err := s.readOperation(op.ID)
	if err != nil || !firewallOwned(durable.Host, "42") {
		t.Fatal("lost unconfirmed resource ID", err)
	}
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "firewalls list") {
			t.Fatal("already absent firewall deleted again")
		}
		return []byte(`[]`), nil
	}
	if err = s.cleanupFirewall(context.Background(), durable.Host); err != nil {
		t.Fatal(err)
	}
	inv, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	host, _ := inv.Host(op.Host.ID)
	if len(host.Resources) != 0 {
		t.Fatal("confirmed absence did not clean ownership", host)
	}
}

func TestFirewallCleanupDeletesUnusedOwnedTagLast(t *testing.T) {
	s, op := firewallFixture(t, "digitalocean")
	addFirewallResource(&op.Host, "cloud-tag", op.ID, true)
	addFirewallResource(&op.Host, "firewall", "fw", true)
	if err := s.persistFirewall(op); err != nil {
		t.Fatal(err)
	}
	var deletes []string
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "firewall list"):
			return []byte(`[{"id":"fw","name":"lc-firewall-fixture","droplet_ids":[]}]`), nil
		case strings.Contains(joined, "tag list"):
			return []byte(`[{"name":"lc-firewall-fixture","resources":{"count":0}}]`), nil
		case strings.Contains(joined, "firewall delete"):
			deletes = append(deletes, "firewall")
			return nil, nil
		case strings.Contains(joined, "tag delete"):
			deletes = append(deletes, "tag")
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected call %s", joined)
	}
	if err := s.cleanupFirewall(context.Background(), op.Host); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deletes, ",") != "firewall,tag" {
		t.Fatal("invalid cleanup order", deletes)
	}
}

func TestFirewallMalformedInventoryCannotEraseOwnership(t *testing.T) {
	for _, reply := range []string{`null`, `{}`, `{"error":"not an inventory"}`, `[{"name":"incomplete"}]`} {
		t.Run(reply, func(t *testing.T) {
			s, op := firewallFixture(t, "digitalocean")
			addFirewallResource(&op.Host, "firewall", "keep-id", true)
			if err := s.persistFirewall(op); err != nil {
				t.Fatal(err)
			}
			s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "delete") {
					t.Fatal("malformed inventory authorized deletion")
				}
				return []byte(reply), nil
			}
			if err := s.cleanupFirewall(context.Background(), op.Host); err == nil {
				t.Fatal("malformed inventory treated as absence")
			}
			durable, err := s.readOperation(op.ID)
			if err != nil || !firewallOwned(durable.Host, "keep-id") {
				t.Fatal("malformed inventory erased resource ID", err)
			}
		})
	}
}
