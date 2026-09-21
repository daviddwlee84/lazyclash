package vps

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

// CLI syntax follows the providers' official references:
// https://docs.digitalocean.com/reference/doctl/reference/compute/firewall/create/
// https://docs.vultr.com/reference/vultr-cli/firewall/rule/create
// https://techdocs.akamai.com/linode-api/reference/post-firewalls
// An owned firewall is prepared before the instance is created. Unknown creates
// are reconciled by the persisted, unique operation name, never blindly retried.

func firewallOwned(host serverstate.Host, id string) bool {
	for _, r := range host.Resources {
		if r.Kind == "firewall" && r.ID == id && r.Owned {
			return true
		}
	}
	return false
}

func addFirewallResource(host *serverstate.Host, kind, id string, owned bool) {
	for _, r := range host.Resources {
		if r.Kind == kind && r.ID == id {
			return
		}
	}
	host.Resources = append(host.Resources, serverstate.Resource{Kind: kind, ID: id, Owned: owned})
}

func (s *Service) persistFirewall(op *operation) error {
	if err := s.writeOperation(*op); err != nil {
		return err
	}
	return s.saveHost(op.Host)
}

func (s *Service) prepareFirewall(ctx context.Context, op *operation) error {
	if op.Request.Provider == "oracle" {
		return nil
	}
	if s.options.ReadOnly {
		return fmt.Errorf("firewall changes are disabled in read-only mode")
	}
	if op.PendingResourceKind != "" {
		return fmt.Errorf("firewall create outcome is unconfirmed; run vps resume %s", op.Request.ID)
	}
	if op.Request.FirewallID != "" {
		if !firewallOwned(op.Host, op.Request.FirewallID) {
			addFirewallResource(&op.Host, "firewall", op.Request.FirewallID, false)
			return s.persistFirewall(op)
		}
		if op.Request.Provider == "vultr" {
			return s.ensureVultrFirewallRules(ctx, op)
		}
		return nil
	}
	if op.Request.Provider == "digitalocean" {
		found := false
		for _, r := range op.Host.Resources {
			found = found || r.Kind == "cloud-tag" && r.ID == op.ID && r.Owned
		}
		if !found {
			op.State, op.PendingResourceKind = "firewall", "firewall-tag"
			if err := s.persistFirewall(op); err != nil {
				return err
			}
			value, err := s.call(ctx, op.Request, "compute", "tag", "create", op.ID)
			if err != nil {
				return fmt.Errorf("tag create outcome is unconfirmed; run vps resume %s: %w", op.Request.ID, err)
			}
			tag, err := one(value, "tag", "tags")
			if err != nil || str(tag["name"]) != op.ID {
				return fmt.Errorf("tag create response does not confirm the operation name; run vps resume %s", op.Request.ID)
			}
			addFirewallResource(&op.Host, "cloud-tag", op.ID, true)
			op.PendingResourceKind = ""
			if err = s.persistFirewall(op); err != nil {
				return err
			}
		}
	}
	args, err := firewallCreateArgs(*op)
	if err != nil {
		return err
	}
	op.State, op.PendingResourceKind = "firewall", "firewall"
	if err = s.persistFirewall(op); err != nil {
		return err
	}
	value, err := s.call(ctx, op.Request, args...)
	if err != nil {
		return fmt.Errorf("firewall create outcome is unconfirmed; run vps resume %s: %w", op.Request.ID, err)
	}
	firewall, err := one(value, "firewall", "firewall_group", "firewalls", "data")
	if err != nil {
		return err
	}
	id := str(firewall["id"])
	if id == "" {
		return fmt.Errorf("firewall response lacks its ID; run vps resume %s", op.Request.ID)
	}
	addFirewallResource(&op.Host, "firewall", id, true)
	op.Request.FirewallID = id
	op.PendingResourceKind = ""
	if err = s.persistFirewall(op); err != nil {
		return err
	}
	if op.Request.Provider == "vultr" {
		return s.ensureVultrFirewallRules(ctx, op)
	}
	return nil
}

func firewallCreateArgs(op operation) ([]string, error) {
	ip, cidr, err := net.ParseCIDR(op.Request.SSHCIDR)
	if err != nil {
		return nil, fmt.Errorf("SSH firewall source must be a CIDR")
	}
	source := cidr.String()
	switch op.Request.Provider {
	case "digitalocean":
		inbound := "protocol:tcp,ports:22,address:" + source + " protocol:tcp,ports:80,address:0.0.0.0/0,address:::/0 protocol:tcp,ports:443,address:0.0.0.0/0,address:::/0 protocol:udp,ports:443,address:0.0.0.0/0,address:::/0"
		outbound := "protocol:icmp,address:0.0.0.0/0,address:::/0 protocol:tcp,ports:all,address:0.0.0.0/0,address:::/0 protocol:udp,ports:all,address:0.0.0.0/0,address:::/0"
		return []string{"compute", "firewall", "create", "--name", op.ID, "--tag-names", op.ID, "--inbound-rules", inbound, "--outbound-rules", outbound}, nil
	case "vultr":
		return []string{"firewall", "group", "create", "--description", op.ID}, nil
	case "linode":
		family := "ipv4"
		if ip.To4() == nil {
			family = "ipv6"
		}
		public := map[string][]string{"ipv4": {"0.0.0.0/0"}, "ipv6": {"::/0"}}
		rules := []any{map[string]any{"label": "ssh", "action": "ACCEPT", "protocol": "TCP", "ports": "22", "addresses": map[string][]string{family: {source}}}, map[string]any{"label": "acme", "action": "ACCEPT", "protocol": "TCP", "ports": "80", "addresses": public}, map[string]any{"label": "proxy-tcp", "action": "ACCEPT", "protocol": "TCP", "ports": "443", "addresses": public}, map[string]any{"label": "proxy-udp", "action": "ACCEPT", "protocol": "UDP", "ports": "443", "addresses": public}}
		return []string{"firewalls", "create", "--label", op.ID, "--rules.inbound_policy", "DROP", "--rules.outbound_policy", "ACCEPT", "--rules.inbound", jsonValue(rules)}, nil
	default:
		return nil, fmt.Errorf("provider has no managed firewall adapter")
	}
}

type firewallRule struct {
	Protocol, Port, Subnet string
	Size                   int
	Family                 string
}

func desiredVultrFirewallRules(cidr string) ([]firewallRule, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ones, _ := network.Mask.Size()
	family := "v4"
	if ip.To4() == nil {
		family = "v6"
	}
	rules := []firewallRule{{"tcp", "22", network.IP.String(), ones, family}}
	for _, family := range []string{"v4", "v6"} {
		subnet := "0.0.0.0"
		if family == "v6" {
			subnet = "::"
		}
		for _, port := range []string{"80", "443"} {
			rules = append(rules, firewallRule{"tcp", port, subnet, 0, family})
		}
		rules = append(rules, firewallRule{"udp", "443", subnet, 0, family})
	}
	return rules, nil
}

func ruleMatches(rule map[string]any, want firewallRule) bool {
	return strings.EqualFold(str(rule["protocol"]), want.Protocol) && str(rule["port"]) == want.Port && str(rule["ip_type"]) == want.Family && net.ParseIP(str(rule["subnet"])).Equal(net.ParseIP(want.Subnet)) && int(num(rule["subnet_size"])) == want.Size
}

func (s *Service) ensureVultrFirewallRules(ctx context.Context, op *operation) error {
	wanted, err := desiredVultrFirewallRules(op.Request.SSHCIDR)
	if err != nil {
		return err
	}
	value, err := s.vultrList(ctx, op.Request, "firewall_rules", "firewall", "rule", "list", op.Request.FirewallID)
	if err != nil {
		return err
	}
	existing, err := strictResourceRows(value, "firewall_rules", "protocol")
	if err != nil {
		return err
	}
	for _, rule := range wanted {
		found := false
		for _, have := range existing {
			found = found || ruleMatches(have, rule)
		}
		if found {
			continue
		}
		// The owned group is already durable; after any timeout the next resume
		// lists its rules before deciding whether a missing rule needs adding.
		_, err = s.call(ctx, op.Request, "firewall", "rule", "create", op.Request.FirewallID, "--ip-type", rule.Family, "--protocol", rule.Protocol, "--subnet", rule.Subnet, "--size", strconv.Itoa(rule.Size), "--port", rule.Port, "--notes", op.ID)
		if err != nil {
			return fmt.Errorf("owned firewall rule result unconfirmed; resume reconciles rules before retrying: %w", err)
		}
	}
	return nil
}

func (s *Service) attachFirewall(ctx context.Context, op *operation) error {
	if op.Request.Provider != "digitalocean" || op.Request.FirewallID == "" {
		return nil
	}
	if firewallOwned(op.Host, op.Request.FirewallID) {
		return nil
	} // Already attached by unique operation tag, including future Droplets.
	if op.Host.ResourceID == "" {
		return fmt.Errorf("cannot attach firewall without saved instance ID")
	}
	_, err := s.call(ctx, op.Request, "compute", "firewall", "add-droplets", op.Request.FirewallID, "--droplet-ids", op.Host.ResourceID)
	if err != nil {
		return fmt.Errorf("existing firewall attachment is unconfirmed; VM remains saved for resume: %w", err)
	}
	return nil
}

func (s *Service) listFirewalls(ctx context.Context, req CreateRequest) ([]map[string]any, error) {
	switch req.Provider {
	case "digitalocean":
		value, err := s.call(ctx, req, "compute", "firewall", "list")
		if err != nil {
			return nil, err
		}
		return strictResourceRows(value, "firewalls", "id")
	case "vultr":
		value, err := s.vultrList(ctx, req, "firewall_groups", "firewall", "group", "list")
		if err != nil {
			return nil, err
		}
		return strictResourceRows(value, "firewall_groups", "id")
	case "linode":
		value, err := s.call(ctx, req, "firewalls", "list", "--all")
		if err != nil {
			return nil, err
		}
		return strictResourceRows(value, "data", "id")
	}
	return nil, fmt.Errorf("provider has no firewall inventory adapter")
}

func firewallName(provider string, row map[string]any) string {
	switch provider {
	case "digitalocean":
		return str(row["name"])
	case "vultr":
		return str(row["description"])
	default:
		return str(row["label"])
	}
}

func (s *Service) resumeFirewall(ctx context.Context, op *operation) error {
	if op.PendingResourceKind == "firewall-tag" {
		value, err := s.call(ctx, op.Request, "compute", "tag", "get", op.ID)
		if err != nil {
			return fmt.Errorf("tag creation remains unconfirmed; no create was retried: %w", err)
		}
		tag, err := one(value, "tag", "tags")
		if err != nil || str(tag["name"]) != op.ID {
			return fmt.Errorf("operation tag was not confirmed; no create was retried")
		}
		addFirewallResource(&op.Host, "cloud-tag", op.ID, true)
		op.PendingResourceKind = ""
		return s.persistFirewall(op)
	}
	if op.PendingResourceKind != "firewall" {
		return fmt.Errorf("pending operation is not a firewall create")
	}
	rows, err := s.listFirewalls(ctx, op.Request)
	if err != nil {
		return err
	}
	var found []map[string]any
	for _, row := range rows {
		if firewallName(op.Request.Provider, row) == op.ID {
			found = append(found, row)
		}
	}
	if len(found) != 1 || str(found[0]["id"]) == "" {
		return fmt.Errorf("firewall reconciliation found %d matches for operation %s; no create was retried", len(found), op.ID)
	}
	id := str(found[0]["id"])
	addFirewallResource(&op.Host, "firewall", id, true)
	op.Request.FirewallID = id
	op.PendingResourceKind = ""
	return s.persistFirewall(op)
}

func (s *Service) cleanupFirewall(ctx context.Context, host serverstate.Host) error {
	owned := false
	for _, r := range host.Resources {
		owned = owned || r.Owned && (r.Kind == "firewall" || r.Kind == "cloud-tag")
	}
	if !owned {
		return nil
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		return err
	}
	op.Host = host
	rows, err := s.listFirewalls(ctx, op.Request)
	if err != nil {
		return err
	}
	for _, resource := range append([]serverstate.Resource(nil), op.Host.Resources...) {
		if !resource.Owned || resource.Kind != "firewall" {
			continue
		}
		var current map[string]any
		for _, row := range rows {
			if str(row["id"]) == resource.ID {
				current = row
				break
			}
		}
		if current != nil {
			if firewallName(op.Request.Provider, current) != op.ID {
				return fmt.Errorf("owned firewall identity changed; refusing to delete %s", resource.ID)
			}
			if len(arr(current["droplet_ids"])) > 0 || num(current["instance_count"]) > 0 {
				return fmt.Errorf("firewall still has attached instances; wait for VM deletion before cleanup")
			}
			if op.Request.Provider == "linode" {
				devices, e := s.call(ctx, op.Request, "firewalls", "devices-list", resource.ID, "--all")
				if e != nil {
					return e
				}
				deviceRows, e := strictResourceRows(devices, "data", "id")
				if e != nil {
					return e
				}
				if len(deviceRows) > 0 {
					return fmt.Errorf("firewall still has attached devices; wait for VM deletion before cleanup")
				}
			}
			var args []string
			switch op.Request.Provider {
			case "digitalocean":
				args = []string{"compute", "firewall", "delete", resource.ID, "--force"}
			case "vultr":
				args = []string{"firewall", "group", "delete", resource.ID}
			case "linode":
				args = []string{"firewalls", "delete", resource.ID}
			}
			if _, err = s.call(ctx, op.Request, args...); err != nil {
				return fmt.Errorf("firewall deletion unconfirmed; retry cleanup after inspecting provider state: %w", err)
			}
		}
		removeFirewallResource(&op.Host, resource.Kind, resource.ID)
		if err = s.persistFirewall(&op); err != nil {
			return err
		}
	}
	for _, resource := range append([]serverstate.Resource(nil), op.Host.Resources...) {
		if !resource.Owned || resource.Kind != "cloud-tag" {
			continue
		}
		value, err := s.call(ctx, op.Request, "compute", "tag", "list")
		if err != nil {
			return fmt.Errorf("cannot confirm tag is unused before cleanup: %w", err)
		}
		if resource.ID != op.ID {
			return fmt.Errorf("operation tag identity changed")
		}
		var tag map[string]any
		tags, err := strictResourceRows(value, "tags", "name")
		if err != nil {
			return err
		}
		for _, row := range tags {
			if str(row["name"]) == resource.ID {
				tag = row
				break
			}
		}
		if tag != nil {
			count, present := resourceCount(obj(tag["resources"]))
			if !present {
				return fmt.Errorf("tag resource usage is missing; cannot confirm safe cleanup")
			}
			if count > 0 {
				return fmt.Errorf("operation tag is still attached to resources; refusing to delete it")
			}
			if _, err = s.call(ctx, op.Request, "compute", "tag", "delete", resource.ID, "--force"); err != nil {
				return fmt.Errorf("tag delete outcome is unconfirmed: %w", err)
			}
		}
		removeFirewallResource(&op.Host, resource.Kind, resource.ID)
		if err = s.persistFirewall(&op); err != nil {
			return err
		}
	}
	return nil
}

func removeFirewallResource(host *serverstate.Host, kind, id string) {
	out := host.Resources[:0]
	for _, r := range host.Resources {
		if r.Kind != kind || r.ID != id {
			out = append(out, r)
		}
	}
	host.Resources = out
}
func resourceCount(value map[string]any) (float64, bool) {
	var count float64
	found := false
	for key, v := range value {
		if key == "count" {
			n, ok := v.(float64)
			if !ok || n < 0 {
				return 0, false
			}
			count += n
			found = true
		} else if nested := obj(v); nested != nil {
			n, present := resourceCount(nested)
			count += n
			found = found || present
		}
	}
	return count, found
}

// A missing/malformed list is not proof that an owned resource disappeared.
// Retain IDs until the provider supplies a complete, correctly shaped inventory.
func strictResourceRows(value any, key, identity string) ([]map[string]any, error) {
	list, ok := value.([]any)
	if !ok {
		list, ok = obj(value)[key].([]any)
	}
	if !ok {
		return nil, fmt.Errorf("provider %s inventory is incomplete; resource absence cannot be confirmed", key)
	}
	rows := make([]map[string]any, 0, len(list))
	for _, item := range list {
		row := obj(item)
		if row == nil || str(row[identity]) == "" {
			return nil, fmt.Errorf("provider %s inventory contains an incomplete resource", key)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
