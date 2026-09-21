package vps

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func (s *Service) call(ctx context.Context, req CreateRequest, args ...string) (any, error) {
	var executable string
	var flags []string
	switch req.Provider {
	case "digitalocean":
		executable = "doctl"
		flags = []string{"--output", "json", "--http-retry-max", "0"}
		if req.Profile != "" {
			flags = append(flags, "--context", req.Profile)
		}
	case "vultr":
		executable = "vultr-cli"
		flags = []string{"--output", "json"}
		if req.Profile != "" {
			flags = append(flags, "--config", req.Profile)
		}
	case "linode":
		executable = "linode-cli"
		flags = []string{"--json", "--no-retry", "--no-defaults"}
		if req.Profile != "" {
			flags = append(flags, "--as-user", req.Profile)
		}
	case "oracle":
		executable = "oci"
		flags = []string{"--output", "json", "--no-retry"}
		if req.Profile != "" {
			flags = append(flags, "--profile", req.Profile)
		}
		if req.Region != "" {
			flags = append(flags, "--region", req.Region)
		}
	default:
		return nil, fmt.Errorf("provider %q does not expose managed cloud operations", req.Provider)
	}
	b, err := s.options.Run(ctx, executable, append(flags, args...))
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var value any
	if err = json.Unmarshal(b, &value); err != nil {
		return nil, fmt.Errorf("%s returned invalid JSON (output withheld)", executable)
	}
	if req.Provider == "oracle" {
		for _, arg := range args {
			if arg == "list" || arg == "list-vnics" {
				if _, err := strictItems(value, "data"); err != nil {
					return nil, err
				}
				break
			}
		}
	}
	return value, nil
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }
func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	}
	return ""
}
func num(v any) float64 { f, _ := v.(float64); return f }
func truth(v any) bool  { b, _ := v.(bool); return b }
func arr(v any) []any   { a, _ := v.([]any); return a }
func items(v any, keys ...string) []map[string]any {
	if m := obj(v); m != nil {
		for _, k := range keys {
			if a, ok := m[k].([]any); ok {
				v = a
				break
			}
			if a, ok := m[k].(map[string]any); ok {
				return []map[string]any{a}
			}
		}
	}
	if m := obj(v); m != nil {
		return []map[string]any{m}
	}
	var result []map[string]any
	for _, v := range arr(v) {
		if m := obj(v); m != nil {
			result = append(result, m)
		}
	}
	return result
}

func strictItems(v any, keys ...string) ([]map[string]any, error) {
	if m := obj(v); m != nil {
		found := false
		for _, key := range keys {
			if value, ok := m[key]; ok {
				v = value
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("provider list response lacks its resource collection")
		}
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("provider list resource collection is not an array")
	}
	result := make([]map[string]any, 0, len(a))
	for _, entry := range a {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("provider list contains a malformed resource")
		}
		result = append(result, m)
	}
	return result, nil
}
func one(v any, keys ...string) (map[string]any, error) {
	a := items(v, keys...)
	if len(a) != 1 {
		return nil, fmt.Errorf("provider returned %d resources; expected one", len(a))
	}
	return a[0], nil
}
func contains(v any, value string) bool {
	for _, x := range arr(v) {
		if str(x) == value {
			return true
		}
	}
	return false
}

func (s *Service) Quote(ctx context.Context, req CreateRequest) (Quote, error) {
	q := Quote{Provider: req.Provider, Plan: req.Plan, Region: req.Region, Live: true, TransferUnit: "GB", Notes: []string{"USD monthly base price only; taxes, traffic overages and optional resources are additional. VM stop does not release billable resources."}}
	var v any
	var err error
	var selected map[string]any
	switch req.Provider {
	case "digitalocean":
		v, err = s.call(ctx, req, "compute", "size", "list")
		if err != nil {
			return q, err
		}
		for _, m := range items(v, "sizes") {
			if str(m["slug"]) == req.Plan {
				selected = m
				break
			}
		}
		if selected == nil {
			return q, fmt.Errorf("DigitalOcean size %q is not available", req.Plan)
		}
		if !truth(selected["available"]) {
			return q, fmt.Errorf("DigitalOcean size %q is not currently available", req.Plan)
		}
		if req.Region != "" && !contains(selected["regions"], req.Region) {
			return q, fmt.Errorf("DigitalOcean size %q is not offered in %s", req.Plan, req.Region)
		}
		q.MonthlyUSD = num(selected["price_monthly"])
		q.MemoryMiB = int(num(selected["memory"]))
		q.VCPUs = int(num(selected["vcpus"]))
		q.DiskGB = int(num(selected["disk"]))
		q.TransferGB = int(num(selected["transfer"]) * 1000)
		q.TransferUnit = "GiB"
		q.Notes = append(q.Notes, "DigitalOcean transfer allowance uses GiB/TiB; preserve provider units when comparing traffic.")
	case "vultr":
		v, err = s.vultrList(ctx, req, "plans", "plans", "list")
		if err != nil {
			return q, err
		}
		for _, m := range items(v, "plans") {
			if str(m["id"]) == req.Plan {
				selected = m
				break
			}
		}
		if selected == nil {
			return q, fmt.Errorf("Vultr plan %q is not available", req.Plan)
		}
		if req.Region != "" && len(arr(selected["locations"])) > 0 && !contains(selected["locations"], req.Region) {
			return q, fmt.Errorf("Vultr plan is not offered in %s", req.Region)
		}
		q.MonthlyUSD = num(selected["monthly_cost"])
		q.MemoryMiB = int(num(selected["ram"]))
		q.VCPUs = int(num(selected["vcpu_count"]))
		q.DiskGB = int(num(selected["disk"]))
		q.TransferGB = int(num(selected["bandwidth"]))
	case "linode":
		v, err = s.call(ctx, req, "linodes", "types")
		if err != nil {
			return q, err
		}
		for _, m := range items(v, "data") {
			if str(m["id"]) == req.Plan {
				selected = m
				break
			}
		}
		if selected == nil {
			return q, fmt.Errorf("Linode type %q is not available", req.Plan)
		}
		q.MonthlyUSD = num(obj(selected["price"])["monthly"])
		q.MemoryMiB = int(num(selected["memory"]))
		q.VCPUs = int(num(selected["vcpus"]))
		q.DiskGB = int(num(selected["disk"]) / 1024)
		q.TransferGB = int(num(selected["transfer"]))
		for _, entry := range arr(selected["region_prices"]) {
			m := obj(entry)
			if str(m["id"]) == req.Region {
				q.MonthlyUSD = num(m["monthly"])
			}
		}
	case "oracle":
		if req.Plan != "VM.Standard.A1.Flex" {
			return q, fmt.Errorf("only Always Free A1 is supported")
		}
		q.VCPUs = 1
		q.MemoryMiB = 6144
		q.DiskGB = 50
		q.TransferGB = 10000
		q.Live = false
		q.Notes = []string{"Conditional Always Free estimate; create preview must verify home region, all tenancy resources and current-period usage. No fallback to paid shapes, trial credits or extra storage."}
	default:
		return q, fmt.Errorf("use vps catalog for %s; no live cloud quote adapter", req.Provider)
	}
	if req.Provider != "oracle" && q.MonthlyUSD <= 0 {
		return q, fmt.Errorf("provider did not return a positive monthly price; refusing an unpriced VM")
	}
	return q, nil
}

func (s *Service) createRemote(ctx context.Context, req CreateRequest, operationID string) (serverstate.Host, error) {
	var args []string
	switch req.Provider {
	case "digitalocean":
		args = []string{"compute", "droplet", "create", req.Name, "--region", req.Region, "--size", req.Plan, "--image", req.Image, "--ssh-keys", req.SSHKey, "--tag-names", operationID}
	case "vultr":
		args = []string{"instance", "create", "--label", req.Name, "--host", req.Name, "--region", req.Region, "--plan", req.Plan, "--os", req.Image, "--ssh-keys", req.SSHKey, "--tags", operationID}
		if req.FirewallID != "" {
			args = append(args, "--firewall-group", req.FirewallID)
		}
	case "linode":
		key, err := reviewedPublicKey(req)
		if err != nil {
			return serverstate.Host{}, err
		}
		args = []string{"linodes", "create", "--label", req.Name, "--region", req.Region, "--type", req.Plan, "--image", req.Image, "--authorized_keys", key, "--tags", operationID, "--booted", "true"}
		if req.FirewallID != "" {
			args = append(args, "--firewall_id", req.FirewallID)
		}
	case "oracle":
		key, err := reviewedPublicKey(req)
		if err != nil {
			return serverstate.Host{}, err
		}
		fields, err := oracleLaunchMetadata(req, key)
		if err != nil {
			return serverstate.Host{}, err
		}
		metadata, _ := json.Marshal(fields)
		tags, _ := json.Marshal(map[string]string{"lazyclash-operation": operationID})
		args = []string{"compute", "instance", "launch", "--compartment-id", req.CompartmentID, "--availability-domain", req.AvailabilityDomain, "--display-name", req.Name, "--shape", req.Plan, "--shape-config", `{"ocpus":1,"memoryInGBs":6}`, "--image-id", req.Image, "--boot-volume-size-in-gbs", "50", "--subnet-id", req.SubnetID, "--assign-public-ip", "true", "--metadata", string(metadata), "--freeform-tags", string(tags), "--opc-retry-token", operationID}
		if req.FirewallID != "" {
			ids, _ := json.Marshal([]string{req.FirewallID})
			args = append(args, "--nsg-ids", string(ids))
		}
	}
	v, err := s.call(ctx, req, args...)
	if err != nil {
		return serverstate.Host{}, err
	}
	m, err := one(v, "data", "instance", "instances")
	if err != nil {
		return serverstate.Host{}, err
	}
	host, err := remoteHost(req.Provider, m)
	if err != nil {
		return host, err
	}
	return host, nil
}

func remoteHost(provider string, m map[string]any) (serverstate.Host, error) {
	host := serverstate.Host{ResourceID: str(m["id"]), Status: str(m["status"])}
	if host.ResourceID == "" {
		return host, fmt.Errorf("provider response lacks the VM resource ID; use resume to reconcile")
	}
	switch provider {
	case "digitalocean":
		for _, n := range arr(obj(m["networks"])["v4"]) {
			if str(obj(n)["type"]) == "public" {
				host.PublicHost = str(obj(n)["ip_address"])
				break
			}
		}
	case "vultr":
		host.PublicHost = str(m["main_ip"])
		if host.PublicHost == "0.0.0.0" {
			host.PublicHost = ""
		}
		if str(m["power_status"]) != "" {
			host.Status += "/" + str(m["power_status"])
		}
	case "linode":
		for _, n := range arr(m["ipv4"]) {
			ip := str(n)
			parsed := net.ParseIP(ip)
			if parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
				host.PublicHost = ip
				break
			}
		}
	case "oracle":
		host.Status = str(m["lifecycle-state"])
	}
	return host, nil
}

func (s *Service) getRemote(ctx context.Context, req CreateRequest, id string) (serverstate.Host, error) {
	var args []string
	switch req.Provider {
	case "digitalocean":
		args = []string{"compute", "droplet", "get", id}
	case "vultr":
		args = []string{"instance", "get", id}
	case "linode":
		args = []string{"linodes", "view", id}
	case "oracle":
		args = []string{"compute", "instance", "get", "--instance-id", id}
	default:
		return serverstate.Host{}, fmt.Errorf("unsupported cloud provider")
	}
	v, err := s.call(ctx, req, args...)
	if err != nil {
		return serverstate.Host{}, err
	}
	m, err := one(v, "data", "instance")
	if err != nil {
		return serverstate.Host{}, err
	}
	h, err := remoteHost(req.Provider, m)
	if err != nil {
		return h, err
	}
	if req.Provider == "oracle" {
		v, err = s.call(ctx, req, "compute", "instance", "list-vnics", "--instance-id", id, "--all")
		if err != nil {
			return h, err
		}
		for _, m := range items(v, "data") {
			if str(m["public-ip"]) != "" {
				h.PublicHost = str(m["public-ip"])
				break
			}
		}
	}
	return h, nil
}

func (s *Service) findRemote(ctx context.Context, req CreateRequest, operationID string) (serverstate.Host, error) {
	h, err := s.lookupRemote(ctx, req, operationID, "")
	if err != nil {
		return serverstate.Host{}, err
	}
	if h == nil {
		return serverstate.Host{}, fmt.Errorf("reconciliation found no VM for operation %s; no create was retried; inspect the provider account", operationID)
	}
	return *h, nil
}

// lookupRemote establishes absence only from a complete, well-formed list.
// For deletion it locates the saved ID independently of tags, so a changed tag
// is not mistaken for an already-deleted VM.
func (s *Service) lookupRemote(ctx context.Context, req CreateRequest, operationID, resourceID string) (*serverstate.Host, error) {
	var args []string
	switch req.Provider {
	case "digitalocean":
		args = []string{"compute", "droplet", "list"}
	case "vultr":
		args = []string{"instance", "list"}
	case "linode":
		args = []string{"linodes", "list", "--all"}
	case "oracle":
		args = []string{"compute", "instance", "list", "--compartment-id", req.CompartmentID, "--all"}
	}
	var v any
	var err error
	if req.Provider == "vultr" {
		v, err = s.vultrList(ctx, req, "instances", args...)
	} else {
		v, err = s.call(ctx, req, args...)
	}
	if err != nil {
		return nil, err
	}
	var found []map[string]any
	rows, err := strictItems(v, "data", "instances", "droplets")
	if err != nil {
		return nil, err
	}
	for _, m := range rows {
		matches := contains(m["tags"], operationID)
		if req.Provider == "oracle" {
			matches = str(obj(m["freeform-tags"])["lazyclash-operation"]) == operationID && str(m["lifecycle-state"]) != "TERMINATED"
		}
		if resourceID != "" {
			if str(m["id"]) != resourceID {
				continue
			}
			if str(m["lifecycle-state"]) == "TERMINATED" {
				continue
			}
			if !matches {
				return nil, fmt.Errorf("saved VM exists but its ownership marker has changed")
			}
		}
		if matches {
			found = append(found, m)
		}
	}
	if len(found) == 0 {
		return nil, nil
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("reconciliation found %d VMs for operation %s; no create was retried; inspect the provider account before resolving this record", len(found), operationID)
	}
	h, err := remoteHost(req.Provider, found[0])
	if err != nil {
		return nil, err
	}
	h, err = s.getRemote(ctx, req, h.ResourceID)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func (s *Service) vultrList(ctx context.Context, req CreateRequest, key string, args ...string) (any, error) {
	var result []any
	cursor := ""
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		pageArgs := append(append([]string(nil), args...), "--per-page", "500")
		if cursor != "" {
			pageArgs = append(pageArgs, "--cursor", cursor)
		}
		v, err := s.call(ctx, req, pageArgs...)
		if err != nil {
			return nil, err
		}
		rows, err := strictItems(v, key)
		if err != nil {
			return nil, err
		}
		for _, m := range rows {
			result = append(result, m)
		}
		next, valid := obj(obj(obj(v)["meta"])["links"])["next"].(string)
		if !valid {
			return nil, fmt.Errorf("Vultr list response lacks complete pagination metadata")
		}
		cursor = next
		if cursor == "" {
			return map[string]any{key: result}, nil
		}
		if seen[cursor] {
			return nil, fmt.Errorf("Vultr repeated a pagination cursor")
		}
		seen[cursor] = true
	}
	return nil, fmt.Errorf("Vultr result pagination exceeds safe bound")
}

func (s *Service) actionRemote(ctx context.Context, host serverstate.Host, action string) error {
	req := CreateRequest{Provider: host.Provider, Profile: host.Profile, Region: host.Region}
	var args []string
	switch host.Provider {
	case "digitalocean":
		if action == "delete" {
			args = []string{"compute", "droplet", "delete", host.ResourceID, "--force"}
		} else {
			a := map[string]string{"start": "power-on", "stop": "shutdown", "reboot": "reboot"}[action]
			args = []string{"compute", "droplet-action", a, host.ResourceID}
		}
	case "vultr":
		a := action
		if action == "reboot" {
			a = "restart"
		}
		args = []string{"instance", a, host.ResourceID}
	case "linode":
		a := map[string]string{"start": "boot", "stop": "shutdown", "reboot": "reboot", "delete": "delete"}[action]
		args = []string{"linodes", a, host.ResourceID}
	case "oracle":
		if action == "delete" {
			args = []string{"compute", "instance", "terminate", "--instance-id", host.ResourceID, "--preserve-boot-volume", "false", "--force", "--wait-for-state", "TERMINATED", "--max-wait-seconds", "120", "--wait-interval-seconds", "2"}
		} else {
			a := map[string]string{"start": "START", "stop": "SOFTSTOP", "reboot": "SOFTRESET"}[action]
			args = []string{"compute", "instance", "action", "--instance-id", host.ResourceID, "--action", a}
		}
	default:
		return fmt.Errorf("unsupported cloud provider")
	}
	_, err := s.call(ctx, req, args...)
	return err
}
