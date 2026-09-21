package vps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type azureSpec struct {
	kind, id, name string
	cli            []string
	args           []string
	parent         string
}

func azureBase(op operation) string  { return op.ID }
func azureGroup(op operation) string { return azureBase(op) + "-rg" }
func azureGroupID(op operation) string {
	return "/subscriptions/" + op.Request.SubscriptionID + "/resourceGroups/" + azureGroup(op)
}
func azureID(op operation, kind string) string {
	base := azureGroupID(op) + "/providers/"
	name := azureBase(op)
	switch kind {
	case "azure-group":
		return azureGroupID(op)
	case "azure-vnet":
		return base + "Microsoft.Network/virtualNetworks/" + name + "-vnet"
	case "azure-subnet":
		return azureID(op, "azure-vnet") + "/subnets/default"
	case "azure-nsg":
		return base + "Microsoft.Network/networkSecurityGroups/" + name + "-nsg"
	case "azure-nsg-ssh", "azure-nsg-web", "azure-nsg-udp":
		return azureID(op, "azure-nsg") + "/securityRules/" + strings.TrimPrefix(kind, "azure-nsg-")
	case "azure-ip":
		return base + "Microsoft.Network/publicIPAddresses/" + name + "-ip"
	case "azure-nic":
		return base + "Microsoft.Network/networkInterfaces/" + name + "-nic"
	case "azure-vm":
		return base + "Microsoft.Compute/virtualMachines/" + name + "-vm"
	case "azure-disk":
		return base + "Microsoft.Compute/disks/" + name + "-os"
	}
	return ""
}
func azureSpecs(op operation) ([]azureSpec, error) {
	r := op.Request
	tag := "lazyclash-operation=" + op.ID
	group := []string{"--resource-group", azureGroup(op)}
	location := []string{"--location", r.Region}
	name := azureBase(op)
	specs := []azureSpec{{kind: "azure-group", name: azureGroup(op), cli: []string{"group"}, args: []string{"--name", azureGroup(op), "--location", r.Region, "--tags", tag}}}
	add := func(kind, suffix string, cli []string, args []string, parent string) {
		flags := append([]string{}, group...)
		flags = append(flags, "--name", name+suffix)
		flags = append(flags, args...)
		specs = append(specs, azureSpec{kind: kind, name: name + suffix, cli: cli, args: flags, parent: parent})
	}
	add("azure-vnet", "-vnet", []string{"network", "vnet"}, append(append([]string{}, location...), "--address-prefixes", "10.208.0.0/16", "--tags", tag), "")
	add("azure-nsg", "-nsg", []string{"network", "nsg"}, append(append([]string{}, location...), "--tags", tag), "")
	for i, rule := range []struct {
		name, protocol, source string
		ports                  []string
	}{{"ssh", "Tcp", r.SSHCIDR, []string{"22"}}, {"web", "Tcp", "0.0.0.0/0", []string{"80", "443"}}, {"udp", "Udp", "0.0.0.0/0", []string{"443"}}} {
		args := append([]string{}, group...)
		args = append(args, "--nsg-name", name+"-nsg", "--name", rule.name, "--priority", strconv.Itoa(100+i), "--direction", "Inbound", "--access", "Allow", "--protocol", rule.protocol, "--source-address-prefixes", rule.source, "--source-port-ranges", "*", "--destination-address-prefixes", "*", "--destination-port-ranges")
		args = append(args, rule.ports...)
		specs = append(specs, azureSpec{kind: "azure-nsg-" + rule.name, name: rule.name, cli: []string{"network", "nsg", "rule"}, args: args, parent: "azure-nsg"})
	}
	specs = append(specs, azureSpec{kind: "azure-subnet", name: "default", cli: []string{"network", "vnet", "subnet"}, parent: "azure-vnet", args: append(append([]string{}, group...), "--vnet-name", name+"-vnet", "--name", "default", "--address-prefixes", "10.208.1.0/24", "--network-security-group", azureID(op, "azure-nsg"), "--default-outbound-access", "false")})
	ipargs := append(append([]string{}, location...), "--sku", "Standard", "--allocation-method", "Static", "--version", "IPv4", "--tags", tag)
	if r.AvailabilityZone != "" {
		ipargs = append(ipargs, "--zone", r.AvailabilityZone)
	}
	add("azure-ip", "-ip", []string{"network", "public-ip"}, ipargs, "")
	add("azure-nic", "-nic", []string{"network", "nic"}, append(append([]string{}, location...), "--subnet", azureID(op, "azure-subnet"), "--network-security-group", azureID(op, "azure-nsg"), "--public-ip-address", azureID(op, "azure-ip"), "--tags", tag), "")
	for i := range specs {
		specs[i].id = azureID(op, specs[i].kind)
	}
	return specs, nil
}
func azureSpecFor(op operation, kind string) (azureSpec, error) {
	ss, _ := azureSpecs(op)
	for _, s := range ss {
		if s.kind == kind {
			return s, nil
		}
	}
	switch kind {
	case "azure-vm":
		return azureSpec{kind: kind, id: azureID(op, kind), name: azureBase(op) + "-vm", cli: []string{"vm"}}, nil
	case "azure-disk":
		return azureSpec{kind: kind, id: azureID(op, kind), name: azureBase(op) + "-os", cli: []string{"disk"}}, nil
	}
	return azureSpec{}, fmt.Errorf("unknown Azure resource kind %s", kind)
}
func (a azureAdapter) checkAccount(ctx context.Context, op operation) error {
	identity, e := a.Identity(ctx, op.Request)
	if e != nil {
		return e
	}
	if identity != op.AccountID {
		return fmt.Errorf("Azure cloud, tenant or subscription changed; no resource was modified")
	}
	return nil
}

// find establishes absence only through a complete successful list. Azure CLI
// paginates these list commands; error text is never treated as a 404.
func (a azureAdapter) find(ctx context.Context, op operation, sp azureSpec) (map[string]any, error) {
	var args []string
	switch sp.kind {
	case "azure-group":
		args = []string{"group", "list"}
	case "azure-subnet":
		args = []string{"network", "vnet", "subnet", "list", "--resource-group", azureGroup(op), "--vnet-name", azureBase(op) + "-vnet"}
	case "azure-nsg-ssh", "azure-nsg-web", "azure-nsg-udp":
		args = []string{"network", "nsg", "rule", "list", "--resource-group", azureGroup(op), "--nsg-name", azureBase(op) + "-nsg"}
	default:
		args = []string{"resource", "list", "--resource-group", azureGroup(op)}
	}
	v, e := a.call(ctx, op.Request, args...)
	if e != nil {
		return nil, e
	}
	rows, e := strictItems(v)
	if e != nil {
		return nil, e
	}
	var match map[string]any
	for _, m := range rows {
		if strings.EqualFold(str(m["id"]), sp.id) {
			if match != nil {
				return nil, fmt.Errorf("Azure returned duplicate resource identity")
			}
			match = m
		}
	}
	if match == nil {
		return nil, nil
	}
	if sp.kind == "azure-group" {
		return match, nil
	}
	// Fetch typed details for disk identity, dependency checks and VM endpoint.
	args = append(append([]string{}, sp.cli...), "show", "--ids", sp.id)
	v, e = a.call(ctx, op.Request, args...)
	if e != nil {
		return nil, e
	}
	m := obj(v)
	if !strings.EqualFold(str(m["id"]), sp.id) {
		return nil, fmt.Errorf("Azure show returned a different resource")
	}
	return m, nil
}
func (a azureAdapter) verifyResource(ctx context.Context, op operation, sp azureSpec, m map[string]any, receipt *cloudResource) error {
	if m == nil {
		return fmt.Errorf("Azure owned %s is missing", sp.kind)
	}
	if sp.kind == "azure-disk" {
		if receipt == nil || receipt.Proof["uniqueId"] == "" || str(m["uniqueId"]) != receipt.Proof["uniqueId"] || !strings.EqualFold(receipt.Proof["vm"], azureID(op, "azure-vm")) {
			return fmt.Errorf("Azure OS disk identity changed; retaining disk")
		}
		if by := str(m["managedBy"]); by != "" && !strings.EqualFold(by, receipt.Proof["vm"]) {
			return fmt.Errorf("Azure OS disk is attached to another VM; retaining disk")
		}
		return nil
	}
	if sp.parent != "" {
		parent, _ := azureSpecFor(op, sp.parent)
		pm, e := a.find(ctx, op, parent)
		if e != nil {
			return e
		}
		if pm == nil || str(obj(pm["tags"])["lazyclash-operation"]) != op.ID {
			return fmt.Errorf("Azure parent ownership changed; retaining %s", sp.kind)
		}
	} else if str(obj(m["tags"])["lazyclash-operation"]) != op.ID {
		return fmt.Errorf("Azure %s ownership changed; resource retained", sp.kind)
	}
	if receipt != nil && receipt.ID != "" && !strings.EqualFold(receipt.ID, str(m["id"])) {
		return fmt.Errorf("Azure resource differs from saved receipt")
	}
	switch sp.kind {
	case "azure-vm":
		if !strings.EqualFold(str(obj(obj(m["storageProfile"])["osDisk"])["name"]), azureBase(op)+"-os") {
			return fmt.Errorf("Azure VM OS disk changed; refuse lifecycle operation")
		}
		if receipt != nil && receipt.Proof["vmId"] != "" && str(m["vmId"]) != receipt.Proof["vmId"] {
			return fmt.Errorf("Azure VM instance identity changed")
		}
	case "azure-nic":
		if by := str(obj(m["virtualMachine"])["id"]); by != "" && !strings.EqualFold(by, azureID(op, "azure-vm")) {
			return fmt.Errorf("Azure NIC is attached to another VM")
		}
	case "azure-ip":
		if id := str(obj(m["ipConfiguration"])["id"]); id != "" && !strings.HasPrefix(strings.ToLower(id), strings.ToLower(azureID(op, "azure-nic"))+"/") {
			return fmt.Errorf("Azure public IP is attached to a foreign NIC")
		}
	}
	return nil
}
func (a azureAdapter) submit(ctx context.Context, op *operation, sp azureSpec, args []string, allow bool) error {
	if old := cloudResourceOf(op, sp.kind); old != nil {
		if old.Deleted {
			return fmt.Errorf("Azure resource was already deleted")
		}
		m, e := a.find(ctx, *op, sp)
		if e != nil {
			return e
		}
		if e = a.verifyResource(ctx, *op, sp, m, old); e != nil {
			return e
		}
		return a.finishResource(ctx, op, sp, m)
	}
	m, e := a.find(ctx, *op, sp)
	if e != nil {
		return e
	}
	if op.PendingResourceKind != "" {
		if op.PendingResourceKind != sp.kind {
			return fmt.Errorf("Azure %s write remains unresolved", op.PendingResourceKind)
		}
		if m == nil {
			return fmt.Errorf("Azure %s creation remains unconfirmed; no create was repeated", sp.kind)
		}
		if e = a.verifyResource(ctx, *op, sp, m, nil); e != nil {
			return e
		}
		return a.record(ctx, op, sp, m)
	}
	if m != nil {
		return fmt.Errorf("Azure resource name collision at %s; refusing to adopt an existing resource", sp.id)
	}
	if !allow {
		return fmt.Errorf("Azure preparation is incomplete; review vps resume to continue")
	}
	if e = a.checkAccount(ctx, *op); e != nil {
		return e
	}
	op.State = "network"
	if sp.kind == "azure-vm" {
		op.State = "submitted"
	}
	op.PendingResourceKind = sp.kind
	if e = a.s.cloudPersist(op); e != nil {
		return e
	}
	if _, e = a.call(ctx, op.Request, args...); e != nil {
		return fmt.Errorf("Azure %s outcome is unconfirmed; resume to reconcile without repeating it: %w", sp.kind, e)
	}
	m, e = a.find(ctx, *op, sp)
	if e != nil {
		return e
	}
	if e = a.verifyResource(ctx, *op, sp, m, nil); e != nil {
		return e
	}
	return a.record(ctx, op, sp, m)
}
func (a azureAdapter) record(ctx context.Context, op *operation, sp azureSpec, m map[string]any) error {
	res := cloudResource{Kind: sp.kind, ID: sp.id, Name: sp.name, Proof: map[string]string{"operation": op.ID}}
	if sp.kind == "azure-vm" {
		if str(m["vmId"]) == "" {
			return fmt.Errorf("Azure VM lacks immutable vmId")
		}
		res.Proof["vmId"] = str(m["vmId"])
		op.Host.ResourceID = sp.id
		op.Host.Status = str(m["provisioningState"])
	}
	if err := a.s.cloudRecord(op, res); err != nil {
		return err
	}
	return a.finishResource(ctx, op, sp, m)
}

// A failed VM can already own a billable OS disk. Capture the disk while
// the VM relationship is still visible before closing provisioning for cleanup.
func (a azureAdapter) finishResource(ctx context.Context, op *operation, sp azureSpec, m map[string]any) error {
	failure := azureProvisioningFailure(m, sp.kind)
	if failure == nil {
		return nil
	}
	var diskErr error
	if sp.kind == "azure-vm" {
		diskErr = a.recordDisk(ctx, op)
	}
	op.State = "cleanup-required"
	op.Host.Status = "cleanup-required"
	return errors.Join(failure, diskErr, a.s.cloudPersist(op))
}

func azureProvisioningFailure(m map[string]any, kind string) error {
	state := strings.ToLower(str(m["provisioningState"]))
	if state == "failed" || state == "canceled" {
		return fmt.Errorf("Azure %s provisioning failed; its owned resource is recorded for reviewed cleanup", kind)
	}
	return nil
}
func (a azureAdapter) Provision(ctx context.Context, op *operation, allow bool) error {
	if e := a.checkAccount(ctx, *op); e != nil {
		return e
	}
	specs, e := azureSpecs(*op)
	if e != nil {
		return e
	}
	for _, sp := range specs {
		if !allow && cloudResourceOf(op, sp.kind) == nil && op.PendingResourceKind == "" {
			return a.s.cloudPersist(op)
		}
		args := append(append([]string{}, sp.cli...), "create")
		args = append(args, sp.args...)
		if e = a.submit(ctx, op, sp, args, allow); e != nil {
			return e
		}
	}
	r := op.Request
	sp, _ := azureSpecFor(*op, "azure-vm")
	if !allow && cloudResourceOf(op, sp.kind) == nil && op.PendingResourceKind == "" {
		return a.s.cloudPersist(op)
	}
	args := []string{"vm", "create", "--resource-group", azureGroup(*op), "--name", sp.name, "--location", r.Region, "--size", r.Plan, "--image", r.Image, "--admin-username", r.SSHUser, "--authentication-type", "ssh", "--nics", azureID(*op, "azure-nic"), "--os-disk-name", azureBase(*op) + "-os", "--os-disk-size-gb", strconv.Itoa(r.DiskGB), "--storage-sku", "StandardSSD_LRS", "--os-disk-delete-option", "Detach", "--nic-delete-option", "Detach", "--security-type", "Standard", "--tags", "lazyclash-operation=" + op.ID}
	if r.AvailabilityZone != "" {
		args = append(args, "--zone", r.AvailabilityZone)
	}
	if cloudResourceOf(op, "azure-vm") == nil && op.PendingResourceKind == "" && allow {
		key, e := reviewedPublicKey(r)
		if e != nil {
			return e
		}
		args = append(args, "--ssh-key-values", key)
		resolved, q, e := a.Resolve(ctx, r)
		if e != nil {
			return e
		}
		if resolved.Plan != r.Plan || resolved.Image != r.Image || resolved.Architecture != r.Architecture || (op.Quote != nil && q.MonthlyUSD != op.Quote.MonthlyUSD) {
			return fmt.Errorf("Azure launch image, architecture or price changed after review")
		}
	}
	if e = a.submit(ctx, op, sp, args, allow); e != nil {
		return e
	}
	if e = a.recordDisk(ctx, op); e != nil {
		return e
	}
	host, e := a.Observe(ctx, *op)
	if e != nil {
		return e
	}
	op.Host = host
	op.State = "created"
	return a.s.cloudPersist(op)
}
func (a azureAdapter) recordDisk(ctx context.Context, op *operation) error {
	sp, _ := azureSpecFor(*op, "azure-disk")
	m, e := a.find(ctx, *op, sp)
	if e != nil {
		return e
	}
	if m == nil {
		return fmt.Errorf("Azure VM OS disk is not observable; preserve the pending inventory")
	}
	if saved := cloudResourceOf(op, "azure-disk"); saved != nil {
		return a.verifyResource(ctx, *op, sp, m, saved)
	}
	vmsp, _ := azureSpecFor(*op, "azure-vm")
	vm, e := a.find(ctx, *op, vmsp)
	if e != nil {
		return e
	}
	if e = a.verifyResource(ctx, *op, vmsp, vm, cloudResourceOf(op, "azure-vm")); e != nil {
		return e
	}
	disk := obj(obj(vm["storageProfile"])["osDisk"])
	if !strings.EqualFold(str(obj(disk["managedDisk"])["id"]), sp.id) || !strings.EqualFold(str(m["managedBy"]), vmsp.id) || str(m["uniqueId"]) == "" {
		return fmt.Errorf("Azure OS disk relationship is not provable; retain it for inspection")
	}
	return a.s.cloudRecord(op, cloudResource{Kind: sp.kind, ID: sp.id, Name: sp.name, Proof: map[string]string{"uniqueId": str(m["uniqueId"]), "vm": vmsp.id}})
}
func (a azureAdapter) Observe(ctx context.Context, op operation) (serverstate.Host, error) {
	h := op.Host
	if e := a.checkAccount(ctx, op); e != nil {
		return h, e
	}
	if h.ResourceID == "" {
		return h, nil
	}
	sp, _ := azureSpecFor(op, "azure-vm")
	m, e := a.find(ctx, op, sp)
	if e != nil {
		return h, e
	}
	if m == nil {
		h.Status = "cleanup-required"
		return h, nil
	}
	if e = a.verifyResource(ctx, op, sp, m, cloudResourceOf(&op, "azure-vm")); e != nil {
		return h, e
	}
	if azureProvisioningFailure(m, sp.kind) != nil {
		h.Status = "cleanup-required"
		return h, nil
	}
	h.Status = str(m["provisioningState"])
	v, e := a.call(ctx, op.Request, "vm", "get-instance-view", "--ids", sp.id)
	if e != nil {
		return h, e
	}
	statuses := arr(obj(v)["statuses"])
	if len(statuses) == 0 {
		statuses = arr(obj(obj(v)["instanceView"])["statuses"])
	}
	for _, entry := range statuses {
		code := str(obj(entry)["code"])
		if strings.HasPrefix(code, "PowerState/") {
			h.Status = strings.TrimPrefix(code, "PowerState/")
		}
	}
	ipsp, _ := azureSpecFor(op, "azure-ip")
	ip, e := a.find(ctx, op, ipsp)
	if e != nil {
		return h, e
	}
	if e = a.verifyResource(ctx, op, ipsp, ip, cloudResourceOf(&op, "azure-ip")); e != nil {
		return h, e
	}
	addr := str(ip["ipAddress"])
	parsed := net.ParseIP(addr)
	if parsed != nil && parsed.To4() != nil {
		h.PublicHost = addr
		h.SSHHost = op.Request.SSHUser + "@" + addr
	}
	return h, nil
}

func (a azureAdapter) ValidateAction(ctx context.Context, op operation, action string) error {
	if e := a.checkAccount(ctx, op); e != nil {
		return e
	}
	if op.PendingResourceKind != "" {
		return fmt.Errorf("Azure resource creation is unconfirmed; reconcile before a lifecycle action")
	}
	if action != "delete" {
		sp, _ := azureSpecFor(op, "azure-vm")
		m, e := a.find(ctx, op, sp)
		if e != nil {
			return e
		}
		return a.verifyResource(ctx, op, sp, m, cloudResourceOf(&op, "azure-vm"))
	}
	for _, r := range op.CloudResources {
		if r.Deleted {
			continue
		}
		sp, e := azureSpecFor(op, r.Kind)
		if e != nil {
			return e
		}
		m, e := a.find(ctx, op, sp)
		if e != nil {
			return e
		}
		if m == nil {
			continue
		}
		if e = a.verifyResource(ctx, op, sp, m, &r); e != nil {
			return e
		}
		switch r.Kind {
		case "azure-vm":
			storage := obj(m["storageProfile"])
			disk := obj(storage["osDisk"])
			if len(arr(storage["dataDisks"])) > 0 || !strings.EqualFold(str(disk["deleteOption"]), "Detach") {
				return fmt.Errorf("Azure VM disks or deletion policy changed; foreign disks are retained")
			}
			nics := arr(obj(m["networkProfile"])["networkInterfaces"])
			if len(nics) != 1 || !strings.EqualFold(str(obj(nics[0])["id"]), azureID(op, "azure-nic")) || !strings.EqualFold(str(obj(nics[0])["deleteOption"]), "Detach") {
				return fmt.Errorf("Azure VM NIC relationships or deletion policy changed")
			}
		case "azure-vnet":
			for _, x := range arr(m["subnets"]) {
				if !strings.EqualFold(str(obj(x)["id"]), azureID(op, "azure-subnet")) {
					return fmt.Errorf("Azure VNet contains a foreign subnet; retain the network")
				}
			}
			if len(arr(m["virtualNetworkPeerings"])) > 0 {
				return fmt.Errorf("Azure VNet contains foreign peerings; retain the network")
			}
		case "azure-nsg":
			for _, x := range arr(m["securityRules"]) {
				id := str(obj(x)["id"])
				if !strings.EqualFold(id, azureID(op, "azure-nsg-ssh")) && !strings.EqualFold(id, azureID(op, "azure-nsg-web")) && !strings.EqualFold(id, azureID(op, "azure-nsg-udp")) {
					return fmt.Errorf("Azure NSG contains a foreign rule; retain the firewall")
				}
			}
		}
	}
	group, _ := azureSpecFor(op, "azure-group")
	g, e := a.find(ctx, op, group)
	if e != nil {
		return e
	}
	if g == nil {
		return nil
	}
	v, e := a.call(ctx, op.Request, "resource", "list", "--resource-group", azureGroup(op))
	if e != nil {
		return e
	}
	rows, e := strictItems(v)
	if e != nil {
		return e
	}
	for _, m := range rows {
		found := false
		for _, r := range op.CloudResources {
			if !r.Deleted && strings.EqualFold(r.ID, str(m["id"])) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Azure resource group contains an unrecorded resource; retain it and review ownership before deletion")
		}
	}
	return nil
}
func (a azureAdapter) Action(ctx context.Context, op *operation, action string) error {
	if e := a.ValidateAction(ctx, *op, action); e != nil {
		return e
	}
	if action != "delete" {
		verb := map[string]string{"start": "start", "stop": "deallocate", "reboot": "restart"}[action]
		if verb == "" {
			return fmt.Errorf("unsupported Azure action %q", action)
		}
		_, e := a.call(ctx, op.Request, "vm", verb, "--ids", op.Host.ResourceID)
		if e != nil {
			return e
		}
		op.Host.Status = action + "-requested"
		return a.s.cloudPersist(op)
	}
	op.State = "delete-submitted"
	op.Host.Status = "delete-pending"
	if e := a.s.cloudPersist(op); e != nil {
		return e
	}
	// Never use group delete: it recursively removes unrecorded resources.
	order := []string{"azure-vm", "azure-disk", "azure-nic", "azure-ip", "azure-subnet", "azure-nsg-udp", "azure-nsg-web", "azure-nsg-ssh", "azure-nsg", "azure-vnet", "azure-group"}
	for _, kind := range order {
		r := cloudResourceOf(op, kind)
		if r == nil || r.Deleted {
			continue
		}
		sp, _ := azureSpecFor(*op, kind)
		m, e := a.find(ctx, *op, sp)
		if e != nil {
			return a.cleanupError(op, e)
		}
		if m == nil {
			r.Deleted = true
			removeFirewallResource(&op.Host, kind, r.ID)
			if e = a.s.cloudPersist(op); e != nil {
				return e
			}
			continue
		}
		if e = a.verifyResource(ctx, *op, sp, m, r); e != nil {
			return a.cleanupError(op, e)
		}
		if e = a.checkAccount(ctx, *op); e != nil {
			return a.cleanupError(op, e)
		}
		args := append(append([]string{}, sp.cli...), "delete", "--ids", sp.id)
		if kind == "azure-group" {
			v, e := a.call(ctx, op.Request, "resource", "list", "--resource-group", azureGroup(*op))
			if e != nil {
				return a.cleanupError(op, e)
			}
			rows, e := strictItems(v)
			if e != nil || len(rows) > 0 {
				return a.cleanupError(op, fmt.Errorf("Azure resource group is not confirmed empty; retain it"))
			}
			args = []string{"group", "delete", "--name", azureGroup(*op), "--yes"}
		} else if kind == "azure-vm" || kind == "azure-disk" {
			args = append(args, "--yes")
		}
		if _, e = a.call(ctx, op.Request, args...); e != nil {
			return a.cleanupError(op, fmt.Errorf("Azure %s delete outcome is unconfirmed; review deletion to reconcile: %w", kind, e))
		}
		live, e := a.find(ctx, *op, sp)
		if e != nil || live != nil {
			if e == nil {
				e = fmt.Errorf("Azure %s deletion is still pending", kind)
			}
			return a.cleanupError(op, e)
		}
		r.Deleted = true
		removeFirewallResource(&op.Host, kind, r.ID)
		if e = a.s.cloudPersist(op); e != nil {
			return e
		}
	}
	op.State = "deleted"
	op.Host.Status = "deleted"
	op.Host.Owned = false
	return a.s.cloudPersist(op)
}
func (a azureAdapter) cleanupError(op *operation, e error) error {
	op.Host.Status = "cleanup-required"
	_ = a.s.cloudPersist(op)
	return fmt.Errorf("Azure cleanup incomplete; retained disks or IPv4 may still bill: %w", e)
}
