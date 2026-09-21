package vps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type lightsailOperationReceipt struct{ ID, Type, Resource string }
type lightsailFailedOperation struct{ Kind string }

func (e lightsailFailedOperation) Error() string { return "Lightsail " + e.Kind + " failed" }

type lightsailPort struct {
	From     int      `json:"fromPort"`
	To       int      `json:"toPort"`
	Protocol string   `json:"protocol"`
	CIDRs    []string `json:"cidrs"`
	IPv6     []string `json:"ipv6Cidrs,omitempty"`
	Aliases  []string `json:"cidrListAliases,omitempty"`
}

func lightsailName(op *operation, kind string) string {
	if kind == "lightsail-ip" {
		return op.ID + "-ip"
	}
	return op.ID
}
func lightsailTag(row map[string]any, key string) string {
	for _, raw := range arr(row["tags"]) {
		m := obj(raw)
		if str(m["key"]) == key {
			return str(m["value"])
		}
	}
	return ""
}
func lightsailTimestamp(v any) (time.Time, error) {
	if value, ok := v.(float64); ok {
		seconds := int64(value)
		return time.Unix(seconds, int64((value-float64(seconds))*1e9)).UTC(), nil
	}
	if s := str(v); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC(), nil
		}
		if seconds, err := strconv.ParseFloat(s, 64); err == nil {
			return lightsailTimestamp(seconds)
		}
	}
	return time.Time{}, fmt.Errorf("Lightsail resource lacks a valid creation timestamp")
}
func lightsailARNMatches(op *operation, arn, kind string) bool {
	p := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || p[0] != "arn" || p[1] != "aws" || p[2] != "lightsail" || p[3] != op.Request.Region || "aws:"+digest([]string{"aws", p[4]}) != op.AccountID {
		return false
	}
	want := "instance/"
	if kind == "lightsail-ip" {
		want = "staticip/"
	}
	return strings.HasPrefix(strings.ToLower(p[5]), want) && len(p[5]) > len(want)
}
func (a lightsailAdapter) find(ctx context.Context, op *operation, kind string) (map[string]any, error) {
	action, key := "get-instances", "instances"
	if kind == "lightsail-ip" {
		action, key = "get-static-ips", "staticIps"
	} else if kind != "instance" {
		return nil, fmt.Errorf("unsupported Lightsail resource")
	}
	rows, err := a.rows(ctx, op.Request, action, key, nil)
	if err != nil {
		return nil, err
	}
	var found map[string]any
	receipt := cloudResourceOf(op, kind)
	for _, row := range rows {
		if str(row["name"]) != lightsailName(op, kind) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("Lightsail resource name is ambiguous")
		}
		arn := str(row["arn"])
		created, err := lightsailTimestamp(row["createdAt"])
		if err != nil {
			return nil, err
		}
		if !lightsailARNMatches(op, arn, kind) || str(obj(row["location"])["regionName"]) != op.Request.Region {
			return nil, fmt.Errorf("Lightsail resource belongs to a different account, region or resource type")
		}
		if receipt != nil {
			if receipt.Deleted || receipt.ID != arn || receipt.Name != str(row["name"]) || receipt.Proof["created_at"] != created.Format(time.RFC3339Nano) || receipt.Proof["account"] != op.AccountID || receipt.Proof["region"] != op.Request.Region {
				return nil, fmt.Errorf("Lightsail resource identity changed; preserve the foreign resource")
			}
		} else {
			if op.PendingResourceKind != kind {
				return nil, fmt.Errorf("Lightsail resource has no matching saved create intent")
			}
			if op.CreatedAt.IsZero() || created.Before(op.CreatedAt.Add(-2*time.Minute)) || created.After(a.s.options.Now().Add(2*time.Minute)) {
				return nil, fmt.Errorf("Lightsail resource predates its allocation intent or has an invalid creation time")
			}
		}
		if kind == "instance" {
			if lightsailTag(row, "lazyclash-operation") != op.ID || lightsailTag(row, "lazyclash-spec") != digest(op.Request) || str(row["blueprintId"]) != op.Request.Image || str(row["bundleId"]) != op.Request.Plan || str(obj(row["location"])["availabilityZone"]) != op.Request.AvailabilityZone {
				return nil, fmt.Errorf("Lightsail instance ownership or reviewed configuration changed")
			}
		}
		found = row
	}
	return found, nil
}
func (a lightsailAdapter) record(op *operation, kind string, row map[string]any) error {
	created, err := lightsailTimestamp(row["createdAt"])
	if err != nil {
		return err
	}
	if kind == "instance" {
		op.Host.ResourceID = str(row["arn"])
	}
	return a.s.cloudRecord(op, cloudResource{Kind: kind, ID: str(row["arn"]), Name: str(row["name"]), Proof: map[string]string{"created_at": created.Format(time.RFC3339Nano), "account": op.AccountID, "region": op.Request.Region}})
}
func (a lightsailAdapter) clearPending(op *operation) error {
	op.PendingResourceKind = ""
	delete(op.PrivateData, "lightsail_pending_ops")
	return a.s.cloudPersist(op)
}
func lightsailOperationType(kind string) string {
	return map[string]string{"instance": "CreateInstance", "lightsail-ip": "AllocateStaticIp", "lightsail-attach": "AttachStaticIp", "lightsail-ports": "PutInstancePublicPorts", "lightsail-delete-instance": "DeleteInstance", "lightsail-release-ip": "ReleaseStaticIp", "lightsail-start": "StartInstance", "lightsail-stop": "StopInstance", "lightsail-reboot": "RebootInstance"}[kind]
}
func (a lightsailAdapter) write(ctx context.Context, op *operation, kind string, args ...string) error {
	if op.PendingResourceKind != "" {
		return fmt.Errorf("Lightsail pending write must be reconciled before another mutation")
	}
	if err := a.s.cloudVerifyAccount(ctx, *op); err != nil {
		return err
	}
	if op.PrivateData == nil {
		op.PrivateData = map[string]json.RawMessage{}
	}
	op.PendingResourceKind = kind
	delete(op.PrivateData, "lightsail_pending_ops")
	if err := a.s.cloudPersist(op); err != nil {
		return err
	}
	v, err := a.s.call(ctx, op.Request, append([]string{"lightsail"}, args...)...)
	if err != nil {
		return fmt.Errorf("Lightsail %s result is unconfirmed; reconcile before retrying: %w", kind, err)
	}
	var ops []map[string]any
	if one := obj(obj(v)["operation"]); one != nil {
		ops = append(ops, one)
	} else {
		ops, err = strictItems(v, "operations")
		if err != nil {
			return err
		}
	}
	var receipts []lightsailOperationReceipt
	for _, item := range ops {
		id, typ, resource := str(item["id"]), str(item["operationType"]), str(item["resourceName"])
		if id == "" || strings.ContainsAny(id, "\x00\r\n") || typ != lightsailOperationType(kind) || (resource != op.ID && resource != op.ID+"-ip") {
			return fmt.Errorf("Lightsail returned an unexpected operation receipt")
		}
		receipts = append(receipts, lightsailOperationReceipt{ID: id, Type: typ, Resource: resource})
	}
	if len(receipts) == 0 {
		return fmt.Errorf("Lightsail did not return an operation receipt; outcome is unconfirmed")
	}
	op.PrivateData["lightsail_pending_ops"], _ = json.Marshal(receipts)
	if err = a.s.cloudPersist(op); err != nil {
		return err
	}
	return a.pending(ctx, op)
}
func (a lightsailAdapter) waitOperations(ctx context.Context, op *operation) error {
	var receipts []lightsailOperationReceipt
	if raw := op.PrivateData["lightsail_pending_ops"]; len(raw) > 0 {
		if json.Unmarshal(raw, &receipts) != nil {
			return fmt.Errorf("invalid saved Lightsail operation receipt")
		}
	}
	if len(receipts) == 0 {
		return nil
	} // A lost response is reconciled from resource identity below.
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var failed *lightsailFailedOperation
	for _, saved := range receipts {
		for {
			v, err := a.s.call(waitCtx, op.Request, "lightsail", "get-operation", "--operation-id", saved.ID)
			if err != nil {
				return err
			}
			m := obj(obj(v)["operation"])
			if str(m["id"]) != saved.ID || str(m["resourceName"]) != saved.Resource || str(m["operationType"]) != saved.Type || saved.Type != lightsailOperationType(op.PendingResourceKind) {
				return fmt.Errorf("Lightsail operation identity changed")
			}
			switch str(m["status"]) {
			case "Succeeded", "Completed":
				if !truth(m["isTerminal"]) {
					return fmt.Errorf("Lightsail operation success is not terminal")
				}
			case "Failed":
				if !truth(m["isTerminal"]) {
					return fmt.Errorf("Lightsail failure is not terminal; outcome remains pending")
				}
				failed = &lightsailFailedOperation{Kind: op.PendingResourceKind}
			case "Started", "NotStarted":
				timer := time.NewTimer(500 * time.Millisecond)
				select {
				case <-waitCtx.Done():
					timer.Stop()
					return fmt.Errorf("Lightsail operation is still pending: %w", waitCtx.Err())
				case <-timer.C:
				}
				continue
			default:
				return fmt.Errorf("Lightsail returned an unknown operation status")
			}
			break
		}
	}
	if failed != nil {
		return *failed
	}
	return nil
}
func (a lightsailAdapter) pending(ctx context.Context, op *operation) error {
	kind := op.PendingResourceKind
	if kind == "" {
		return nil
	}
	if err := a.waitOperations(ctx, op); err != nil {
		var failed lightsailFailedOperation
		if errors.As(err, &failed) {
			return a.reconcileFailed(ctx, op, failed.Kind)
		}
		return err
	}
	switch kind {
	case "instance", "lightsail-ip":
		row, err := a.find(ctx, op, kind)
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("Lightsail %s creation is not observed; do not repeat an ambiguous create", kind)
		}
		if err = a.record(op, kind, row); err != nil {
			return err
		}
	case "lightsail-attach":
		row, err := a.find(ctx, op, "lightsail-ip")
		if err != nil {
			return err
		}
		if row == nil || !truth(row["isAttached"]) || str(row["attachedTo"]) != op.ID {
			return fmt.Errorf("Lightsail static IP attachment remains unconfirmed")
		}
	case "lightsail-ports":
		ports, err := a.ports(ctx, op)
		if err != nil {
			return err
		}
		if digest(ports) != digest(lightsailDesiredPorts(op.Request)) {
			return fmt.Errorf("Lightsail firewall result differs from the reviewed rules; no overwrite attempted")
		}
		op.PrivateData["lightsail_ports_applied"], _ = json.Marshal(ports)
	case "lightsail-delete-instance", "lightsail-release-ip":
		resourceKind := "instance"
		if kind == "lightsail-release-ip" {
			resourceKind = "lightsail-ip"
		}
		row, err := a.find(ctx, op, resourceKind)
		if err != nil {
			return err
		}
		if row != nil {
			return fmt.Errorf("Lightsail deletion remains unconfirmed; retained resource may still bill")
		}
		if receipt := cloudResourceOf(op, resourceKind); receipt != nil {
			receipt.Deleted = true
			removeFirewallResource(&op.Host, resourceKind, receipt.ID)
		}
	case "lightsail-start", "lightsail-stop", "lightsail-reboot":
		if kind == "lightsail-reboot" && len(op.PrivateData["lightsail_pending_ops"]) == 0 {
			return fmt.Errorf("Lightsail reboot has no operation receipt; do not repeat an ambiguous reboot")
		}
		row, err := a.find(ctx, op, "instance")
		if err != nil {
			return err
		}
		want := "running"
		if kind == "lightsail-stop" {
			want = "stopped"
		}
		if row == nil || str(obj(row["state"])["name"]) != want {
			return fmt.Errorf("Lightsail power transition remains pending")
		}
		op.Host.Status = want
	default:
		return fmt.Errorf("unknown saved Lightsail pending phase")
	}
	return a.clearPending(op)
}

// A terminal provider failure does not strand already billable resources. Read
// their identities back, retain any partial effects, and allow reviewed cleanup.
// No failed create is automatically retried.
func (a lightsailAdapter) reconcileFailed(ctx context.Context, op *operation, kind string) error {
	cleanup := kind == "instance" || kind == "lightsail-ip" || kind == "lightsail-attach" || kind == "lightsail-ports"
	if cleanup {
		op.State = "cleanup-required"
		op.Host.Status = "cleanup-required"
	}
	if kind == "instance" || kind == "lightsail-ip" {
		row, err := a.find(ctx, op, kind)
		if err != nil {
			return err
		}
		if row != nil {
			if err = a.record(op, kind, row); err != nil {
				return err
			}
		}
	}
	if kind == "lightsail-delete-instance" || kind == "lightsail-release-ip" {
		resourceKind := "instance"
		if kind == "lightsail-release-ip" {
			resourceKind = "lightsail-ip"
		}
		row, err := a.find(ctx, op, resourceKind)
		if err != nil {
			return err
		}
		if row == nil {
			if r := cloudResourceOf(op, resourceKind); r != nil {
				r.Deleted = true
				removeFirewallResource(&op.Host, resourceKind, r.ID)
			}
		}
		op.State = "delete-pending"
		op.Host.Status = "cleanup-required"
	}
	if err := a.clearPending(op); err != nil {
		return err
	}
	if cleanup {
		return fmt.Errorf("Lightsail %s failed; partial resources are recorded for vps delete", kind)
	}
	return fmt.Errorf("Lightsail %s failed; inspect a fresh lifecycle preview before retrying", kind)
}

func lightsailDesiredPorts(r CreateRequest) []lightsailPort {
	return []lightsailPort{{From: 22, To: 22, Protocol: "tcp", CIDRs: []string{r.SSHCIDR}}, {From: 80, To: 80, Protocol: "tcp", CIDRs: []string{"0.0.0.0/0"}}, {From: 443, To: 443, Protocol: "tcp", CIDRs: []string{"0.0.0.0/0"}}, {From: 443, To: 443, Protocol: "udp", CIDRs: []string{"0.0.0.0/0"}}}
}
func lightsailStrings(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("invalid Lightsail firewall source list")
	}
	var values []string
	for _, raw := range items {
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid Lightsail firewall source")
		}
		values = append(values, s)
	}
	sort.Strings(values)
	return values, nil
}
func (a lightsailAdapter) ports(ctx context.Context, op *operation) ([]lightsailPort, error) {
	v, err := a.s.call(ctx, op.Request, "lightsail", "get-instance-port-states", "--instance-name", op.ID)
	if err != nil {
		return nil, err
	}
	rows, err := strictItems(v, "portStates")
	if err != nil {
		return nil, err
	}
	ports := []lightsailPort{}
	for _, m := range rows {
		if str(m["state"]) != "open" {
			return nil, fmt.Errorf("Lightsail returned an unknown firewall state")
		}
		p := lightsailPort{From: int(num(m["fromPort"])), To: int(num(m["toPort"])), Protocol: str(m["protocol"])}
		if p.CIDRs, err = lightsailStrings(m["cidrs"]); err != nil {
			return nil, err
		}
		if p.IPv6, err = lightsailStrings(m["ipv6Cidrs"]); err != nil {
			return nil, err
		}
		if p.Aliases, err = lightsailStrings(m["cidrListAliases"]); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		x, y := ports[i], ports[j]
		if x.From != y.From {
			return x.From < y.From
		}
		if x.To != y.To {
			return x.To < y.To
		}
		return lightsailJSON(x) < lightsailJSON(y)
	})
	return ports, nil
}
func lightsailDefaultPorts(ports []lightsailPort) bool {
	// AWS Ubuntu/base OS blueprints open SSH and HTTP by default:
	// https://docs.aws.amazon.com/lightsail/latest/userguide/understanding-firewall-and-port-mappings-in-amazon-lightsail.html
	seen := map[int]bool{}
	for _, p := range ports {
		if p.Protocol != "tcp" || (p.From != 22 && p.From != 80) || p.To != p.From || seen[p.From] || len(p.CIDRs) != 1 || p.CIDRs[0] != "0.0.0.0/0" || len(p.IPv6) > 1 || (len(p.IPv6) == 1 && p.IPv6[0] != "::/0") || len(p.Aliases) > 0 {
			return false
		}
		seen[p.From] = true
	}
	return len(ports) <= 2
}
func (a lightsailAdapter) snapshotPorts(ctx context.Context, op *operation) error {
	if len(op.PrivateData["lightsail_ports_before"]) > 0 {
		return nil
	}
	ports, err := a.ports(ctx, op)
	if err != nil {
		return err
	}
	if !lightsailDefaultPorts(ports) {
		return fmt.Errorf("Lightsail instance has non-default firewall rules; preserve them for explicit review")
	}
	if op.PrivateData == nil {
		op.PrivateData = map[string]json.RawMessage{}
	}
	op.PrivateData["lightsail_ports_before"], _ = json.Marshal(ports)
	return a.s.cloudPersist(op)
}

func (a lightsailAdapter) Provision(ctx context.Context, op *operation, writes bool) error {
	if err := a.pending(ctx, op); err != nil {
		return err
	}
	if writes && op.State == "cleanup-required" {
		return fmt.Errorf("Lightsail provisioning failed; use vps delete for reviewed cleanup")
	}
	if !writes {
		h, err := a.Observe(ctx, *op)
		if err != nil {
			return err
		}
		op.Host = h
		return a.s.cloudPersist(op)
	}
	for _, kind := range []string{"instance", "lightsail-ip"} {
		row, err := a.find(ctx, op, kind)
		if err != nil {
			return err
		}
		if receipt := cloudResourceOf(op, kind); receipt != nil {
			if receipt.Deleted || row == nil {
				return fmt.Errorf("saved Lightsail resource is missing; no replacement created")
			}
		} else {
			if row != nil {
				return fmt.Errorf("unowned Lightsail resource blocks create")
			}
			var args []string
			if kind == "instance" {
				resolved, q, err := a.Resolve(ctx, op.Request)
				if err != nil {
					return err
				}
				if digest(resolved) != digest(op.Request) || (op.Quote != nil && digest(q) != digest(*op.Quote)) {
					return fmt.Errorf("Lightsail launch specification or quote changed after review")
				}
				data, err := lightsailUserData(op.Request)
				if err != nil {
					return err
				}
				tags := []map[string]string{{"key": "Name", "value": op.Request.Name}, {"key": "lazyclash-operation", "value": op.ID}, {"key": "lazyclash-spec", "value": digest(op.Request)}}
				args = []string{"create-instances", "--instance-names", op.ID, "--availability-zone", op.Request.AvailabilityZone, "--blueprint-id", op.Request.Image, "--bundle-id", op.Request.Plan, "--ip-address-type", "ipv4", "--user-data", data, "--tags", lightsailJSON(tags)}
			} else {
				args = []string{"allocate-static-ip", "--static-ip-name", lightsailName(op, kind)}
			}
			if err = a.write(ctx, op, kind, args...); err != nil {
				return err
			}
		}
		if kind == "instance" {
			if err = a.snapshotPorts(ctx, op); err != nil {
				return err
			}
		}
	}
	ip, err := a.find(ctx, op, "lightsail-ip")
	if err != nil {
		return err
	}
	if ip == nil {
		return fmt.Errorf("Lightsail static IP is missing")
	}
	if str(ip["attachedTo"]) != "" && str(ip["attachedTo"]) != op.ID {
		return fmt.Errorf("Lightsail static IP is attached to another instance; no changes made")
	}
	if !truth(ip["isAttached"]) {
		instance, err := a.find(ctx, op, "instance")
		if err != nil {
			return err
		}
		if instance == nil || str(obj(instance["state"])["name"]) != "running" {
			return fmt.Errorf("Lightsail instance is not running yet; resume after it becomes ready")
		}
		if err = a.write(ctx, op, "lightsail-attach", "attach-static-ip", "--static-ip-name", lightsailName(op, "lightsail-ip"), "--instance-name", op.ID); err != nil {
			return err
		}
	}
	ports, err := a.ports(ctx, op)
	if err != nil {
		return err
	}
	desired := lightsailDesiredPorts(op.Request)
	if raw := op.PrivateData["lightsail_ports_applied"]; len(raw) > 0 {
		var saved []lightsailPort
		if json.Unmarshal(raw, &saved) != nil || digest(saved) != digest(ports) {
			return fmt.Errorf("Lightsail firewall changed outside lazyclash; no overwrite attempted")
		}
	} else {
		var before []lightsailPort
		if json.Unmarshal(op.PrivateData["lightsail_ports_before"], &before) != nil || digest(before) != digest(ports) {
			return fmt.Errorf("Lightsail firewall changed since its initial snapshot; no overwrite attempted")
		}
		if err = a.write(ctx, op, "lightsail-ports", "put-instance-public-ports", "--instance-name", op.ID, "--port-infos", lightsailJSON(desired)); err != nil {
			return err
		}
	}
	h, err := a.Observe(ctx, *op)
	if err != nil {
		return err
	}
	op.Host = h
	if h.PublicHost == "" {
		return fmt.Errorf("Lightsail static endpoint is not ready")
	}
	op.State = "created"
	return a.s.cloudPersist(op)
}

func (a lightsailAdapter) Observe(ctx context.Context, op operation) (serverstate.Host, error) {
	h := op.Host
	deferCleanup := op.State == "cleanup-required" || op.State == "delete-pending" || op.Host.Status == "cleanup-required"
	if receipt := cloudResourceOf(&op, "instance"); receipt == nil || receipt.Deleted {
		h.Status = "creating"
		if op.State == "deleted" {
			h.Status = "deleted"
		} else if deferCleanup {
			h.Status = "cleanup-required"
		}
		h.PublicHost, h.SSHHost = "", ""
		return h, nil
	}
	instance, err := a.find(ctx, &op, "instance")
	if err != nil {
		return h, err
	}
	if instance == nil {
		h.Status = "missing"
		h.PublicHost = ""
		h.SSHHost = ""
		return h, nil
	}
	h.Status = str(obj(instance["state"])["name"])
	if h.Status == "" {
		h.Status = "unknown"
	}
	if deferCleanup {
		h.Status = "cleanup-required"
	}
	if receipt := cloudResourceOf(&op, "lightsail-ip"); receipt == nil || receipt.Deleted {
		h.PublicHost = ""
		h.SSHHost = ""
		return h, nil
	}
	ip, err := a.find(ctx, &op, "lightsail-ip")
	if err != nil {
		return h, err
	}
	if ip == nil || !truth(ip["isAttached"]) || str(ip["attachedTo"]) != op.ID {
		h.PublicHost = ""
		h.SSHHost = ""
		return h, nil
	}
	address := net.ParseIP(str(ip["ipAddress"]))
	if address == nil || address.To4() == nil {
		return h, fmt.Errorf("Lightsail static IP response lacks an IPv4 endpoint")
	}
	h.PublicHost = address.String()
	h.SSHHost = "ubuntu@" + h.PublicHost
	return h, nil
}

var _ cloudAdapter = lightsailAdapter{}
