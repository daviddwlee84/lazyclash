package vps

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

var oracleNetworkKinds = []string{"vcn", "internet-gateway", "route-table", "security-list", "subnet"}

func oracleResourceKind(kind string) string {
	if kind == "internet-gateway" {
		return "oracle-igw"
	}
	return "oracle-" + kind
}

func networkID(host serverstate.Host, kind string) string {
	for _, r := range host.Resources {
		if r.Kind == oracleResourceKind(kind) && r.Owned {
			return r.ID
		}
	}
	return ""
}

func appendNetworkResource(host *serverstate.Host, kind, id string, owned bool) {
	for _, r := range host.Resources {
		if r.Kind == oracleResourceKind(kind) && r.ID == id {
			return
		}
	}
	host.Resources = append(host.Resources, serverstate.Resource{Kind: oracleResourceKind(kind), ID: id, Owned: owned})
}

func jsonValue(v any) string { b, _ := json.Marshal(v); return string(b) }

func oracleNetworkRows(v any) ([]map[string]any, error) {
	if _, ok := obj(v)["data"].([]any); !ok {
		return nil, fmt.Errorf("Oracle network inventory response is incomplete; no absence or cleanup can be confirmed")
	}
	return items(v, "data"), nil
}

// prepareOracleNetwork creates only the network included in the reviewed plan.
// Every returned ID is durable before the next resource is attempted. It never
// touches a supplied subnet or creates a metered NAT gateway/load balancer.
func (s *Service) prepareOracleNetwork(ctx context.Context, op *operation) error {
	if op.Request.Provider != "oracle" {
		return nil
	}
	if op.Request.SubnetID != "" {
		if networkID(op.Host, "subnet") == "" {
			appendNetworkResource(&op.Host, "subnet", op.Request.SubnetID, false)
		}
		return s.persistOracleNetwork(op)
	}
	for _, kind := range oracleNetworkKinds {
		if networkID(op.Host, kind) != "" {
			continue
		}
		// A prior unresolved write can only be reconciled, never repeated.
		if op.PendingResourceKind != "" {
			return fmt.Errorf("Oracle network write %s is unconfirmed; reconcile with vps resume first", op.PendingResourceKind)
		}
		args, err := oracleNetworkCreateArgs(*op, kind)
		if err != nil {
			return err
		}
		op.State = "network"
		op.PendingResourceKind = oracleResourceKind(kind)
		if err = s.persistOracleNetwork(op); err != nil {
			return err
		}
		value, err := s.call(ctx, op.Request, args...)
		if err != nil {
			return fmt.Errorf("Oracle %s creation outcome is unknown; run vps resume %s: %w", kind, op.Request.ID, err)
		}
		resource, err := one(value, "data")
		if err != nil {
			return err
		}
		id := str(resource["id"])
		if id == "" {
			return fmt.Errorf("Oracle %s response lacks its ID; reconcile before retrying", kind)
		}
		appendNetworkResource(&op.Host, kind, id, true)
		op.PendingResourceKind = ""
		if kind == "subnet" {
			op.Request.SubnetID = id
		}
		if err = s.persistOracleNetwork(op); err != nil {
			return fmt.Errorf("Oracle %s %s exists; reconcile its saved operation before continuing: %w", kind, id, err)
		}
	}
	return nil
}

func oracleNetworkCreateArgs(op operation, kind string) ([]string, error) {
	r := op.Request
	args := []string{"network", kind, "create", "--compartment-id", r.CompartmentID, "--display-name", "lazyclash-" + r.ID + "-" + kind, "--freeform-tags", jsonValue(map[string]string{"lazyclash-operation": op.ID})}
	vcn := networkID(op.Host, "vcn")
	if kind != "vcn" {
		if vcn == "" {
			return nil, fmt.Errorf("Oracle network requires its saved VCN")
		}
		args = append(args, "--vcn-id", vcn)
	}
	switch kind {
	case "vcn":
		args = append(args, "--cidr-blocks", `["10.208.0.0/16"]`)
	case "internet-gateway":
		args = append(args, "--is-enabled", "true")
	case "route-table":
		gateway := networkID(op.Host, "internet-gateway")
		if gateway == "" {
			return nil, fmt.Errorf("Oracle route table requires its saved internet gateway")
		}
		args = append(args, "--route-rules", jsonValue([]any{map[string]any{"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK", "networkEntityId": gateway}}))
	case "security-list":
		source := r.SSHCIDR
		if source == "" {
			source = "0.0.0.0/0"
		}
		ingress := []any{}
		for _, entry := range []struct {
			port             int
			protocol, source string
		}{{22, "6", source}, {80, "6", "0.0.0.0/0"}, {443, "6", "0.0.0.0/0"}, {443, "17", "0.0.0.0/0"}} {
			options := "tcpOptions"
			if entry.protocol == "17" {
				options = "udpOptions"
			}
			ingress = append(ingress, map[string]any{"protocol": entry.protocol, "source": entry.source, "sourceType": "CIDR_BLOCK", "isStateless": false, options: map[string]any{"destinationPortRange": map[string]int{"min": entry.port, "max": entry.port}}})
		}
		args = append(args, "--ingress-security-rules", jsonValue(ingress), "--egress-security-rules", `[{"protocol":"all","destination":"0.0.0.0/0","destinationType":"CIDR_BLOCK","isStateless":false}]`)
	case "subnet":
		route, security := networkID(op.Host, "route-table"), networkID(op.Host, "security-list")
		if route == "" || security == "" {
			return nil, fmt.Errorf("Oracle subnet requires saved routing and security resources")
		}
		args = append(args, "--cidr-block", "10.208.1.0/24", "--route-table-id", route, "--security-list-ids", jsonValue([]string{security}), "--prohibit-public-ip-on-vnic", "false")
	default:
		return nil, fmt.Errorf("unknown Oracle network resource")
	}
	return append(args, "--wait-for-state", "AVAILABLE", "--max-wait-seconds", "120", "--wait-interval-seconds", "2"), nil
}

func (s *Service) persistOracleNetwork(op *operation) error {
	if err := s.writeOperation(*op); err != nil {
		return err
	}
	return s.saveHost(op.Host)
}

// resumeOracleNetwork is observation only. It locates the exact operation tag;
// a missing or ambiguous result never authorizes another create request.
func (s *Service) resumeOracleNetwork(ctx context.Context, op *operation) error {
	if op.Request.Provider != "oracle" {
		return nil
	}
	for _, kind := range oracleNetworkKinds {
		if networkID(op.Host, kind) != "" {
			continue
		}
		if op.PendingResourceKind != oracleResourceKind(kind) {
			continue
		}
		value, err := s.call(ctx, op.Request, "network", kind, "list", "--compartment-id", op.Request.CompartmentID, "--all")
		if err != nil {
			return err
		}
		rows, err := oracleNetworkRows(value)
		if err != nil {
			return err
		}
		var matches []map[string]any
		for _, row := range rows {
			if str(row["lifecycle-state"]) == "TERMINATED" {
				continue
			}
			if str(obj(row["freeform-tags"])["lazyclash-operation"]) == op.ID {
				matches = append(matches, row)
			}
		}
		if len(matches) != 1 || str(matches[0]["id"]) == "" {
			return fmt.Errorf("Oracle %s reconciliation found %d matches; outcome remains unconfirmed and no resource was recreated", kind, len(matches))
		}
		row := matches[0]
		if kind != "vcn" && str(row["vcn-id"]) != networkID(op.Host, "vcn") {
			return fmt.Errorf("Oracle resource belongs to a different VCN; refusing to adopt it")
		}
		appendNetworkResource(&op.Host, kind, str(row["id"]), true)
		op.PendingResourceKind = ""
		if kind == "subnet" {
			op.Request.SubnetID = str(row["id"])
		}
		return s.persistOracleNetwork(op)
	}
	return nil
}

// cleanupOracleNetwork is invoked only by an explicit reviewed delete. Shared
// resources are skipped, and live operation tags must still match before each
// deletion. OCI itself rejects parents still used by unrelated resources.
func (s *Service) cleanupOracleNetwork(ctx context.Context, host serverstate.Host) error {
	if host.Provider != "oracle" {
		return nil
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		return err
	}
	for n := len(oracleNetworkKinds) - 1; n >= 0; n-- {
		kind := oracleNetworkKinds[n]
		id := networkID(host, kind)
		if id == "" {
			continue
		}
		value, err := s.call(ctx, op.Request, "network", kind, "list", "--compartment-id", op.Request.CompartmentID, "--all")
		if err != nil {
			return err
		}
		rows, err := oracleNetworkRows(value)
		if err != nil {
			return err
		}
		var live map[string]any
		for _, row := range rows {
			if str(row["id"]) == id && str(row["lifecycle-state"]) != "TERMINATED" {
				live = row
				break
			}
		}
		if live == nil {
			continue
		}
		if str(obj(live["freeform-tags"])["lazyclash-operation"]) != host.OperationID {
			return fmt.Errorf("Oracle %s ownership changed; resource retained", kind)
		}
		flag := "--" + kind + "-id"
		_, err = s.call(ctx, op.Request, "network", kind, "delete", flag, id, "--force", "--wait-for-state", "TERMINATED", "--max-wait-seconds", "120", "--wait-interval-seconds", "2")
		if err != nil {
			return fmt.Errorf("Oracle %s cleanup is incomplete; retain the operation and inspect before retrying: %w", kind, err)
		}
	}
	return nil
}

func hasOracleNetwork(host serverstate.Host) bool {
	for _, r := range host.Resources {
		if r.Owned && strings.HasPrefix(r.Kind, "oracle-") {
			return true
		}
	}
	return false
}
