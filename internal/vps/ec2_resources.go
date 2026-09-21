package vps

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

func (a ec2Adapter) checkAccount(ctx context.Context, op *operation) error {
	identity, err := a.Identity(ctx, op.Request)
	if err != nil {
		return err
	}
	if identity != op.AccountID {
		return fmt.Errorf("AWS account or partition changed; no further cloud mutation was performed")
	}
	return nil
}

type ec2ResourceSpec struct{ action, collection, id, filter, resourceType string }

var ec2ResourceSpecs = map[string]ec2ResourceSpec{
	"ec2-vpc":            {"describe-vpcs", "Vpcs", "VpcId", "vpc-id", "vpc"},
	"ec2-subnet":         {"describe-subnets", "Subnets", "SubnetId", "subnet-id", "subnet"},
	"ec2-igw":            {"describe-internet-gateways", "InternetGateways", "InternetGatewayId", "internet-gateway-id", "internet-gateway"},
	"ec2-route-table":    {"describe-route-tables", "RouteTables", "RouteTableId", "route-table-id", "route-table"},
	"ec2-security-group": {"describe-security-groups", "SecurityGroups", "GroupId", "group-id", "security-group"},
	"ec2-key-pair":       {"describe-key-pairs", "KeyPairs", "KeyPairId", "key-pair-id", "key-pair"},
	"ec2-address":        {"describe-addresses", "Addresses", "AllocationId", "allocation-id", "elastic-ip"},
	"instance":           {"describe-instances", "Reservations", "InstanceId", "instance-id", "instance"},
	"ec2-volume":         {"describe-volumes", "Volumes", "VolumeId", "volume-id", "volume"},
	"ec2-eni":            {"describe-network-interfaces", "NetworkInterfaces", "NetworkInterfaceId", "network-interface-id", "network-interface"},
}
var ec2CreateOrder = []string{"ec2-vpc", "ec2-subnet", "ec2-igw", "ec2-route-table", "ec2-security-group", "ec2-key-pair", "ec2-address", "instance"}

func ec2RecordedID(op *operation, kind string) string {
	r := cloudResourceOf(op, kind)
	if r == nil {
		return ""
	}
	return r.ID
}
func ec2ID(op *operation, kind string) string {
	r := cloudResourceOf(op, kind)
	if r == nil || r.Deleted {
		return ""
	}
	return r.ID
}
func ec2Tag(row map[string]any, key string) string {
	for _, raw := range arr(row["Tags"]) {
		m := obj(raw)
		if str(m["Key"]) == key {
			return str(m["Value"])
		}
	}
	return ""
}
func ec2Tags(op *operation, kind string) []map[string]string {
	return []map[string]string{{"Key": "Name", "Value": op.Request.Name}, {"Key": "lazyclash-operation", "Value": op.ID}, {"Key": "lazyclash-kind", "Value": kind}}
}
func ec2TagSpec(op *operation, kind string) string {
	return jsonValue([]any{map[string]any{"ResourceType": ec2ResourceSpecs[kind].resourceType, "Tags": ec2Tags(op, kind)}})
}
func ec2HasOwnership(row map[string]any, op *operation, kind string) bool {
	return ec2Tag(row, "lazyclash-operation") == op.ID && ec2Tag(row, "lazyclash-kind") == kind
}
func (a ec2Adapter) list(ctx context.Context, req CreateRequest, kind string, filters []map[string]any) ([]map[string]any, error) {
	spec, ok := ec2ResourceSpecs[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported EC2 resource kind %s", kind)
	}
	args := []string{"ec2", spec.action}
	if len(filters) > 0 {
		args = append(args, "--filters", jsonValue(filters))
	}
	rows, err := a.s.ec2Rows(ctx, req, spec.collection, args...)
	if err != nil {
		return nil, err
	}
	if kind == "instance" {
		var instances []map[string]any
		for _, res := range rows {
			list, err := strictItems(res, "Instances")
			if err != nil {
				return nil, err
			}
			instances = append(instances, list...)
		}
		rows = instances
	}
	for _, r := range rows {
		if str(r[spec.id]) == "" {
			return nil, fmt.Errorf("EC2 %s list contains a resource without identity", kind)
		}
	}
	return rows, nil
}
func (a ec2Adapter) find(ctx context.Context, op *operation, kind string) (map[string]any, error) {
	return a.findWithTerminal(ctx, op, kind, false)
}

// A terminal instance is absent for power operations, but is still evidence
// that an uncertain RunInstances request completed. Recovery must retain that
// evidence so its disk/IP/network resources can be cleaned up.
func (a ec2Adapter) findWithTerminal(ctx context.Context, op *operation, kind string, includeTerminal bool) (map[string]any, error) {
	spec := ec2ResourceSpecs[kind]
	receipt := cloudResourceOf(op, kind)
	filters := []map[string]any{{"Name": "tag:lazyclash-operation", "Values": []string{op.ID}}, {"Name": "tag:lazyclash-kind", "Values": []string{kind}}}
	if receipt != nil {
		filters = []map[string]any{{"Name": spec.filter, "Values": []string{receipt.ID}}}
	}
	rows, err := a.list(ctx, op.Request, kind, filters)
	if err != nil {
		return nil, err
	}
	var found []map[string]any
	for _, row := range rows {
		if receipt != nil && str(row[spec.id]) != receipt.ID {
			continue
		}
		if kind == "instance" && !includeTerminal && str(obj(row["State"])["Name"]) == "terminated" {
			continue
		}
		if !ec2HasOwnership(row, op, kind) {
			return nil, fmt.Errorf("EC2 %s ownership changed; resource retained", kind)
		}
		if receipt != nil && receipt.Deleted {
			return nil, fmt.Errorf("previously deleted EC2 %s unexpectedly exists; refusing to adopt it", kind)
		}
		if err = a.validateResource(op, kind, row); err != nil {
			return nil, err
		}
		found = append(found, row)
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("EC2 reconciliation found %d %s resources for one operation; no create was retried", len(found), kind)
	}
	if len(found) == 0 {
		return nil, nil
	}
	return found[0], nil
}
func (a ec2Adapter) validateResource(op *operation, kind string, row map[string]any) error {
	vpc := ec2ID(op, "ec2-vpc")
	switch kind {
	case "ec2-subnet", "ec2-route-table", "ec2-security-group":
		if vpc != "" && str(row["VpcId"]) != vpc {
			return fmt.Errorf("EC2 %s belongs to another VPC", kind)
		}
	case "instance":
		if str(row["ClientToken"]) != op.ID || str(row["ImageId"]) != op.Request.Image || str(row["InstanceType"]) != op.Request.Plan || str(obj(row["Placement"])["AvailabilityZone"]) != op.Request.AvailabilityZone || str(row["SubnetId"]) != ec2ID(op, "ec2-subnet") {
			return fmt.Errorf("EC2 instance no longer matches its pinned client token, image, type, subnet or Availability Zone")
		}
		if pair := cloudResourceOf(op, "ec2-key-pair"); pair != nil && str(row["KeyName"]) != pair.Name {
			return fmt.Errorf("EC2 instance key identity changed")
		}
	case "ec2-eni":
		if str(row["VpcId"]) != ec2RecordedID(op, "ec2-vpc") || str(row["SubnetId"]) != ec2RecordedID(op, "ec2-subnet") {
			return fmt.Errorf("EC2 network interface belongs to another VPC or subnet")
		}
	case "ec2-volume":
		if str(row["AvailabilityZone"]) != op.Request.AvailabilityZone {
			return fmt.Errorf("EC2 volume belongs to another Availability Zone")
		}
		if receipt := cloudResourceOf(op, kind); receipt != nil && receipt.Proof["availability_zone"] != "" && str(row["AvailabilityZone"]) != receipt.Proof["availability_zone"] {
			return fmt.Errorf("EC2 root volume Availability Zone changed")
		}
	case "ec2-key-pair":
		if receipt := cloudResourceOf(op, kind); receipt != nil && (str(row["KeyName"]) != receipt.Name || str(row["KeyFingerprint"]) != receipt.Proof["fingerprint"]) {
			return fmt.Errorf("EC2 SSH key fingerprint or name changed")
		}
	}
	return nil
}
func (a ec2Adapter) record(ctx context.Context, op *operation, kind string, row map[string]any) error {
	spec := ec2ResourceSpecs[kind]
	id := str(row[spec.id])
	if id == "" {
		return fmt.Errorf("EC2 %s response lacks its resource ID; reconcile before retrying", kind)
	}
	r := cloudResource{Kind: kind, ID: id, Name: str(row["Name"]), Proof: map[string]string{}}
	switch kind {
	case "ec2-key-pair":
		r.Name = str(row["KeyName"])
		r.Proof["fingerprint"] = str(row["KeyFingerprint"])
		if r.Name != op.ID || r.Proof["fingerprint"] == "" {
			return fmt.Errorf("EC2 imported key identity is incomplete")
		}
	case "ec2-subnet":
		r.Proof["vpc"] = str(row["VpcId"])
		r.Proof["availability_zone"] = str(row["AvailabilityZone"])
	case "ec2-volume":
		r.Proof["availability_zone"] = str(row["AvailabilityZone"])
	case "ec2-address":
		r.Proof["public_ip"] = str(row["PublicIp"])
	case "instance":
		op.Host.ResourceID = id
		op.Host.Status = str(obj(row["State"])["Name"])
	}
	return a.s.cloudRecord(op, r)
}
func (a ec2Adapter) pending(ctx context.Context, op *operation) error {
	kind := op.PendingResourceKind
	if kind == "" {
		return nil
	}
	if _, ok := ec2ResourceSpecs[kind]; ok {
		row, err := a.findWithTerminal(ctx, op, kind, kind == "instance")
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("EC2 %s creation remains unconfirmed; no create was retried", kind)
		}
		if kind == "instance" {
			if err = a.validateLaunchRecord(op); err != nil {
				return err
			}
		}
		return a.record(ctx, op, kind, row)
	}
	// Mutations to existing resources are reconciled by observation before they
	// can be considered complete, and never blindly replayed after a timeout.
	done, err := a.linkDone(ctx, op, kind)
	if err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("EC2 %s result remains unconfirmed; no write was retried", kind)
	}
	op.PendingResourceKind = ""
	return a.s.cloudPersist(op)
}
func (a ec2Adapter) createArgs(ctx context.Context, op *operation, kind string) ([]string, string, error) {
	tags := ec2TagSpec(op, kind)
	vpc := ec2ID(op, "ec2-vpc")
	switch kind {
	case "ec2-vpc":
		return []string{"ec2", "create-vpc", "--cidr-block", "10.208.0.0/16", "--tag-specifications", tags}, "Vpc", nil
	case "ec2-subnet":
		return []string{"ec2", "create-subnet", "--vpc-id", vpc, "--cidr-block", "10.208.1.0/24", "--availability-zone", op.Request.AvailabilityZone, "--tag-specifications", tags}, "Subnet", nil
	case "ec2-igw":
		return []string{"ec2", "create-internet-gateway", "--tag-specifications", tags}, "InternetGateway", nil
	case "ec2-route-table":
		return []string{"ec2", "create-route-table", "--vpc-id", vpc, "--tag-specifications", tags}, "RouteTable", nil
	case "ec2-security-group":
		return []string{"ec2", "create-security-group", "--vpc-id", vpc, "--group-name", op.ID, "--description", "lazyclash dedicated proxy ingress", "--tag-specifications", tags}, "", nil
	case "ec2-key-pair":
		key, err := reviewedPublicKey(op.Request)
		if err != nil {
			return nil, "", err
		}
		fields := strings.Fields(key)
		if len(fields) < 2 || (fields[0] != "ssh-ed25519" && fields[0] != "ssh-rsa") {
			return nil, "", fmt.Errorf("EC2 supports RSA or Ed25519 SSH public keys")
		}
		return []string{"ec2", "import-key-pair", "--key-name", op.ID, "--public-key-material", base64.StdEncoding.EncodeToString([]byte(key)), "--cli-binary-format", "base64", "--tag-specifications", tags}, "", nil
	case "ec2-address":
		return []string{"ec2", "allocate-address", "--domain", "vpc", "--tag-specifications", tags}, "", nil
	case "instance":
		body, err := a.launchRecord(ctx, op)
		if err != nil {
			return nil, "", err
		}
		return []string{"ec2", "run-instances", "--cli-input-json", string(body)}, "Instances", nil
	}
	return nil, "", fmt.Errorf("unknown EC2 create kind")
}
func (a ec2Adapter) launchRecord(ctx context.Context, op *operation) (json.RawMessage, error) {
	if raw := op.PrivateData["ec2_run_instances"]; len(raw) > 0 {
		return raw, a.validateLaunchRecord(op)
	}
	img, err := a.image(ctx, op.Request)
	if err != nil {
		return nil, err
	}
	root := str(img["RootDeviceName"])
	key := cloudResourceOf(op, "ec2-key-pair")
	if key == nil {
		return nil, fmt.Errorf("EC2 launch requires saved key-pair receipt")
	}
	body := map[string]any{"ImageId": op.Request.Image, "InstanceType": op.Request.Plan, "MinCount": 1, "MaxCount": 1, "ClientToken": op.ID, "KeyName": key.Name, "Placement": map[string]any{"AvailabilityZone": op.Request.AvailabilityZone, "Tenancy": "default"}, "NetworkInterfaces": []any{map[string]any{"DeviceIndex": 0, "SubnetId": ec2ID(op, "ec2-subnet"), "Groups": []string{ec2ID(op, "ec2-security-group")}, "AssociatePublicIpAddress": false, "DeleteOnTermination": true}}, "MetadataOptions": map[string]any{"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1}, "CreditSpecification": map[string]string{"CpuCredits": "standard"}, "BlockDeviceMappings": []any{map[string]any{"DeviceName": root, "Ebs": map[string]any{"VolumeType": "gp3", "VolumeSize": op.Request.DiskGB, "Encrypted": true, "DeleteOnTermination": true, "Iops": 3000, "Throughput": 125}}}, "TagSpecifications": []any{map[string]any{"ResourceType": "instance", "Tags": ec2Tags(op, "instance")}, map[string]any{"ResourceType": "volume", "Tags": ec2Tags(op, "ec2-volume")}, map[string]any{"ResourceType": "network-interface", "Tags": ec2Tags(op, "ec2-eni")}}}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if op.PrivateData == nil {
		op.PrivateData = map[string]json.RawMessage{}
	}
	op.PrivateData["ec2_run_instances"] = raw
	op.PrivateData["ec2_run_instances_sha256"] = json.RawMessage(jsonValue(digest(body)))
	if err = a.s.cloudPersist(op); err != nil {
		return nil, err
	}
	return raw, nil
}
func (a ec2Adapter) validateLaunchRecord(op *operation) error {
	raw := op.PrivateData["ec2_run_instances"]
	var body map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &body) != nil {
		return fmt.Errorf("EC2 pinned launch request is missing or malformed")
	}
	var saved string
	if json.Unmarshal(op.PrivateData["ec2_run_instances_sha256"], &saved) != nil || digest(body) != saved {
		return fmt.Errorf("EC2 pinned launch request digest changed")
	}
	if str(body["ClientToken"]) != op.ID || str(body["ImageId"]) != op.Request.Image || str(body["InstanceType"]) != op.Request.Plan || str(obj(body["Placement"])["AvailabilityZone"]) != op.Request.AvailabilityZone {
		return fmt.Errorf("EC2 launch token, image, type or Availability Zone changed; refusing to replay")
	}
	return nil
}
func (a ec2Adapter) Provision(ctx context.Context, op *operation, writes bool) error {
	if err := a.pending(ctx, op); err != nil {
		return err
	}
	if op.Host.ResourceID != "" {
		terminal, err := a.findWithTerminal(ctx, op, "instance", true)
		if err != nil {
			return err
		}
		if terminal != nil && str(obj(terminal["State"])["Name"]) == "terminated" {
			// A rapid launch failure can leave billable children even though
			// its terminated instance no longer contains attachment details.
			for _, kind := range []string{"ec2-volume", "ec2-eni"} {
				if cloudResourceOf(op, kind) != nil {
					continue
				}
				child, err := a.find(ctx, op, kind)
				if err != nil {
					return err
				}
				if child != nil {
					if err = a.validateAttachments(ctx, op, kind, child); err != nil {
						return err
					}
					if err = a.record(ctx, op, kind, child); err != nil {
						return err
					}
				}
			}
			op.Host.Status = "cleanup-required"
			op.State = "cleanup-required"
			return a.s.cloudPersist(op)
		}
	}
	if !writes {
		if op.Host.ResourceID != "" {
			if err := a.captureChildren(ctx, op); err != nil {
				return err
			}
			h, err := a.Observe(ctx, *op)
			if err != nil {
				return err
			}
			op.Host = h
		}
		return a.s.cloudPersist(op)
	}
	if err := a.quota(ctx, op.Request); err != nil {
		return err
	}
	if _, err := reviewedPublicKey(op.Request); err != nil {
		return err
	}
	for _, kind := range ec2CreateOrder {
		if kind == "instance" {
			for _, link := range []string{"ec2-attach-igw", "ec2-route", "ec2-associate-route", "ec2-rules"} {
				if err := a.ensureLink(ctx, op, link); err != nil {
					return err
				}
			}
		}
		if receipt := cloudResourceOf(op, kind); receipt != nil {
			if receipt.Deleted {
				return fmt.Errorf("EC2 creation cannot resume after resource deletion")
			}
			row, err := a.find(ctx, op, kind)
			if err != nil {
				return err
			}
			if row == nil {
				return fmt.Errorf("saved EC2 %s is missing; no replacement was created", kind)
			}
			continue
		}
		args, key, err := a.createArgs(ctx, op, kind)
		if err != nil {
			return err
		}
		if kind == "instance" {
			if err = a.quota(ctx, op.Request); err != nil {
				return err
			}
		}
		if err = a.checkAccount(ctx, op); err != nil {
			return err
		}
		op.PendingResourceKind = kind
		op.State = "provisioning"
		if err = a.s.cloudPersist(op); err != nil {
			return err
		}
		v, err := a.s.call(ctx, op.Request, args...)
		if err != nil {
			return fmt.Errorf("EC2 %s create outcome is unconfirmed; resume before retrying: %w", kind, err)
		}
		row := obj(v)
		if key != "" {
			if kind == "instance" {
				list, e := strictItems(v, key)
				if e != nil || len(list) != 1 {
					return fmt.Errorf("EC2 RunInstances did not return exactly one instance")
				}
				row = list[0]
			} else {
				row = obj(row[key])
			}
		}
		if err = a.record(ctx, op, kind, row); err != nil {
			return err
		}
		// Several create responses (notably AllocateAddress) omit tags. Read
		// the durable ID back before using it as a parent of another resource.
		live, err := a.find(ctx, op, kind)
		if err != nil {
			return err
		}
		if live == nil {
			return fmt.Errorf("new EC2 %s is not yet visible; resume after eventual consistency settles", kind)
		}
	}
	if err := a.captureChildren(ctx, op); err != nil {
		return err
	}
	if err := a.ensureLink(ctx, op, "ec2-associate-address"); err != nil {
		return err
	}
	host, err := a.Observe(ctx, *op)
	if err != nil {
		return err
	}
	op.Host = host
	op.State = "created"
	return a.s.cloudPersist(op)
}
func (a ec2Adapter) quota(ctx context.Context, req CreateRequest) error {
	v, err := a.s.call(ctx, req, "service-quotas", "get-service-quota", "--service-code", "ec2", "--quota-code", "L-1216C47A")
	if err != nil {
		return fmt.Errorf("cannot verify EC2 Standard on-demand vCPU quota: %w", err)
	}
	q := obj(obj(v)["Quota"])
	value, ok := q["Value"].(float64)
	if !ok || value < 2 {
		return fmt.Errorf("EC2 Standard on-demand vCPU quota is below the two vCPUs required by the selected micro instance")
	}
	return nil
}
func (a ec2Adapter) captureChildren(ctx context.Context, op *operation) error {
	row, err := a.find(ctx, op, "instance")
	if err != nil {
		return err
	}
	if row == nil {
		return fmt.Errorf("EC2 instance is not yet visible; resume after eventual consistency settles")
	}
	children := []struct{ kind, field, id string }{{"ec2-volume", "BlockDeviceMappings", ""}, {"ec2-eni", "NetworkInterfaces", ""}}
	for _, child := range children {
		if cloudResourceOf(op, child.kind) != nil {
			continue
		}
		var ids []string
		for _, raw := range arr(row[child.field]) {
			m := obj(raw)
			id := str(m["NetworkInterfaceId"])
			if child.kind == "ec2-volume" {
				id = str(obj(m["Ebs"])["VolumeId"])
			}
			if id != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) != 1 {
			return fmt.Errorf("EC2 instance must have exactly one owned root volume and primary network interface")
		}
		spec := ec2ResourceSpecs[child.kind]
		rows, e := a.list(ctx, op.Request, child.kind, []map[string]any{{"Name": spec.filter, "Values": ids}})
		if e != nil {
			return e
		}
		if len(rows) != 1 || !ec2HasOwnership(rows[0], op, child.kind) {
			return fmt.Errorf("EC2 child ownership is missing or ambiguous")
		}
		if err = a.record(ctx, op, child.kind, rows[0]); err != nil {
			return err
		}
	}
	return nil
}

func ec2DesiredRules(cidr string) ([]any, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("EC2 SSH source must be an IP CIDR")
	}
	ssh := map[string]any{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}
	if ip.To4() == nil {
		ssh["Ipv6Ranges"] = []any{map[string]any{"CidrIpv6": network.String()}}
	} else {
		ssh["IpRanges"] = []any{map[string]any{"CidrIp": network.String()}}
	}
	rules := []any{ssh}
	for _, r := range []struct {
		p string
		n int
	}{{"tcp", 80}, {"tcp", 443}, {"udp", 443}} {
		rules = append(rules, map[string]any{"IpProtocol": r.p, "FromPort": r.n, "ToPort": r.n, "IpRanges": []any{map[string]any{"CidrIp": "0.0.0.0/0"}}})
	}
	return rules, nil
}
func ec2PermissionKey(raw any) string {
	m := obj(raw)
	var ranges []string
	for _, r := range arr(m["IpRanges"]) {
		ranges = append(ranges, "v4:"+str(obj(r)["CidrIp"]))
	}
	for _, r := range arr(m["Ipv6Ranges"]) {
		ranges = append(ranges, "v6:"+str(obj(r)["CidrIpv6"]))
	}
	for _, r := range arr(m["UserIdGroupPairs"]) {
		ranges = append(ranges, "group:"+str(obj(r)["GroupId"]))
	}
	for _, r := range arr(m["PrefixListIds"]) {
		ranges = append(ranges, "prefix:"+str(obj(r)["PrefixListId"]))
	}
	sort.Strings(ranges)
	return str(m["IpProtocol"]) + ":" + fmt.Sprint(m["FromPort"]) + ":" + fmt.Sprint(m["ToPort"]) + ":" + strings.Join(ranges, ",")
}
func (a ec2Adapter) linkDone(ctx context.Context, op *operation, kind string) (bool, error) {
	switch kind {
	case "ec2-attach-igw":
		row, err := a.find(ctx, op, "ec2-igw")
		if err != nil {
			return false, err
		}
		if row == nil {
			return false, fmt.Errorf("EC2 gateway disappeared")
		}
		attachments := arr(row["Attachments"])
		if len(attachments) == 0 {
			return false, nil
		}
		if len(attachments) != 1 || str(obj(attachments[0])["VpcId"]) != ec2ID(op, "ec2-vpc") {
			return false, fmt.Errorf("EC2 gateway is attached to a foreign VPC")
		}
		return str(obj(attachments[0])["State"]) == "available", nil
	case "ec2-route":
		row, err := a.find(ctx, op, "ec2-route-table")
		if err != nil {
			return false, err
		}
		for _, raw := range arr(row["Routes"]) {
			r := obj(raw)
			if str(r["DestinationCidrBlock"]) == "0.0.0.0/0" {
				if str(r["GatewayId"]) != ec2ID(op, "ec2-igw") {
					return false, fmt.Errorf("EC2 default route points to a foreign gateway")
				}
				return str(r["State"]) == "active", nil
			}
		}
		return false, nil
	case "ec2-associate-route":
		rows, err := a.list(ctx, op.Request, "ec2-route-table", []map[string]any{{"Name": "vpc-id", "Values": []string{ec2ID(op, "ec2-vpc")}}})
		if err != nil {
			return false, err
		}
		for _, r := range rows {
			for _, raw := range arr(r["Associations"]) {
				assoc := obj(raw)
				if str(assoc["SubnetId"]) == ec2ID(op, "ec2-subnet") {
					if str(r["RouteTableId"]) != ec2ID(op, "ec2-route-table") {
						return false, fmt.Errorf("EC2 subnet is associated with a foreign route table")
					}
					state := str(obj(assoc["AssociationState"])["State"])
					return state == "associated", nil
				}
			}
		}
		return false, nil
	case "ec2-rules":
		row, err := a.find(ctx, op, "ec2-security-group")
		if err != nil {
			return false, err
		}
		want, err := ec2DesiredRules(op.Request.SSHCIDR)
		if err != nil {
			return false, err
		}
		have := map[string]bool{}
		for _, p := range arr(row["IpPermissions"]) {
			have[ec2PermissionKey(p)] = true
		}
		for _, p := range want {
			if !have[ec2PermissionKey(p)] {
				return false, nil
			}
		}
		return true, nil
	case "ec2-associate-address":
		row, err := a.find(ctx, op, "ec2-address")
		if err != nil {
			return false, err
		}
		if row == nil {
			return false, fmt.Errorf("EC2 static IPv4 disappeared")
		}
		if str(row["AssociationId"]) == "" {
			return false, nil
		}
		if str(row["InstanceId"]) != ec2ID(op, "instance") || str(row["NetworkInterfaceId"]) != ec2ID(op, "ec2-eni") {
			return false, fmt.Errorf("EC2 static IPv4 is attached to another resource; it will not be reassociated")
		}
		return true, nil
	}
	return false, fmt.Errorf("unknown EC2 pending attachment %s", kind)
}
func (a ec2Adapter) ensureLink(ctx context.Context, op *operation, kind string) error {
	done, err := a.linkDone(ctx, op, kind)
	if err != nil || done {
		return err
	}
	var args []string
	switch kind {
	case "ec2-attach-igw":
		args = []string{"ec2", "attach-internet-gateway", "--internet-gateway-id", ec2ID(op, "ec2-igw"), "--vpc-id", ec2ID(op, "ec2-vpc")}
	case "ec2-route":
		args = []string{"ec2", "create-route", "--route-table-id", ec2ID(op, "ec2-route-table"), "--destination-cidr-block", "0.0.0.0/0", "--gateway-id", ec2ID(op, "ec2-igw")}
	case "ec2-associate-route":
		args = []string{"ec2", "associate-route-table", "--route-table-id", ec2ID(op, "ec2-route-table"), "--subnet-id", ec2ID(op, "ec2-subnet")}
	case "ec2-rules":
		row, e := a.find(ctx, op, "ec2-security-group")
		if e != nil {
			return e
		}
		have := map[string]bool{}
		for _, p := range arr(row["IpPermissions"]) {
			have[ec2PermissionKey(p)] = true
		}
		want, e := ec2DesiredRules(op.Request.SSHCIDR)
		if e != nil {
			return e
		}
		var missing []any
		for _, p := range want {
			if !have[ec2PermissionKey(p)] {
				missing = append(missing, p)
			}
		}
		args = []string{"ec2", "authorize-security-group-ingress", "--group-id", ec2ID(op, "ec2-security-group"), "--ip-permissions", jsonValue(missing)}
	case "ec2-associate-address":
		// Pending instances cannot always be associated immediately. The official
		// waiter is read-only; failure leaves the saved VM available for resume.
		if _, e := a.s.call(ctx, op.Request, "ec2", "wait", "instance-running", "--instance-ids", ec2ID(op, "instance")); e != nil {
			return e
		}
		args = []string{"ec2", "associate-address", "--allocation-id", ec2ID(op, "ec2-address"), "--instance-id", ec2ID(op, "instance"), "--no-allow-reassociation"}
	default:
		return fmt.Errorf("unknown EC2 attachment")
	}
	if err = a.checkAccount(ctx, op); err != nil {
		return err
	}
	op.PendingResourceKind = kind
	if err = a.s.cloudPersist(op); err != nil {
		return err
	}
	if _, err = a.s.call(ctx, op.Request, args...); err != nil {
		return fmt.Errorf("EC2 %s outcome is unconfirmed; resume reconciles it before any further write: %w", kind, err)
	}
	op.PendingResourceKind = ""
	return a.s.cloudPersist(op)
}

var _ cloudAdapter = ec2Adapter{}
