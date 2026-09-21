package vps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type ec2Fixture struct {
	t              *testing.T
	rows           map[string][]map[string]any
	calls          [][]string
	writes         []string
	failAfter      string
	failBefore     string
	account        string
	quota          float64
	onWrite        func(string)
	lastLaunch     map[string]any
	unsupportedARM bool
}

func newEC2Fixture(t *testing.T) *ec2Fixture {
	return &ec2Fixture{t: t, rows: map[string][]map[string]any{}, account: "123456789012", quota: 16}
}
func ec2Arg(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}
func ec2FixtureTags(args []string) []any {
	var specs []map[string]any
	_ = json.Unmarshal([]byte(ec2Arg(args, "--tag-specifications")), &specs)
	if len(specs) > 0 {
		return arr(specs[0]["Tags"])
	}
	return nil
}
func (f *ec2Fixture) run(_ context.Context, exe string, args []string) ([]byte, error) {
	if exe != "aws" {
		f.t.Fatalf("unexpected executable %s", exe)
	}
	f.calls = append(f.calls, append([]string(nil), args...))
	var svc, action string
	for i, a := range args {
		if a == "ec2" || a == "pricing" || a == "sts" || a == "ssm" || a == "service-quotas" {
			svc = a
			if i+1 < len(args) {
				action = args[i+1]
			}
			break
		}
	}
	encode := func(v any) ([]byte, error) { return json.Marshal(v) }
	switch svc {
	case "sts":
		return encode(map[string]any{"Account": f.account, "Arn": "arn:aws:sts::" + f.account + ":assumed-role/dev/session"})
	case "ssm":
		arch := "amd64"
		if strings.Contains(ec2Arg(args, "--name"), "/arm64/") {
			arch = "arm64"
		}
		return encode(map[string]any{"Parameter": map[string]any{"Value": map[string]string{"arm64": "ami-aaaaaaaaaaaaaaaaa", "amd64": "ami-bbbbbbbbbbbbbbbbb"}[arch]}})
	case "service-quotas":
		return encode(map[string]any{"Quota": map[string]any{"Value": f.quota}})
	case "pricing":
		return f.prices(args)
	}
	switch action {
	case "describe-regions":
		return encode(map[string]any{"Regions": []any{map[string]any{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}}})
	case "describe-availability-zones":
		return encode(map[string]any{"AvailabilityZones": []any{map[string]any{"ZoneName": "us-east-1b", "ZoneType": "availability-zone", "State": "available", "RegionName": "us-east-1"}, map[string]any{"ZoneName": "us-east-1a", "ZoneType": "availability-zone", "State": "available", "RegionName": "us-east-1"}}})
	case "describe-instance-type-offerings":
		var filters []map[string]any
		_ = json.Unmarshal([]byte(ec2Arg(args, "--filters")), &filters)
		plan := str(arr(filters[0]["Values"])[0])
		rows := []any{}
		if !f.unsupportedARM || plan != "t4g.micro" {
			for _, z := range []string{"us-east-1a", "us-east-1b"} {
				rows = append(rows, map[string]any{"InstanceType": plan, "LocationType": "availability-zone", "Location": z})
			}
		}
		return encode(map[string]any{"InstanceTypeOfferings": rows})
	case "describe-instance-types":
		plan := ec2Arg(args, "--instance-types")
		return encode(map[string]any{"InstanceTypes": []any{map[string]any{"InstanceType": plan, "ProcessorInfo": map[string]any{"SupportedArchitectures": []string{ec2AWSArchitecture(ec2Architecture(plan))}}, "MemoryInfo": map[string]any{"SizeInMiB": 1024}, "VCpuInfo": map[string]any{"DefaultVCpus": 2}}}})
	case "describe-images":
		id := ec2Arg(args, "--image-ids")
		arch := "x86_64"
		if id == "ami-aaaaaaaaaaaaaaaaa" {
			arch = "arm64"
		}
		return encode(map[string]any{"Images": []any{map[string]any{"ImageId": id, "OwnerId": "099720109477", "State": "available", "RootDeviceType": "ebs", "VirtualizationType": "hvm", "Architecture": arch, "Name": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-server-20260901", "CreationDate": "2026-09-01T00:00:00.000Z", "RootDeviceName": "/dev/sda1", "BlockDeviceMappings": []any{map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeSize": 8}}}}}})
	case "wait":
		return nil, nil
	}
	if strings.HasPrefix(action, "describe-") {
		for kind, spec := range ec2ResourceSpecs {
			if action != spec.action {
				continue
			}
			rows := []any{}
			var filters []map[string]any
			_ = json.Unmarshal([]byte(ec2Arg(args, "--filters")), &filters)
			for _, row := range f.rows[kind] {
				match := true
				for _, filter := range filters {
					field := str(filter["Name"])
					want := str(arr(filter["Values"])[0])
					actual := ""
					switch {
					case strings.HasPrefix(field, "tag:"):
						actual = ec2Tag(row, strings.TrimPrefix(field, "tag:"))
					case field == spec.filter:
						actual = str(row[spec.id])
					case field == "vpc-id":
						actual = str(row["VpcId"])
					case field == "key-name":
						actual = str(row["KeyName"])
					case field == "attachment.vpc-id":
						if as := arr(row["Attachments"]); len(as) > 0 {
							actual = str(obj(as[0])["VpcId"])
						}
					}
					match = match && actual == want
				}
				if match {
					rows = append(rows, row)
				}
			}
			if kind == "instance" {
				return encode(map[string]any{"Reservations": []any{map[string]any{"Instances": rows}}})
			}
			return encode(map[string]any{spec.collection: rows})
		}
	}
	if action == "" {
		f.t.Fatalf("unrecognized command: %v", args)
	}
	f.writes = append(f.writes, action)
	if f.onWrite != nil {
		f.onWrite(action)
	}
	if f.failBefore == action {
		f.failBefore = ""
		return nil, errors.New("simulated request timeout before confirmation")
	}
	var response any = map[string]any{}
	tags := ec2FixtureTags(args)
	create := func(kind string, row map[string]any, key string) {
		row["Tags"] = tags
		f.rows[kind] = append(f.rows[kind], row)
		if key != "" {
			response = map[string]any{key: row}
		} else {
			response = row
		}
	}
	switch action {
	case "create-vpc":
		create("ec2-vpc", map[string]any{"VpcId": "vpc-1", "CidrBlock": "10.208.0.0/16"}, "Vpc")
	case "create-subnet":
		create("ec2-subnet", map[string]any{"SubnetId": "subnet-1", "VpcId": "vpc-1", "AvailabilityZone": "us-east-1a"}, "Subnet")
	case "create-internet-gateway":
		create("ec2-igw", map[string]any{"InternetGatewayId": "igw-1", "Attachments": []any{}}, "InternetGateway")
	case "create-route-table":
		create("ec2-route-table", map[string]any{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Routes": []any{map[string]any{"GatewayId": "local", "DestinationCidrBlock": "10.208.0.0/16", "State": "active"}}, "Associations": []any{}}, "RouteTable")
	case "create-security-group":
		create("ec2-security-group", map[string]any{"GroupId": "sg-1", "VpcId": "vpc-1", "GroupName": ec2Arg(args, "--group-name"), "IpPermissions": []any{}}, "")
	case "import-key-pair":
		create("ec2-key-pair", map[string]any{"KeyPairId": "key-1", "KeyName": ec2Arg(args, "--key-name"), "KeyFingerprint": "aa:bb:cc"}, "")
	case "allocate-address":
		create("ec2-address", map[string]any{"AllocationId": "eipalloc-1", "PublicIp": "198.51.100.7", "Domain": "vpc"}, "")
		// Real AllocateAddress omits tags from its response; DescribeAddresses
		// provides the ownership marker used before association and deletion.
		response = map[string]any{"AllocationId": "eipalloc-1", "PublicIp": "198.51.100.7", "Domain": "vpc"}
	case "attach-internet-gateway":
		f.rows["ec2-igw"][0]["Attachments"] = []any{map[string]any{"VpcId": "vpc-1", "State": "available"}}
	case "create-route":
		f.rows["ec2-route-table"][0]["Routes"] = append(arr(f.rows["ec2-route-table"][0]["Routes"]), map[string]any{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"})
	case "associate-route-table":
		f.rows["ec2-route-table"][0]["Associations"] = []any{map[string]any{"SubnetId": "subnet-1", "RouteTableAssociationId": "rtbassoc-1", "Main": false, "AssociationState": map[string]any{"State": "associated"}}}
	case "authorize-security-group-ingress":
		var rules []any
		_ = json.Unmarshal([]byte(ec2Arg(args, "--ip-permissions")), &rules)
		f.rows["ec2-security-group"][0]["IpPermissions"] = append(arr(f.rows["ec2-security-group"][0]["IpPermissions"]), rules...)
	case "run-instances":
		var body map[string]any
		if err := json.Unmarshal([]byte(ec2Arg(args, "--cli-input-json")), &body); err != nil {
			f.t.Fatal(err)
		}
		f.lastLaunch = body
		tagFor := func(rt string) any {
			for _, raw := range arr(body["TagSpecifications"]) {
				m := obj(raw)
				if str(m["ResourceType"]) == rt {
					return m["Tags"]
				}
			}
			return nil
		}
		row := map[string]any{"InstanceId": "i-1", "VpcId": "vpc-1", "SubnetId": "subnet-1", "ImageId": body["ImageId"], "InstanceType": body["InstanceType"], "ClientToken": body["ClientToken"], "KeyName": body["KeyName"], "Placement": body["Placement"], "State": map[string]any{"Name": "running"}, "Tags": tagFor("instance"), "BlockDeviceMappings": []any{map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeId": "vol-1", "DeleteOnTermination": true}}}, "NetworkInterfaces": []any{map[string]any{"NetworkInterfaceId": "eni-1"}}}
		f.rows["instance"] = []map[string]any{row}
		f.rows["ec2-volume"] = []map[string]any{{"VolumeId": "vol-1", "AvailabilityZone": "us-east-1a", "Tags": tagFor("volume"), "Attachments": []any{map[string]any{"InstanceId": "i-1"}}}}
		f.rows["ec2-eni"] = []map[string]any{{"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1", "SubnetId": "subnet-1", "Tags": tagFor("network-interface"), "Attachment": map[string]any{"InstanceId": "i-1", "AttachmentId": "eniattach-1"}}}
		response = map[string]any{"Instances": []any{row}}
	case "associate-address":
		for k, v := range map[string]any{"AssociationId": "eipassoc-1", "InstanceId": "i-1", "NetworkInterfaceId": "eni-1"} {
			f.rows["ec2-address"][0][k] = v
		}
	case "start-instances", "stop-instances", "reboot-instances":
	case "terminate-instances":
		f.rows["instance"][0]["State"] = map[string]any{"Name": "terminated"}
		f.rows["ec2-volume"] = nil
		f.rows["ec2-eni"] = nil
		for _, k := range []string{"AssociationId", "InstanceId", "NetworkInterfaceId"} {
			delete(f.rows["ec2-address"][0], k)
		}
	case "disassociate-address":
		for _, k := range []string{"AssociationId", "InstanceId", "NetworkInterfaceId"} {
			delete(f.rows["ec2-address"][0], k)
		}
	case "disassociate-route-table":
		f.rows["ec2-route-table"][0]["Associations"] = []any{}
	case "detach-internet-gateway":
		f.rows["ec2-igw"][0]["Attachments"] = []any{}
	case "release-address":
		f.rows["ec2-address"] = nil
	case "delete-volume":
		f.rows["ec2-volume"] = nil
	case "delete-network-interface":
		f.rows["ec2-eni"] = nil
	case "delete-key-pair":
		f.rows["ec2-key-pair"] = nil
	case "delete-security-group":
		f.rows["ec2-security-group"] = nil
	case "delete-route-table":
		f.rows["ec2-route-table"] = nil
	case "delete-subnet":
		f.rows["ec2-subnet"] = nil
	case "delete-internet-gateway":
		f.rows["ec2-igw"] = nil
	case "delete-vpc":
		f.rows["ec2-vpc"] = nil
	default:
		f.t.Fatalf("unexpected write: %s %v", action, args)
	}
	if f.failAfter == action {
		f.failAfter = ""
		return nil, errors.New("simulated successful mutation with lost response")
	}
	return encode(response)
}
func ec2Product(service, family string, attrs map[string]string, tiers []ec2PriceDimension) map[string]any {
	attrs["servicecode"] = service
	dimensions := map[string]any{}
	for i, tier := range tiers {
		end := fmt.Sprint(tier.End)
		if math.IsInf(tier.End, 1) {
			end = "Inf"
		}
		dimensions[fmt.Sprint(i)] = map[string]any{"beginRange": fmt.Sprint(tier.Begin), "endRange": end, "unit": tier.Unit, "pricePerUnit": map[string]string{"USD": fmt.Sprint(tier.USD)}, "appliesTo": []any{}}
	}
	return map[string]any{"product": map[string]any{"sku": "sku-" + family, "productFamily": family, "attributes": attrs}, "terms": map[string]any{"OnDemand": map[string]any{"term": map[string]any{"termAttributes": map[string]any{}, "priceDimensions": dimensions}}}}
}
func (f *ec2Fixture) prices(args []string) ([]byte, error) {
	var filters []map[string]string
	_ = json.Unmarshal([]byte(ec2Arg(args, "--filters")), &filters)
	attrs := map[string]string{}
	for _, p := range filters {
		attrs[p["Field"]] = p["Value"]
	}
	service := ec2Arg(args, "--service-code")
	unit, family := "Hrs", "Compute Instance"
	rate := 0.0104
	switch service {
	case "AmazonEC2":
		if attrs["volumeApiName"] == "gp3" {
			unit = "GB-Mo"
			family = "Storage"
			rate = .08
		} else if attrs["instanceType"] == "t4g.micro" {
			rate = .0084
		} else if attrs["instanceType"] == "t3a.micro" {
			rate = .0094
		}
	case "AmazonVPC":
		attrs["usagetype"] = "USE1-PublicIPv4:InUseAddress"
		family = "IPv4"
		rate = .005
	case "AWSDataTransfer":
		family = "Data Transfer"
		unit = "GB"
		rate = .09
	}
	tiers := []ec2PriceDimension{{Begin: 0, End: math.Inf(1), USD: rate, Unit: unit}}
	if service == "AWSDataTransfer" {
		tiers = []ec2PriceDimension{{Begin: 0, End: 10240, USD: .09, Unit: "GB"}, {Begin: 10240, End: math.Inf(1), USD: .085, Unit: "GB"}}
	}
	priceList := []string{jsonValue(ec2Product(service, family, attrs, tiers))}
	if service == "AmazonVPC" {
		attrs["usagetype"] = "USE1-PublicIPv4:IdleAddress"
		priceList = append(priceList, jsonValue(ec2Product(service, "IPv4 Idle", attrs, tiers)))
	}
	return json.Marshal(map[string]any{"PriceList": priceList})
}
func ec2TestService(t *testing.T) (*Service, *ec2Fixture, CreateRequest) {
	t.Helper()
	f := newEC2Fixture(t)
	root := t.TempDir()
	key := filepath.Join(root, "id.pub")
	if err := os.WriteFile(key, []byte("ssh-ed25519 AAAA ec2-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(serverstate.Store{Path: filepath.Join(root, "servers.toml"), StateDir: filepath.Join(root, "state")}, Options{Run: f.run, Now: func() time.Time { return time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC) }})
	req := CreateRequest{ID: "ec2-test", Name: "ec2-test", Provider: "aws-ec2", Region: "us-east-1", Architecture: "auto", SSHKey: key, SSHKeyFingerprint: digest("ssh-ed25519 AAAA ec2-fixture"), SSHUser: "ubuntu", SSHCIDR: "192.0.2.0/24"}
	return s, f, req
}
func ec2TestOperation(t *testing.T, s *Service, r CreateRequest) operation {
	t.Helper()
	a := ec2Adapter{s}
	r, q, err := a.Resolve(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Identity(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	op := operation{Version: 1, ID: "lc-ec2-fixture", Request: r, Quote: &q, AccountID: id, State: "intent", PrivateData: map[string]json.RawMessage{}, Host: serverstate.Host{ID: r.ID, Name: r.Name, Provider: r.Provider, Region: r.Region, Plan: r.Plan, Owned: true, OperationID: "lc-ec2-fixture", Status: "creating"}}
	if err = s.cloudPersist(&op); err != nil {
		t.Fatal(err)
	}
	return op
}
func TestEC2ResolvePinsCheapestArchitectureAndAllFixedCosts(t *testing.T) {
	s, f, r := ec2TestService(t)
	got, q, err := (ec2Adapter{s}).Resolve(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Plan != "t4g.micro" || got.Architecture != "arm64" || got.Image != "ami-aaaaaaaaaaaaaaaaa" || got.AvailabilityZone != "us-east-1a" || got.DiskGB != 20 {
		t.Fatalf("unpinned request: %+v", got)
	}
	if math.Abs(q.MonthlyUSD-11.382) > 1e-9 || len(q.Components) != 3 || q.StoppedMonthlyUSD == nil || math.Abs(*q.StoppedMonthlyUSD-5.25) > 1e-9 {
		t.Fatalf("incomplete costs: %+v", q)
	}
	if q.TransferGB != 0 || q.TransferPricing == nil || q.TransferPricing.SharedAllowanceGB != 100 || len(q.TransferPricing.Tiers) != 2 {
		t.Fatalf("transfer quote: %+v", q)
	}
	if len(f.writes) != 0 {
		t.Fatal("resolve mutated AWS")
	}
	for _, call := range f.calls {
		if strings.Contains(strings.Join(call, " "), "pricing get-products") && ec2Arg(call, "--region") != "us-east-1" {
			t.Fatal("pricing region not pinned")
		}
	}
}
func TestEC2ResolveArchitectureAndAvailability(t *testing.T) {
	s, f, r := ec2TestService(t)
	a := ec2Adapter{s}
	r.Architecture = "amd64"
	got, _, err := a.Resolve(context.Background(), r)
	if err != nil || got.Plan != "t3a.micro" {
		t.Fatalf("AMD: %+v %v", got, err)
	}
	r.Architecture = "auto"
	f.unsupportedARM = true
	got, _, err = a.Resolve(context.Background(), r)
	if err != nil || got.Plan != "t3a.micro" {
		t.Fatalf("unavailable ARM: %+v %v", got, err)
	}
	r.Plan = "t4g.micro"
	if _, _, err = a.Resolve(context.Background(), r); err == nil {
		t.Fatal("explicit unavailable plan accepted")
	}
	r.Plan = "t3a.micro"
	r.Architecture = "arm64"
	if _, _, err = a.Resolve(context.Background(), r); err == nil {
		t.Fatal("architecture mismatch accepted")
	}
	r.Architecture = "amd64"
	r.Image = "ami-aaaaaaaaaaaaaaaaa"
	if _, _, err = a.Resolve(context.Background(), r); err == nil {
		t.Fatal("AMI architecture mismatch accepted")
	}
	r.Image = ""
	r.AvailabilityZone = "us-east-1z"
	if _, _, err = a.Resolve(context.Background(), r); err == nil {
		t.Fatal("unavailable AZ accepted")
	}
	r.AvailabilityZone = ""
	f.quota = 0
	if _, _, err = a.Resolve(context.Background(), r); err == nil {
		t.Fatal("zero quota accepted")
	}
}
func TestEC2LifecycleUsesDurableLaunchAndReleasesOwnedGraph(t *testing.T) {
	s, f, r := ec2TestService(t)
	op := ec2TestOperation(t, s, r)
	a := ec2Adapter{s}
	f.onWrite = func(action string) {
		saved, err := s.readOperation(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if action == "run-instances" {
			if saved.PendingResourceKind != "instance" || len(saved.PrivateData["ec2_run_instances"]) == 0 {
				t.Fatal("launch not durable before AWS write")
			}
		}
	}
	if err := a.Provision(context.Background(), &op, true); err != nil {
		t.Fatal(err)
	}
	if op.Host.PublicHost != "198.51.100.7" || op.Host.SSHHost != "ubuntu@198.51.100.7" || len(op.CloudResources) != 10 {
		t.Fatalf("incomplete graph %+v", op)
	}
	b := f.lastLaunch
	if str(obj(b["CreditSpecification"])["CpuCredits"]) != "standard" || str(obj(b["MetadataOptions"])["HttpTokens"]) != "required" || str(b["ClientToken"]) != op.ID {
		t.Fatalf("unsafe instance options %s", jsonValue(b))
	}
	ebs := obj(obj(arr(b["BlockDeviceMappings"])[0])["Ebs"])
	if str(ebs["VolumeType"]) != "gp3" || !truth(ebs["Encrypted"]) || !truth(ebs["DeleteOnTermination"]) {
		t.Fatal("root disk options")
	}
	nic := obj(arr(b["NetworkInterfaces"])[0])
	if truth(nic["AssociatePublicIpAddress"]) {
		t.Fatal("unpriced extra public IP")
	}
	count := len(f.writes)
	if err := a.Provision(context.Background(), &op, false); err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != count {
		t.Fatal("reconcile-only mutated AWS")
	}
	for _, action := range []string{"stop", "start", "reboot"} {
		if err := a.Action(context.Background(), &op, action); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if err := a.Action(context.Background(), &op, "delete"); err != nil {
		t.Fatal(err)
	}
	if op.Host.Status != "deleted" || op.Host.Owned {
		t.Fatalf("delete not complete %+v", op.Host)
	}
	for _, resource := range op.CloudResources {
		if !resource.Deleted {
			t.Fatalf("resource leaked %+v", resource)
		}
	}
}
func TestEC2EveryCreationCheckpointReconcilesLostResponse(t *testing.T) {
	actions := []string{"create-vpc", "create-subnet", "create-internet-gateway", "create-route-table", "create-security-group", "import-key-pair", "allocate-address", "attach-internet-gateway", "create-route", "associate-route-table", "authorize-security-group-ingress", "run-instances", "associate-address"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			s, f, r := ec2TestService(t)
			op := ec2TestOperation(t, s, r)
			a := ec2Adapter{s}
			f.failAfter = action
			if err := a.Provision(context.Background(), &op, true); err == nil {
				t.Fatal("lost response accepted")
			}
			if op.PendingResourceKind == "" {
				t.Fatal("pending write not retained")
			}
			count := len(f.writes)
			// Reload the operation exactly as a fresh process would after termination.
			var err error
			op, err = s.readOperation(op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Provision(context.Background(), &op, false); err != nil {
				t.Fatal(err)
			}
			if len(f.writes) != count {
				t.Fatal("reconciliation replayed a mutation")
			}
			if err = a.Provision(context.Background(), &op, true); err != nil {
				t.Fatal(err)
			}
			occurrences := 0
			for _, write := range f.writes {
				if write == action {
					occurrences++
				}
			}
			if occurrences != 1 {
				t.Fatalf("%s replayed %d times", action, occurrences)
			}
			if op.Host.PublicHost == "" {
				t.Fatal("IP not attached")
			}
		})
	}
}
func TestEC2UnconfirmedAbsentCreateIsNeverReplayed(t *testing.T) {
	s, f, r := ec2TestService(t)
	op := ec2TestOperation(t, s, r)
	a := ec2Adapter{s}
	f.failBefore = "create-vpc"
	if a.Provision(context.Background(), &op, true) == nil {
		t.Fatal("expected failure")
	}
	count := len(f.writes)
	for _, writes := range []bool{false, true} {
		if a.Provision(context.Background(), &op, writes) == nil {
			t.Fatal("absent ambiguous create accepted")
		}
	}
	if len(f.writes) != count {
		t.Fatal("ambiguous create was replayed")
	}
}
func TestEC2DeletionPreservesForeignAttachmentsAndChangedTags(t *testing.T) {
	cases := map[string]func(*ec2Fixture){"volume": func(f *ec2Fixture) { f.rows["ec2-volume"][0]["Tags"] = []any{} }, "foreign-volume": func(f *ec2Fixture) {
		f.rows["ec2-volume"][0]["Attachments"] = []any{map[string]any{"InstanceId": "i-foreign"}}
	}, "foreign-ip": func(f *ec2Fixture) { f.rows["ec2-address"][0]["InstanceId"] = "i-foreign" }, "foreign-subnet": func(f *ec2Fixture) {
		f.rows["ec2-subnet"] = append(f.rows["ec2-subnet"], map[string]any{"SubnetId": "subnet-foreign", "VpcId": "vpc-1"})
	}, "foreign-route": func(f *ec2Fixture) {
		f.rows["ec2-route-table"][0]["Associations"] = []any{map[string]any{"SubnetId": "subnet-foreign", "Main": false}}
	}, "foreign-eni": func(f *ec2Fixture) { f.rows["ec2-eni"][0]["Attachment"] = map[string]any{"InstanceId": "i-foreign"} }, "foreign-key-use": func(f *ec2Fixture) {
		f.rows["instance"] = append(f.rows["instance"], map[string]any{"InstanceId": "i-foreign", "VpcId": "vpc-foreign", "KeyName": "lc-ec2-fixture", "State": map[string]any{"Name": "running"}})
	}}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			s, f, r := ec2TestService(t)
			op := ec2TestOperation(t, s, r)
			a := ec2Adapter{s}
			if err := a.Provision(context.Background(), &op, true); err != nil {
				t.Fatal(err)
			}
			alter(f)
			before := len(f.writes)
			if err := a.Action(context.Background(), &op, "delete"); err == nil {
				t.Fatal("foreign graph deletion allowed")
			}
			if len(f.writes) != before {
				t.Fatal("graph mutated before preflight failed")
			}
		})
	}
}
func TestEC2PartialDeleteReconcilesSuccessAndDoesNotLoseReceipts(t *testing.T) {
	for _, action := range []string{"terminate-instances", "release-address", "delete-key-pair", "delete-security-group", "delete-route-table", "delete-subnet", "delete-internet-gateway", "delete-vpc"} {
		t.Run(action, func(t *testing.T) {
			s, f, r := ec2TestService(t)
			op := ec2TestOperation(t, s, r)
			a := ec2Adapter{s}
			if err := a.Provision(context.Background(), &op, true); err != nil {
				t.Fatal(err)
			}
			f.failAfter = action
			if err := a.Action(context.Background(), &op, "delete"); err == nil {
				t.Fatal("lost response accepted")
			}
			saved, err := s.readOperation(op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = a.Action(context.Background(), &saved, "delete"); err != nil {
				t.Fatal(err)
			}
			if saved.Host.Status != "deleted" {
				t.Fatal("cleanup incomplete")
			}
		})
	}
}
func TestEC2LaunchRecordRejectsTokenOrZoneDrift(t *testing.T) {
	s, _, r := ec2TestService(t)
	op := ec2TestOperation(t, s, r)
	a := ec2Adapter{s}
	if err := a.Provision(context.Background(), &op, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*operation){func(o *operation) { o.ID = "other-token" }, func(o *operation) { o.Request.AvailabilityZone = "us-east-1b" }, func(o *operation) {
		o.PrivateData = map[string]json.RawMessage{"ec2_run_instances": json.RawMessage(`{}`)}
	}} {
		copy := op
		change(&copy)
		if a.validateLaunchRecord(&copy) == nil {
			t.Fatal("launch drift accepted")
		}
	}
}
func TestEC2PricingPaginationAndMalformedTerms(t *testing.T) {
	s, _, r := ec2TestService(t)
	pages := 0
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		pages++
		if pages == 1 {
			return []byte(`{"PriceList":[],"NextToken":"second"}`), nil
		}
		if ec2Arg(args, "--next-token") != "second" {
			t.Fatal("missing continuation token")
		}
		p := ec2Product("AmazonEC2", "Compute Instance", map[string]string{"regionCode": "us-east-1"}, []ec2PriceDimension{{0, math.Inf(1), .01, "Hrs"}})
		return json.Marshal(map[string]any{"PriceList": []string{jsonValue(p)}})
	}
	products, err := s.ec2Prices(context.Background(), r, "AmazonEC2", ec2Filter("regionCode", "us-east-1"))
	if err != nil || pages != 2 || len(products) != 1 {
		t.Fatalf("pagination: %d %v", pages, err)
	}
	rate, err := ec2FixedRate(products, "Hrs")
	if err != nil || rate != .01 {
		t.Fatalf("rate %v %v", rate, err)
	}
	for _, bad := range []map[string]any{ec2Product("AmazonEC2", "Compute Instance", map[string]string{}, []ec2PriceDimension{{0, math.Inf(1), 0, "Hrs"}}), ec2Product("AmazonEC2", "Compute Instance", map[string]string{}, []ec2PriceDimension{{0, 10, .01, "Hrs"}}), ec2Product("AmazonEC2", "Compute Instance", map[string]string{}, []ec2PriceDimension{{0, math.Inf(1), .01, "GB"}})} {
		if _, err = ec2FixedRate([]map[string]any{bad}, "Hrs"); err == nil {
			t.Fatal("invalid fixed price accepted")
		}
	}
	s.options.Run = func(context.Context, string, []string) ([]byte, error) {
		return []byte(`{"PriceList":[],"NextToken":"repeat"}`), nil
	}
	if _, err = s.ec2Prices(context.Background(), r, "AmazonEC2"); err == nil {
		t.Fatal("repeated pagination accepted")
	}
}
func TestEC2PublicServiceIdentityBindingAndPrivateRequest(t *testing.T) {
	s, f, r := ec2TestService(t)
	p, err := s.PlanCreate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	host, err := s.Create(context.Background(), r, p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if host.MonthlyUSD != p.Quote.MonthlyUSD || host.PublicHost == "" {
		t.Fatalf("host %+v", host)
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(op.Quote, p.Quote) {
		t.Fatal("quote not retained")
	}
	before := len(f.writes)
	f.account = "999999999999"
	if _, err = s.PlanAction(context.Background(), host.ID, "stop"); err == nil {
		t.Fatal("account switch accepted")
	}
	if len(f.writes) != before {
		t.Fatal("switched account mutated")
	}
}

func TestEC2PublicLifecycleReviewStatusAndDelete(t *testing.T) {
	ctx := context.Background()
	s, f, req := ec2TestService(t)
	preview, err := s.PlanCreate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(ctx, req, "wrong-digest"); err == nil {
		t.Fatal("unreviewed create accepted")
	}
	if len(f.writes) != 0 {
		t.Fatal("unreviewed create wrote to AWS")
	}
	host, err := s.Create(ctx, req, preview.Digest)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "running" || status.PublicHost != host.PublicHost {
		t.Fatalf("unexpected status %+v", status)
	}
	for _, action := range []string{"stop", "start", "delete"} {
		p, e := s.PlanAction(ctx, host.ID, action)
		if e != nil {
			t.Fatalf("%s preview: %v", action, e)
		}
		h, e := s.Action(ctx, host.ID, action, p.Digest)
		if e != nil {
			t.Fatalf("%s apply: %v", action, e)
		}
		want := action + "-requested"
		if action == "delete" {
			want = "deleted"
		}
		if h.Status != want {
			t.Fatalf("%s status=%s", action, h.Status)
		}
	}
	inv, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := inv.Host(host.ID)
	if err != nil || saved.Owned || saved.Status != "deleted" || len(saved.Resources) != 0 {
		t.Fatalf("incomplete deletion %+v %v", saved, err)
	}
}
func TestEC2PublicResumeAfterNetworkAndInstanceResponseLoss(t *testing.T) {
	for _, action := range []string{"create-subnet", "run-instances"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			s, f, req := ec2TestService(t)
			p, err := s.PlanCreate(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			f.failAfter = action
			host, err := s.Create(ctx, req, p.Digest)
			if err == nil {
				t.Fatal("expected lost response")
			}
			count := len(f.writes)
			host, err = s.Resume(ctx, host.ID)
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if len(f.writes) != count {
				t.Fatal("reconcile-only wrote to AWS")
			}
			p, err = s.PlanResume(ctx, host.ID)
			if err != nil {
				t.Fatalf("resume preview: %v", err)
			}
			host, err = s.Resume(ctx, host.ID, p.Digest)
			if err != nil {
				t.Fatalf("reviewed resume: %v", err)
			}
			if host.PublicHost == "" {
				t.Fatal("resume did not attach static IPv4")
			}
			n := 0
			for _, write := range f.writes {
				if write == action {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%s replayed %d times", action, n)
			}
		})
	}
}

func TestEC2LostLaunchResponseReconcilesTerminalInstanceForCleanup(t *testing.T) {
	ctx := context.Background()
	s, f, req := ec2TestService(t)
	p, err := s.PlanCreate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	f.failAfter = "run-instances"
	host, err := s.Create(ctx, req, p.Digest)
	if err == nil {
		t.Fatal("expected unconfirmed launch")
	}
	// A KMS/launch failure can terminate the instance before the next polling
	// process sees it, while leaving an allocated EIP and tagged children.
	f.rows["instance"][0]["State"] = map[string]any{"Name": "terminated"}
	f.rows["ec2-volume"][0]["Attachments"] = []any{}
	f.rows["ec2-eni"][0]["Attachment"] = map[string]any{}
	before := len(f.writes)
	host, err = s.Resume(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if host.Status != "cleanup-required" || host.ResourceID == "" || len(f.writes) != before {
		t.Fatalf("terminal recovery mutated or lost identity: %+v", host)
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if op.PendingResourceKind != "" || ec2ID(&op, "ec2-volume") == "" || ec2ID(&op, "ec2-eni") == "" {
		t.Fatal("terminal launch receipts incomplete")
	}
	deletion, err := s.PlanAction(ctx, host.ID, "delete")
	if err != nil {
		t.Fatal(err)
	}
	host, err = s.Action(ctx, host.ID, "delete", deletion.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if host.Status != "deleted" || len(f.rows["ec2-address"]) != 0 || len(f.rows["ec2-volume"]) != 0 {
		t.Fatal("terminal launch billable resources leaked")
	}
	n := 0
	for _, w := range f.writes {
		if w == "run-instances" {
			n++
		}
	}
	if n != 1 {
		t.Fatal("terminal launch was resubmitted")
	}
}
func TestEC2TerminalLaunchDoesNotBypassOwnershipValidation(t *testing.T) {
	s, f, r := ec2TestService(t)
	op := ec2TestOperation(t, s, r)
	a := ec2Adapter{s}
	f.failAfter = "run-instances"
	if a.Provision(context.Background(), &op, true) == nil {
		t.Fatal("expected uncertainty")
	}
	f.rows["instance"][0]["State"] = map[string]any{"Name": "terminated"}
	f.rows["instance"][0]["ClientToken"] = "foreign"
	before := len(f.writes)
	if a.Provision(context.Background(), &op, false) == nil {
		t.Fatal("unproven terminal instance adopted")
	}
	if len(f.writes) != before || op.PendingResourceKind != "instance" {
		t.Fatal("terminal mismatch changed ownership")
	}
}

func TestEC2AccountDriftBetweenWritesStopsProvisionAndCleanup(t *testing.T) {
	t.Run("provision", func(t *testing.T) {
		s, f, r := ec2TestService(t)
		op := ec2TestOperation(t, s, r)
		a := ec2Adapter{s}
		f.onWrite = func(action string) {
			if action == "create-vpc" {
				f.account = "999999999999"
			}
		}
		err := a.Provision(context.Background(), &op, true)
		if err == nil || !strings.Contains(err.Error(), "account") {
			t.Fatalf("account drift not detected: %v", err)
		}
		if !reflect.DeepEqual(f.writes, []string{"create-vpc"}) {
			t.Fatalf("wrote after drift: %v", f.writes)
		}
		if op.PendingResourceKind != "" {
			t.Fatal("unsubmitted write became ambiguous")
		}
	})
	t.Run("delete", func(t *testing.T) {
		s, f, r := ec2TestService(t)
		op := ec2TestOperation(t, s, r)
		a := ec2Adapter{s}
		if err := a.Provision(context.Background(), &op, true); err != nil {
			t.Fatal(err)
		}
		before := len(f.writes)
		f.onWrite = func(action string) {
			if action == "terminate-instances" {
				f.account = "999999999999"
			}
		}
		err := a.Action(context.Background(), &op, "delete")
		if err == nil || !strings.Contains(err.Error(), "account") {
			t.Fatalf("delete drift not detected: %v", err)
		}
		if !reflect.DeepEqual(f.writes[before:], []string{"terminate-instances"}) {
			t.Fatalf("deleted after drift: %v", f.writes[before:])
		}
	})
}

func TestEC2ResumeRepairsJournalAheadOfInventory(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		name := "valid"
		if foreign {
			name = "foreign-instance"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, f, req := ec2TestService(t)
			p, err := s.PlanCreate(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			host, err := s.Create(ctx, req, p.Digest)
			if err != nil {
				t.Fatal(err)
			}
			// Simulate a crash after the private instance receipt was fsynced but
			// before that resource ID reached the public inventory.
			if err = s.store.Update(func(inv *serverstate.Inventory) error {
				h, e := inv.Host(host.ID)
				if e != nil {
					return e
				}
				h.ResourceID = ""
				h.Status = "creating"
				return inv.UpsertHost(h)
			}); err != nil {
				t.Fatal(err)
			}
			if foreign {
				f.rows["instance"][0]["Tags"] = []any{map[string]any{"Key": "lazyclash-operation", "Value": "foreign"}}
			}
			before := len(f.writes)
			if !foreign {
				if _, err = s.PlanResume(ctx, host.ID); err != nil {
					t.Fatalf("journal-ahead preview: %v", err)
				}
			}
			repaired, err := s.Resume(ctx, host.ID)
			if len(f.writes) != before {
				t.Fatal("inventory repair mutated the provider")
			}
			inv, loadErr := s.store.Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			saved, loadErr := inv.Host(host.ID)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if foreign {
				if err == nil || saved.ResourceID != "" {
					t.Fatalf("foreign instance accepted: %+v %v", saved, err)
				}
				return
			}
			if err != nil || repaired.ResourceID != host.ResourceID || saved.ResourceID != host.ResourceID {
				t.Fatalf("inventory not repaired: %+v %v", saved, err)
			}
			if _, err = s.PlanAction(ctx, host.ID, "stop"); err != nil {
				t.Fatalf("repaired identity cannot be managed: %v", err)
			}
		})
	}
}

func TestEC2ResumeRepairsFinalDeletionJournalAheadOfInventory(t *testing.T) {
	for _, mode := range []string{"valid", "account-drift", "incomplete-receipts"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, f, req := ec2TestService(t)
			p, err := s.PlanCreate(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			host, err := s.Create(ctx, req, p.Digest)
			if err != nil {
				t.Fatal(err)
			}
			deletion, err := s.PlanAction(ctx, host.ID, "delete")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Action(ctx, host.ID, "delete", deletion.Digest); err != nil {
				t.Fatal(err)
			}
			// The cloud and durable private receipt reached deleted; the final public
			// Owned/status write was interrupted and still contains the prior host.
			if err = s.store.Update(func(inv *serverstate.Inventory) error { return inv.UpsertHost(host) }); err != nil {
				t.Fatal(err)
			}
			if mode == "account-drift" {
				f.account = "999999999999"
			}
			if mode == "incomplete-receipts" {
				op, e := s.readOperation(host.OperationID)
				if e != nil {
					t.Fatal(e)
				}
				op.CloudResources[0].Deleted = false
				if e = s.writeOperation(op); e != nil {
					t.Fatal(e)
				}
			}
			before := len(f.writes)
			repaired, err := s.Resume(ctx, host.ID)
			if len(f.writes) != before {
				t.Fatal("final receipt repair mutated the provider")
			}
			inv, e := s.store.Load()
			if e != nil {
				t.Fatal(e)
			}
			saved, e := inv.Host(host.ID)
			if e != nil {
				t.Fatal(e)
			}
			if mode != "valid" {
				if err == nil || !saved.Owned {
					t.Fatalf("unproven deletion accepted: %+v %v", saved, err)
				}
				return
			}
			if err != nil || repaired.Status != "deleted" || repaired.Owned || saved.Status != "deleted" || saved.Owned {
				t.Fatalf("final deletion not repaired: %+v %v", saved, err)
			}
		})
	}
}
