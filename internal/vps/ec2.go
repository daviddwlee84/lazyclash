package vps

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type ec2Adapter struct{ s *Service }

var ec2Plans = []string{"t4g.micro", "t3a.micro", "t3.micro"}

func ec2Architecture(plan string) string {
	if strings.HasPrefix(plan, "t4g.") {
		return "arm64"
	}
	return "amd64"
}
func ec2AWSArchitecture(architecture string) string {
	if architecture == "amd64" {
		return "x86_64"
	}
	return architecture
}
func ec2Supported(plan string) bool {
	for _, p := range ec2Plans {
		if p == plan {
			return true
		}
	}
	return false
}

func (a ec2Adapter) Identity(ctx context.Context, req CreateRequest) (string, error) {
	v, err := a.s.call(ctx, req, "sts", "get-caller-identity")
	if err != nil {
		return "", err
	}
	m := obj(v)
	account, arn := str(m["Account"]), str(m["Arn"])
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) || !strings.HasPrefix(arn, "arn:aws:") {
		return "", fmt.Errorf("EC2 requires an AWS commercial-partition account with a valid STS identity")
	}
	return "aws-ec2:" + digest("aws:"+account), nil
}

func (a ec2Adapter) region(ctx context.Context, req CreateRequest) error {
	if req.Region == "" {
		return fmt.Errorf("EC2 requires --region")
	}
	rows, err := a.s.ec2Rows(ctx, req, "Regions", "ec2", "describe-regions", "--region-names", req.Region, "--all-regions")
	if err != nil {
		return err
	}
	if len(rows) != 1 || str(rows[0]["RegionName"]) != req.Region {
		return fmt.Errorf("EC2 region is unavailable")
	}
	status := str(rows[0]["OptInStatus"])
	if status != "opt-in-not-required" && status != "opted-in" {
		return fmt.Errorf("EC2 region %s is not enabled for this account", req.Region)
	}
	if strings.HasPrefix(req.Region, "cn-") || strings.HasPrefix(req.Region, "us-gov-") {
		return fmt.Errorf("only AWS commercial regions are supported")
	}
	return nil
}
func (a ec2Adapter) zones(ctx context.Context, req CreateRequest, plan string) ([]string, error) {
	filters := []map[string]any{{"Name": "state", "Values": []string{"available"}}, {"Name": "zone-type", "Values": []string{"availability-zone"}}}
	rows, err := a.s.ec2Rows(ctx, req, "AvailabilityZones", "ec2", "describe-availability-zones", "--filters", jsonValue(filters))
	if err != nil {
		return nil, err
	}
	available := map[string]bool{}
	for _, r := range rows {
		if str(r["State"]) == "available" && str(r["ZoneType"]) == "availability-zone" && str(r["RegionName"]) == req.Region {
			available[str(r["ZoneName"])] = true
		}
	}
	if plan != "" {
		rows, err = a.s.ec2Rows(ctx, req, "InstanceTypeOfferings", "ec2", "describe-instance-type-offerings", "--location-type", "availability-zone", "--filters", jsonValue([]map[string]any{{"Name": "instance-type", "Values": []string{plan}}}))
		if err != nil {
			return nil, err
		}
		offered := map[string]bool{}
		for _, r := range rows {
			if str(r["InstanceType"]) == plan && str(r["LocationType"]) == "availability-zone" {
				offered[str(r["Location"])] = true
			}
		}
		for zone := range available {
			if !offered[zone] {
				delete(available, zone)
			}
		}
	}
	var zones []string
	for zone := range available {
		if req.AvailabilityZone == "" || req.AvailabilityZone == zone {
			zones = append(zones, zone)
		}
	}
	sort.Strings(zones)
	if len(zones) == 0 {
		return nil, fmt.Errorf("EC2 type %s has no available standard Availability Zone matching the request", plan)
	}
	return zones, nil
}
func (a ec2Adapter) image(ctx context.Context, req CreateRequest) (map[string]any, error) {
	if req.Image == "" {
		path := "/aws/service/canonical/ubuntu/server/24.04/stable/current/" + req.Architecture + "/hvm/ebs-gp3/ami-id"
		v, err := a.s.call(ctx, req, "ssm", "get-parameter", "--name", path)
		if err != nil {
			return nil, err
		}
		req.Image = str(obj(obj(v)["Parameter"])["Value"])
	}
	if !regexp.MustCompile(`^ami-[a-f0-9]{8,17}$`).MatchString(req.Image) {
		return nil, fmt.Errorf("Canonical SSM did not return a valid AMI ID")
	}
	rows, err := a.s.ec2Rows(ctx, req, "Images", "ec2", "describe-images", "--image-ids", req.Image, "--owners", "099720109477")
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("EC2 AMI is not an available official Canonical Ubuntu image")
	}
	m := rows[0]
	if str(m["ImageId"]) != req.Image || str(m["OwnerId"]) != "099720109477" || str(m["State"]) != "available" || str(m["RootDeviceType"]) != "ebs" || str(m["VirtualizationType"]) != "hvm" || str(m["Architecture"]) != ec2AWSArchitecture(req.Architecture) || !strings.HasPrefix(str(m["Name"]), "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-") {
		return nil, fmt.Errorf("EC2 requires an official Ubuntu 24.04 gp3 AMI matching the selected architecture")
	}
	root := str(m["RootDeviceName"])
	if root == "" {
		return nil, fmt.Errorf("EC2 AMI lacks a root device")
	}
	found := false
	for _, raw := range arr(m["BlockDeviceMappings"]) {
		b := obj(raw)
		if str(b["DeviceName"]) == root {
			found = true
			if req.DiskGB > 0 && num(obj(b["Ebs"])["VolumeSize"]) > float64(req.DiskGB) {
				return nil, fmt.Errorf("EC2 disk is smaller than the selected AMI root volume")
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("EC2 AMI root device mapping is missing")
	}
	return m, nil
}
func (a ec2Adapter) Resolve(ctx context.Context, req CreateRequest) (CreateRequest, Quote, error) {
	var empty Quote
	if req.Provider != "aws-ec2" {
		return req, empty, fmt.Errorf("wrong EC2 provider")
	}
	if req.FirewallID != "" || req.SubnetID != "" {
		return req, empty, fmt.Errorf("EC2 creates a dedicated VPC and security group; register existing VMs instead of supplying shared network IDs")
	}
	if req.Architecture == "" {
		req.Architecture = "auto"
	}
	if req.Architecture != "auto" && req.Architecture != "amd64" && req.Architecture != "arm64" {
		return req, empty, fmt.Errorf("architecture must be auto, amd64 or arm64")
	}
	if req.DiskGB == 0 {
		req.DiskGB = 20
	}
	if req.DiskGB < 8 || req.DiskGB > 16384 {
		return req, empty, fmt.Errorf("EC2 gp3 disk must be 8–16384 GiB")
	}
	if req.SSHUser == "" {
		req.SSHUser = "ubuntu"
	}
	if req.SSHUser != "ubuntu" {
		return req, empty, fmt.Errorf("EC2 Canonical Ubuntu images require SSH user ubuntu")
	}
	if req.Plan != "" && !ec2Supported(req.Plan) {
		return req, empty, fmt.Errorf("EC2 baseline plans are t4g.micro, t3a.micro and t3.micro")
	}
	if err := a.region(ctx, req); err != nil {
		return req, empty, err
	}
	candidates := ec2Plans
	if req.Plan != "" {
		candidates = []string{req.Plan}
	}
	best := math.Inf(1)
	var selected CreateRequest
	var quote Quote
	var failures []string
	for _, plan := range candidates {
		arch := ec2Architecture(plan)
		if req.Architecture != "auto" && req.Architecture != arch {
			continue
		}
		candidate := req
		candidate.Plan = plan
		candidate.Architecture = arch
		zones, err := a.zones(ctx, candidate, plan)
		if err != nil {
			if req.Plan != "" {
				return req, empty, err
			}
			failures = append(failures, plan+": unavailable")
			continue
		}
		candidate.AvailabilityZone = zones[0]
		rows, err := a.s.ec2Rows(ctx, candidate, "InstanceTypes", "ec2", "describe-instance-types", "--instance-types", plan)
		if err != nil {
			return req, empty, err
		}
		if len(rows) != 1 || str(rows[0]["InstanceType"]) != plan || !contains(obj(rows[0]["ProcessorInfo"])["SupportedArchitectures"], ec2AWSArchitecture(arch)) || num(obj(rows[0]["MemoryInfo"])["SizeInMiB"]) < 1024 || num(obj(rows[0]["VCpuInfo"])["DefaultVCpus"]) != 2 {
			return req, empty, fmt.Errorf("EC2 plan does not meet the reviewed 1 GiB architecture requirements")
		}
		img, err := a.image(ctx, candidate)
		if err != nil {
			if req.Plan != "" || req.Architecture != "auto" {
				return req, empty, err
			}
			failures = append(failures, plan+": Ubuntu image unavailable")
			continue
		}
		candidate.Image = str(img["ImageId"])
		candidate.ImageVersion = str(img["CreationDate"])
		costs, err := a.s.ec2Cost(ctx, candidate, candidate.DiskGB)
		if err != nil {
			return req, empty, err
		}
		price := costs.Compute + costs.Disk + costs.IPv4
		if price >= best {
			continue
		}
		best = price
		selected = candidate
		source := "https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html"
		stop := costs.Disk + costs.IdleIPv4
		quote = Quote{Provider: req.Provider, Plan: plan, Region: req.Region, MonthlyUSD: price, MemoryMiB: int(num(obj(rows[0]["MemoryInfo"])["SizeInMiB"])), VCPUs: int(num(obj(rows[0]["VCpuInfo"])["DefaultVCpus"])), DiskGB: req.DiskGB, TransferUnit: "GB", Live: true, Architecture: arch, StoppedMonthlyUSD: &stop, Components: []CostComponent{{Name: "compute", MonthlyUSD: costs.Compute, Unit: "hour", UnitUSD: costs.Compute / 730, Quantity: 730, Source: source}, {Name: "disk", MonthlyUSD: costs.Disk, Unit: "GiB-month", UnitUSD: costs.Disk / float64(req.DiskGB), Quantity: float64(req.DiskGB), Source: source}, {Name: "ipv4", MonthlyUSD: costs.IPv4, Unit: "hour", UnitUSD: costs.IPv4 / 730, Quantity: 730, Source: source}}, Notes: []string{"730-hour on-demand month; includes one encrypted gp3 root disk and one static public IPv4. Taxes and outbound data are additional.", "Burstable CPU credits are explicitly Standard: performance falls to the baseline when credits run out; no unlimited-credit surcharge.", "Stopping preserves billable EBS storage and the Elastic IP. Delete the owned resources to release those costs.", "Account-wide free transfer, trial credits and negotiated discounts are not deducted. Availability and quota do not reserve regional capacity."}, TransferPricing: &TransferPricing{Basis: "outbound", Source: source, Checked: a.s.options.Now().UTC().Format("2006-01-02"), SharedAllowanceGB: 100}}
		for _, tier := range costs.Transfer {
			to := tier.End
			if math.IsInf(to, 1) {
				to = 0
			}
			quote.TransferPricing.Tiers = append(quote.TransferPricing.Tiers, PriceTier{From: tier.Begin, To: to, USD: tier.USD})
		}
	}
	if math.IsInf(best, 1) {
		return req, empty, fmt.Errorf("no compatible EC2 baseline plan is available (%s)", strings.Join(failures, ", "))
	}
	if selected.SSHKey != "" {
		if err := a.quota(ctx, selected); err != nil {
			return req, empty, err
		}
	}
	if len(failures) > 0 {
		quote.Notes = append(quote.Notes, "Unavailable candidates: "+strings.Join(failures, ", "))
	}
	return selected, quote, nil
}
func (a ec2Adapter) Discover(ctx context.Context, req CreateRequest, kind string) ([]Choice, error) {
	var result []Choice
	switch kind {
	case "regions":
		if req.Region == "" {
			req.Region = "us-east-1"
		}
		rows, err := a.s.ec2Rows(ctx, req, "Regions", "ec2", "describe-regions", "--all-regions")
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			status := str(r["OptInStatus"])
			name := str(r["RegionName"])
			if (status == "opt-in-not-required" || status == "opted-in") && name != "" && !strings.HasPrefix(name, "cn-") && !strings.HasPrefix(name, "us-gov-") {
				result = append(result, Choice{ID: name, Label: name})
			}
		}
	case "zones", "availability-zones":
		zones, err := a.zones(ctx, req, req.Plan)
		if err != nil {
			return nil, err
		}
		for _, z := range zones {
			result = append(result, Choice{ID: z, Label: z})
		}
	case "plans":
		for _, plan := range ec2Plans {
			candidate := req
			candidate.Plan = plan
			candidate.Image = ""
			if _, err := a.zones(ctx, candidate, plan); err != nil {
				continue
			}
			if candidate.Architecture != "" && candidate.Architecture != "auto" && candidate.Architecture != ec2Architecture(plan) {
				continue
			}
			candidate, q, err := a.Resolve(ctx, candidate)
			if err != nil {
				return nil, err
			}
			result = append(result, Choice{ID: plan, Label: fmt.Sprintf("%s · %s · %d MiB · $%.2f/mo fixed incl. disk/IPv4 · CPU credits Standard", plan, candidate.Architecture, q.MemoryMiB, q.MonthlyUSD)})
		}
	case "images":
		arches := []string{"arm64", "amd64"}
		if req.Plan != "" {
			if !ec2Supported(req.Plan) {
				return nil, fmt.Errorf("unsupported EC2 plan")
			}
			arches = []string{ec2Architecture(req.Plan)}
		} else if req.Architecture != "" && req.Architecture != "auto" {
			arches = []string{req.Architecture}
		}
		for _, arch := range arches {
			candidate := req
			candidate.Architecture = arch
			candidate.Image = ""
			m, err := a.image(ctx, candidate)
			if err != nil {
				return nil, err
			}
			result = append(result, Choice{ID: str(m["ImageId"]), Label: "Ubuntu 24.04 LTS " + arch + " · " + str(m["CreationDate"])})
		}
	case "keys":
		return nil, fmt.Errorf("EC2 uses a local SSH public key file; no account key is reused")
	default:
		return nil, fmt.Errorf("unsupported EC2 discovery %s", kind)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Label < result[j].Label })
	if len(result) == 0 {
		return nil, fmt.Errorf("EC2 returned no suitable %s", kind)
	}
	return result, nil
}

// Observe never changes the route graph or creates replacement resources.
func (a ec2Adapter) Observe(ctx context.Context, op operation) (serverstate.Host, error) {
	host := op.Host
	row, err := a.find(ctx, &op, "instance")
	if err != nil {
		return host, err
	}
	if row == nil {
		if host.ResourceID != "" {
			host.Status = "cleanup-required"
		}
		return host, nil
	}
	host.ResourceID = str(row["InstanceId"])
	host.Status = str(obj(row["State"])["Name"])
	address, err := a.find(ctx, &op, "ec2-address")
	if err != nil {
		return host, err
	}
	if address != nil && str(address["InstanceId"]) == host.ResourceID {
		host.PublicHost = str(address["PublicIp"])
		host.SSHHost = op.Request.SSHUser + "@" + host.PublicHost
	} else {
		host.PublicHost = ""
		host.SSHHost = ""
	}
	return host, nil
}
