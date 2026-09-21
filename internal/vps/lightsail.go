package vps

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

type lightsailAdapter struct{ s *Service }

const lightsailPriceSource = "https://aws.amazon.com/lightsail/pricing/"
const lightsailTransferSource = "https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-faq-data-transfer-allowance.html"
const lightsailInitializerVersion = "lightsail-ubuntu-ssh-v1"

// Lightsail does not expose an AMI architecture on its blueprint API. The
// reviewed Ubuntu blueprint is x86; a future ARM blueprint needs an explicit
// reviewed mapping, rather than inferring its compatibility from a bundle.
func lightsailBlueprintArchitecture(id string) string {
	if id == "ubuntu_24_04" {
		return "amd64"
	}
	return ""
}

// Bundle.instanceType is a size such as "micro", not an EC2 CPU family.
// AWS defines bundle/blueprint compatibility by platform and power. Architecture
// comes from the explicitly reviewed blueprint, never from a size label.
// https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_Bundle.html
func lightsailBundleSupportsBlueprint(bundle, blueprint map[string]any) bool {
	return contains(bundle["supportedPlatforms"], str(blueprint["platform"])) && num(bundle["power"]) >= num(blueprint["minPower"])
}
func lightsailJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func (a lightsailAdapter) Identity(ctx context.Context, r CreateRequest) (string, error) {
	v, err := a.s.call(ctx, r, "sts", "get-caller-identity")
	if err != nil {
		return "", err
	}
	m := obj(v)
	account, arn := str(m["Account"]), strings.Split(str(m["Arn"]), ":")
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) || len(arn) < 6 || arn[0] != "arn" || arn[1] != "aws" || arn[4] != account {
		return "", fmt.Errorf("Lightsail requires a valid AWS commercial-partition STS account")
	}
	return "aws:" + digest([]string{"aws", account}), nil
}

// Suppress the CLI paginator and pass service page tokens as structured input.
// This supports every returned page without interpreting tokens as shell data.
func (a lightsailAdapter) rows(ctx context.Context, r CreateRequest, action, key string, input map[string]any) ([]map[string]any, error) {
	request := map[string]any{}
	for k, v := range input {
		request[k] = v
	}
	seen := map[string]bool{}
	var rows []map[string]any
	for page := 0; page < 100; page++ {
		v, err := a.s.call(ctx, r, "lightsail", action, "--no-paginate", "--cli-input-json", lightsailJSON(request))
		if err != nil {
			return nil, err
		}
		batch, err := strictItems(v, key)
		if err != nil {
			return nil, err
		}
		rows = append(rows, batch...)
		var token string
		if raw := obj(v)["nextPageToken"]; raw != nil {
			var ok bool
			token, ok = raw.(string)
			if !ok {
				return nil, fmt.Errorf("Lightsail returned a malformed page token; inventory is incomplete")
			}
		}
		if token == "" {
			return rows, nil
		}
		if seen[token] || strings.ContainsAny(token, "\x00\r\n") {
			return nil, fmt.Errorf("Lightsail returned an invalid or repeated page token")
		}
		seen[token] = true
		request["pageToken"] = token
	}
	return nil, fmt.Errorf("Lightsail exceeded the 100-page discovery limit")
}
func (a lightsailAdapter) zones(ctx context.Context, r CreateRequest) ([]string, error) {
	if r.Region == "" || strings.HasPrefix(r.Region, "cn-") || strings.HasPrefix(r.Region, "us-gov-") {
		return nil, fmt.Errorf("Lightsail requires a commercial AWS --region")
	}
	rows, err := a.rows(ctx, r, "get-regions", "regions", map[string]any{"includeAvailabilityZones": true})
	if err != nil {
		return nil, err
	}
	var zones []string
	for _, row := range rows {
		if str(row["name"]) != r.Region {
			continue
		}
		for _, item := range arr(row["availabilityZones"]) {
			zone := obj(item)
			name := str(zone["zoneName"])
			if name != "" && str(zone["state"]) == "available" {
				zones = append(zones, name)
			}
		}
	}
	sort.Strings(zones)
	if len(zones) == 0 {
		return nil, fmt.Errorf("Lightsail region has no available availability zones")
	}
	return zones, nil
}
func (a lightsailAdapter) bundles(ctx context.Context, r CreateRequest) ([]map[string]any, error) {
	rows, err := a.rows(ctx, r, "get-bundles", "bundles", map[string]any{"includeInactive": false})
	if err != nil {
		return nil, err
	}
	var suitable []map[string]any
	for _, m := range rows {
		price, memory := num(m["price"]), num(m["ramSizeInGb"])*1024
		if !truth(m["isActive"]) || !contains(m["supportedPlatforms"], "LINUX_UNIX") || num(m["publicIpv4AddressCount"]) != 1 || memory < 1024 || memory > 4096 || price <= 0 || math.IsNaN(price) || math.IsInf(price, 0) || str(m["bundleId"]) == "" || num(m["diskSizeInGb"]) <= 0 || num(m["transferPerMonthInGb"]) < 0 {
			continue
		}
		suitable = append(suitable, m)
	}
	sort.SliceStable(suitable, func(i, j int) bool {
		if num(suitable[i]["price"]) == num(suitable[j]["price"]) {
			return str(suitable[i]["bundleId"]) < str(suitable[j]["bundleId"])
		}
		return num(suitable[i]["price"]) < num(suitable[j]["price"])
	})
	return suitable, nil
}
func (a lightsailAdapter) blueprints(ctx context.Context, r CreateRequest) ([]map[string]any, error) {
	rows, err := a.rows(ctx, r, "get-blueprints", "blueprints", map[string]any{"includeInactive": false})
	if err != nil {
		return nil, err
	}
	var suitable []map[string]any
	for _, m := range rows {
		arch := lightsailBlueprintArchitecture(str(m["blueprintId"]))
		if !truth(m["isActive"]) || str(m["type"]) != "os" || str(m["platform"]) != "LINUX_UNIX" || !strings.HasPrefix(str(m["version"]), "24.04") || str(m["versionCode"]) == "" || arch == "" {
			continue
		}
		if r.Architecture != "" && r.Architecture != "auto" && r.Architecture != arch {
			continue
		}
		suitable = append(suitable, m)
	}
	return suitable, nil
}

func (a lightsailAdapter) Resolve(ctx context.Context, r CreateRequest) (CreateRequest, Quote, error) {
	var q Quote
	zones, err := a.zones(ctx, r)
	if err != nil {
		return r, q, err
	}
	if r.AvailabilityZone == "" {
		r.AvailabilityZone = zones[0]
	}
	zoneOK := false
	for _, z := range zones {
		zoneOK = zoneOK || z == r.AvailabilityZone
	}
	if !zoneOK {
		return r, q, fmt.Errorf("Lightsail availability zone is not available in the requested region")
	}
	if r.DiskGB != 0 {
		return r, q, fmt.Errorf("Lightsail disk size is fixed by the bundle")
	}
	bundles, err := a.bundles(ctx, r)
	if err != nil {
		return r, q, err
	}
	images, err := a.blueprints(ctx, r)
	if err != nil {
		return r, q, err
	}
	var bundle, blueprint map[string]any
	for _, b := range bundles {
		if r.Plan != "" && r.Plan != str(b["bundleId"]) {
			continue
		}
		for _, image := range images {
			if (r.Image != "" && r.Image != str(image["blueprintId"])) || !lightsailBundleSupportsBlueprint(b, image) {
				continue
			}
			bundle, blueprint = b, image
			break
		}
		if bundle != nil {
			break
		}
	}
	if bundle == nil {
		return r, q, fmt.Errorf("no active Lightsail Linux IPv4 bundle with at least 1 GiB RAM matches the reviewed Ubuntu 24.04 architecture and minimum power")
	}
	r.Plan, r.Architecture, r.Image = str(bundle["bundleId"]), lightsailBlueprintArchitecture(str(blueprint["blueprintId"])), str(blueprint["blueprintId"])
	version := str(blueprint["versionCode"])
	if r.ImageVersion != "" && r.ImageVersion != version {
		return r, q, fmt.Errorf("Lightsail blueprint version changed; inspect a new preview")
	}
	r.ImageVersion = version
	if r.SSHKey != "" {
		data, err := lightsailUserData(r)
		if err != nil {
			return r, q, err
		}
		sum := sha256.Sum256([]byte(data))
		hash := hex.EncodeToString(sum[:])
		if (r.InitializerVersion != "" && r.InitializerVersion != lightsailInitializerVersion) || (r.InitializerSHA256 != "" && r.InitializerSHA256 != hash) {
			return r, q, fmt.Errorf("Lightsail SSH initializer differs from the reviewed version/hash")
		}
		r.InitializerVersion, r.InitializerSHA256 = lightsailInitializerVersion, hash
	}
	price := num(bundle["price"])
	q = Quote{Provider: "aws-lightsail", Plan: r.Plan, Region: r.Region, Architecture: r.Architecture, MonthlyUSD: price, MemoryMiB: int(num(bundle["ramSizeInGb"]) * 1024), VCPUs: int(num(bundle["cpuCount"])), DiskGB: int(num(bundle["diskSizeInGb"])), TransferGB: int(num(bundle["transferPerMonthInGb"])), TransferUnit: "GB", Live: true,
		Components: []CostComponent{{Name: "bundle", MonthlyUSD: price, Unit: "month", Quantity: 1, UnitUSD: price, Source: lightsailPriceSource}}, StoppedMonthlyUSD: &price,
		TransferPricing: &TransferPricing{Basis: "combined", Source: lightsailTransferSource, Checked: "2026-09-21"},
		Notes:           []string{"Linux IPv4 bundle includes compute, root disk and one static IPv4 while attached; an unattached static IP can incur additional charges.", "Stopped Lightsail instances continue accruing bundle charges until deleted.", "Inbound and outbound both consume the bundle allowance; only excess outbound is charged. A verified regional instance-overage rate is unavailable, so excess-transfer totals remain unknown.", "Burstable CPUs have a sustained baseline and burst capacity; benchmark the required proxy throughput.", "The active Ubuntu blueprint ID/version and SSH initializer hash are reviewed; the provider API accepts the blueprint ID, so its version is rechecked immediately before launch."}}
	return r, q, nil
}

func lightsailUserData(r CreateRequest) (string, error) {
	key, err := publicKey(r.SSHKey)
	if err != nil {
		return "", err
	}
	if r.SSHKeyFingerprint != "" && digest(key) != r.SSHKeyFingerprint {
		return "", fmt.Errorf("Lightsail SSH public key changed after review")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	return "#!/bin/sh\nset -eu\ninstall -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh\ntouch /home/ubuntu/.ssh/authorized_keys\nchown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys\nchmod 600 /home/ubuntu/.ssh/authorized_keys\nkey=$(printf '%s' '" + encoded + "' | base64 -d)\ngrep -Fqx -- \"$key\" /home/ubuntu/.ssh/authorized_keys || printf '%s\\n' \"$key\" >> /home/ubuntu/.ssh/authorized_keys\n", nil
}

func (a lightsailAdapter) Discover(ctx context.Context, r CreateRequest, kind string) ([]Choice, error) {
	var choices []Choice
	switch kind {
	case "regions":
		rows, err := a.rows(ctx, r, "get-regions", "regions", map[string]any{"includeAvailabilityZones": true})
		if err != nil {
			return nil, err
		}
		for _, m := range rows {
			if name := str(m["name"]); name != "" && !strings.HasPrefix(name, "cn-") && !strings.HasPrefix(name, "us-gov-") {
				choices = append(choices, Choice{ID: name, Label: name + " · " + str(m["displayName"])})
			}
		}
	case "zones", "availability-zones":
		zones, err := a.zones(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, z := range zones {
			choices = append(choices, Choice{ID: z, Label: z})
		}
	case "plans":
		if _, err := a.zones(ctx, r); err != nil {
			return nil, err
		}
		rows, err := a.bundles(ctx, r)
		if err != nil {
			return nil, err
		}
		images, err := a.blueprints(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, m := range rows {
			architecture := ""
			for _, image := range images {
				if lightsailBundleSupportsBlueprint(m, image) {
					architecture = lightsailBlueprintArchitecture(str(image["blueprintId"]))
					break
				}
			}
			if architecture != "" {
				id := str(m["bundleId"])
				choices = append(choices, Choice{ID: id, Label: fmt.Sprintf("%s · %s · %.0f MiB · $%.2f/mo bundle incl. IPv4", id, architecture, num(m["ramSizeInGb"])*1024, num(m["price"]))})
			}
		}
	case "images":
		var selectedBundle map[string]any
		if r.Plan != "" {
			bundles, err := a.bundles(ctx, r)
			if err != nil {
				return nil, err
			}
			for _, b := range bundles {
				if str(b["bundleId"]) == r.Plan {
					selectedBundle = b
				}
			}
			if selectedBundle == nil {
				return nil, fmt.Errorf("Lightsail plan is unavailable or incompatible")
			}
		}
		rows, err := a.blueprints(ctx, r)
		if err != nil {
			return nil, err
		}
		for _, m := range rows {
			if selectedBundle != nil && !lightsailBundleSupportsBlueprint(selectedBundle, m) {
				continue
			}
			id := str(m["blueprintId"])
			choices = append(choices, Choice{ID: id, Label: "Ubuntu 24.04 · " + lightsailBlueprintArchitecture(id) + " · " + str(m["versionCode"])})
		}
	default:
		return nil, fmt.Errorf("Lightsail supports regions, zones, plans and images discovery; SSH keys are local public-key files")
	}
	if len(choices) == 0 {
		return nil, fmt.Errorf("Lightsail returned no compatible %s", kind)
	}
	return choices, nil
}
