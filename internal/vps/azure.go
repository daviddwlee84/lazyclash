package vps

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type azureAdapter struct{ s *Service }

const azurePriceSource = "https://prices.azure.com/api/retail/prices"

func (a azureAdapter) call(ctx context.Context, r CreateRequest, args ...string) (any, error) {
	return a.s.call(ctx, r, args...)
}

func (a azureAdapter) Identity(ctx context.Context, r CreateRequest) (string, error) {
	if r.SubscriptionID == "" {
		return "", fmt.Errorf("Azure requires --subscription; the CLI default subscription is not used")
	}
	v, err := a.call(ctx, r, "account", "show")
	if err != nil {
		return "", err
	}
	m := obj(v)
	if str(m["environmentName"]) != "AzureCloud" {
		return "", fmt.Errorf("only the AzureCloud commercial cloud is supported")
	}
	if !strings.EqualFold(str(m["id"]), r.SubscriptionID) || str(m["tenantId"]) == "" || str(m["state"]) != "Enabled" {
		return "", fmt.Errorf("Azure subscription identity is unavailable, disabled or differs from --subscription")
	}
	return "azure:" + digest([]string{"AzureCloud", strings.ToLower(str(m["tenantId"])), strings.ToLower(str(m["id"]))}), nil
}

type azureSize struct {
	name, arch   string
	memory, cpus int
	zones        []string
}

func (a azureAdapter) sizes(ctx context.Context, r CreateRequest) ([]azureSize, error) {
	if r.Region == "" {
		return nil, fmt.Errorf("Azure size discovery requires --region")
	}
	v, err := a.call(ctx, r, "vm", "list-skus", "--location", r.Region, "--resource-type", "virtualMachines", "--all")
	if err != nil {
		return nil, err
	}
	rows, err := strictItems(v)
	if err != nil {
		return nil, err
	}
	var out []azureSize
	for _, m := range rows {
		if str(m["resourceType"]) != "virtualMachines" {
			continue
		}
		x := azureSize{name: str(m["name"])}
		if !contains(m["locations"], r.Region) {
			continue
		}
		caps := map[string]string{}
		for _, cv := range arr(m["capabilities"]) {
			c := obj(cv)
			caps[str(c["name"])] = str(c["value"])
		}
		mem, _ := strconv.ParseFloat(caps["MemoryGB"], 64)
		x.memory = int(mem * 1024)
		x.cpus, _ = strconv.Atoi(caps["vCPUs"])
		switch strings.ToLower(caps["CpuArchitectureType"]) {
		case "arm64":
			x.arch = "arm64"
		case "x64", "x86_64", "amd64":
			x.arch = "amd64"
		default:
			continue
		}
		if x.memory < 1024 || x.cpus < 1 || !strings.Contains(caps["HyperVGenerations"], "V2") {
			continue
		}
		for _, li := range arr(m["locationInfo"]) {
			l := obj(li)
			if str(l["location"]) == r.Region {
				for _, z := range arr(l["zones"]) {
					x.zones = append(x.zones, str(z))
				}
			}
		}
		blocked := false
		for _, rv := range arr(m["restrictions"]) {
			rr := obj(rv)
			ri := obj(rr["restrictionInfo"])
			if str(rr["type"]) == "Location" && (len(arr(rr["values"])) == 0 || contains(rr["values"], r.Region)) {
				blocked = true
			}
			if r.AvailabilityZone != "" && str(rr["type"]) == "Zone" && (len(arr(ri["locations"])) == 0 || contains(ri["locations"], r.Region)) && contains(ri["zones"], r.AvailabilityZone) {
				blocked = true
			}
		}
		if blocked || (r.AvailabilityZone != "" && !azureContains(x.zones, r.AvailabilityZone)) {
			continue
		}
		if r.Architecture != "" && r.Architecture != "auto" && r.Architecture != x.arch {
			continue
		}
		out = append(out, x)
	}
	return out, nil
}
func azureContains(a []string, v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}
func azureRecommended(s string) bool {
	return azureContains([]string{"Standard_B1s", "Standard_B2ats_v2", "Standard_B2pts_v2", "Standard_B2ts_v2"}, s)
}

func (a azureAdapter) Resolve(ctx context.Context, r CreateRequest) (CreateRequest, Quote, error) {
	if r.SubscriptionID == "" {
		return r, Quote{}, fmt.Errorf("Azure requires --subscription")
	}
	if r.Profile != "" {
		return r, Quote{}, fmt.Errorf("Azure uses --subscription, not --profile")
	}
	if r.FirewallID != "" || r.SubnetID != "" {
		return r, Quote{}, fmt.Errorf("Azure creation uses a dedicated owned network; register an existing VM to use existing networking")
	}
	if r.DiskGB == 0 {
		r.DiskGB = 32
	}
	if _, err := azureDiskTier(r.DiskGB); err != nil {
		return r, Quote{}, err
	}
	sizes, err := a.sizes(ctx, r)
	if err != nil {
		return r, Quote{}, err
	}
	var selected *azureSize
	var quote Quote
	for _, size := range sizes {
		if r.Plan != "" && size.name != r.Plan {
			continue
		}
		if r.Plan == "" && !azureRecommended(size.name) {
			continue
		}
		q, e := a.quoteSize(ctx, r, size)
		if e != nil {
			if r.Plan != "" {
				return r, q, e
			}
			continue
		}
		if selected == nil || q.MonthlyUSD < quote.MonthlyUSD || (q.MonthlyUSD == quote.MonthlyUSD && size.name < selected.name) {
			x := size
			selected = &x
			quote = q
		}
	}
	if selected == nil {
		return r, Quote{}, fmt.Errorf("no fully priced compatible Azure size is available in %s; inspect subscription quota, SKU restrictions, architecture and zone", r.Region)
	}
	r.Plan = selected.name
	r.Architecture = selected.arch
	if r.Image == "" {
		choices, e := a.images(ctx, r)
		if e != nil {
			return r, quote, e
		}
		r.Image = choices[len(choices)-1].ID
	}
	fields := strings.Split(r.Image, ":")
	sku := "server"
	if r.Architecture == "arm64" {
		sku = "server-arm64"
	}
	if len(fields) != 4 || !strings.EqualFold(fields[0], "Canonical") || fields[1] != "ubuntu-24_04-lts" || fields[2] != sku || fields[3] == "latest" || fields[3] == "" {
		return r, quote, fmt.Errorf("Azure requires a pinned Canonical Ubuntu 24.04 %s image URN", r.Architecture)
	}
	v, e := a.call(ctx, r, "vm", "image", "show", "--location", r.Region, "--urn", r.Image)
	if e != nil {
		return r, quote, e
	}
	m := obj(v)
	arch := strings.ToLower(str(m["architecture"]))
	if (r.Architecture == "arm64" && arch != "arm64") || (r.Architecture == "amd64" && arch != "x64") || str(obj(m["osDiskImage"])["operatingSystem"]) != "Linux" || str(m["hyperVGeneration"]) != "V2" {
		return r, quote, fmt.Errorf("Azure image architecture, operating system or generation differs from the reviewed size")
	}
	if version := str(m["name"]); version != "" && version != fields[3] {
		return r, quote, fmt.Errorf("Azure image version changed")
	}
	r.ImageVersion = fields[3]
	return r, quote, nil
}
func (a azureAdapter) images(ctx context.Context, r CreateRequest) ([]Choice, error) {
	arch := r.Architecture
	if arch == "" || arch == "auto" {
		if r.Plan == "" {
			return nil, fmt.Errorf("select an Azure plan before image discovery")
		}
		ss, e := a.sizes(ctx, r)
		if e != nil {
			return nil, e
		}
		for _, s := range ss {
			if s.name == r.Plan {
				arch = s.arch
			}
		}
	}
	sku := "server"
	if arch == "arm64" {
		sku = "server-arm64"
	} else if arch != "amd64" {
		return nil, fmt.Errorf("Azure image architecture is not resolved")
	}
	v, e := a.call(ctx, r, "vm", "image", "list", "--location", r.Region, "--publisher", "Canonical", "--offer", "ubuntu-24_04-lts", "--sku", sku, "--all")
	if e != nil {
		return nil, e
	}
	rows, e := strictItems(v)
	if e != nil {
		return nil, e
	}
	var out []Choice
	for _, m := range rows {
		if !strings.EqualFold(str(m["publisher"]), "Canonical") || str(m["offer"]) != "ubuntu-24_04-lts" || str(m["sku"]) != sku {
			continue
		}
		ver := str(m["version"])
		if ver == "" || ver == "latest" {
			continue
		}
		out = append(out, Choice{ID: "Canonical:ubuntu-24_04-lts:" + sku + ":" + ver, Label: "Ubuntu 24.04 " + arch + " · " + ver})
	}
	sort.Slice(out, func(i, j int) bool { return azureVersionLess(out[i].ID, out[j].ID) })
	if len(out) == 0 {
		return nil, fmt.Errorf("no pinned Canonical Ubuntu 24.04 image available")
	}
	return out, nil
}
func azureVersionLess(a, b string) bool {
	aa := strings.Split(a[strings.LastIndex(a, ":")+1:], ".")
	bb := strings.Split(b[strings.LastIndex(b, ":")+1:], ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		x, _ := strconv.Atoi(aa[i])
		y, _ := strconv.Atoi(bb[i])
		if x != y {
			return x < y
		}
	}
	return a < b
}
func (a azureAdapter) Discover(ctx context.Context, r CreateRequest, kind string) ([]Choice, error) {
	var out []Choice
	switch kind {
	case "subscriptions":
		v, e := a.call(ctx, r, "account", "list")
		if e != nil {
			return nil, e
		}
		rows, e := strictItems(v)
		if e != nil {
			return nil, e
		}
		for _, m := range rows {
			if str(m["environmentName"]) == "AzureCloud" && str(m["state"]) == "Enabled" {
				out = append(out, Choice{ID: str(m["id"]), Label: str(m["name"]) + " · " + str(m["id"])})
			}
		}
	case "regions":
		v, e := a.call(ctx, r, "account", "list-locations")
		if e != nil {
			return nil, e
		}
		rows, e := strictItems(v)
		if e != nil {
			return nil, e
		}
		for _, m := range rows {
			if str(obj(m["metadata"])["regionType"]) != "Physical" {
				continue
			}
			out = append(out, Choice{ID: str(m["name"]), Label: str(m["displayName"])})
		}
	case "images":
		return a.images(ctx, r)
	case "plans", "zones":
		ss, e := a.sizes(ctx, r)
		if e != nil {
			return nil, e
		}
		if r.DiskGB == 0 {
			r.DiskGB = 32
		}
		seen := map[string]bool{}
		for _, s := range ss {
			if kind == "zones" {
				if r.Plan != "" && s.name != r.Plan {
					continue
				}
				for _, z := range s.zones {
					if !seen[z] {
						seen[z] = true
						out = append(out, Choice{ID: z, Label: r.Region + " zone " + z})
					}
				}
				continue
			}
			if !azureRecommended(s.name) {
				continue
			}
			q, e := a.quoteSize(ctx, r, s)
			if e != nil {
				continue
			}
			out = append(out, Choice{ID: s.name, Label: fmt.Sprintf("%s · %s · %d MiB · $%.2f/mo including disk/IPv4", s.name, s.arch, s.memory, q.MonthlyUSD)})
		}
	default:
		return nil, fmt.Errorf("unsupported Azure discovery %q", kind)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	if len(out) == 0 {
		return nil, fmt.Errorf("Azure returned no suitable %s", kind)
	}
	return out, nil
}

func azureHost(m map[string]any) serverstate.Host {
	h := serverstate.Host{ResourceID: str(m["id"]), Status: str(m["powerState"])}
	if h.Status == "" {
		h.Status = str(m["provisioningState"])
	}
	return h
}
