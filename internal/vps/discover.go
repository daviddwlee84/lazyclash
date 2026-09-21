package vps

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Discover returns only fields suitable for a picker; raw cloud output (which
// may contain access tokens, startup scripts or passwords) is never returned.
func (s *Service) Discover(ctx context.Context, req CreateRequest, kind string) ([]Choice, error) {
	if isCloudProvider(req.Provider) {
		if err := validateCloudDraft(req); err != nil {
			return nil, err
		}
		return s.cloudAdapter(req.Provider).Discover(ctx, req, kind)
	}
	var args []string
	key := ""
	idField := "id"
	labelField := "name"
	switch req.Provider {
	case "digitalocean":
		switch kind {
		case "regions":
			args = []string{"compute", "region", "list"}
			key = "regions"
			idField = "slug"
		case "plans":
			args = []string{"compute", "size", "list"}
			key = "sizes"
			idField = "slug"
			labelField = "slug"
		case "keys":
			args = []string{"compute", "ssh-key", "list"}
			key = "ssh_keys"
		case "images":
			return []Choice{{ID: "ubuntu-24-04-x64", Label: "Ubuntu 24.04 LTS x64"}}, nil
		default:
			return nil, fmt.Errorf("unsupported discovery %s", kind)
		}
	case "vultr":
		switch kind {
		case "regions":
			args = []string{"regions", "list"}
			key = "regions"
		case "plans":
			args = []string{"plans", "list"}
			key = "plans"
			labelField = "id"
		case "images":
			args = []string{"os", "list"}
			key = "os"
		case "keys":
			args = []string{"ssh-key", "list"}
			key = "ssh_keys"
		default:
			return nil, fmt.Errorf("unsupported discovery %s", kind)
		}
	case "linode":
		switch kind {
		case "regions":
			args = []string{"regions", "list"}
			key = "data"
			labelField = "label"
		case "plans":
			args = []string{"linodes", "types"}
			key = "data"
			labelField = "label"
		case "images":
			return []Choice{{ID: "linode/ubuntu24.04", Label: "Ubuntu 24.04 LTS"}}, nil
		default:
			return nil, fmt.Errorf("unsupported discovery %s", kind)
		}
	case "oracle":
		key = "data"
		switch kind {
		case "regions":
			args = []string{"iam", "region-subscription", "list", "--tenancy-id", req.TenancyID, "--all"}
			idField = "region-name"
			labelField = "region-name"
		case "plans":
			return []Choice{{ID: "VM.Standard.A1.Flex", Label: "Always Free A1 · 1 OCPU / 6 GB / 50 GB"}}, nil
		case "images":
			args = []string{"compute", "image", "list", "--compartment-id", req.CompartmentID, "--operating-system", "Canonical Ubuntu", "--operating-system-version", "24.04", "--shape", "VM.Standard.A1.Flex", "--all"}
			labelField = "display-name"
		case "ads":
			args = []string{"iam", "availability-domain", "list", "--compartment-id", req.TenancyID, "--all"}
			idField = "name"
		case "compartments":
			args = []string{"iam", "compartment", "list", "--compartment-id", req.TenancyID, "--compartment-id-in-subtree", "true", "--access-level", "ACCESSIBLE", "--all"}
		default:
			return nil, fmt.Errorf("unsupported discovery %s", kind)
		}
	default:
		return nil, fmt.Errorf("unknown provider %q", req.Provider)
	}
	var v any
	var err error
	if req.Provider == "vultr" {
		v, err = s.vultrList(ctx, req, key, args...)
	} else {
		v, err = s.call(ctx, req, args...)
	}
	if err != nil {
		return nil, err
	}
	var choices []Choice
	for _, m := range items(v, key) {
		id, label := str(m[idField]), str(m[labelField])
		if id == "" {
			continue
		}
		if label == "" {
			label = id
		}
		if kind == "regions" {
			if req.Provider == "digitalocean" && !truth(m["available"]) {
				continue
			}
			if req.Provider == "oracle" && !truth(m["is-home-region"]) {
				continue
			}
		}
		if kind == "images" {
			if req.Provider == "vultr" && (!strings.Contains(strings.ToLower(label), "ubuntu") || !strings.Contains(label, "24.04")) {
				continue
			}
			if req.Provider == "oracle" && str(m["compartment-id"]) != "" {
				continue
			}
		}
		if kind == "plans" {
			var memory, price float64
			switch req.Provider {
			case "digitalocean":
				memory = num(m["memory"])
				price = num(m["price_monthly"])
				if !truth(m["available"]) || !contains(m["regions"], req.Region) {
					continue
				}
			case "vultr":
				memory = num(m["ram"])
				price = num(m["monthly_cost"])
				if len(arr(m["locations"])) > 0 && !contains(m["locations"], req.Region) {
					continue
				}
			case "linode":
				memory = num(m["memory"])
				price = num(obj(m["price"])["monthly"])
			}
			if memory > 4096 || price > 30 || price <= 0 {
				continue
			}
			label = fmt.Sprintf("%s · %.0f MiB · $%.2f/mo base", id, memory, price)
		}
		choices = append(choices, Choice{ID: id, Label: label})
	}
	if kind == "compartments" {
		choices = append(choices, Choice{ID: req.TenancyID, Label: "Root tenancy compartment"})
	}
	sort.SliceStable(choices, func(i, j int) bool { return choices[i].Label < choices[j].Label })
	if len(choices) == 0 {
		return nil, fmt.Errorf("provider returned no suitable %s; inspect %s CLI account, region and permissions", kind, req.Provider)
	}
	return choices, nil
}

func ValidateDraft(req CreateRequest) error {
	if isCloudProvider(req.Provider) {
		return validateCloudDraft(req)
	}
	if req.Provider != "" && req.Provider != "digitalocean" && req.Provider != "vultr" && req.Provider != "linode" && req.Provider != "oracle" {
		return fmt.Errorf("provider must be azure, aws-lightsail, aws-ec2, digitalocean, vultr, linode, or oracle")
	}
	if req.Architecture != "" && req.Architecture != "auto" && req.Architecture != "amd64" && req.Architecture != "arm64" {
		return fmt.Errorf("architecture must be auto, amd64 or arm64")
	}
	if req.Provider != "" && (req.SubscriptionID != "" || req.AvailabilityZone != "" || req.DiskGB != 0 || (req.Architecture != "" && req.Architecture != "auto")) {
		return fmt.Errorf("subscription, architecture, availability-zone and disk-gb overrides apply only to Azure/AWS providers")
	}
	if req.ID != "" && !safeID.MatchString(req.ID) {
		return fmt.Errorf("invalid host ID")
	}
	for _, value := range []string{req.Name, req.Profile, req.Region, req.Plan, req.Image, req.SSHKey, req.SSHUser, req.FirewallID, req.TenancyID, req.CompartmentID, req.SubnetID, req.AvailabilityDomain} {
		if strings.ContainsAny(value, "\x00\r\n") || strings.HasPrefix(value, "-") {
			return fmt.Errorf("invalid cloud option")
		}
	}
	return nil
}

func ValidateRequest(req CreateRequest) error { _, err := normalize(req); return err }
