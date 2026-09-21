package vps

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// oracleFree deliberately uses the lower 2026 documented allowance (2 OCPUs,
// 12 GB, 1,500 OCPU-hours / 9,000 GB-hours), never the historical 4/24 limit.
// Every query must succeed. Trial credits and service-limit headroom are not
// evidence of Always Free eligibility.
func (s *Service) oracleFree(ctx context.Context, req CreateRequest) error {
	v, err := s.call(ctx, req, "iam", "region-subscription", "list", "--tenancy-id", req.TenancyID, "--all")
	if err != nil {
		return fmt.Errorf("cannot verify Oracle home region: %w", err)
	}
	home := ""
	for _, m := range items(v, "data") {
		if truth(m["is-home-region"]) {
			home = str(m["region-name"])
		}
	}
	if home == "" || home != req.Region {
		return fmt.Errorf("Always Free requires the verified tenancy home region (%s)", home)
	}
	v, err = s.call(ctx, req, "compute", "image", "get", "--image-id", req.Image)
	if err != nil {
		return err
	}
	image, err := one(v, "data")
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToLower(str(image["operating-system"])), "ubuntu") || !strings.HasPrefix(str(image["operating-system-version"]), "24.04") || str(image["compartment-id"]) != "" {
		return fmt.Errorf("Oracle requires an official platform Ubuntu 24.04 image, without marketplace software fees")
	}
	v, err = s.call(ctx, req, "compute", "image-shape-compatibility-entry", "list", "--image-id", req.Image, "--all")
	if err != nil {
		return err
	}
	compatible := false
	for _, entry := range items(v, "data") {
		compatible = compatible || str(entry["shape"]) == "VM.Standard.A1.Flex"
	}
	if !compatible {
		return fmt.Errorf("Oracle Ubuntu image is not compatible with the Always Free Arm A1 shape")
	}
	if req.SubnetID != "" {
		v, err = s.call(ctx, req, "network", "subnet", "get", "--subnet-id", req.SubnetID)
		if err != nil {
			return err
		}
		subnet, e := one(v, "data")
		if e != nil {
			return e
		}
		if truth(subnet["prohibit-public-ip-on-vnic"]) {
			return fmt.Errorf("Oracle subnet prohibits the required public IPv4 address")
		}
	}
	// ANY + subtree requires tenancy INSPECT and exposes even compartments the
	// principal cannot operate in. Missing READ in any one then fails closed.
	v, err = s.call(ctx, req, "iam", "compartment", "list", "--compartment-id", req.TenancyID, "--compartment-id-in-subtree", "true", "--access-level", "ANY", "--all")
	if err != nil {
		return fmt.Errorf("cannot inventory the whole tenancy for free limits: %w", err)
	}
	compartments := []string{req.TenancyID}
	for _, m := range items(v, "data") {
		if str(m["id"]) == "" || str(m["lifecycle-state"]) == "" {
			return fmt.Errorf("Oracle compartment inventory is incomplete")
		}
		if str(m["lifecycle-state"]) == "ACTIVE" {
			compartments = append(compartments, str(m["id"]))
		}
	}
	v, err = s.call(ctx, req, "iam", "availability-domain", "list", "--compartment-id", req.TenancyID, "--all")
	if err != nil {
		return err
	}
	var ads []string
	for _, m := range items(v, "data") {
		if str(m["name"]) == "" {
			return fmt.Errorf("Oracle availability-domain inventory is incomplete")
		}
		if str(m["name"]) != "" {
			ads = append(ads, str(m["name"]))
		}
	}
	if len(ads) == 0 {
		return fmt.Errorf("cannot verify Oracle availability domains")
	}
	var cpus, memory, storage float64
	for _, compartment := range compartments {
		v, err = s.call(ctx, req, "compute", "instance", "list", "--compartment-id", compartment, "--all")
		if err != nil {
			return fmt.Errorf("cannot inspect every tenancy instance: %w", err)
		}
		for _, m := range items(v, "data") {
			if str(m["id"]) == "" || str(m["lifecycle-state"]) == "" {
				return fmt.Errorf("Oracle instance inventory is incomplete")
			}
			if str(m["lifecycle-state"]) == "TERMINATED" {
				continue
			}
			if str(m["shape"]) == "" {
				return fmt.Errorf("Oracle instance shape is unknown")
			}
			if str(m["shape"]) == "VM.Standard.A1.Flex" {
				shape := obj(m["shape-config"])
				c, g := num(shape["ocpus"]), num(shape["memory-in-gbs"])
				if c <= 0 || g <= 0 {
					return fmt.Errorf("Oracle A1 allocation data is incomplete")
				}
				cpus += c
				memory += g
			}
		}
		v, err = s.call(ctx, req, "bv", "volume", "list", "--compartment-id", compartment, "--all")
		if err != nil {
			return fmt.Errorf("cannot inspect every tenancy block volume: %w", err)
		}
		for _, m := range items(v, "data") {
			if str(m["id"]) == "" || str(m["lifecycle-state"]) == "" {
				return fmt.Errorf("Oracle block-volume inventory is incomplete")
			}
			if str(m["lifecycle-state"]) != "TERMINATED" {
				size := num(m["size-in-gbs"])
				if size <= 0 {
					return fmt.Errorf("Oracle volume size is unknown")
				}
				storage += size
				if num(m["vpus-per-gb"]) > 10 {
					return fmt.Errorf("Oracle volume performance exceeds the Always Free baseline")
				}
			}
		}
		for _, ad := range ads {
			v, err = s.call(ctx, req, "bv", "boot-volume", "list", "--compartment-id", compartment, "--availability-domain", ad, "--all")
			if err != nil {
				return fmt.Errorf("cannot inspect every tenancy boot volume: %w", err)
			}
			for _, m := range items(v, "data") {
				if str(m["id"]) == "" || str(m["lifecycle-state"]) == "" {
					return fmt.Errorf("Oracle boot-volume inventory is incomplete")
				}
				if str(m["lifecycle-state"]) != "TERMINATED" {
					size := num(m["size-in-gbs"])
					if size <= 0 {
						return fmt.Errorf("Oracle boot volume size is unknown")
					}
					storage += size
					if num(m["vpus-per-gb"]) > 10 {
						return fmt.Errorf("Oracle boot volume performance exceeds the Always Free baseline")
					}
				}
			}
		}
	}
	if cpus+1 > 2 || memory+6 > 12 || storage+50 > 200 {
		return fmt.Errorf("Oracle free budget insufficient: current %.0f OCPUs / %.0f GB RAM / %.0f GB storage; requested 1 / 6 / 50, conservative free limits 2 / 12 / 200", cpus, memory, storage)
	}
	now := s.options.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	next := start.AddDate(0, 1, 0)
	// DAILY requires midnight UTC boundaries. Use tomorrow's exclusive boundary
	// so today's reported usage is included, including at the start of a month.
	// The reporting-lag reserve below still covers usage not yet reported.
	usageEnd := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	v, err = s.call(ctx, req, "usage-api", "usage-summary", "request-summarized-usages", "--tenant-id", req.TenancyID, "--time-usage-started", start.Format(time.RFC3339), "--time-usage-ended", usageEnd.Format(time.RFC3339), "--granularity", "DAILY", "--query-type", "USAGE", "--group-by", `["skuPartNumber","unit"]`)
	if err != nil {
		return fmt.Errorf("Oracle remaining monthly free allowance is unknown: %w", err)
	}
	data := obj(obj(v)["data"])
	rows, ok := data["items"].([]any)
	if !ok {
		return fmt.Errorf("Oracle usage API did not provide complete usage items; free eligibility is unknown")
	}
	var usedCPU, usedMemory float64
	var sawCPU, sawMemory bool
	for _, entry := range rows {
		m := obj(entry)
		sku := str(m["sku-part-number"])
		if sku == "B93297" || sku == "B93298" {
			quantity, valid := m["computed-quantity"].(float64)
			if !valid || quantity < 0 {
				return fmt.Errorf("Oracle A1 usage is incomplete")
			}
			if sku == "B93297" {
				usedCPU += quantity
				sawCPU = true
			} else {
				usedMemory += quantity
				sawMemory = true
			}
		}
	}
	if (sawCPU && !sawMemory) || (!sawCPU && sawMemory) {
		return fmt.Errorf("Oracle usage has reported only one A1 meter; remaining free allowance cannot be verified")
	}
	// Include 48 hours of reporting lag at the whole conservative allowance.
	// This intentionally refuses near-limit accounts rather than spending credit.
	hours := next.Sub(now).Hours()
	if usedCPU+(cpus+1)*hours+2*48 > 1500 || usedMemory+(memory+6)*hours+12*48 > 9000 {
		return fmt.Errorf("Oracle remaining monthly A1 free allowance is insufficient after reserving current and new allocations plus usage-report delay")
	}
	return nil
}
