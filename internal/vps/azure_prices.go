package vps

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
)

func azureDiskTier(gb int) (string, error) {
	if gb < 32 {
		return "", fmt.Errorf("Azure Ubuntu boot disk requires at least 32 GiB")
	}
	for _, tier := range []struct {
		gb   int
		name string
	}{{32, "E4"}, {64, "E6"}, {128, "E10"}, {256, "E15"}, {512, "E20"}, {1024, "E30"}} {
		if gb > 0 && gb <= tier.gb {
			return tier.name, nil
		}
	}
	return "", fmt.Errorf("Azure Standard SSD boot disk must be 32–1024 GiB")
}
func (a azureAdapter) prices(ctx context.Context, r CreateRequest, filter string) ([]map[string]any, error) {
	u := azurePriceSource + "?" + url.Values{"api-version": {"2023-01-01-preview"}, "currencyCode": {"'USD'"}, "$filter": {"armRegionName eq '" + strings.ReplaceAll(r.Region, "'", "''") + "' and priceType eq 'Consumption' and " + filter}}.Encode()
	seen := map[string]bool{}
	var out []map[string]any
	for page := 0; u != ""; page++ {
		if page >= 100 || seen[u] {
			return nil, fmt.Errorf("Azure Retail price pagination is incomplete or cyclic")
		}
		seen[u] = true
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "https" || p.Host != "prices.azure.com" || p.User != nil || p.Path != "/api/retail/prices" {
			return nil, fmt.Errorf("untrusted Azure Retail price page URL")
		}
		v, err := a.s.cloudHTTPJSON(ctx, u)
		if err != nil {
			return nil, err
		}
		m := obj(v)
		if str(m["BillingCurrency"]) != "USD" {
			return nil, fmt.Errorf("Azure Retail response is not USD")
		}
		rows, err := strictItems(v, "Items")
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if str(row["currencyCode"]) != "USD" || str(row["type"]) != "Consumption" || str(row["armRegionName"]) != r.Region {
				continue
			}
			if date := str(row["effectiveStartDate"]); date != "" {
				t, e := time.Parse(time.RFC3339, date)
				if e != nil || t.After(a.s.options.Now()) {
					continue
				}
			}
			if f, ok := row["retailPrice"].(float64); !ok || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
				continue
			}
			out = append(out, row)
		}
		if next, ok := m["NextPageLink"]; ok && next != nil {
			var valid bool
			u, valid = next.(string)
			if !valid {
				return nil, fmt.Errorf("malformed Azure Retail NextPageLink")
			}
		} else {
			u = ""
		}
	}
	return out, nil
}
func azureSinglePrice(rows []map[string]any, accept func(map[string]any) bool) (float64, error) {
	latest := map[string]map[string]any{}
	for _, r := range rows {
		if !accept(r) || num(r["tierMinimumUnits"]) != 0 {
			continue
		}
		id := str(r["meterId"])
		if id == "" {
			return 0, fmt.Errorf("Azure Retail price lacks meter identity")
		}
		if prior := latest[id]; prior == nil || str(prior["effectiveStartDate"]) < str(r["effectiveStartDate"]) {
			latest[id] = r
		}
	}
	var price float64
	found := false
	for _, r := range latest {
		p := num(r["retailPrice"])
		if p <= 0 {
			return 0, fmt.Errorf("Azure price is missing or nonpositive")
		}
		if found && p != price {
			return 0, fmt.Errorf("Azure Retail price is ambiguous")
		}
		found = true
		price = p
	}
	if !found {
		return 0, fmt.Errorf("Azure Retail has no exact on-demand price for the selected component")
	}
	return price, nil
}
func (a azureAdapter) quoteSize(ctx context.Context, r CreateRequest, size azureSize) (Quote, error) {
	q := Quote{Provider: "azure", Plan: size.name, Region: r.Region, Architecture: size.arch, VCPUs: size.cpus, MemoryMiB: size.memory, DiskGB: r.DiskGB, Live: true, TransferUnit: "GB", Notes: []string{"730 hours per month at USD retail rates; no trial credits, contracts or account-shared free allowances are deducted.", "B-series CPUs use burst credits; sustained throughput falls to the size's baseline when credits run out.", "Stop deallocates compute. Standard SSD disk and static IPv4 continue billing; disk I/O transactions, outbound traffic and tax are additional."}}
	if q.DiskGB == 0 {
		q.DiskGB = 32
	}
	tier, err := azureDiskTier(q.DiskGB)
	if err != nil {
		return q, err
	}
	computeRows, err := a.prices(ctx, r, "serviceName eq 'Virtual Machines' and armSkuName eq '"+strings.ReplaceAll(size.name, "'", "''")+"'")
	if err != nil {
		return q, err
	}
	compute, err := azureSinglePrice(computeRows, func(m map[string]any) bool {
		p := str(m["productName"])
		n := strings.ToLower(str(m["skuName"]) + " " + str(m["meterName"]))
		return str(m["serviceName"]) == "Virtual Machines" && str(m["armSkuName"]) == size.name && strings.HasPrefix(p, "Virtual Machines ") && !strings.Contains(strings.ToLower(p), "windows") && !strings.Contains(n, "spot") && !strings.Contains(n, "low priority") && str(m["unitOfMeasure"]) == "1 Hour"
	})
	if err != nil {
		return q, fmt.Errorf("Azure compute: %w", err)
	}
	diskRows, err := a.prices(ctx, r, "serviceName eq 'Storage' and meterName eq '"+tier+" LRS Disk'")
	if err != nil {
		return q, err
	}
	disk, err := azureSinglePrice(diskRows, func(m map[string]any) bool {
		return str(m["serviceName"]) == "Storage" && str(m["productName"]) == "Standard SSD Managed Disks" && str(m["meterName"]) == tier+" LRS Disk" && str(m["unitOfMeasure"]) == "1/Month"
	})
	if err != nil {
		return q, fmt.Errorf("Azure disk: %w", err)
	}
	ipRows, err := a.prices(ctx, r, "serviceName eq 'Virtual Network' and meterName eq 'Standard IPv4 Static Public IP'")
	if err != nil {
		return q, err
	}
	ip, err := azureSinglePrice(ipRows, func(m map[string]any) bool {
		return str(m["serviceName"]) == "Virtual Network" && str(m["productName"]) == "IP Addresses" && str(m["meterName"]) == "Standard IPv4 Static Public IP" && str(m["unitOfMeasure"]) == "1 Hour"
	})
	if err != nil {
		return q, fmt.Errorf("Azure IPv4: %w", err)
	}
	q.Components = []CostComponent{{Name: "compute", MonthlyUSD: compute * 730, Unit: "hour", UnitUSD: compute, Quantity: 730, Source: azurePriceSource}, {Name: "disk", MonthlyUSD: disk, Unit: tier + " LRS Disk/month", UnitUSD: disk, Quantity: 1, Source: azurePriceSource}, {Name: "ipv4", MonthlyUSD: ip * 730, Unit: "hour", UnitUSD: ip, Quantity: 730, Source: azurePriceSource}}
	q.MonthlyUSD = math.Round((compute*730+disk+ip*730)*10000) / 10000
	stopped := disk + ip*730
	q.StoppedMonthlyUSD = &stopped
	traffic, err := a.prices(ctx, r, "serviceName eq 'Bandwidth' and productName eq 'Rtn Preference: MGN' and meterName eq 'Standard Data Transfer Out'")
	if err != nil {
		return q, fmt.Errorf("Azure bandwidth price unavailable: %w", err)
	}
	q.TransferPricing, err = azureTransferPricing(traffic, a.s.options.Now())
	if err != nil {
		return q, err
	}
	return q, nil
}
func azureTransferPricing(rows []map[string]any, now time.Time) (*TransferPricing, error) {
	latest := map[float64]map[string]any{}
	meter := ""
	for _, m := range rows {
		if str(m["serviceName"]) != "Bandwidth" || str(m["productName"]) != "Rtn Preference: MGN" || str(m["meterName"]) != "Standard Data Transfer Out" || str(m["unitOfMeasure"]) != "1 GB" {
			continue
		}
		id := str(m["meterId"])
		if id == "" || (meter != "" && id != meter) {
			return nil, fmt.Errorf("Azure outbound meter is missing or ambiguous")
		}
		meter = id
		from := num(m["tierMinimumUnits"])
		if from < 0 {
			return nil, fmt.Errorf("invalid Azure transfer tier")
		}
		if old := latest[from]; old == nil || str(old["effectiveStartDate"]) < str(m["effectiveStartDate"]) {
			latest[from] = m
		}
	}
	var paid []PriceTier
	for from, m := range latest {
		if num(m["retailPrice"]) > 0 {
			paid = append(paid, PriceTier{From: from, USD: num(m["retailPrice"])})
		}
	}
	sort.Slice(paid, func(i, j int) bool { return paid[i].From < paid[j].From })
	if len(paid) == 0 {
		return nil, fmt.Errorf("Azure Retail did not return a paid internet outbound tier")
	}
	shared := paid[0].From
	for i := range paid {
		paid[i].From -= shared
		if i+1 < len(paid) {
			paid[i].To = paid[i+1].From - shared
		}
	}
	return &TransferPricing{Basis: "outbound", Tiers: paid, Source: azurePriceSource, Checked: now.UTC().Format("2006-01-02"), SharedAllowanceGB: shared}, nil
}
