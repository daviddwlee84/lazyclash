package vps

import (
	"fmt"
	"math"
)

// CostEstimate separates live machine pricing from the dated published traffic
// rule. It is an estimate for one VM, not a provider billing limit or invoice.
type CostEstimate struct {
	Quote                 Quote    `json:"quote"`
	MonthlyOutbound       float64  `json:"monthly_outbound"`
	MonthlyInbound        *float64 `json:"monthly_inbound,omitempty"`
	TransferUnit          string   `json:"transfer_unit"`
	AllowanceBasis        string   `json:"allowance_basis,omitempty"`
	IncludedTransfer      float64  `json:"included_transfer,omitempty"`
	IncludedOutbound      float64  `json:"included_outbound"`
	ExcessOutbound        float64  `json:"excess_outbound"`
	ExcessOutboundHigh    float64  `json:"excess_outbound_high,omitempty"`
	OverageUSDLow         float64  `json:"overage_usd_per_unit_low,omitempty"`
	OverageUSDHigh        float64  `json:"overage_usd_per_unit_high,omitempty"`
	EstimatedTotalUSDLow  *float64 `json:"estimated_total_usd_low"`
	EstimatedTotalUSDHigh *float64 `json:"estimated_total_usd_high"`
	RateSource            string   `json:"rate_source"`
	RateChecked           string   `json:"rate_checked"`
	Notes                 []string `json:"notes"`
}

func EstimateCost(q Quote, outbound float64) (CostEstimate, error) {
	return EstimateCostWithUsage(q, outbound, nil)
}

// EstimateCostWithUsage accepts optional ingress because Lightsail consumes its
// bundle allowance in both directions, but charges overage only on outbound.
func EstimateCostWithUsage(q Quote, outbound float64, inbound *float64) (CostEstimate, error) {
	if inbound != nil && (*inbound < 0 || math.IsNaN(*inbound) || math.IsInf(*inbound, 0)) {
		return CostEstimate{}, fmt.Errorf("monthly inbound must be a finite nonnegative value")
	}
	if isCloudProvider(q.Provider) {
		return estimateCloudCost(q, outbound, inbound)
	}
	return estimateLegacyCost(q, outbound)
}

func estimateLegacyCost(q Quote, outbound float64) (CostEstimate, error) {
	e := CostEstimate{Quote: q, MonthlyOutbound: outbound, TransferUnit: q.TransferUnit, IncludedOutbound: float64(q.TransferGB), RateChecked: "2026-09-21", Notes: []string{"Input is billable VM outbound in the displayed provider unit, not a speed or an assumed number of users.", "Excludes tax, optional backups, additional disks/IPs and other account resources. Live base price and dated overage rules have different freshness."}}
	if outbound < 0 || math.IsNaN(outbound) || math.IsInf(outbound, 0) || q.TransferGB < 0 || q.MonthlyUSD < 0 || math.IsNaN(q.MonthlyUSD) || math.IsInf(q.MonthlyUSD, 0) {
		return e, fmt.Errorf("monthly outbound and quoted costs must be finite nonnegative values")
	}
	if e.TransferUnit == "" {
		e.TransferUnit = "GB"
	}
	e.ExcessOutbound = math.Max(0, outbound-e.IncludedOutbound)
	switch q.Provider {
	case "vultr":
		e.OverageUSDLow, e.OverageUSDHigh = 0.01, 0.01
		e.RateSource = "https://docs.vultr.com/support/platform/billing/what-is-the-bandwidth-overage-rate"
	case "digitalocean":
		e.TransferUnit = "GiB"
		e.OverageUSDLow, e.OverageUSDHigh = 0.01, 0.01
		e.RateSource = "https://docs.digitalocean.com/platform/billing/bandwidth/"
	case "linode":
		e.OverageUSDLow, e.OverageUSDHigh = 0.005, 0.01
		e.RateSource = "https://www.akamai.com/cloud/pricing"
		e.Notes = append(e.Notes, "The range covers standard versus distributed-region overage rates. Confirm the chosen region's rate and applicable transfer pool; this tool does not assume all account pools are interchangeable.")
	case "oracle":
		e.RateSource = "https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm"
		e.Notes = append(e.Notes, "Oracle's transfer and compute allowances are shared account entitlements. Total is unknown until the create audit establishes eligibility; no zero-dollar bill is promised and no paid fallback is selected.")
		return e, nil
	default:
		return e, fmt.Errorf("no verified outbound pricing rule for this provider; inspect its published terms")
	}
	low := math.Round((q.MonthlyUSD+e.ExcessOutbound*e.OverageUSDLow)*100) / 100
	high := math.Round((q.MonthlyUSD+e.ExcessOutbound*e.OverageUSDHigh)*100) / 100
	e.EstimatedTotalUSDLow, e.EstimatedTotalUSDHigh = &low, &high
	return e, nil
}
