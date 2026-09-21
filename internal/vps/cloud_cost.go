package vps

import (
	"errors"
	"fmt"
	"math"
)

func finiteNonnegative(n float64) bool { return n >= 0 && !math.IsNaN(n) && !math.IsInf(n, 0) }

func estimateCloudCost(q Quote, outbound float64, inbound *float64) (CostEstimate, error) {
	e := CostEstimate{Quote: q, MonthlyOutbound: outbound, MonthlyInbound: inbound, TransferUnit: q.TransferUnit, IncludedTransfer: float64(q.TransferGB), AllowanceBasis: "outbound", Notes: []string{
		"Base price includes required compute, disk and one public IPv4. Optional resources, taxes and account discounts are excluded.",
		"This is a full-month usage estimate, not a billing limit. Account-wide free transfer is not automatically deducted.",
	}}
	if !finiteNonnegative(outbound) || !finiteNonnegative(q.MonthlyUSD) || q.TransferGB < 0 {
		return e, errors.New("monthly outbound and quoted costs must be finite nonnegative values")
	}
	if e.TransferUnit == "" {
		e.TransferUnit = "GB"
	}
	if q.Provider == "aws-lightsail" {
		e.AllowanceBasis = "combined"
	}
	if p := q.TransferPricing; p != nil {
		if p.Basis != e.AllowanceBasis {
			return e, errors.New("transfer allowance basis does not match the provider")
		}
		e.RateSource, e.RateChecked = p.Source, p.Checked
		if !finiteNonnegative(p.SharedAllowanceGB) {
			return e, errors.New("invalid shared transfer allowance")
		}
		if p.SharedAllowanceGB > 0 {
			e.Notes = append(e.Notes, fmt.Sprintf("The published %.0f %s free allocation is shared across the account and is not deducted from this VM estimate.", p.SharedAllowanceGB, e.TransferUnit))
		}
	}
	e.IncludedOutbound = e.IncludedTransfer
	if e.AllowanceBasis == "combined" {
		e.Notes = append(e.Notes, "Lightsail ingress and egress both consume the bundle allowance; only excess outbound is billed. Stopped instances continue to incur the bundle charge.")
		if inbound == nil {
			// The two extrema allocate the entire allowance to egress or none.
			e.IncludedOutbound = 0 // no outbound allowance can be guaranteed
			e.ExcessOutbound = math.Max(0, outbound-e.IncludedTransfer)
			e.ExcessOutboundHigh = outbound
			e.Notes = append(e.Notes, "Ingress is unknown. Excess outbound and total are a range; the low end assumes zero ingress, and the high end assumes ingress has consumed the allowance. Supply --ingress to narrow it.")
		} else {
			e.IncludedOutbound = math.Max(0, e.IncludedTransfer-*inbound)
			e.ExcessOutbound = math.Max(0, outbound-e.IncludedOutbound)
			e.ExcessOutboundHigh = e.ExcessOutbound
		}
	} else {
		e.ExcessOutbound = math.Max(0, outbound-e.IncludedOutbound)
		e.ExcessOutboundHigh = e.ExcessOutbound
	}
	var tiers []PriceTier
	if q.TransferPricing != nil {
		tiers = q.TransferPricing.Tiers
	}
	if len(tiers) > 0 {
		if err := validateTransferTiers(tiers); err != nil {
			return e, err
		}
		e.OverageUSDLow, e.OverageUSDHigh = tiers[0].USD, tiers[0].USD
		for _, t := range tiers[1:] {
			e.OverageUSDLow = math.Min(e.OverageUSDLow, t.USD)
			e.OverageUSDHigh = math.Max(e.OverageUSDHigh, t.USD)
		}
	}
	// Missing prices may still permit a bound when no excess transfer occurs.
	if e.ExcessOutbound == 0 {
		base := cents(q.MonthlyUSD)
		e.EstimatedTotalUSDLow = &base
	}
	if e.ExcessOutboundHigh == 0 {
		base := cents(q.MonthlyUSD)
		e.EstimatedTotalUSDHigh = &base
	}
	if len(tiers) == 0 && e.ExcessOutboundHigh > 0 {
		e.Notes = append(e.Notes, "No verified outbound rate is available for this region. Totals requiring paid transfer remain unknown; the fixed monthly cost is not an all-inclusive bill.")
		return e, nil
	}
	for _, target := range []struct {
		units float64
		dst   **float64
	}{{e.ExcessOutbound, &e.EstimatedTotalUSDLow}, {e.ExcessOutboundHigh, &e.EstimatedTotalUSDHigh}} {
		fee, err := tierCost(tiers, target.units)
		if err != nil {
			return e, err
		}
		total := cents(q.MonthlyUSD + fee)
		if !finiteNonnegative(total) {
			return e, errors.New("estimated cost exceeds the supported numeric range")
		}
		*target.dst = &total
	}
	return e, nil
}

func cents(n float64) float64 { return math.Round(n*100) / 100 }

func validateTransferTiers(tiers []PriceTier) error {
	next := float64(0)
	for i, t := range tiers {
		if !finiteNonnegative(t.From) || !finiteNonnegative(t.To) || !finiteNonnegative(t.USD) || t.From != next || (t.To != 0 && t.To <= t.From) || (t.To == 0 && i != len(tiers)-1) {
			return errors.New("outbound price tiers must be finite, nonnegative, contiguous and ordered from zero")
		}
		next = t.To
	}
	return nil
}

func tierCost(tiers []PriceTier, units float64) (float64, error) {
	if units == 0 {
		return 0, nil
	}
	var cost float64
	for _, t := range tiers {
		end := units
		if t.To != 0 {
			end = math.Min(end, t.To)
		}
		cost += math.Max(0, end-t.From) * t.USD
		if units <= end {
			return cost, nil
		}
	}
	return 0, errors.New("outbound usage exceeds the verified pricing tiers")
}
