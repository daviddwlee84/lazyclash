package vps

import (
	"math"
	"testing"
)

func TestCloudCostsTieredWithoutSharedFreeDeduction(t *testing.T) {
	for _, provider := range []string{"azure", "aws-ec2"} {
		q := Quote{Provider: provider, MonthlyUSD: 12, TransferUnit: "GB", TransferPricing: &TransferPricing{Basis: "outbound", SharedAllowanceGB: 100, Tiers: []PriceTier{{From: 0, To: 10000, USD: .09}, {From: 10000, USD: .085}}}}
		for _, tt := range []struct{ out, total float64 }{{0, 12}, {100, 21}, {10000, 912}, {11000, 997}} {
			e, err := EstimateCost(q, tt.out)
			if err != nil || e.EstimatedTotalUSDLow == nil || e.EstimatedTotalUSDHigh == nil || *e.EstimatedTotalUSDLow != tt.total || *e.EstimatedTotalUSDHigh != tt.total {
				t.Fatalf("%s out %.0f: %+v %v", provider, tt.out, e, err)
			}
		}
	}
}

func TestLightsailCombinedUsageKnownAndUnknown(t *testing.T) {
	q := Quote{Provider: "aws-lightsail", MonthlyUSD: 7, TransferGB: 2000, TransferPricing: &TransferPricing{Basis: "combined", Tiers: []PriceTier{{USD: .1}}}}
	zero, partial, full := 0.0, 1800.0, 3000.0
	for _, tt := range []struct {
		in                                              *float64
		out, excessLow, excessHigh, totalLow, totalHigh float64
	}{{nil, 500, 0, 500, 7, 57}, {nil, 2500, 500, 2500, 57, 257}, {&zero, 500, 0, 0, 7, 7}, {&partial, 500, 300, 300, 37, 37}, {&full, 500, 500, 500, 57, 57}, {nil, 0, 0, 0, 7, 7}} {
		e, err := EstimateCostWithUsage(q, tt.out, tt.in)
		if err != nil || e.ExcessOutbound != tt.excessLow || e.ExcessOutboundHigh != tt.excessHigh || e.EstimatedTotalUSDLow == nil || e.EstimatedTotalUSDHigh == nil || *e.EstimatedTotalUSDLow != tt.totalLow || *e.EstimatedTotalUSDHigh != tt.totalHigh || e.AllowanceBasis != "combined" {
			t.Fatalf("in %v out %.0f: %+v %v", tt.in, tt.out, e, err)
		}
	}
}

func TestCloudCostsMissingRatesPreserveUncertainty(t *testing.T) {
	q := Quote{Provider: "aws-lightsail", MonthlyUSD: 7, TransferGB: 2000}
	e, err := EstimateCost(q, 500)
	if err != nil || e.EstimatedTotalUSDLow == nil || *e.EstimatedTotalUSDLow != 7 || e.EstimatedTotalUSDHigh != nil {
		t.Fatalf("missing ingress/rate must retain known lower bound only: %+v %v", e, err)
	}
	e, err = EstimateCost(q, 2500)
	if err != nil || e.EstimatedTotalUSDLow != nil || e.EstimatedTotalUSDHigh != nil {
		t.Fatalf("paid rate unknown: %+v %v", e, err)
	}
	zero := 0.0
	e, err = EstimateCostWithUsage(q, 500, &zero)
	if err != nil || e.EstimatedTotalUSDLow == nil || e.EstimatedTotalUSDHigh == nil || *e.EstimatedTotalUSDHigh != 7 {
		t.Fatalf("known included transfer: %+v %v", e, err)
	}
}

func TestCloudCostsRejectMalformedTiersAndNumbers(t *testing.T) {
	for _, tiers := range [][]PriceTier{
		{{From: 1, USD: .1}}, {{To: 10, USD: .1}, {From: 11, USD: .1}}, {{To: 10, USD: .1}, {From: 9, USD: .1}}, {{USD: .1}, {From: 10, USD: .1}}, {{USD: -1}}, {{USD: math.NaN()}}, {{To: -1, USD: .1}}, {{To: 10, USD: .1}},
	} {
		if _, err := EstimateCost(Quote{Provider: "azure", MonthlyUSD: 12, TransferPricing: &TransferPricing{Basis: "outbound", Tiers: tiers}}, 100); err == nil {
			t.Fatalf("accepted invalid or insufficient tiers: %+v", tiers)
		}
	}
	for _, n := range []float64{-1, math.NaN(), math.Inf(1)} {
		if _, err := EstimateCostWithUsage(Quote{Provider: "aws-lightsail", MonthlyUSD: 7}, 100, &n); err == nil {
			t.Fatal("accepted invalid ingress")
		}
		if _, err := EstimateCost(Quote{Provider: "aws-ec2", MonthlyUSD: 12}, n); err == nil {
			t.Fatal("accepted invalid egress")
		}
	}
}
