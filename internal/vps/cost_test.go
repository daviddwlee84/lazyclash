package vps

import (
	"math"
	"testing"
)

func TestMachinePlusTrafficCostsPreserveUnitsAndUnknowns(t *testing.T) {
	for _, tt := range []struct {
		provider         string
		price            float64
		included         int
		usage, low, high float64
		unit             string
	}{
		{"vultr", 5, 1024, 1524, 10, 10, "GB"},
		{"digitalocean", 4, 500, 700, 6, 6, "GiB"},
		{"linode", 5, 1000, 2000, 10, 15, "GB"},
		{"vultr", 5, 1024, 0, 5, 5, "GB"},
	} {
		got, err := EstimateCost(Quote{Provider: tt.provider, MonthlyUSD: tt.price, TransferGB: tt.included}, tt.usage)
		if err != nil || got.EstimatedTotalUSDLow == nil || *got.EstimatedTotalUSDLow != tt.low || *got.EstimatedTotalUSDHigh != tt.high || got.TransferUnit != tt.unit {
			t.Fatalf("%s: %+v %v", tt.provider, got, err)
		}
	}
	free, err := EstimateCost(Quote{Provider: "oracle", TransferGB: 10000}, 500)
	if err != nil || free.EstimatedTotalUSDLow != nil || free.EstimatedTotalUSDHigh != nil {
		t.Fatalf("unverified entitlement promised free bill: %+v %v", free, err)
	}
	for _, invalid := range []float64{-1, math.NaN(), math.Inf(1)} {
		if _, err := EstimateCost(Quote{Provider: "vultr"}, invalid); err == nil {
			t.Fatal("invalid usage accepted")
		}
	}
}
