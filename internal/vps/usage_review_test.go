package vps

import (
	"fmt"
	"testing"
	"time"
)

func TestOracleNetworkCoverageRequiresEveryReturnedVNIC(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	row := func(id int, hours ...int) map[string]any {
		points := []any{}
		for _, hour := range hours {
			points = append(points, map[string]any{"timestamp": start.Add(time.Duration(hour) * time.Hour).Format(time.RFC3339), "value": float64(10)})
		}
		return map[string]any{"name": "VnicToNetworkBytes", "metadata": map[string]any{"unit": "bytes"}, "dimensions": map[string]any{"resourceId": fmt.Sprintf("ocid1.vnic.oc1.%d", id), "instanceId": "instance"}, "aggregated-datapoints": points}
	}
	for _, tc := range []struct {
		name     string
		second   []int
		coverage int
		bytes    float64
		latest   time.Time
	}{
		{"all-covered", []int{0, 1, 2}, 3, 60, start.Add(2 * time.Hour)},
		{"stale-vnic", []int{0}, 1, 40, start},
		{"gapped-vnic", []int{0, 2}, 2, 50, start.Add(2 * time.Hour)},
		{"empty-vnic", nil, 0, 30, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := map[string]any{"data": []any{row(1, 0, 1, 2), row(2, tc.second...)}}
			bytes, coverage, latest, err := parseOracleNetwork(v, "VnicToNetworkBytes", "instance", start, start.Add(3*time.Hour))
			if err != nil || bytes == nil || *bytes != tc.bytes || coverage != tc.coverage || !latest.Equal(tc.latest) {
				t.Fatalf("a complete VNIC masked another's coverage: bytes=%v, coverage=%d, latest=%s, error=%v", bytes, coverage, latest, err)
			}
		})
	}
}

func TestOracleNetworkRejectsMultipleSamplesWithinRequestedHour(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	row := map[string]any{"name": "VnicToNetworkBytes", "metadata": map[string]any{"unit": "bytes"}, "dimensions": map[string]any{"resourceId": "ocid1.vnic.oc1.v", "instanceId": "instance"}, "aggregated-datapoints": []any{
		map[string]any{"timestamp": start.Format(time.RFC3339), "value": float64(10)},
		map[string]any{"timestamp": start.Add(30 * time.Minute).Format(time.RFC3339), "value": float64(10)},
	}}
	if _, _, _, err := parseOracleNetwork(map[string]any{"data": []any{row}}, "VnicToNetworkBytes", "instance", start, start.Add(time.Hour)); err == nil {
		t.Fatal("multiple samples in one requested hourly bucket were double counted")
	}
}
