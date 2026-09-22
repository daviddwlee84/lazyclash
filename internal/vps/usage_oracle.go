package vps

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func (s *Service) oracleUsage(ctx context.Context, h serverstate.Host, b serverstate.CloudObservationBinding, r UsageReport) (UsageReport, error) {
	req := CreateRequest{Provider: "oracle", Profile: b.Profile, Region: b.Region, TenancyID: b.TenancyID}
	v, err := s.call(ctx, req, "compute", "instance", "get", "--instance-id", b.ResourceID)
	if err != nil {
		return r, err
	}
	instance := obj(obj(v)["data"])
	if str(instance["id"]) != b.ResourceID || str(instance["compartment-id"]) != b.CompartmentID {
		return r, fmt.Errorf("Oracle instance no longer matches the observation binding")
	}
	r.Observed.Source = "Oracle Monitoring / oci_vcn (returned VNIC streams for this instance)"
	r.Warnings = append(r.Warnings, "Coverage is checked across returned VNIC streams only; this query cannot prove that no entire VNIC stream is missing.")
	r.Observed.Partial = true
	instanceJSON, _ := json.Marshal(b.ResourceID)
	for _, metric := range []string{"VnicFromNetworkBytes", "VnicToNetworkBytes"} {
		query := metric + "[1h]{instanceId = " + string(instanceJSON) + "}.sum()"
		data, e := s.call(ctx, req, "monitoring", "metric-data", "summarize-metrics-data", "--compartment-id", b.CompartmentID, "--namespace", "oci_vcn", "--query-text", query, "--resolution", "1h", "--start-time", r.PeriodStart.Format(time.RFC3339), "--end-time", r.PeriodEnd.Format(time.RFC3339))
		var total *float64
		var count int
		var latest time.Time
		if e == nil {
			total, count, latest, e = parseOracleNetwork(data, metric, b.ResourceID, r.PeriodStart, r.PeriodEnd)
		}
		if e != nil {
			r.Warnings = append(r.Warnings, metric+" unavailable: "+e.Error())
			continue
		}
		if metric == "VnicFromNetworkBytes" {
			r.Observed.InboundBytes = total
			r.Observed.InboundPoints = count
		} else {
			r.Observed.OutboundBytes = total
			r.Observed.OutboundPoints = count
		}
		if !latest.IsZero() && (r.Observed.LatestAt.IsZero() || latest.Before(r.Observed.LatestAt)) {
			r.Observed.LatestAt = latest
		}
	}
	r.Observed.Partial = r.Observed.InboundBytes == nil || r.Observed.OutboundBytes == nil || r.Observed.InboundPoints < r.Observed.ExpectedPoints || r.Observed.OutboundPoints < r.Observed.ExpectedPoints || r.Observed.LatestAt.Before(r.PeriodEnd.Add(-2*time.Hour))
	if r.Observed.Partial {
		r.Warnings = append(r.Warnings, "Monitoring coverage is incomplete or stale for the requested month; absent samples are not zero traffic. A newly created VM also has no samples before creation.")
	}
	r.Billing = BillingObservation{Source: "Oracle Usage API / DAILY USAGE", Scope: "tenancy " + b.TenancyID + "; network meters grouped by SKU and native unit across its resources", Status: "unavailable", Meters: []UsageMeter{}, PublishedAllowance: "Published internet egress free tier: 10 TB/month per origin pricing-zone service. This is shared pricing context, not a per-VM allocation or verified remaining balance.", Warnings: []string{"Provider usage can lag. Tenancy-versus-linked-subscription allowance pooling and billing-GB-to-byte conversion are not established; no remaining quota, percentage or overage is calculated."}}
	meters, e := s.oracleNetworkBilling(ctx, req, r.PeriodStart, r.PeriodEnd)
	if e != nil {
		r.Billing.Warnings = append(r.Billing.Warnings, e.Error())
		return r, nil
	}
	r.Billing.Meters = meters
	r.Billing.Status = "reported"
	if len(meters) == 0 {
		r.Billing.Status = "no-data"
	}
	for _, m := range meters {
		if m.LatestAt.After(r.Billing.LatestAt) {
			r.Billing.LatestAt = m.LatestAt
		}
	}
	return r, nil
}

func parseOracleNetwork(v any, metric, instance string, start, end time.Time) (*float64, int, time.Time, error) {
	rows, err := strictItems(v, "data")
	if err != nil {
		return nil, 0, time.Time{}, err
	}
	if str(obj(v)["opc-next-page"]) != "" {
		return nil, 0, time.Time{}, fmt.Errorf("monitoring returned an incomplete page")
	}
	streams := map[string]bool{}
	var hours map[int64]bool
	var total float64
	var latest time.Time
	points := 0
	for index, row := range rows {
		dims := obj(row["dimensions"])
		vnic := str(dims["resourceId"])
		if str(row["name"]) != metric || str(dims["instanceId"]) != instance || !strings.HasPrefix(vnic, "ocid1.vnic.") || str(obj(row["metadata"])["unit"]) != "bytes" || streams[vnic] {
			return nil, 0, time.Time{}, fmt.Errorf("monitoring stream identity, unit or uniqueness is invalid")
		}
		streams[vnic] = true
		data, err := strictItems(row, "aggregated-datapoints")
		if err != nil {
			return nil, 0, time.Time{}, err
		}
		seen := map[int64]bool{}
		var streamLatest time.Time
		for _, p := range data {
			at, e := time.Parse(time.RFC3339Nano, str(p["timestamp"]))
			value, ok := p["value"].(float64)
			hour := at.Truncate(time.Hour).Unix()
			if e != nil || at.Before(start) || !at.Before(end) || seen[hour] || !ok || !finiteNonnegative(value) {
				return nil, 0, time.Time{}, fmt.Errorf("monitoring datapoint has an invalid timestamp, value or duplicate")
			}
			seen[hour] = true
			total += value
			if math.IsInf(total, 0) {
				return nil, 0, time.Time{}, fmt.Errorf("monitoring byte total is out of range")
			}
			points++
			if at.After(streamLatest) {
				streamLatest = at
			}
		}
		// Totals retain every returned byte, but coverage is complete only
		// where every returned VNIC has a sample. A healthy VNIC must not hide
		// another VNIC's missing/stale stream, including an empty stream.
		if index == 0 {
			hours = seen
		} else {
			for hour := range hours {
				if !seen[hour] {
					delete(hours, hour)
				}
			}
		}
		if index == 0 || streamLatest.Before(latest) {
			latest = streamLatest
		}
	}
	if points == 0 {
		return nil, 0, time.Time{}, nil
	}
	return &total, len(hours), latest, nil
}

func (s *Service) oracleNetworkBilling(ctx context.Context, req CreateRequest, start, end time.Time) ([]UsageMeter, error) {
	// DAILY requests must have UTC-midnight boundaries. The last day remains
	// provisional; timestamps below describe the provider's reported day bucket.
	usageEnd := time.Date(end.Year(), end.Month(), end.Day()+1, 0, 0, 0, 0, time.UTC)
	if end.Equal(end.Truncate(24 * time.Hour)) {
		usageEnd = end
	}
	base := []string{"usage-api", "usage-summary", "request-summarized-usages", "--tenant-id", req.TenancyID, "--time-usage-started", start.Format(time.RFC3339), "--time-usage-ended", usageEnd.Format(time.RFC3339), "--granularity", "DAILY", "--query-type", "USAGE", "--group-by", `["skuPartNumber","unit","service"]`, "--limit", "1000"}
	groups := map[string]UsageMeter{}
	seenRows := map[string]bool{}
	seenPages := map[string]bool{}
	page := ""
	for n := 0; ; n++ {
		if n >= 100 {
			return nil, fmt.Errorf("Oracle billing pagination exceeded its safety limit")
		}
		args := append([]string(nil), base...)
		if page != "" {
			args = append(args, "--page", page)
		}
		v, err := s.call(ctx, req, args...)
		if err != nil {
			return nil, err
		}
		rows, err := strictItems(obj(v)["data"], "items")
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if str(row["service"]) != "Virtual Cloud Network" {
				continue
			}
			id, unit := str(row["sku-part-number"]), str(row["unit"])
			quantity, ok := row["computed-quantity"].(float64)
			at, e := time.Parse(time.RFC3339Nano, str(row["time-usage-started"]))
			if id == "" || unit == "" || !ok || !finiteNonnegative(quantity) || e != nil || at.Before(start) || !at.Before(end) || truth(row["is-forecast"]) {
				return nil, fmt.Errorf("Oracle network billing meter is incomplete or outside the requested period")
			}
			key := id + "\x00" + unit
			rowKey := key + "\x00" + at.Format(time.RFC3339Nano)
			if seenRows[rowKey] {
				return nil, fmt.Errorf("Oracle billing returned a duplicate daily network meter")
			}
			seenRows[rowKey] = true
			meter := groups[key]
			meter.ID = id
			meter.Name = "Virtual Cloud Network / " + id
			meter.Unit = unit
			meter.Quantity += quantity
			if !finiteNonnegative(meter.Quantity) {
				return nil, fmt.Errorf("Oracle billing quantity is out of range")
			}
			if at.After(meter.LatestAt) {
				meter.LatestAt = at
			}
			groups[key] = meter
		}
		page = str(obj(v)["opc-next-page"])
		if page == "" {
			break
		}
		if seenPages[page] {
			return nil, fmt.Errorf("Oracle billing pagination is cyclic")
		}
		seenPages[page] = true
	}
	result := make([]UsageMeter, 0, len(groups))
	for _, m := range groups {
		result = append(result, m)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID+result[i].Unit < result[j].ID+result[j].Unit })
	return result, nil
}
