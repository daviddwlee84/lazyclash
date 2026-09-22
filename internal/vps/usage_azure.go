package vps

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

const azureUsageAPIVersion = "2024-08-01"

func (s *Service) azureUsage(ctx context.Context, _ serverstate.Host, b serverstate.CloudObservationBinding, report UsageReport) (UsageReport, error) {
	if err := azureUsageResource(b); err != nil {
		return report, err
	}
	r := CreateRequest{Provider: "azure", SubscriptionID: b.SubscriptionID}
	v, err := s.call(ctx, r, "vm", "show", "--ids", b.ResourceID)
	if err != nil {
		return report, fmt.Errorf("read Azure VM identity: %w", err)
	}
	vm := obj(v)
	if !strings.EqualFold(str(vm["id"]), b.ResourceID) || !strings.EqualFold(str(vm["location"]), b.Region) {
		return report, fmt.Errorf("Azure VM identity or location differs from its observation binding")
	}

	report.Observed.Source = "Azure Monitor: Network In Total / Network Out Total; Total aggregation, hourly, all VM NICs"
	report.Observed.ExpectedPoints = int(math.Ceil(report.PeriodEnd.Sub(report.PeriodStart).Hours()))
	v, err = s.call(ctx, r, "monitor", "metrics", "list", "--resource", b.ResourceID,
		"--namespace", "Microsoft.Compute/virtualMachines", "--metrics", "Network In Total", "Network Out Total",
		"--aggregation", "Total", "--interval", "PT1H", "--start-time", report.PeriodStart.Format(time.RFC3339),
		"--end-time", report.PeriodEnd.Format(time.RFC3339))
	if err == nil {
		report.Observed, err = azureUsageMetrics(v, b, report.PeriodStart, report.PeriodEnd, report.Observed)
	}
	if err != nil {
		// A malformed response must not expose partial sums as complete totals.
		report.Observed.InboundBytes, report.Observed.OutboundBytes = nil, nil
		report.Observed.InboundPoints, report.Observed.OutboundPoints = 0, 0
		report.Observed.LatestAt = time.Time{}
		report.Observed.Partial = true
		report.Warnings = append(report.Warnings, fmt.Sprintf("Azure VM network observations unavailable: %v", err))
	} else if report.Observed.Partial {
		report.Warnings = append(report.Warnings, "Azure VM network totals cover only returned hourly samples; missing/null samples are unknown, not zero.")
	}
	report.Billing = s.azureUsageBilling(ctx, r, b, report.PeriodStart, report.PeriodEnd)
	return report, nil
}

func azureUsageResource(b serverstate.CloudObservationBinding) error {
	p := strings.Split(strings.TrimPrefix(b.ResourceID, "/"), "/")
	if b.SubscriptionID == "" || b.Region == "" || len(p) != 8 || !strings.HasPrefix(b.ResourceID, "/") ||
		!strings.EqualFold(p[0], "subscriptions") || !strings.EqualFold(p[1], b.SubscriptionID) ||
		!strings.EqualFold(p[2], "resourceGroups") || !strings.EqualFold(p[4], "providers") ||
		!strings.EqualFold(p[5], "Microsoft.Compute") || !strings.EqualFold(p[6], "virtualMachines") ||
		strings.ContainsAny(b.ResourceID, "?#\\") {
		return fmt.Errorf("Azure usage requires a VM resource ID matching its explicit subscription and region")
	}
	for _, part := range p {
		if !azureUsageText(part) || part == "." || part == ".." || strings.Contains(part, "%") {
			return fmt.Errorf("Azure VM resource ID is invalid")
		}
	}
	return nil
}

func azureUsageMetrics(v any, b serverstate.CloudObservationBinding, start, end time.Time, out TransferObservation) (TransferObservation, error) {
	m := obj(v)
	if n := str(m["namespace"]); n != "" && !strings.EqualFold(n, "Microsoft.Compute/virtualMachines") {
		return out, fmt.Errorf("unexpected Azure metric namespace")
	}
	if n := str(m["resourceregion"]); n != "" && !strings.EqualFold(n, b.Region) {
		return out, fmt.Errorf("unexpected Azure metric region")
	}
	if str(m["interval"]) != "PT1H" {
		return out, fmt.Errorf("Azure metric interval is not one hour")
	}
	rows, err := strictItems(v, "value")
	if err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for _, row := range rows {
		name := str(obj(row["name"])["value"])
		if (name != "Network In Total" && name != "Network Out Total") || seen[name] {
			return out, fmt.Errorf("unexpected or duplicated Azure network metric")
		}
		seen[name] = true
		metricID := b.ResourceID + "/providers/Microsoft.Insights/metrics/" + name
		if !strings.EqualFold(str(row["id"]), metricID) || !strings.EqualFold(str(row["unit"]), "Bytes") {
			return out, fmt.Errorf("Azure metric resource or unit differs from the requested VM bytes")
		}
		if code := str(row["errorCode"]); code != "" && code != "Success" {
			return out, fmt.Errorf("Azure network metric is unavailable")
		}
		series, err := strictItems(row, "timeseries")
		if err != nil || len(series) > 1 {
			return out, fmt.Errorf("Azure VM network metric must have at most one dimensionless series")
		}
		var sum float64
		count := 0
		for _, series := range series {
			dimensions, validDimensions := series["metadatavalues"].([]any)
			if (series["metadatavalues"] != nil && !validDimensions) || len(dimensions) != 0 {
				return out, fmt.Errorf("Azure VM network metric contains unexpected dimensions")
			}
			points, err := strictItems(series, "data")
			if err != nil {
				return out, err
			}
			seenHours := map[int64]bool{}
			for _, point := range points {
				at, err := time.Parse(time.RFC3339Nano, str(point["timeStamp"]))
				hour := int64(at.Sub(start) / time.Hour)
				if err != nil || at.Before(start) || !at.Before(end) || seenHours[hour] {
					return out, fmt.Errorf("Azure metric timestamp is invalid, outside the requested window or duplicated")
				}
				seenHours[hour] = true
				if point["total"] == nil {
					continue
				}
				n, ok := azureUsageNumber(point["total"])
				if !ok || n < 0 || math.IsInf(sum+n, 0) {
					return out, fmt.Errorf("Azure metric total is not a finite nonnegative byte count")
				}
				sum += n
				count++
				if at.After(out.LatestAt) {
					out.LatestAt = at
				}
			}
		}
		if count > out.ExpectedPoints {
			return out, fmt.Errorf("Azure metric has more samples than the requested hourly window")
		}
		if name == "Network In Total" {
			out.InboundPoints = count
			if count > 0 {
				out.InboundBytes = &sum
			}
		} else {
			out.OutboundPoints = count
			if count > 0 {
				out.OutboundBytes = &sum
			}
		}
	}
	out.Partial = out.InboundPoints < out.ExpectedPoints || out.OutboundPoints < out.ExpectedPoints || out.InboundBytes == nil || out.OutboundBytes == nil
	return out, nil
}

func (s *Service) azureUsageBilling(ctx context.Context, r CreateRequest, b serverstate.CloudObservationBinding, start, end time.Time) BillingObservation {
	out := BillingObservation{
		Source:             "Azure Consumption Usage Details (legacy), API " + azureUsageAPIVersion,
		Scope:              "subscription " + b.SubscriptionID + "; Bandwidth meters across all resources",
		Status:             "unavailable",
		Meters:             []UsageMeter{},
		PublishedAllowance: "Published Internet pricing includes the first 100 GB/month free; pooling scope is not verified here. Pricing context only: https://azure.microsoft.com/en-us/pricing/details/bandwidth/",
		Warnings:           []string{"Reported quantities retain native billing units, including 10 GB or 1 TB; no byte conversion or remaining quota is inferred. Billing can lag up to 72 hours and is separate from VM telemetry."},
	}
	path := "/subscriptions/" + url.PathEscape(b.SubscriptionID) + "/providers/Microsoft.Consumption/usageDetails"
	u := url.URL{Scheme: "https", Host: "management.azure.com", Path: path}
	q := u.Query()
	q.Set("api-version", azureUsageAPIVersion)
	q.Set("$expand", "properties/meterDetails")
	// UsageDetails uses inclusive dates, while the report's end is exclusive.
	// A completed UTC month must not include the next month's first day.
	billingEnd := end.UTC()
	if billingEnd.Equal(time.Date(billingEnd.Year(), billingEnd.Month(), billingEnd.Day(), 0, 0, 0, 0, time.UTC)) {
		billingEnd = billingEnd.AddDate(0, 0, -1)
	}
	q.Set("$filter", "properties/usageStart ge '"+start.UTC().Format("2006-01-02")+"' and properties/usageEnd le '"+billingEnd.Format("2006-01-02")+"'")
	u.RawQuery = q.Encode()
	meters, latest, err := s.azureUsageBillingPages(ctx, r, b, u.String(), path, start, end)
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("Azure billing usage unavailable: %v", err))
		return out
	}
	out.Meters, out.LatestAt = meters, latest
	if len(meters) == 0 {
		out.Status = "no-data"
		out.Warnings = append(out.Warnings, "No Bandwidth meter records were returned; this does not establish zero usage.")
	} else {
		out.Status = "reported"
		for _, m := range meters {
			if m.Cost == nil {
				out.Warnings = append(out.Warnings, "Some meter records lacked reported cost; the affected aggregate cost is unknown.")
				break
			}
		}
	}
	return out
}

func (s *Service) azureUsageBillingPages(ctx context.Context, r CreateRequest, b serverstate.CloudObservationBinding, next, path string, start, end time.Time) ([]UsageMeter, time.Time, error) {
	meters := map[string]UsageMeter{}
	missingCost := map[string]bool{}
	seenPages := map[string]bool{}
	seenRows := map[string][32]byte{}
	var latest time.Time
	for page := 0; next != ""; page++ {
		if page >= 100 || seenPages[next] {
			return nil, latest, fmt.Errorf("Azure usage pagination exceeded its limit or repeated a page")
		}
		if err := azureUsageNextLink(next, path); err != nil {
			return nil, latest, err
		}
		seenPages[next] = true
		v, err := s.call(ctx, r, "rest", "--method", "get", "--url", next)
		if err != nil {
			return nil, latest, err
		}
		rows, err := strictItems(v, "value")
		if err != nil {
			return nil, latest, err
		}
		for _, row := range rows {
			if str(row["kind"]) != "legacy" {
				return nil, latest, fmt.Errorf("billing agreement is not supported by the legacy Usage Details adapter; EA/MCA require Cost Details")
			}
			id := str(row["id"])
			if !azureUsageText(id) {
				return nil, latest, fmt.Errorf("Azure usage record lacks a valid deduplication ID")
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				return nil, latest, fmt.Errorf("Azure usage record is malformed")
			}
			rowHash := sha256.Sum256(encoded)
			if previous, ok := seenRows[id]; ok {
				if previous != rowHash {
					return nil, latest, fmt.Errorf("Azure usage returned conflicting records with the same ID")
				}
				continue
			}
			seenRows[id] = rowHash
			p := obj(row["properties"])
			if subscription := str(p["subscriptionId"]); subscription != "" && !strings.EqualFold(subscription, b.SubscriptionID) {
				return nil, latest, fmt.Errorf("Azure usage record subscription differs from the observation binding")
			}
			if resource := str(p["resourceId"]); strings.HasPrefix(strings.ToLower(resource), "/subscriptions/") && !strings.HasPrefix(strings.ToLower(resource), "/subscriptions/"+strings.ToLower(b.SubscriptionID)+"/") {
				return nil, latest, fmt.Errorf("Azure usage record resource belongs to another subscription")
			}
			m := obj(p["meterDetails"])
			if !azureUsageText(str(m["meterCategory"])) {
				return nil, latest, fmt.Errorf("Azure usage record is missing its meter category")
			}
			if !strings.EqualFold(str(m["meterCategory"]), "Bandwidth") {
				continue
			}
			meterID, name, unit, currency := str(p["meterId"]), str(m["meterName"]), str(m["unitOfMeasure"]), str(p["billingCurrency"])
			if !azureUsageText(meterID) || !azureUsageText(name) || !azureUsageText(unit) || !azureUsageText(currency) {
				return nil, latest, fmt.Errorf("Azure Bandwidth record lacks meter identity, name, native unit or currency")
			}
			quantity, ok := azureUsageNumber(p["quantity"])
			if !ok || quantity < 0 {
				return nil, latest, fmt.Errorf("Azure Bandwidth quantity is not a finite nonnegative number")
			}
			at, err := time.Parse(time.RFC3339Nano, str(p["date"]))
			if err != nil {
				at, err = time.Parse("2006-01-02", str(p["date"]))
			}
			if err != nil || at.Before(start) || !at.Before(end) {
				return nil, latest, fmt.Errorf("Azure Bandwidth record date is invalid or outside the requested window")
			}
			key := meterID + "\x00" + unit + "\x00" + currency
			meter, found := meters[key]
			if !found {
				meter = UsageMeter{ID: meterID, Name: name, Unit: unit, Currency: currency}
			} else if meter.Name != name {
				return nil, latest, fmt.Errorf("Azure usage returned conflicting names for a billing meter")
			}
			if math.IsInf(meter.Quantity+quantity, 0) {
				return nil, latest, fmt.Errorf("Azure usage meter quantity overflow")
			}
			meter.Quantity += quantity
			if p["cost"] == nil {
				missingCost[key] = true
				meter.Cost = nil
			} else {
				cost, ok := azureUsageNumber(p["cost"])
				if !ok {
					return nil, latest, fmt.Errorf("Azure Bandwidth reported cost is not finite")
				}
				if !missingCost[key] {
					if meter.Cost != nil {
						cost += *meter.Cost
					}
					if math.IsInf(cost, 0) {
						return nil, latest, fmt.Errorf("Azure usage meter cost overflow")
					}
					meter.Cost = &cost
				}
			}
			if at.After(meter.LatestAt) {
				meter.LatestAt = at
			}
			if at.After(latest) {
				latest = at
			}
			meters[key] = meter
		}
		nextValue := obj(v)["nextLink"]
		if nextValue != nil {
			var ok bool
			next, ok = nextValue.(string)
			if !ok {
				return nil, latest, fmt.Errorf("Azure usage pagination link is malformed")
			}
		} else {
			next = ""
		}
	}
	keys := make([]string, 0, len(meters))
	for key := range meters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]UsageMeter, 0, len(keys))
	for _, key := range keys {
		out = append(out, meters[key])
	}
	return out, latest, nil
}

func azureUsageNextLink(raw, path string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "management.azure.com") || u.User != nil || u.Fragment != "" || u.Opaque != "" ||
		!strings.EqualFold(u.Path, path) || u.RawPath != "" || u.Query().Get("api-version") != azureUsageAPIVersion {
		return fmt.Errorf("Azure usage pagination link is outside the expected subscription Usage Details endpoint")
	}
	return nil
}

func azureUsageNumber(v any) (float64, bool) {
	n, ok := v.(float64)
	return n, ok && !math.IsNaN(n) && !math.IsInf(n, 0)
}

func azureUsageText(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && !strings.EqualFold(s, "None") && !strings.EqualFold(s, "null")
}
