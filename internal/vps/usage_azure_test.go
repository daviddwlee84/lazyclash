package vps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func azureUsageTestBinding() serverstate.CloudObservationBinding {
	return serverstate.CloudObservationBinding{Provider: "azure", SubscriptionID: "subscription", Region: "japaneast", ResourceID: "/subscriptions/subscription/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"}
}

func azureUsageTestPeriod() (time.Time, time.Time) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return start, start.Add(3 * time.Hour)
}

func azureUsageTestMetric(name string, totals ...any) map[string]any {
	b := azureUsageTestBinding()
	start, _ := azureUsageTestPeriod()
	var points []any
	for i, total := range totals {
		points = append(points, map[string]any{"timeStamp": start.Add(time.Duration(i) * time.Hour).Format(time.RFC3339), "total": total})
	}
	return map[string]any{"id": b.ResourceID + "/providers/Microsoft.Insights/metrics/" + name,
		"name": map[string]any{"value": name}, "unit": "Bytes", "errorCode": "Success",
		"timeseries": []any{map[string]any{"metadatavalues": []any{}, "data": points}}}
}

func azureUsageTestMetrics() map[string]any {
	return map[string]any{"interval": "PT1H", "namespace": "Microsoft.Compute/virtualMachines", "resourceregion": "japaneast", "value": []any{
		azureUsageTestMetric("Network In Total", float64(1), nil, float64(3)),
		azureUsageTestMetric("Network Out Total", float64(0), float64(2), float64(3)),
	}}
}

func TestAzureUsageMetricsMissingSamplesStayUnknown(t *testing.T) {
	start, end := azureUsageTestPeriod()
	out, err := azureUsageMetrics(azureUsageTestMetrics(), azureUsageTestBinding(), start, end, TransferObservation{ExpectedPoints: 3})
	if err != nil {
		t.Fatal(err)
	}
	if out.InboundBytes == nil || *out.InboundBytes != 4 || out.OutboundBytes == nil || *out.OutboundBytes != 5 || out.InboundPoints != 2 || out.OutboundPoints != 3 || !out.Partial || !out.LatestAt.Equal(start.Add(2*time.Hour)) {
		t.Fatalf("incorrect aggregation: %+v", out)
	}
	v := azureUsageTestMetrics()
	v["value"] = []any{azureUsageTestMetric("Network In Total", nil, nil, nil), azureUsageTestMetric("Network Out Total", float64(0), float64(0), float64(0))}
	out, err = azureUsageMetrics(v, azureUsageTestBinding(), start, end, TransferObservation{ExpectedPoints: 3})
	if err != nil || out.InboundBytes != nil || out.OutboundBytes == nil || *out.OutboundBytes != 0 || !out.Partial {
		t.Fatalf("missing data became zero or real zero was lost: %+v, %v", out, err)
	}
	v["value"] = []any{}
	out, err = azureUsageMetrics(v, azureUsageTestBinding(), start, end, TransferObservation{ExpectedPoints: 3})
	if err != nil || out.InboundBytes != nil || out.OutboundBytes != nil || !out.Partial {
		t.Fatalf("empty metrics became zero: %+v, %v", out, err)
	}
}

func TestAzureUsageRejectsMalformedMetrics(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any, map[string]any)
	}{
		{"wrong-resource", func(_ map[string]any, row map[string]any) { row["id"] = "/another/vm" }},
		{"wrong-unit", func(_ map[string]any, row map[string]any) { row["unit"] = "Count" }},
		{"wrong-namespace", func(v map[string]any, _ map[string]any) { v["namespace"] = "Other" }},
		{"wrong-region", func(v map[string]any, _ map[string]any) { v["resourceregion"] = "eastus" }},
		{"wrong-interval", func(v map[string]any, _ map[string]any) { v["interval"] = "PT1M" }},
		{"wrong-name", func(_ map[string]any, row map[string]any) { row["name"] = map[string]any{"value": "Network In"} }},
		{"error", func(_ map[string]any, row map[string]any) { row["errorCode"] = "Forbidden" }},
		{"duplicate-metric", func(v map[string]any, row map[string]any) { v["value"] = []any{row, row} }},
		{"duplicate-series", func(_ map[string]any, row map[string]any) {
			row["timeseries"] = append(arr(row["timeseries"]), arr(row["timeseries"])[0])
		}},
		{"dimensions", func(_ map[string]any, row map[string]any) {
			obj(arr(row["timeseries"])[0])["metadatavalues"] = []any{map[string]any{"value": "nic"}}
		}},
		{"negative", func(_ map[string]any, row map[string]any) {
			obj(arr(obj(arr(row["timeseries"])[0])["data"])[0])["total"] = float64(-1)
		}},
		{"nan", func(_ map[string]any, row map[string]any) {
			obj(arr(obj(arr(row["timeseries"])[0])["data"])[0])["total"] = math.NaN()
		}},
		{"string-None", func(_ map[string]any, row map[string]any) {
			obj(arr(obj(arr(row["timeseries"])[0])["data"])[0])["total"] = "None"
		}},
		{"timestamp-before-window", func(_ map[string]any, row map[string]any) {
			obj(arr(obj(arr(row["timeseries"])[0])["data"])[0])["timeStamp"] = "2026-08-31T23:00:00Z"
		}},
		{"timestamp-at-end", func(_ map[string]any, row map[string]any) {
			obj(arr(obj(arr(row["timeseries"])[0])["data"])[0])["timeStamp"] = "2026-09-01T03:00:00Z"
		}},
		{"duplicate-timestamp", func(_ map[string]any, row map[string]any) {
			obj(arr(obj(arr(row["timeseries"])[0])["data"])[1])["timeStamp"] = "2026-09-01T00:00:00Z"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := azureUsageTestMetrics()
			tc.edit(v, obj(arr(v["value"])[0]))
			start, end := azureUsageTestPeriod()
			if _, err := azureUsageMetrics(v, azureUsageTestBinding(), start, end, TransferObservation{ExpectedPoints: 3}); err == nil {
				t.Fatal("accepted malformed metrics")
			}
		})
	}
}

func azureUsageTestRow(id, meter, name, unit string, quantity, cost float64) map[string]any {
	return map[string]any{"id": id, "kind": "legacy", "properties": map[string]any{
		"subscriptionId": "subscription", "meterId": meter, "quantity": quantity, "cost": cost,
		"date": "2026-09-01T00:00:00Z", "billingCurrency": "TWD",
		"meterDetails": map[string]any{"meterCategory": "Bandwidth", "meterName": name, "unitOfMeasure": unit},
	}}
}

func azureUsageTestService(t *testing.T, respond func([]string) (any, error)) *Service {
	t.Helper()
	return New(serverstate.Store{}, Options{ReadOnly: true, Run: func(_ context.Context, exe string, args []string) ([]byte, error) {
		if exe != "az" || azureFlag(args, "--subscription") != "subscription" {
			t.Fatalf("missing explicit Azure subscription: %s %v", exe, args)
		}
		args = azureArgs(args)
		if len(args) < 2 || !((args[0] == "vm" && args[1] == "show") || (args[0] == "monitor" && args[1] == "metrics") || (args[0] == "rest" && azureFlag(args, "--method") == "get")) {
			t.Fatalf("unexpected or mutating Azure call: %v", args)
		}
		v, err := respond(args)
		if err != nil {
			return nil, err
		}
		return json.Marshal(v)
	}})
}

func TestAzureUsageBillingPreservesNativeUnitsAndDeduplicatesPages(t *testing.T) {
	internet := azureUsageTestRow("record-1", "internet", "Standard Data Transfer Out", "10 GB", 12.5, 32)
	intercontinental := azureUsageTestRow("record-2", "intercontinental", "Inter-Continent Data Transfer Out", "1 TB", .125, 3)
	moreInternet := azureUsageTestRow("record-3", "internet", "Standard Data Transfer Out", "10 GB", 2.5, 5)
	storage := azureUsageTestRow("storage", "storage", "Storage", "GB", 99, 4)
	obj(obj(storage["properties"])["meterDetails"])["meterCategory"] = "Storage"
	calls := 0
	s := azureUsageTestService(t, func(args []string) (any, error) {
		calls++
		u, err := url.Parse(azureFlag(args, "--url"))
		if err != nil || u.Host != "management.azure.com" || u.Query().Get("$expand") != "properties/meterDetails" || !strings.Contains(u.Query().Get("$filter"), "2026-09-01") {
			t.Fatalf("unexpected billing URL: %s", u)
		}
		if calls == 1 {
			q := u.Query()
			q.Set("$skiptoken", "page-2")
			u.RawQuery = q.Encode()
			return map[string]any{"value": []any{internet, storage}, "nextLink": u.String()}, nil
		}
		return map[string]any{"value": []any{internet, intercontinental, moreInternet}}, nil
	})
	start, end := azureUsageTestPeriod()
	b := azureUsageTestBinding()
	out := s.azureUsageBilling(context.Background(), CreateRequest{Provider: "azure", SubscriptionID: b.SubscriptionID}, b, start, end)
	if out.Status != "reported" || len(out.Meters) != 2 || calls != 2 || !strings.Contains(out.Scope, "across all resources") {
		t.Fatalf("unexpected billing result: %+v", out)
	}
	for _, m := range out.Meters {
		switch m.ID {
		case "internet":
			if m.Unit != "10 GB" || m.Quantity != 15 || m.Cost == nil || *m.Cost != 37 || m.Currency != "TWD" {
				t.Fatalf("changed native billing quantity/cost: %+v", m)
			}
		case "intercontinental":
			if m.Unit != "1 TB" || m.Quantity != .125 || m.Cost == nil || *m.Cost != 3 {
				t.Fatalf("mixed Internet and intercontinent meters: %+v", m)
			}
		default:
			t.Fatalf("included unrelated meter: %+v", m)
		}
	}
}

func TestAzureUsageMissingCostDoesNotReportKnownSubset(t *testing.T) {
	s := azureUsageTestService(t, func(_ []string) (any, error) {
		first := azureUsageTestRow("1", "internet", "Internet", "10 GB", 1, 2)
		missing := azureUsageTestRow("2", "internet", "Internet", "10 GB", 3, 0)
		delete(obj(missing["properties"]), "cost")
		last := azureUsageTestRow("3", "internet", "Internet", "10 GB", 5, 6)
		return map[string]any{"value": []any{first, missing, last}}, nil
	})
	start, end := azureUsageTestPeriod()
	b := azureUsageTestBinding()
	out := s.azureUsageBilling(context.Background(), CreateRequest{Provider: "azure", SubscriptionID: b.SubscriptionID}, b, start, end)
	if out.Status != "reported" || len(out.Meters) != 1 || out.Meters[0].Quantity != 9 || out.Meters[0].Cost != nil || len(out.Warnings) < 2 {
		t.Fatalf("reported incomplete cost as complete: %+v", out)
	}
}

func TestAzureUsageBillingUnavailableAndNoData(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(map[string]any)
		empty  bool
		denied bool
	}{
		{name: "modern", edit: func(r map[string]any) { r["kind"] = "modern" }},
		{name: "no-id", edit: func(r map[string]any) { delete(r, "id") }},
		{name: "missing-unit", edit: func(r map[string]any) { delete(obj(obj(r["properties"])["meterDetails"]), "unitOfMeasure") }},
		{name: "missing-currency", edit: func(r map[string]any) { delete(obj(r["properties"]), "billingCurrency") }},
		{name: "missing-date", edit: func(r map[string]any) { delete(obj(r["properties"]), "date") }},
		{name: "literal-None", edit: func(r map[string]any) { obj(r["properties"])["quantity"] = "None" }},
		{name: "negative-quantity", edit: func(r map[string]any) { obj(r["properties"])["quantity"] = -1.0 }},
		{name: "other-subscription", edit: func(r map[string]any) { obj(r["properties"])["subscriptionId"] = "another" }},
		{name: "outside-period", edit: func(r map[string]any) { obj(r["properties"])["date"] = "2026-08-31T00:00:00Z" }},
		{name: "empty", empty: true},
		{name: "permission", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := azureUsageTestService(t, func(_ []string) (any, error) {
				if tc.denied {
					return nil, errors.New("access denied")
				}
				row := azureUsageTestRow("1", "internet", "Internet", "10 GB", 1, 2)
				if tc.edit != nil {
					tc.edit(row)
				}
				rows := []any{row}
				if tc.empty {
					rows = []any{}
				}
				return map[string]any{"value": rows}, nil
			})
			start, end := azureUsageTestPeriod()
			b := azureUsageTestBinding()
			out := s.azureUsageBilling(context.Background(), CreateRequest{Provider: "azure", SubscriptionID: b.SubscriptionID}, b, start, end)
			want := "unavailable"
			if tc.empty {
				want = "no-data"
			}
			if out.Status != want || len(out.Meters) != 0 || len(out.Warnings) < 2 {
				t.Fatalf("missing data incorrectly reported: %+v", out)
			}
		})
	}
}

func TestAzureUsagePaginationRestrictsCredentialsAndDetectsConflicts(t *testing.T) {
	path := "/subscriptions/subscription/providers/Microsoft.Consumption/usageDetails"
	for _, raw := range []string{
		"https://attacker.example" + path + "?api-version=" + azureUsageAPIVersion,
		"http://management.azure.com" + path + "?api-version=" + azureUsageAPIVersion,
		"https://management.azure.com/subscriptions/other/providers/Microsoft.Consumption/usageDetails?api-version=" + azureUsageAPIVersion,
		"https://user@management.azure.com" + path + "?api-version=" + azureUsageAPIVersion,
		"https://management.azure.com" + path + "?api-version=other",
		"https://management.azure.com" + path + "?api-version=" + azureUsageAPIVersion + "#fragment",
	} {
		if err := azureUsageNextLink(raw, path); err == nil {
			t.Fatalf("accepted unsafe nextLink %s", raw)
		}
	}
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflict-%v", conflict), func(t *testing.T) {
			calls := 0
			s := azureUsageTestService(t, func(args []string) (any, error) {
				calls++
				row := azureUsageTestRow("same-id", "internet", "Internet", "10 GB", float64(calls), 2)
				if !conflict || calls == 1 {
					next := azureFlag(args, "--url")
					if conflict {
						next += "&%24skiptoken=2"
					}
					return map[string]any{"value": []any{row}, "nextLink": next}, nil
				}
				return map[string]any{"value": []any{row}}, nil
			})
			start, end := azureUsageTestPeriod()
			b := azureUsageTestBinding()
			out := s.azureUsageBilling(context.Background(), CreateRequest{Provider: "azure", SubscriptionID: b.SubscriptionID}, b, start, end)
			if out.Status != "unavailable" || len(out.Meters) != 0 || calls > 2 {
				t.Fatalf("unsafe pagination was accepted: %+v (%d calls)", out, calls)
			}
		})
	}
}

func TestAzureUsageReadOnlyPartialReportAndBindingValidation(t *testing.T) {
	start, end := azureUsageTestPeriod()
	b := azureUsageTestBinding()
	s := azureUsageTestService(t, func(args []string) (any, error) {
		switch args[0] {
		case "vm":
			return map[string]any{"id": b.ResourceID, "location": b.Region}, nil
		case "monitor":
			if azureFlag(args, "--interval") != "PT1H" || azureFlag(args, "--aggregation") != "Total" || azureFlag(args, "--resource") != b.ResourceID {
				t.Fatalf("incorrect Azure metrics request: %v", args)
			}
			return azureUsageTestMetrics(), nil
		default:
			return nil, errors.New("billing access denied")
		}
	})
	out, err := s.azureUsage(context.Background(), serverstate.Host{Owned: false}, b, UsageReport{PeriodStart: start, PeriodEnd: end})
	if err != nil || out.Observed.OutboundBytes == nil || *out.Observed.OutboundBytes != 5 || out.Billing.Status != "unavailable" || !s.options.ReadOnly {
		t.Fatalf("lost partial read-only telemetry: %+v, %v", out, err)
	}
	b.SubscriptionID = "other"
	if _, err = s.azureUsage(context.Background(), serverstate.Host{}, b, UsageReport{PeriodStart: start, PeriodEnd: end}); err == nil {
		t.Fatal("accepted resource ID in another subscription")
	}
}

func TestAzureUsageHistoricalMonthUsesRequestedWindow(t *testing.T) {
	for _, tc := range []struct {
		name, start, end, last, filterEnd string
	}{
		{"past-month", "2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z", "2026-08-31T23:00:00Z", "2026-08-31"},
		{"leap-month", "2024-02-01T00:00:00Z", "2024-03-01T00:00:00Z", "2024-02-29T23:00:00Z", "2024-02-29"},
		{"year-boundary", "2025-12-01T00:00:00Z", "2026-01-01T00:00:00Z", "2025-12-31T23:00:00Z", "2025-12-31"},
		{"current-partial-day", "2026-09-01T00:00:00Z", "2026-09-22T10:05:00Z", "2026-09-22T09:00:00Z", "2026-09-22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, _ := time.Parse(time.RFC3339, tc.start)
			end, _ := time.Parse(time.RFC3339, tc.end)
			last, _ := time.Parse(time.RFC3339, tc.last)
			b := azureUsageTestBinding()
			s := azureUsageTestService(t, func(args []string) (any, error) {
				switch args[0] {
				case "vm":
					return map[string]any{"id": b.ResourceID, "location": b.Region}, nil
				case "monitor":
					if azureFlag(args, "--start-time") != tc.start || azureFlag(args, "--end-time") != tc.end {
						t.Fatalf("used current time instead of the selected month: %v", args)
					}
					v := azureUsageTestMetrics()
					for _, row := range arr(v["value"]) {
						obj(arr(obj(row)["timeseries"])[0])["data"] = []any{map[string]any{"timeStamp": tc.last, "total": float64(12)}}
					}
					return v, nil
				case "rest":
					u, _ := url.Parse(azureFlag(args, "--url"))
					want := "properties/usageStart ge '" + start.Format("2006-01-02") + "' and properties/usageEnd le '" + tc.filterEnd + "'"
					if got := u.Query().Get("$filter"); got != want {
						t.Fatalf("billing query crossed the exclusive month end: %s, want %s", got, want)
					}
					row := azureUsageTestRow("history", "internet", "Internet", "10 GB", 1, 2)
					obj(row["properties"])["date"] = last.Format("2006-01-02")
					return map[string]any{"value": []any{row}}, nil
				default:
					t.Fatalf("unexpected call: %v", args)
					return nil, nil
				}
			})
			out, err := s.azureUsage(context.Background(), serverstate.Host{}, b, UsageReport{PeriodStart: start, PeriodEnd: end})
			if err != nil || out.Observed.OutboundBytes == nil || *out.Observed.OutboundBytes != 12 || !out.Observed.LatestAt.Equal(last) || out.Billing.Status != "reported" || len(out.Billing.Meters) != 1 {
				t.Fatalf("historical window was not preserved: %+v, %v", out, err)
			}
		})
	}
}
