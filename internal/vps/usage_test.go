package vps

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func oracleUsageFixture(t *testing.T) (*Service, serverstate.CloudObservationBinding, *[]string) {
	t.Helper()
	dir := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}
	now := time.Date(2026, 9, 22, 3, 30, 0, 0, time.UTC)
	b := serverstate.CloudObservationBinding{Provider: "oracle", Profile: "DEFAULT", Region: "ap-singapore-1", ResourceID: "ocid1.instance.oc1.ap-singapore-1.example", TenancyID: "ocid1.tenancy.oc1..example", CompartmentID: "ocid1.tenancy.oc1..example"}
	h := serverstate.Host{ID: "vm", Provider: "oracle", SSHHost: "ubuntu@example", PublicHost: "192.0.2.1", Status: "registered", CreatedAt: now, UpdatedAt: now}
	if err := store.Update(func(i *serverstate.Inventory) error { return i.UpsertHost(h) }); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	s := New(store, Options{Now: func() time.Time { return now }})
	s.options.Run = func(_ context.Context, executable string, args []string) ([]byte, error) {
		call := strings.Join(args, " ")
		calls = append(calls, executable+" "+call)
		for _, word := range []string{" create ", " delete ", " update ", " launch ", " stop "} {
			if strings.Contains(" "+call+" ", word) {
				t.Fatalf("unexpected provider mutation: %s", call)
			}
		}
		var result any
		switch {
		case strings.Contains(call, "iam tenancy get"):
			result = map[string]any{"data": map[string]any{"id": b.TenancyID}}
		case strings.Contains(call, "compute instance get"):
			result = map[string]any{"data": map[string]any{"id": b.ResourceID, "compartment-id": b.CompartmentID}}
		case strings.Contains(call, "compute instance list-vnics"):
			result = map[string]any{"data": []any{map[string]any{"id": "ocid1.vnic.oc1.example", "public-ip": "192.0.2.1"}}}
		case strings.Contains(call, "monitoring metric-data"):
			metric := "VnicFromNetworkBytes"
			if strings.Contains(call, "VnicToNetworkBytes") {
				metric = "VnicToNetworkBytes"
			}
			rows := []any{}
			for index, value := range []float64{100, 200} {
				rows = append(rows, map[string]any{"name": metric, "metadata": map[string]any{"unit": "bytes"}, "dimensions": map[string]any{"resourceId": fmt.Sprintf("ocid1.vnic.oc1.%d", index), "instanceId": b.ResourceID}, "aggregated-datapoints": []any{map[string]any{"timestamp": "2026-09-22T02:00:00Z", "value": value}, map[string]any{"timestamp": "2026-09-22T03:00:00Z", "value": value}}})
			}
			result = map[string]any{"data": rows}
		case strings.Contains(call, "usage-api usage-summary"):
			if !strings.Contains(call, "--time-usage-started 2026-09-01T00:00:00Z") || !strings.Contains(call, "--time-usage-ended 2026-09-23T00:00:00Z") {
				t.Fatalf("wrong UTC usage boundaries: %s", call)
			}
			result = map[string]any{"data": map[string]any{"items": []any{map[string]any{"service": "Virtual Cloud Network", "sku-part-number": "B93455", "unit": "GB Months", "computed-quantity": 0.125, "time-usage-started": "2026-09-21T00:00:00Z"}, map[string]any{"service": "Virtual Cloud Network", "sku-part-number": "B93455", "unit": "GB Months", "computed-quantity": 0.25, "time-usage-started": "2026-09-22T00:00:00Z"}, map[string]any{"service": "Compute", "sku-part-number": "B97384", "computed-quantity": 500}}}}
		default:
			return nil, fmt.Errorf("unexpected cloud read: %s", call)
		}
		return json.Marshal(result)
	}
	return s, b, &calls
}

func TestBindCloudPreviewAndApplyPreserveOwnership(t *testing.T) {
	s, b, calls := oracleUsageFixture(t)
	before, _ := os.ReadFile(s.store.Path)
	p, err := s.PlanBindCloud(context.Background(), "vm", b)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.store.Path)
	if string(before) != string(after) {
		t.Fatal("preview wrote inventory")
	}
	if p.Owned || p.Binding.AccountID == "" || !p.Binding.VerifiedAt.IsZero() {
		t.Fatalf("bad preview: %+v", p)
	}
	if _, err = s.BindCloud(context.Background(), "vm", b, "wrong"); err == nil {
		t.Fatal("accepted wrong digest")
	}
	h, err := s.BindCloud(context.Background(), "vm", b, p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if h.Owned || h.ResourceID != "" || h.OperationID != "" || h.Observation == nil || h.Observation.VerifiedAt.IsZero() {
		t.Fatalf("binding changed lifecycle identity: %+v", h)
	}
	if _, err = s.PlanAction(context.Background(), "vm", "delete"); err == nil {
		t.Fatal("observation binding granted delete permission")
	}
	if len(*calls) == 0 {
		t.Fatal("binding did not verify cloud resource")
	}
	if _, err = os.Stat(s.store.StateDir); !os.IsNotExist(err) {
		t.Fatal("binding created lifecycle history")
	}
}

func TestUsageOracleSeparateMetricsAndBillingReadOnly(t *testing.T) {
	s, b, _ := oracleUsageFixture(t)
	p, err := s.PlanBindCloud(context.Background(), "vm", b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.BindCloud(context.Background(), "vm", b, p.Digest); err != nil {
		t.Fatal(err)
	}
	if err = s.store.Update(func(i *serverstate.Inventory) error {
		return i.UpsertDeployment(serverstate.Deployment{ID: "proxy", HostID: "vm", PublicPort: 443, ListenPort: 443})
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.store.Path)
	s.options.ReadOnly = true
	r, err := s.UsageForServer(context.Background(), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if r.HostID != "vm" || r.ServerID != "proxy" || r.Observed.InboundBytes == nil || *r.Observed.InboundBytes != 600 || r.Observed.OutboundBytes == nil || *r.Observed.OutboundBytes != 600 || r.Observed.InboundPoints != 2 || !r.Observed.Partial {
		t.Fatalf("incorrect multi-VNIC observations: %+v", r)
	}
	if len(r.Billing.Meters) != 1 || r.Billing.Meters[0].Quantity != 0.375 || r.Billing.Meters[0].Unit != "GB Months" || r.Billing.Status != "reported" {
		t.Fatalf("billing normalization or unrelated meter leakage: %+v", r.Billing)
	}
	encoded, _ := json.Marshal(r)
	for _, field := range []string{"remaining_quota", "quota_percentage", "estimated_overage"} {
		if strings.Contains(string(encoded), field) {
			t.Fatalf("invented quota: %s", encoded)
		}
	}
	after, _ := os.ReadFile(s.store.Path)
	if string(before) != string(after) {
		t.Fatal("usage wrote inventory")
	}
	if _, err = s.BindCloud(context.Background(), "vm", b, p.Digest); err == nil {
		t.Fatal("read-only binding apply allowed")
	}
}

func TestOracleUsageUnavailableSourcesNeverBecomeZero(t *testing.T) {
	s, b, _ := oracleUsageFixture(t)
	p, _ := s.PlanBindCloud(context.Background(), "vm", b)
	if _, err := s.BindCloud(context.Background(), "vm", b, p.Digest); err != nil {
		t.Fatal(err)
	}
	run := s.options.Run
	s.options.Run = func(ctx context.Context, e string, args []string) ([]byte, error) {
		call := strings.Join(args, " ")
		if strings.Contains(call, "monitoring metric-data") {
			return []byte(`{"data":[]}`), nil
		}
		if strings.Contains(call, "usage-api") {
			return nil, fmt.Errorf("provider exited with status 1")
		}
		return run(ctx, e, args)
	}
	r, err := s.Usage(context.Background(), "vm")
	if err != nil {
		t.Fatal(err)
	}
	if r.Observed.InboundBytes != nil || r.Observed.OutboundBytes != nil || !r.Observed.Partial || r.Billing.Status != "unavailable" {
		t.Fatalf("unknown presented as zero: %+v", r)
	}
}

func TestOracleMetricIdentityDuplicatesAndNegativeValues(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	base := func() map[string]any {
		return map[string]any{"name": "VnicToNetworkBytes", "metadata": map[string]any{"unit": "bytes"}, "dimensions": map[string]any{"resourceId": "ocid1.vnic.oc1.v", "instanceId": "instance"}, "aggregated-datapoints": []any{map[string]any{"timestamp": start.Format(time.RFC3339), "value": float64(0)}}}
	}
	for _, test := range []string{"other-instance", "unit", "duplicate-stream", "negative", "nil", "outside"} {
		t.Run(test, func(t *testing.T) {
			row := base()
			rows := []any{row}
			switch test {
			case "other-instance":
				obj(row["dimensions"])["instanceId"] = "other"
			case "unit":
				obj(row["metadata"])["unit"] = "GB"
			case "duplicate-stream":
				rows = append(rows, base())
			case "negative":
				obj(arr(row["aggregated-datapoints"])[0])["value"] = float64(-1)
			case "nil":
				obj(arr(row["aggregated-datapoints"])[0])["value"] = nil
			case "outside":
				obj(arr(row["aggregated-datapoints"])[0])["timestamp"] = end.Format(time.RFC3339)
			}
			if _, _, _, err := parseOracleNetwork(map[string]any{"data": rows}, "VnicToNetworkBytes", "instance", start, end); err == nil {
				t.Fatal("accepted invalid stream")
			}
		})
	}
	value, n, _, err := parseOracleNetwork(map[string]any{"data": []any{base()}}, "VnicToNetworkBytes", "instance", start, end)
	if err != nil || value == nil || *value != 0 || n != 1 {
		t.Fatal("observed zero lost")
	}
}

func TestObservationRequestRejectsUnscopedAzureAndOracle(t *testing.T) {
	for _, b := range []serverstate.CloudObservationBinding{{Provider: "azure", Region: "japaneast", ResourceID: "/subscriptions/a/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"}, {Provider: "oracle", Region: "ap-singapore-1", ResourceID: "ocid1.instance.oc1.example"}, {Provider: "oracle", Region: "bad\nregion", ResourceID: "ocid1.instance.oc1.example", TenancyID: "ocid1.tenancy.oc1..t"}} {
		if err := validateObservationRequest(b); err == nil {
			t.Fatalf("accepted invalid cloud scope: %+v", b)
		}
	}
}

func TestUsageMonthUTCAndRetention(t *testing.T) {
	now := time.Date(2026, 9, 22, 3, 30, 0, 0, time.UTC)
	for _, month := range []string{"", "2026-08", "2026-07"} {
		start, end, err := usageWindow(now.In(time.FixedZone("local", 8*3600)), month, "oracle")
		if err != nil {
			t.Fatal(err)
		}
		if start.Location() != time.UTC || end.Location() != time.UTC || start.Day() != 1 || start.Hour() != 0 {
			t.Fatalf("not a UTC month: %s to %s", start, end)
		}
		if month == "" && !end.Equal(now) {
			t.Fatal("current month did not end at now")
		}
		if month != "" && !end.Equal(start.AddDate(0, 1, 0)) {
			t.Fatal("past month not exclusive at next month midnight")
		}
	}
	for _, month := range []string{"2026-9", "2026-13", "2026-10", "2026-06"} {
		if _, _, err := usageWindow(now, month, "oracle"); err == nil {
			t.Fatalf("accepted unsupported month %q", month)
		}
	}
	boundary := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, end, err := usageWindow(boundary, "2026-09", "oracle"); err != nil || !end.Equal(boundary) {
		t.Fatalf("month/year boundary: %s %v", end, err)
	}
	if _, _, err := usageWindow(boundary, "", "oracle"); err == nil {
		t.Fatal("empty first-instant window accepted")
	}
}

func TestOracleHistoricalBillingExclusiveMonthEnd(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	s := New(serverstate.Store{}, Options{Run: func(_ context.Context, _ string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--time-usage-started 2026-08-01T00:00:00Z") || !strings.Contains(joined, "--time-usage-ended 2026-09-01T00:00:00Z") {
			t.Fatalf("query included next-month day: %s", joined)
		}
		return []byte(`{"data":{"items":[]}}`), nil
	}})
	if _, err := s.oracleNetworkBilling(context.Background(), CreateRequest{Provider: "oracle", TenancyID: "ocid1.tenancy.oc1..t"}, start, end); err != nil {
		t.Fatal(err)
	}
}

func TestObservationIdentityUsesLiveAzureSubscriptionAndPermitsHistoricalDisabledReads(t *testing.T) {
	b := serverstate.CloudObservationBinding{Provider: "azure", SubscriptionID: "11111111-1111-4111-8111-111111111111"}
	liveRead := false
	s := New(serverstate.Store{}, Options{ReadOnly: true, Run: func(_ context.Context, _ string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.HasPrefix(joined, "account show") {
			return json.Marshal(map[string]any{"id": b.SubscriptionID, "tenantId": "tenant", "environmentName": "AzureCloud", "state": "Enabled"})
		}
		if strings.HasPrefix(joined, "rest --method get") {
			liveRead = true
			return json.Marshal(map[string]any{"subscriptionId": b.SubscriptionID, "state": "Disabled"})
		}
		return nil, fmt.Errorf("unexpected call: %s", joined)
	}})
	got, err := s.observationIdentity(context.Background(), b)
	if err != nil || !liveRead || got != "azure:"+digest([]string{"AzureCloud", "tenant", b.SubscriptionID}) {
		t.Fatalf("live Disabled subscription history rejected: %s %v", got, err)
	}
}
