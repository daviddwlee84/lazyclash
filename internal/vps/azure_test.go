package vps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type azureFixture struct {
	t             *testing.T
	s             *Service
	a             azureAdapter
	op            *operation
	resources     map[string]map[string]any
	writes        []string
	failKind      string
	failBefore    bool
	tenant        string
	publicAPI     bool
	queryOverride func(string) ([]byte, error)
}

func newAzureFixture(t *testing.T) *azureFixture {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "id.pub")
	if e := os.WriteFile(key, []byte("ssh-ed25519 AAAA azure-fixture\n"), 0600); e != nil {
		t.Fatal(e)
	}
	f := &azureFixture{t: t, resources: map[string]map[string]any{}, tenant: "tenant"}
	f.s = New(serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}, Options{Now: func() time.Time { return time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC) }, Run: f.run, HTTPGet: f.prices})
	f.a = azureAdapter{s: f.s}
	r := CreateRequest{ID: "az-test", Name: "az-test", Provider: "azure", SubscriptionID: "subscription", Region: "eastus", Architecture: "arm64", Plan: "Standard_B2pts_v2", DiskGB: 32, Image: "Canonical:ubuntu-24_04-lts:server-arm64:24.04.202609010", ImageVersion: "24.04.202609010", SSHKey: key, SSHKeyFingerprint: digest("ssh-ed25519 AAAA azure-fixture"), SSHUser: "ubuntu", SSHCIDR: "192.0.2.0/24"}
	f.op = &operation{Version: 1, ID: "lc-azure-fixture", AccountID: "azure:" + digest([]string{"AzureCloud", "tenant", "subscription"}), Request: r, Host: serverstate.Host{ID: r.ID, Provider: r.Provider, Region: r.Region, OperationID: "lc-azure-fixture", Owned: true, Status: "creating"}, State: "intent"}
	if e := f.s.cloudPersist(f.op); e != nil {
		t.Fatal(e)
	}
	return f
}
func azureTestJSON(v any) ([]byte, error) { return json.Marshal(v) }
func azureArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--subscription", "--output":
			i++
		case "--only-show-errors":
		default:
			out = append(out, args[i])
		}
	}
	return out
}
func azureFlag(args []string, key string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}
func (f *azureFixture) resource(kind string) map[string]any {
	op := *f.op
	m := map[string]any{"id": azureID(op, kind), "name": strings.TrimPrefix(kind, "azure-"), "tags": map[string]any{"lazyclash-operation": op.ID}, "provisioningState": "Succeeded"}
	switch kind {
	case "azure-vm":
		m["vmId"] = "immutable-vm"
		m["storageProfile"] = map[string]any{"osDisk": map[string]any{"name": azureBase(op) + "-os", "deleteOption": "Detach", "managedDisk": map[string]any{"id": azureID(op, "azure-disk")}}, "dataDisks": []any{}}
		m["networkProfile"] = map[string]any{"networkInterfaces": []any{map[string]any{"id": azureID(op, "azure-nic"), "deleteOption": "Detach"}}}
	case "azure-disk":
		delete(m, "tags")
		m["uniqueId"] = "immutable-disk"
		m["managedBy"] = azureID(op, "azure-vm")
	case "azure-ip":
		m["ipAddress"] = "198.51.100.8"
		m["ipConfiguration"] = map[string]any{"id": azureID(op, "azure-nic") + "/ipConfigurations/ipconfig1"}
	case "azure-nic":
		if f.resources["azure-vm"] != nil {
			m["virtualMachine"] = map[string]any{"id": azureID(op, "azure-vm")}
		}
	case "azure-vnet":
		m["subnets"] = []any{map[string]any{"id": azureID(op, "azure-subnet")}}
	case "azure-nsg":
		m["securityRules"] = []any{map[string]any{"id": azureID(op, "azure-nsg-ssh")}, map[string]any{"id": azureID(op, "azure-nsg-web")}, map[string]any{"id": azureID(op, "azure-nsg-udp")}}
	}
	return m
}
func (f *azureFixture) run(_ context.Context, exe string, raw []string) ([]byte, error) {
	f.t.Helper()
	if f.publicAPI {
		inv, err := f.s.store.Load()
		if err != nil {
			f.t.Fatal(err)
		}
		if host, err := inv.Host(f.op.Request.ID); err == nil {
			op, err := f.s.readOperation(host.OperationID)
			if err != nil {
				f.t.Fatal(err)
			}
			f.op = &op
		}
	}
	if exe != "az" {
		f.t.Fatalf("unexpected executable %s", exe)
	}
	args := azureArgs(raw)
	joined := strings.Join(args, " ")
	if strings.HasPrefix(joined, "account show") {
		return azureTestJSON(map[string]any{"id": "subscription", "tenantId": f.tenant, "state": "Enabled", "environmentName": "AzureCloud"})
	}
	if strings.HasPrefix(joined, "vm list-skus") {
		var rows []any
		for _, x := range []struct{ name, arch string }{{"Standard_B2pts_v2", "Arm64"}, {"Standard_B2ats_v2", "x64"}, {"Standard_B1s", "x64"}} {
			rows = append(rows, map[string]any{"name": x.name, "resourceType": "virtualMachines", "locations": []string{"eastus"}, "locationInfo": []any{map[string]any{"location": "eastus", "zones": []string{"1", "2"}}}, "capabilities": []any{map[string]any{"name": "MemoryGB", "value": "1"}, map[string]any{"name": "vCPUs", "value": "2"}, map[string]any{"name": "CpuArchitectureType", "value": x.arch}, map[string]any{"name": "HyperVGenerations", "value": "V2"}}})
		}
		return azureTestJSON(rows)
	}
	if strings.HasPrefix(joined, "vm image list") {
		sku := azureFlag(args, "--sku")
		return azureTestJSON([]any{map[string]any{"publisher": "Canonical", "offer": "ubuntu-24_04-lts", "sku": sku, "version": "24.04.202609010"}, map[string]any{"publisher": "Canonical", "offer": "ubuntu-24_04-lts", "sku": sku, "version": "24.04.202608010"}})
	}
	if strings.HasPrefix(joined, "vm image show") {
		arch := "x64"
		if strings.Contains(azureFlag(args, "--urn"), "server-arm64") {
			arch = "Arm64"
		}
		return azureTestJSON(map[string]any{"name": "24.04.202609010", "architecture": arch, "hyperVGeneration": "V2", "osDiskImage": map[string]any{"operatingSystem": "Linux"}})
	}
	if strings.HasPrefix(joined, "vm get-instance-view") {
		return []byte(`{"instanceView":{"statuses":[{"code":"PowerState/running"}]}}`), nil
	}
	if strings.HasPrefix(joined, "group list") {
		rows := []any{}
		if g := f.resources["azure-group"]; g != nil {
			rows = append(rows, g)
		}
		return azureTestJSON(rows)
	}
	if strings.HasPrefix(joined, "resource list") || strings.Contains(joined, "subnet list") || strings.Contains(joined, "rule list") {
		rows := []any{}
		for kind, r := range f.resources {
			if kind == "azure-group" {
				continue
			}
			if strings.Contains(joined, "subnet list") {
				if kind != "azure-subnet" {
					continue
				}
			} else if strings.Contains(joined, "rule list") {
				if !strings.HasPrefix(kind, "azure-nsg-") {
					continue
				}
			} else if kind == "azure-subnet" || strings.HasPrefix(kind, "azure-nsg-") {
				continue
			}
			rows = append(rows, r)
		}
		return azureTestJSON(rows)
	}
	if strings.Contains(joined, " show ") {
		id := azureFlag(args, "--ids")
		for _, r := range f.resources {
			if strings.EqualFold(str(r["id"]), id) {
				return azureTestJSON(r)
			}
		}
		return nil, errors.New("missing fixture resource")
	}
	kind := ""
	switch {
	case strings.HasPrefix(joined, "group "):
		kind = "azure-group"
	case strings.HasPrefix(joined, "network vnet subnet "):
		kind = "azure-subnet"
	case strings.HasPrefix(joined, "network vnet "):
		kind = "azure-vnet"
	case strings.HasPrefix(joined, "network nsg rule "):
		kind = "azure-nsg-" + azureFlag(args, "--name")
		if kind == "azure-nsg-" {
			kind = "azure-nsg-" + args[len(args)-1][strings.LastIndex(args[len(args)-1], "/")+1:]
		}
	case strings.HasPrefix(joined, "network nsg "):
		kind = "azure-nsg"
	case strings.HasPrefix(joined, "network nic "):
		kind = "azure-nic"
	case strings.HasPrefix(joined, "network public-ip "):
		kind = "azure-ip"
	case strings.HasPrefix(joined, "vm "):
		kind = "azure-vm"
	case strings.HasPrefix(joined, "disk "):
		kind = "azure-disk"
	}
	if strings.Contains(joined, " create ") {
		durable, e := f.s.readOperation(f.op.ID)
		if e != nil {
			f.t.Fatal(e)
		}
		if durable.PendingResourceKind != kind {
			f.t.Fatalf("write without matching durable intent: %s %+v", kind, durable)
		}
		f.writes = append(f.writes, "create:"+kind)
		fail := f.failKind == kind
		if fail && f.failBefore {
			f.failKind = ""
			return nil, errors.New("connection lost")
		}
		if kind == "azure-vm" {
			for _, value := range []string{"--storage-sku StandardSSD_LRS", "--os-disk-size-gb 32", "--os-disk-delete-option Detach", "--nic-delete-option Detach", "--image Canonical:ubuntu-24_04-lts:server-arm64:24.04.202609010"} {
				if !strings.Contains(joined, value) {
					f.t.Errorf("missing explicit Azure create option %s", value)
				}
			}
			f.resources["azure-disk"] = f.resource("azure-disk")
		}
		f.resources[kind] = f.resource(kind)
		if fail {
			f.failKind = ""
			return nil, errors.New("response lost")
		}
		return azureTestJSON(f.resources[kind])
	}
	if strings.Contains(joined, " delete ") {
		f.writes = append(f.writes, "delete:"+kind)
		if kind == "azure-group" && len(f.resources) > 1 {
			f.t.Fatal("recursive deletion of a nonempty group")
		}
		delete(f.resources, kind)
		if kind == "azure-vm" {
			f.resources["azure-disk"]["managedBy"] = ""
		}
		return nil, nil
	}
	if strings.Contains(joined, " deallocate ") || strings.Contains(joined, " start ") || strings.Contains(joined, " restart ") {
		f.writes = append(f.writes, joined)
		return nil, nil
	}
	return nil, fmt.Errorf("unhandled fixture command: %s", joined)
}
func azurePriceRow(service, product, meter, sku, unit string, price float64) map[string]any {
	return map[string]any{"currencyCode": "USD", "type": "Consumption", "armRegionName": "eastus", "serviceName": service, "productName": product, "meterName": meter, "armSkuName": sku, "unitOfMeasure": unit, "meterId": service + meter, "retailPrice": price, "tierMinimumUnits": float64(0), "effectiveStartDate": "2023-01-01T00:00:00Z"}
}
func (f *azureFixture) prices(_ context.Context, raw string) ([]byte, error) {
	if f.queryOverride != nil {
		return f.queryOverride(raw)
	}
	u, _ := url.Parse(raw)
	filter := u.Query().Get("$filter")
	var rows []any
	switch {
	case strings.Contains(filter, "Virtual Machines"):
		size := "Standard_B1s"
		cost := .012
		for name, p := range map[string]float64{"Standard_B2pts_v2": .008, "Standard_B2ats_v2": .0094} {
			if strings.Contains(filter, name) {
				size = name
				cost = p
			}
		}
		rows = append(rows, azurePriceRow("Virtual Machines", "Virtual Machines B Series", "B regular", size, "1 Hour", cost))
		rows = append(rows, azurePriceRow("Virtual Machines", "B Series Cloud Services", "B regular", size, "1 Hour", .001))
	case strings.Contains(filter, "Storage"):
		rows = append(rows, azurePriceRow("Storage", "Standard SSD Managed Disks", "E4 LRS Disk", "", "1/Month", 2.4))
	case strings.Contains(filter, "Virtual Network"):
		rows = append(rows, azurePriceRow("Virtual Network", "IP Addresses", "Standard IPv4 Static Public IP", "", "1 Hour", .005))
	case strings.Contains(filter, "Bandwidth"):
		m := azurePriceRow("Bandwidth", "Rtn Preference: MGN", "Standard Data Transfer Out", "", "1 GB", .087)
		m["tierMinimumUnits"] = 100.
		rows = append(rows, m)
	default:
		return nil, fmt.Errorf("unrecognized price query")
	}
	return azureTestJSON(map[string]any{"BillingCurrency": "USD", "Items": rows, "NextPageLink": nil})
}
func TestAzureResolvePinsCheapestCompatibleImageAndAllFixedCosts(t *testing.T) {
	f := newAzureFixture(t)
	r := f.op.Request
	r.Plan = ""
	r.Image = ""
	r.Architecture = "auto"
	resolved, q, e := f.a.Resolve(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	if resolved.Plan != "Standard_B2pts_v2" || resolved.Architecture != "arm64" || resolved.Image != f.op.Request.Image || q.MonthlyUSD != 11.89 || len(q.Components) != 3 || q.StoppedMonthlyUSD == nil || *q.StoppedMonthlyUSD != 6.05 {
		t.Fatalf("unexpected resolution: %+v %+v", resolved, q)
	}
	if q.TransferGB != 0 || q.TransferPricing.SharedAllowanceGB != 100 || q.TransferPricing.Tiers[0].From != 0 {
		t.Fatal("credited an account-wide traffic allowance")
	}
	if len(f.writes) != 0 {
		t.Fatal("resolve wrote cloud state")
	}
}
func TestAzureProvisionRecordsResourceGraphAndDeallocates(t *testing.T) {
	f := newAzureFixture(t)
	if e := f.a.Provision(context.Background(), f.op, true); e != nil {
		t.Fatal(e)
	}
	if f.op.State != "created" || len(f.op.CloudResources) != 11 || f.op.Host.PublicHost != "198.51.100.8" || f.op.PendingResourceKind != "" {
		t.Fatalf("incomplete graph: %+v", f.op)
	}
	disk := cloudResourceOf(f.op, "azure-disk")
	if disk.Proof["uniqueId"] != "immutable-disk" {
		t.Fatal("missing disk receipt")
	}
	if e := f.a.Action(context.Background(), f.op, "stop"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(f.writes[len(f.writes)-1], "deallocate") {
		t.Fatal("stop did not deallocate")
	}
}
func TestAzurePartialWritesReconcileWithoutRepeating(t *testing.T) {
	for _, kind := range []string{"azure-group", "azure-vnet", "azure-nsg", "azure-nsg-ssh", "azure-nsg-web", "azure-nsg-udp", "azure-subnet", "azure-ip", "azure-nic", "azure-vm"} {
		t.Run(kind, func(t *testing.T) {
			f := newAzureFixture(t)
			f.failKind = kind
			if e := f.a.Provision(context.Background(), f.op, true); e == nil {
				t.Fatal("expected uncertain result")
			}
			if f.op.PendingResourceKind != kind {
				t.Fatal("missing pending checkpoint")
			}
			writes := len(f.writes)
			_ = f.a.Provision(context.Background(), f.op, false)
			if len(f.writes) != writes {
				t.Fatal("reconcile-only mutated cloud")
			}
			if e := f.a.Provision(context.Background(), f.op, true); e != nil {
				t.Fatal(e)
			}
			count := 0
			for _, w := range f.writes {
				if w == "create:"+kind {
					count++
				}
			}
			if count != 1 {
				t.Fatal("repeated uncertain create")
			}
		})
	}
}
func TestAzureUnobservedPendingResourceNeverRecreated(t *testing.T) {
	f := newAzureFixture(t)
	f.failKind = "azure-ip"
	f.failBefore = true
	if e := f.a.Provision(context.Background(), f.op, true); e == nil {
		t.Fatal("expected failure")
	}
	n := len(f.writes)
	if e := f.a.Provision(context.Background(), f.op, true); e == nil {
		t.Fatal("accepted missing pending resource")
	}
	if len(f.writes) != n {
		t.Fatal("retried create")
	}
}
func TestAzureDeleteOrderAndChangedIdentityPreservation(t *testing.T) {
	f := newAzureFixture(t)
	if e := f.a.Provision(context.Background(), f.op, true); e != nil {
		t.Fatal(e)
	}
	f.resources["azure-disk"]["uniqueId"] = "foreign-disk"
	n := len(f.writes)
	if e := f.a.Action(context.Background(), f.op, "delete"); e == nil {
		t.Fatal("deleted replaced disk")
	}
	if len(f.writes) != n {
		t.Fatal("mutated before ownership preflight")
	}
	f.resources["azure-disk"]["uniqueId"] = "immutable-disk"
	if e := f.a.Action(context.Background(), f.op, "delete"); e != nil {
		t.Fatal(e)
	}
	var got []string
	for _, w := range f.writes[n:] {
		got = append(got, w)
	}
	want := []string{"delete:azure-vm", "delete:azure-disk", "delete:azure-nic", "delete:azure-ip", "delete:azure-subnet", "delete:azure-nsg-udp", "delete:azure-nsg-web", "delete:azure-nsg-ssh", "delete:azure-nsg", "delete:azure-vnet", "delete:azure-group"}
	if !reflect.DeepEqual(got, want) || f.op.Host.Owned {
		t.Fatalf("bad delete order: %v", got)
	}
}
func TestAzureForeignResourcesAndAccountDriftBlockDeletion(t *testing.T) {
	for _, mode := range []string{"resource", "rule", "subnet", "tenant", "tag"} {
		t.Run(mode, func(t *testing.T) {
			f := newAzureFixture(t)
			if e := f.a.Provision(context.Background(), f.op, true); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "resource":
				f.resources["foreign"] = map[string]any{"id": azureGroupID(*f.op) + "/providers/Foreign/thing/name"}
			case "rule":
				f.resources["azure-nsg"]["securityRules"] = []any{map[string]any{"id": "foreign-rule"}}
			case "subnet":
				f.resources["azure-vnet"]["subnets"] = []any{map[string]any{"id": "foreign-subnet"}}
			case "tenant":
				f.tenant = "other-tenant"
			case "tag":
				f.resources["azure-ip"]["tags"] = map[string]any{"lazyclash-operation": "foreign"}
			}
			n := len(f.writes)
			if e := f.a.Action(context.Background(), f.op, "delete"); e == nil {
				t.Fatal("accepted changed ownership")
			}
			if len(f.writes) != n {
				t.Fatal("cloud mutated")
			}
		})
	}
}

func TestAzureRetailPaginationAndUnsafeNextPage(t *testing.T) {
	f := newAzureFixture(t)
	calls := 0
	f.queryOverride = func(raw string) ([]byte, error) {
		calls++
		row := azurePriceRow("Storage", "Standard SSD Managed Disks", "E4 LRS Disk", "", "1/Month", 2.4)
		if calls == 1 {
			return azureTestJSON(map[string]any{"BillingCurrency": "USD", "Items": []any{}, "NextPageLink": azurePriceSource + "?page=2"})
		}
		return azureTestJSON(map[string]any{"BillingCurrency": "USD", "Items": []any{row}, "NextPageLink": nil})
	}
	rows, e := f.a.prices(context.Background(), f.op.Request, "serviceName eq 'Storage'")
	if e != nil || calls != 2 || len(rows) != 1 {
		t.Fatalf("lost paginated prices: %d %v %v", calls, rows, e)
	}
	for _, next := range []string{"https://evil.example/prices", "http://prices.azure.com/api/retail/prices", "https://prices.azure.com/other"} {
		f.queryOverride = func(raw string) ([]byte, error) {
			return azureTestJSON(map[string]any{"BillingCurrency": "USD", "Items": []any{}, "NextPageLink": next})
		}
		if _, e = f.a.prices(context.Background(), f.op.Request, "x"); e == nil {
			t.Fatalf("followed untrusted next page %s", next)
		}
	}
}
func TestAzureMissingOrWrongServicePriceRefusesQuote(t *testing.T) {
	for _, component := range []string{"Storage", "Virtual Network", "Virtual Machines", "Bandwidth"} {
		t.Run(component, func(t *testing.T) {
			f := newAzureFixture(t)
			f.queryOverride = func(raw string) ([]byte, error) {
				u, _ := url.Parse(raw)
				if strings.Contains(u.Query().Get("$filter"), "serviceName eq '"+component+"'") {
					bad := azurePriceRow("Wrong Service", "Standard SSD Managed Disks", "E4 LRS Disk", "Standard_B2pts_v2", "1/Month", .001)
					return azureTestJSON(map[string]any{"BillingCurrency": "USD", "Items": []any{bad}})
				}
				save := f.queryOverride
				f.queryOverride = nil
				b, e := f.prices(context.Background(), raw)
				f.queryOverride = save
				return b, e
			}
			if _, _, e := f.a.Resolve(context.Background(), f.op.Request); e == nil {
				t.Fatal("accepted unrelated or missing component price")
			}
		})
	}
}
func TestAzureImageArchitectureAndZoneValidation(t *testing.T) {
	f := newAzureFixture(t)
	r := f.op.Request
	r.Architecture = "amd64"
	if _, _, e := f.a.Resolve(context.Background(), r); e == nil {
		t.Fatal("accepted ARM size for AMD64")
	}
	r = f.op.Request
	r.AvailabilityZone = "9"
	if _, _, e := f.a.Resolve(context.Background(), r); e == nil {
		t.Fatal("accepted unavailable zone")
	}
	r = f.op.Request
	r.Image = "Canonical:ubuntu-24_04-lts:server-arm64:latest"
	if _, _, e := f.a.Resolve(context.Background(), r); e == nil {
		t.Fatal("accepted floating image")
	}
}
func TestAzureDeletePartialResponseReconcilesAbsence(t *testing.T) {
	f := newAzureFixture(t)
	if e := f.a.Provision(context.Background(), f.op, true); e != nil {
		t.Fatal(e)
	}
	original := f.s.options.Run
	fail := true
	f.s.options.Run = func(ctx context.Context, name string, args []string) ([]byte, error) {
		out, e := original(ctx, name, args)
		if fail && strings.Contains(strings.Join(args, " "), "disk delete") {
			fail = false
			return nil, errors.New("response lost")
		}
		return out, e
	}
	if e := f.a.Action(context.Background(), f.op, "delete"); e == nil {
		t.Fatal("expected delete uncertainty")
	}
	if f.op.Host.Status != "cleanup-required" {
		t.Fatal("lost cleanup status")
	}
	if e := f.a.Action(context.Background(), f.op, "delete"); e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, w := range f.writes {
		if w == "delete:azure-disk" {
			n++
		}
	}
	if n != 1 {
		t.Fatal("repeated deleted disk operation")
	}
}

func newAzurePublicFixture(t *testing.T) (*azureFixture, CreateRequest) {
	t.Helper()
	f := newAzureFixture(t)
	if err := f.s.store.Update(func(inv *serverstate.Inventory) error { inv.Hosts = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	f.publicAPI = true
	return f, f.op.Request
}

func TestAzurePublicServiceLifecyclePreservesOwnershipAndPricing(t *testing.T) {
	f, request := newAzurePublicFixture(t)
	ctx := context.Background()
	request.Plan, request.Image, request.ImageVersion, request.Architecture = "", "", "", "auto"
	preview, err := f.s.PlanCreate(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Request.Plan != "Standard_B2pts_v2" || preview.Request.Architecture != "arm64" || preview.Quote.MonthlyUSD != 11.89 {
		t.Fatalf("preview did not resolve request: %+v", preview)
	}
	if len(f.writes) != 0 {
		t.Fatal("preview wrote cloud state")
	}
	if _, err := f.s.Create(ctx, *preview.Request, "wrong-digest"); err == nil || len(f.writes) != 0 {
		t.Fatal("invalid digest permitted provisioning")
	}
	host, err := f.s.Create(ctx, *preview.Request, preview.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if host.ResourceID == "" || host.SubscriptionID != "subscription" || host.Architecture != "arm64" || host.MonthlyUSD != 11.89 || host.ComputeMonthlyUSD != 5.84 || host.DiskMonthlyUSD != 2.4 || host.IPv4MonthlyUSD != 3.65 || !host.Owned {
		t.Fatalf("incomplete host metadata: %+v", host)
	}
	status, err := f.s.Status(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.ResourceID != host.ResourceID || status.Status != "running" || status.SSHHost != "ubuntu@198.51.100.8" {
		t.Fatalf("unexpected status: %+v", status)
	}
	stop, err := f.s.PlanAction(ctx, host.ID, "stop")
	if err != nil {
		t.Fatal(err)
	}
	stopped, err := f.s.Action(ctx, host.ID, "stop", stop.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status != "stop-requested" || !strings.Contains(f.writes[len(f.writes)-1], "deallocate") {
		t.Fatal("public stop did not deallocate")
	}
	deletion, err := f.s.PlanAction(ctx, host.ID, "delete")
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := f.s.Action(ctx, host.ID, "delete", deletion.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Owned || deleted.Status != "deleted" || len(f.resources) != 0 || len(deleted.Resources) != 0 {
		t.Fatalf("incomplete delete: %+v resources=%v", deleted, f.resources)
	}
	persisted, err := f.s.readOperation(host.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.State != "deleted" || len(persisted.CloudResources) != 11 {
		t.Fatalf("lost durable receipts: %+v", persisted)
	}
	for _, resource := range persisted.CloudResources {
		if !resource.Deleted {
			t.Fatalf("resource not acknowledged deleted: %+v", resource)
		}
	}
}

func TestAzurePublicServiceResumeAfterResponseLoss(t *testing.T) {
	for _, failedKind := range []string{"azure-ip", "azure-vm"} {
		t.Run(failedKind, func(t *testing.T) {
			f, request := newAzurePublicFixture(t)
			ctx := context.Background()
			preview, err := f.s.PlanCreate(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			f.failKind = failedKind
			failed, err := f.s.Create(ctx, *preview.Request, preview.Digest)
			if err == nil || failed.OperationID == "" {
				t.Fatal("expected durable uncertain create")
			}
			writes := len(f.writes)
			_, _ = f.s.Resume(ctx, request.ID)
			if len(f.writes) != writes {
				t.Fatal("reconcile-only resume wrote cloud state")
			}
			resume, err := f.s.PlanResume(ctx, request.ID)
			if err != nil {
				t.Fatal(err)
			}
			host, err := f.s.Resume(ctx, request.ID, resume.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if host.ResourceID == "" || host.PublicHost == "" {
				t.Fatalf("resume did not complete host: %+v", host)
			}
			count := 0
			for _, write := range f.writes {
				if write == "create:"+failedKind {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("submitted uncertain %s %d times", failedKind, count)
			}
			if _, err := f.s.Status(ctx, request.ID); err != nil {
				t.Fatalf("resumed private/public ownership mismatch: %v", err)
			}
		})
	}
}

func TestAzureFailedVMRetainsProvableDiskForReviewedCleanup(t *testing.T) {
	for _, state := range []string{"Failed", "Canceled"} {
		t.Run(state, func(t *testing.T) {
			f, request := newAzurePublicFixture(t)
			ctx := context.Background()
			original := f.s.options.Run
			f.s.options.Run = func(ctx context.Context, exe string, args []string) ([]byte, error) {
				out, err := original(ctx, exe, args)
				if strings.Contains(strings.Join(args, " "), "vm create") {
					f.resources["azure-vm"]["provisioningState"] = state
				}
				return out, err
			}
			preview, err := f.s.PlanCreate(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			host, err := f.s.Create(ctx, *preview.Request, preview.Digest)
			if err == nil || host.Status != "cleanup-required" {
				t.Fatalf("terminal VM was not surfaced for cleanup: %+v %v", host, err)
			}
			op, err := f.s.readOperation(host.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			disk := cloudResourceOf(&op, "azure-disk")
			if disk == nil || disk.Proof["uniqueId"] != "immutable-disk" || op.PendingResourceKind != "" {
				t.Fatalf("failed VM lost disk ownership: %+v", op)
			}
			status, err := f.s.Status(ctx, host.ID)
			if err != nil || status.Status != "cleanup-required" {
				t.Fatalf("terminal status was lost: %+v %v", status, err)
			}
			deletion, err := f.s.PlanAction(ctx, host.ID, "delete")
			if err != nil {
				t.Fatal(err)
			}
			deleted, err := f.s.Action(ctx, host.ID, "delete", deletion.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if deleted.Status != "deleted" || len(f.resources) != 0 {
				t.Fatal("failed VM resources were not cleaned")
			}
		})
	}
}
