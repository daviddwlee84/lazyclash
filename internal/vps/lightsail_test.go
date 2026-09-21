package vps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type lightsailFixture struct {
	t                     *testing.T
	s                     *Service
	a                     lightsailAdapter
	op                    *operation
	instance, ip          map[string]any
	ports                 []map[string]any
	operations            map[string]map[string]any
	account               string
	bundleRows, imageRows []map[string]any
	writes, calls         []string
	failPhase             string
	failBefore            bool
	pageMode              string
	beforeRead            func(string)
	activeHostID          string
}

func lightsailTestJSON(v any) ([]byte, error) { return json.Marshal(v) }
func lightsailTestFlag(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}
func newLightsailFixture(t *testing.T) *lightsailFixture {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "id.pub")
	if err := os.WriteFile(key, []byte("ssh-ed25519 AAAA fixture-public-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	f := &lightsailFixture{t: t, account: "123456789012", operations: map[string]map[string]any{}}
	f.bundleRows = []map[string]any{{"bundleId": "micro_3_0", "name": "Micro", "price": 7., "cpuCount": 2., "ramSizeInGb": 1., "diskSizeInGb": 40., "transferPerMonthInGb": 2048., "instanceType": "micro", "publicIpv4AddressCount": 1., "power": 500., "isActive": true, "supportedPlatforms": []any{"LINUX_UNIX"}}}
	f.imageRows = []map[string]any{{"blueprintId": "ubuntu_24_04", "name": "Ubuntu", "group": "ubuntu_24", "version": "24.04", "versionCode": "20260901", "platform": "LINUX_UNIX", "type": "os", "isActive": true, "minPower": 0.}}
	f.s = New(serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}, Options{Now: func() time.Time { return now }, Run: f.run})
	f.a = lightsailAdapter{s: f.s}
	r, err := normalizeCloud(CreateRequest{ID: "lightsail-test", Name: "lightsail-test", Provider: "aws-lightsail", Region: "us-east-1", Profile: "fixture", SSHKey: key, SSHCIDR: "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	r, q, err := f.a.Resolve(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	f.op = &operation{ID: "lc-lightsail-fixture", Version: 1, Request: r, AccountID: "aws:" + digest([]string{"aws", f.account}), CreatedAt: now, State: "intent", Quote: &q, PrivateData: map[string]json.RawMessage{}, Host: serverstate.Host{ID: r.ID, Provider: r.Provider, Profile: r.Profile, Region: r.Region, Architecture: r.Architecture, AvailabilityZone: r.AvailabilityZone, Plan: r.Plan, OperationID: "lc-lightsail-fixture", Owned: true, Status: "creating"}}
	applyCloudQuote(&f.op.Host, q)
	if err = f.s.cloudPersist(f.op); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *lightsailFixture) run(_ context.Context, executable string, args []string) ([]byte, error) {
	if executable != "aws" {
		f.t.Fatalf("unexpected executable %s", executable)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "sts get-caller-identity") {
		return lightsailTestJSON(map[string]any{"Account": f.account, "Arn": "arn:aws:sts::" + f.account + ":assumed-role/fixture/session-a"})
	}
	index := -1
	for i, s := range args {
		if s == "lightsail" {
			index = i
			break
		}
	}
	if index < 0 || index+1 >= len(args) {
		return nil, fmt.Errorf("unexpected mock command")
	}
	action := args[index+1]
	f.calls = append(f.calls, action)
	if f.beforeRead != nil && strings.HasPrefix(action, "get-") {
		f.beforeRead(action)
	}
	var input map[string]any
	if raw := lightsailTestFlag(args, "--cli-input-json"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			f.t.Fatal(err)
		}
	}
	switch action {
	case "get-regions":
		return lightsailTestJSON(map[string]any{"regions": []any{map[string]any{"name": "us-east-1", "displayName": "Fixture", "availabilityZones": []any{map[string]any{"zoneName": "us-east-1a", "state": "available"}, map[string]any{"zoneName": "us-east-1z", "state": "unavailable"}}}}})
	case "get-bundles":
		if f.pageMode != "" && str(input["pageToken"]) == "" {
			return lightsailTestJSON(map[string]any{"bundles": []any{}, "nextPageToken": "second"})
		}
		if f.pageMode == "repeat" {
			return lightsailTestJSON(map[string]any{"bundles": []any{}, "nextPageToken": "second"})
		}
		return lightsailTestJSON(map[string]any{"bundles": f.bundleRows})
	case "get-blueprints":
		return lightsailTestJSON(map[string]any{"blueprints": f.imageRows})
	case "get-instances":
		rows := []any{}
		if f.instance != nil {
			rows = append(rows, f.instance)
		}
		return lightsailTestJSON(map[string]any{"instances": rows})
	case "get-static-ips":
		rows := []any{}
		if f.ip != nil {
			rows = append(rows, f.ip)
		}
		return lightsailTestJSON(map[string]any{"staticIps": rows})
	case "get-instance-port-states":
		rows := []map[string]any{}
		rows = append(rows, f.ports...)
		return lightsailTestJSON(map[string]any{"portStates": rows})
	case "get-operation":
		return lightsailTestJSON(map[string]any{"operation": f.operations[lightsailTestFlag(args, "--operation-id")]})
	}
	phase := map[string]string{"create-instances": "instance", "allocate-static-ip": "lightsail-ip", "attach-static-ip": "lightsail-attach", "put-instance-public-ports": "lightsail-ports", "delete-instance": "lightsail-delete-instance", "release-static-ip": "lightsail-release-ip", "start-instance": "lightsail-start", "stop-instance": "lightsail-stop", "reboot-instance": "lightsail-reboot"}[action]
	if phase == "" {
		return nil, fmt.Errorf("unknown/mutating command rejected by fixture: %s", action)
	}
	if f.activeHostID != "" {
		inv, err := f.s.store.Load()
		if err != nil {
			f.t.Fatal(err)
		}
		host, err := inv.Host(f.activeHostID)
		if err != nil {
			f.t.Fatal(err)
		}
		op, err := f.s.readOperation(host.OperationID)
		if err != nil {
			f.t.Fatal(err)
		}
		f.op = &op
	}
	f.writes = append(f.writes, phase)
	if f.op.PendingResourceKind != phase {
		f.t.Fatalf("mutation %s had no durable pending intent", phase)
	}
	disk, err := f.s.readOperation(f.op.ID)
	if err != nil || disk.PendingResourceKind != phase {
		f.t.Fatalf("mutation did not persist phase before cloud call: %s %v", phase, err)
	}
	fail := f.failPhase == phase
	if fail && f.failBefore {
		f.failPhase = ""
		return nil, errors.New("response lost before observation")
	}
	created := f.op.CreatedAt.Format(time.RFC3339Nano)
	location := map[string]any{"regionName": "us-east-1", "availabilityZone": "us-east-1a"}
	resource := f.op.ID
	switch phase {
	case "instance":
		if f.instance != nil {
			f.t.Fatal("repeated instance creation")
		}
		if lightsailTestFlag(args, "--ip-address-type") != "ipv4" || strings.Contains(joined, "--key-pair-name") || strings.Contains(joined, "get-key-pair") {
			f.t.Fatal("unexpected default key or IPv6 workflow")
		}
		data := lightsailTestFlag(args, "--user-data")
		if !strings.Contains(data, "authorized_keys") || !strings.Contains(data, "grep -Fqx") || !strings.Contains(data, " >> /home/ubuntu/.ssh/authorized_keys") {
			f.t.Fatal("initializer replaced platform key")
		}
		var tags []any
		if err = json.Unmarshal([]byte(lightsailTestFlag(args, "--tags")), &tags); err != nil {
			f.t.Fatal(err)
		}
		f.instance = map[string]any{"name": f.op.ID, "arn": "arn:aws:lightsail:us-east-1:123456789012:Instance/immutable-instance", "createdAt": created, "location": location, "tags": tags, "blueprintId": "ubuntu_24_04", "bundleId": "micro_3_0", "state": map[string]any{"name": "running"}, "hardware": map[string]any{"disks": []any{map[string]any{"isSystemDisk": true}}}}
		f.ports = []map[string]any{{"fromPort": 22., "toPort": 22., "protocol": "tcp", "state": "open", "cidrs": []any{"0.0.0.0/0"}}, {"fromPort": 80., "toPort": 80., "protocol": "tcp", "state": "open", "cidrs": []any{"0.0.0.0/0"}}}
	case "lightsail-ip":
		if f.ip != nil {
			f.t.Fatal("repeated static IP allocation")
		}
		resource = f.op.ID + "-ip"
		f.ip = map[string]any{"name": resource, "arn": "arn:aws:lightsail:us-east-1:123456789012:StaticIp/immutable-ip", "createdAt": created, "location": location, "ipAddress": "198.51.100.7", "isAttached": false, "attachedTo": ""}
	case "lightsail-attach":
		resource = f.op.ID + "-ip"
		f.ip["isAttached"] = true
		f.ip["attachedTo"] = f.op.ID
	case "lightsail-ports":
		if err = json.Unmarshal([]byte(lightsailTestFlag(args, "--port-infos")), &f.ports); err != nil {
			f.t.Fatal(err)
		}
		for _, p := range f.ports {
			p["state"] = "open"
		}
	case "lightsail-delete-instance":
		f.instance = nil
		if f.ip != nil {
			f.ip["isAttached"] = false
			f.ip["attachedTo"] = ""
		}
	case "lightsail-release-ip":
		resource = f.op.ID + "-ip"
		if truth(f.ip["isAttached"]) {
			f.t.Fatal("released attached static IP")
		}
		f.ip = nil
	case "lightsail-start", "lightsail-reboot":
		f.instance["state"] = map[string]any{"name": "running"}
	case "lightsail-stop":
		f.instance["state"] = map[string]any{"name": "stopped"}
	}
	id := fmt.Sprintf("operation-%d", len(f.writes))
	operation := map[string]any{"id": id, "resourceName": resource, "operationType": lightsailOperationType(phase), "isTerminal": true, "status": "Succeeded"}
	f.operations[id] = operation
	if fail {
		f.failPhase = ""
		return nil, errors.New("response lost after mutation")
	}
	if phase == "lightsail-ports" {
		return lightsailTestJSON(map[string]any{"operation": operation})
	}
	return lightsailTestJSON(map[string]any{"operations": []any{operation}})
}

func TestLightsailResolvePinsBundleBlueprintInitializerAndStoppedCost(t *testing.T) {
	f := newLightsailFixture(t)
	r, q, err := f.a.Resolve(context.Background(), f.op.Request)
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan != "micro_3_0" || r.Architecture != "amd64" || r.ImageVersion != "20260901" || r.InitializerSHA256 == "" || r.InitializerVersion != lightsailInitializerVersion || r.AvailabilityZone != "us-east-1a" {
		t.Fatalf("incomplete resolution: %+v", r)
	}
	if q.MonthlyUSD != 7 || q.MemoryMiB != 1024 || len(q.Components) != 1 || q.Components[0].Name != "bundle" || q.StoppedMonthlyUSD == nil || *q.StoppedMonthlyUSD != 7 || q.TransferPricing.Basis != "combined" || len(q.TransferPricing.Tiers) != 0 {
		t.Fatalf("incorrect costs: %+v", q)
	}
	if len(f.writes) != 0 {
		t.Fatal("resolution mutated cloud")
	}
	for _, edit := range []func(*CreateRequest){func(r *CreateRequest) { r.ImageVersion = "changed" }, func(r *CreateRequest) { r.InitializerSHA256 = "changed" }, func(r *CreateRequest) { r.Architecture = "arm64" }, func(r *CreateRequest) { r.AvailabilityZone = "us-east-1z" }, func(r *CreateRequest) { r.DiskGB = 20 }} {
		r = f.op.Request
		edit(&r)
		if _, _, err = f.a.Resolve(context.Background(), r); err == nil {
			t.Fatalf("accepted incompatible/pinning change %+v", r)
		}
	}
}
func TestLightsailBundleFilteringPaginationAndNoSpeculativeARM(t *testing.T) {
	f := newLightsailFixture(t)
	f.pageMode = "pages"
	choices, err := f.a.Discover(context.Background(), f.op.Request, "plans")
	if err != nil || len(choices) != 1 {
		t.Fatalf("lost second page: %v %v", choices, err)
	}
	f.pageMode = "repeat"
	if _, err = f.a.Discover(context.Background(), f.op.Request, "plans"); err == nil {
		t.Fatal("accepted repeated token")
	}
	f.pageMode = ""
	for _, change := range []struct {
		key   string
		value any
	}{{"publicIpv4AddressCount", 0.}, {"ramSizeInGb", .5}, {"supportedPlatforms", []any{"WINDOWS"}}, {"power", -1.}, {"isActive", false}} {
		old := f.bundleRows[0][change.key]
		f.bundleRows[0][change.key] = change.value
		if _, _, err = f.a.Resolve(context.Background(), f.op.Request); err == nil {
			t.Fatalf("accepted unsupported bundle %s=%v", change.key, change.value)
		}
		f.bundleRows[0][change.key] = old
	}
}

func TestLightsailLiveCatalogSchema(t *testing.T) {
	// Public catalog fields returned by get-bundles/get-blueprints in
	// ap-southeast-1 on 2026-09-22. instanceType is a size, not an EC2 family.
	f := newLightsailFixture(t)
	f.bundleRows = []map[string]any{{"bundleId": "micro_3_0", "name": "Micro", "price": 7., "cpuCount": 2., "ramSizeInGb": 1., "diskSizeInGb": 40., "transferPerMonthInGb": 2048., "instanceType": "micro", "publicIpv4AddressCount": 1., "power": 500., "isActive": true, "supportedPlatforms": []any{"LINUX_UNIX"}}}
	f.imageRows = []map[string]any{{"blueprintId": "ubuntu_24_04", "name": "Ubuntu", "group": "ubuntu_24", "version": "24.04 LTS", "versionCode": "1", "platform": "LINUX_UNIX", "type": "os", "isActive": true, "minPower": 0.}}
	r := f.op.Request
	r.Plan, r.ImageVersion = "", ""
	choices, err := f.a.Discover(context.Background(), r, "plans")
	if err != nil || len(choices) != 1 || choices[0].ID != "micro_3_0" {
		t.Fatalf("real Lightsail catalog was rejected: %v %v", choices, err)
	}
	resolved, quote, err := f.a.Resolve(context.Background(), r)
	if err != nil || resolved.Plan != "micro_3_0" || resolved.Architecture != "amd64" || resolved.ImageVersion != "1" || quote.MonthlyUSD != 7 || quote.MemoryMiB != 1024 {
		t.Fatalf("real Lightsail quote mismatch: %+v %+v %v", resolved, quote, err)
	}
	r.Plan = resolved.Plan
	choices, err = f.a.Discover(context.Background(), r, "images")
	if err != nil || len(choices) != 1 || choices[0].ID != "ubuntu_24_04" {
		t.Fatalf("real Ubuntu blueprint was rejected: %v %v", choices, err)
	}
	f.imageRows[0]["minPower"] = 1000.
	if _, err = f.a.Discover(context.Background(), r, "images"); err == nil {
		t.Fatal("image discovery ignored the selected bundle's power")
	}
	f.imageRows[0]["minPower"] = 0.
	r.Architecture = "arm64"
	if _, _, err = f.a.Resolve(context.Background(), r); err == nil {
		t.Fatal("x86 Ubuntu blueprint accepted for explicit ARM request")
	}
	if _, err = f.a.Discover(context.Background(), r, "images"); err == nil {
		t.Fatal("image discovery replaced the requested ARM architecture")
	}
	r.Architecture = "auto"
	f.imageRows[0]["blueprintId"] = "ubuntu_24_04_unreviewed"
	if _, _, err = f.a.Resolve(context.Background(), r); err == nil {
		t.Fatal("unreviewed Ubuntu blueprint accepted")
	}
}
func TestLightsailProvisionLifecycleAndOwnedResourceReceipts(t *testing.T) {
	f := newLightsailFixture(t)
	if err := f.a.Provision(context.Background(), f.op, true); err != nil {
		t.Fatal(err)
	}
	if f.op.State != "created" || len(f.op.CloudResources) != 2 || f.op.Host.PublicHost != "198.51.100.7" || f.op.Host.SSHHost != "ubuntu@198.51.100.7" || f.op.PendingResourceKind != "" {
		t.Fatalf("incomplete deployment: %+v", f.op)
	}
	r := cloudResourceOf(f.op, "lightsail-ip")
	if r.Proof["created_at"] == "" || r.Proof["account"] != f.op.AccountID || !strings.Contains(r.ID, "StaticIp/") {
		t.Fatal("static IP lacks immutable receipt")
	}
	for _, action := range []string{"stop", "start", "reboot"} {
		if err := f.a.Action(context.Background(), f.op, action); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.a.Action(context.Background(), f.op, "delete"); err != nil {
		t.Fatal(err)
	}
	if f.instance != nil || f.ip != nil || f.op.Host.Owned || f.op.State != "deleted" {
		t.Fatal("incomplete cleanup")
	}
	if got := strings.Join(f.writes[len(f.writes)-2:], ","); got != "lightsail-delete-instance,lightsail-release-ip" {
		t.Fatal(got)
	}
}
func TestLightsailResponseLossReconcilesEveryPhaseWithoutDuplicateWrites(t *testing.T) {
	for _, phase := range []string{"instance", "lightsail-ip", "lightsail-attach", "lightsail-ports"} {
		t.Run(phase, func(t *testing.T) {
			f := newLightsailFixture(t)
			f.failPhase = phase
			if err := f.a.Provision(context.Background(), f.op, true); err == nil {
				t.Fatal("missing uncertain outcome")
			}
			if f.op.PendingResourceKind != phase {
				t.Fatal("lost pending intent")
			}
			count := len(f.writes)
			if err := f.a.Provision(context.Background(), f.op, false); err != nil {
				t.Fatal(err)
			}
			if len(f.writes) != count {
				t.Fatal("reconcile-only mutated cloud")
			}
			if err := f.a.Provision(context.Background(), f.op, true); err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, w := range f.writes {
				if w == phase {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("repeated %s %d times", phase, n)
			}
		})
	}
}
func TestLightsailUnobservedCreateIsNeverRepeated(t *testing.T) {
	for _, phase := range []string{"instance", "lightsail-ip"} {
		t.Run(phase, func(t *testing.T) {
			f := newLightsailFixture(t)
			f.failPhase = phase
			f.failBefore = true
			if err := f.a.Provision(context.Background(), f.op, true); err == nil {
				t.Fatal("expected uncertain create")
			}
			n := len(f.writes)
			for _, writes := range []bool{false, true} {
				if err := f.a.Provision(context.Background(), f.op, writes); err == nil {
					t.Fatal("accepted unobserved create")
				}
			}
			if len(f.writes) != n {
				t.Fatal("repeated ambiguous create")
			}
		})
	}
}
func TestLightsailDeletionResponseLossPreservesRecovery(t *testing.T) {
	for _, phase := range []string{"lightsail-delete-instance", "lightsail-release-ip"} {
		t.Run(phase, func(t *testing.T) {
			f := newLightsailFixture(t)
			if err := f.a.Provision(context.Background(), f.op, true); err != nil {
				t.Fatal(err)
			}
			f.failPhase = phase
			if err := f.a.Action(context.Background(), f.op, "delete"); err == nil {
				t.Fatal("expected uncertain delete")
			}
			if err := f.a.Action(context.Background(), f.op, "delete"); err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, w := range f.writes {
				if w == phase {
					n++
				}
			}
			if n != 1 {
				t.Fatal("repeated confirmed deletion")
			}
		})
	}
}
func TestLightsailForeignIPInstanceAndDisksBlockDeleteBeforeMutation(t *testing.T) {
	for _, change := range []string{"moved-ip", "replaced-ip", "timestamp", "tag", "extra-disk", "account"} {
		t.Run(change, func(t *testing.T) {
			f := newLightsailFixture(t)
			if err := f.a.Provision(context.Background(), f.op, true); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "moved-ip":
				f.ip["attachedTo"] = "someone-else"
			case "replaced-ip":
				f.ip["arn"] = "arn:aws:lightsail:us-east-1:123456789012:StaticIp/replaced"
			case "timestamp":
				f.ip["createdAt"] = "2025-01-01T00:00:00Z"
			case "tag":
				f.instance["tags"] = []any{}
			case "extra-disk":
				obj(f.instance["hardware"])["disks"] = []any{map[string]any{"isSystemDisk": false}}
			case "account":
				f.account = "999999999999"
			}
			n := len(f.writes)
			if err := f.a.Action(context.Background(), f.op, "delete"); err == nil {
				t.Fatal("accepted foreign state")
			}
			if len(f.writes) != n {
				t.Fatal("mutated before full ownership preflight")
			}
		})
	}
}
func TestLightsailForeignFirewallAndMidOperationAccountChangesArePreserved(t *testing.T) {
	f := newLightsailFixture(t)
	if err := f.a.Provision(context.Background(), f.op, true); err != nil {
		t.Fatal(err)
	}
	f.ports = append(f.ports, map[string]any{"fromPort": 8080., "toPort": 8080., "protocol": "tcp", "state": "open", "cidrs": []any{"0.0.0.0/0"}})
	n := len(f.writes)
	if err := f.a.Provision(context.Background(), f.op, true); err == nil {
		t.Fatal("overwrote foreign firewall")
	}
	if len(f.writes) != n {
		t.Fatal("mutated foreign firewall")
	}
	f = newLightsailFixture(t)
	f.beforeRead = func(action string) {
		if action == "get-static-ips" && f.instance != nil {
			f.account = "999999999999"
		}
	}
	if err := f.a.Provision(context.Background(), f.op, true); err == nil {
		t.Fatal("accepted mid-operation account change")
	}
	if len(f.writes) != 1 || f.writes[0] != "instance" {
		t.Fatalf("wrote in changed account: %v", f.writes)
	}
}
func TestLightsailPendingStaticIPCannotAdoptOldAllocation(t *testing.T) {
	f := newLightsailFixture(t)
	f.failPhase = "lightsail-ip"
	if err := f.a.Provision(context.Background(), f.op, true); err == nil {
		t.Fatal("expected lost allocation response")
	}
	f.ip["createdAt"] = "2025-01-01T00:00:00Z"
	n := len(f.writes)
	if err := f.a.Provision(context.Background(), f.op, false); err == nil {
		t.Fatal("adopted old untaggable static IP")
	}
	if len(f.writes) != n {
		t.Fatal("reconcile wrote resources")
	}
}
func TestLightsailInitializerPreservesDefaultKeyAndRejectsChangedPublicKey(t *testing.T) {
	f := newLightsailFixture(t)
	data, err := lightsailUserData(f.op.Request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data, " >> /home/ubuntu/.ssh/authorized_keys") || strings.Contains(data, "rm ") {
		t.Fatal("initializer does not preserve provider keys")
	}
	if err = os.WriteFile(f.op.Request.SSHKey, []byte("ssh-ed25519 BBBB changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.a.Resolve(context.Background(), f.op.Request); err == nil {
		t.Fatal("accepted changed public key")
	}
	if len(f.writes) != 0 {
		t.Fatal("key validation mutated cloud")
	}
}

func TestLightsailServiceLifecycleAndPostDeleteStatus(t *testing.T) {
	f := newLightsailFixture(t)
	r := f.op.Request
	r.ID = "service-lightsail"
	r.Name = r.ID
	f.activeHostID = r.ID
	ctx := context.Background()
	preview, err := f.s.PlanCreate(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	host, err := f.s.Create(ctx, *preview.Request, preview.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if host.PublicHost != "198.51.100.7" || host.ResourceID == "" {
		t.Fatalf("missing created host: %+v", host)
	}
	for _, action := range []string{"stop", "start", "delete"} {
		preview, err = f.s.PlanAction(ctx, r.ID, action)
		if err != nil {
			t.Fatal(err)
		}
		host, err = f.s.Action(ctx, r.ID, action, preview.Digest)
		if err != nil {
			t.Fatal(err)
		}
	}
	n := len(f.calls)
	host, err = f.s.Status(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if host.Status != "deleted" || host.Owned || len(f.calls) != n {
		t.Fatalf("post-delete status contacted cloud or lost tombstone: %+v", host)
	}
}

func TestLightsailTerminalFailureAllowsReviewedCleanup(t *testing.T) {
	for _, phase := range []string{"instance", "lightsail-ip", "lightsail-ports"} {
		t.Run(phase, func(t *testing.T) {
			f := newLightsailFixture(t)
			run := f.s.options.Run
			f.s.options.Run = func(ctx context.Context, executable string, args []string) ([]byte, error) {
				data, err := run(ctx, executable, args)
				if err != nil || !strings.Contains(strings.Join(args, " "), "get-operation") || f.op.PendingResourceKind != phase {
					return data, err
				}
				var v map[string]any
				if err = json.Unmarshal(data, &v); err != nil {
					t.Fatal(err)
				}
				obj(v["operation"])["status"] = "Failed"
				if phase == "lightsail-ip" {
					f.ip = nil
				} // Allocation definitively failed with no IP.
				return json.Marshal(v)
			}
			if err := f.a.Provision(context.Background(), f.op, true); err == nil {
				t.Fatal("provider failure was hidden")
			}
			if f.op.PendingResourceKind != "" || f.op.Host.Status != "cleanup-required" {
				t.Fatalf("failed operation stranded billable resources: %+v", f.op)
			}
			n := len(f.writes)
			if err := f.a.Provision(context.Background(), f.op, true); err == nil {
				t.Fatal("failed creation was automatically retried")
			}
			if len(f.writes) != n {
				t.Fatal("failure retry wrote cloud state")
			}
			f.activeHostID = f.op.Request.ID
			preview, err := f.s.PlanAction(context.Background(), f.op.Request.ID, "delete")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.Action(context.Background(), f.op.Request.ID, "delete", preview.Digest); err != nil {
				t.Fatal(err)
			}
			if f.instance != nil || f.ip != nil {
				t.Fatal("failed creation retained undeletable resources")
			}
		})
	}
}

func TestLightsailMalformedInventoryTokenCannotConfirmDeletion(t *testing.T) {
	f := newLightsailFixture(t)
	if err := f.a.Provision(context.Background(), f.op, true); err != nil {
		t.Fatal(err)
	}
	run := f.s.options.Run
	f.s.options.Run = func(ctx context.Context, executable string, args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "get-instances") {
			return json.Marshal(map[string]any{"instances": []any{}, "nextPageToken": map[string]any{"bad": "token"}})
		}
		return run(ctx, executable, args)
	}
	n := len(f.writes)
	if err := f.a.Action(context.Background(), f.op, "delete"); err == nil {
		t.Fatal("malformed pagination was interpreted as resource absence")
	}
	if len(f.writes) != n || cloudResourceOf(f.op, "instance").Deleted {
		t.Fatal("incomplete inventory authorized a destructive mutation")
	}
}
