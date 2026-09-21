package vps

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func oracleNetworkFixture(t *testing.T) (*Service, *operation) {
	t.Helper()
	dir := t.TempDir()
	s := New(serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}, Options{})
	op := &operation{Version: 1, ID: "lc-network-fixture", Request: CreateRequest{ID: "free", Provider: "oracle", Profile: "FREE", Region: "home-region", CompartmentID: "compartment", SSHCIDR: "192.0.2.0/24"}, State: "intent", Host: serverstate.Host{ID: "free", Provider: "oracle", OperationID: "lc-network-fixture", Owned: true, Status: "creating"}}
	if err := s.persistOracleNetwork(op); err != nil {
		t.Fatal(err)
	}
	return s, op
}

func networkInvocation(t *testing.T, args []string) (string, string) {
	t.Helper()
	for n, arg := range args {
		if arg == "network" && n+2 < len(args) {
			return args[n+1], args[n+2]
		}
	}
	t.Fatalf("not a network call: %v", args)
	return "", ""
}

func TestOracleNetworkRecordsEveryResourceBeforeNextWrite(t *testing.T) {
	s, op := oracleNetworkFixture(t)
	var calls []string
	s.options.Run = func(ctx context.Context, name string, args []string) ([]byte, error) {
		kind, action := networkInvocation(t, args)
		if name != "oci" || action != "create" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		durable, err := s.readOperation(op.ID)
		if err != nil {
			t.Fatal(err)
		}
		if durable.PendingResourceKind != oracleResourceKind(kind) || len(durable.Host.Resources) != len(calls) {
			t.Fatalf("intent not durable before creating %s: %+v", kind, durable)
		}
		if strings.Contains(strings.Join(args, " "), "nat-gateway") {
			t.Fatal("created a paid NAT")
		}
		if kind == "security-list" {
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "192.0.2.0/24") || !strings.Contains(joined, `"protocol":"17"`) {
				t.Fatal("lost SSH CIDR or UDP rule")
			}
		}
		calls = append(calls, kind)
		return json.Marshal(map[string]any{"data": map[string]any{"id": "id-" + kind}})
	}
	if err := s.prepareOracleNetwork(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, oracleNetworkKinds) || op.Request.SubnetID != "id-subnet" || op.PendingResourceKind != "" {
		t.Fatalf("incomplete network: %v %+v", calls, op)
	}
	inv, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := inv.Host("free")
	if len(h.Resources) != 5 {
		t.Fatal("resource inventory not durable")
	}
}

func TestOracleNetworkUncertainWriteOnlyReconciles(t *testing.T) {
	s, op := oracleNetworkFixture(t)
	creates := 0
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		kind, action := networkInvocation(t, args)
		if action != "create" {
			t.Fatal("unexpected read")
		}
		creates++
		if kind == "internet-gateway" {
			return nil, errors.New("timeout")
		}
		return json.Marshal(map[string]any{"data": map[string]any{"id": "id-" + kind}})
	}
	if err := s.prepareOracleNetwork(context.Background(), op); err == nil {
		t.Fatal("expected ambiguous gateway")
	}
	if op.PendingResourceKind != "oracle-igw" || creates != 2 {
		t.Fatal("missing uncertain intent")
	}
	if err := s.prepareOracleNetwork(context.Background(), op); err == nil || creates != 2 {
		t.Fatal("retried ambiguous write")
	}
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		kind, action := networkInvocation(t, args)
		if kind != "internet-gateway" || action != "list" {
			t.Fatalf("resume mutated: %v", args)
		}
		return []byte(`{"data":[]}`), nil
	}
	if err := s.resumeOracleNetwork(context.Background(), op); err == nil {
		t.Fatal("absence treated as permission to recreate")
	}
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		_, action := networkInvocation(t, args)
		if action != "list" {
			t.Fatal("resume mutated")
		}
		return json.Marshal(map[string]any{"data": []any{map[string]any{"id": "id-internet-gateway", "vcn-id": "id-vcn", "freeform-tags": map[string]string{"lazyclash-operation": op.ID}}}})
	}
	if err := s.resumeOracleNetwork(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if op.PendingResourceKind != "" || networkID(op.Host, "internet-gateway") == "" || creates != 2 {
		t.Fatal("did not reconcile exactly one owned gateway")
	}
}

func TestOracleNetworkCleanupOrderAndOwnership(t *testing.T) {
	s, op := oracleNetworkFixture(t)
	for _, kind := range oracleNetworkKinds {
		appendNetworkResource(&op.Host, kind, "id-"+kind, true)
	}
	op.Host.Resources = append(op.Host.Resources, serverstate.Resource{Kind: "oracle-subnet", ID: "shared-subnet", Owned: false})
	if err := s.persistOracleNetwork(op); err != nil {
		t.Fatal(err)
	}
	var deleted []string
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		kind, action := networkInvocation(t, args)
		if action == "delete" {
			if strings.Contains(strings.Join(args, " "), "shared-subnet") {
				t.Fatal("deleted shared resource")
			}
			deleted = append(deleted, kind)
			return nil, nil
		}
		return json.Marshal(map[string]any{"data": []any{map[string]any{"id": "id-" + kind, "freeform-tags": map[string]string{"lazyclash-operation": op.ID}}}})
	}
	if err := s.cleanupOracleNetwork(context.Background(), op.Host); err != nil {
		t.Fatal(err)
	}
	want := []string{"subnet", "security-list", "route-table", "internet-gateway", "vcn"}
	if !reflect.DeepEqual(deleted, want) {
		t.Fatalf("cleanup order %v", deleted)
	}
	deleted = nil
	s.options.Run = func(_ context.Context, _ string, args []string) ([]byte, error) {
		kind, action := networkInvocation(t, args)
		if action == "delete" {
			t.Fatal("deleted resource with changed ownership")
		}
		return json.Marshal(map[string]any{"data": []any{map[string]any{"id": "id-" + kind, "freeform-tags": map[string]string{"lazyclash-operation": "another-operation"}}}})
	}
	if err := s.cleanupOracleNetwork(context.Background(), op.Host); err == nil {
		t.Fatal("accepted changed owner")
	}
}

func TestOracleSuppliedSubnetIsNotMutated(t *testing.T) {
	s, op := oracleNetworkFixture(t)
	op.Request.SubnetID = "existing-subnet"
	s.options.Run = func(context.Context, string, []string) ([]byte, error) {
		t.Fatal("supplied network mutated")
		return nil, nil
	}
	if err := s.prepareOracleNetwork(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if len(op.Host.Resources) != 1 || op.Host.Resources[0].Owned {
		t.Fatal("claimed preexisting subnet")
	}
}
