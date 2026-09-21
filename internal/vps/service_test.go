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

type fakeCloud struct {
	t            *testing.T
	provider     string
	account      string
	tag          string
	created      bool
	createError  bool
	deleteError  bool
	deleted      bool
	createCalls  int
	mutations    []string
	requests     [][]string
	beforeCreate func()
}

func (f *fakeCloud) run(_ context.Context, executable string, args []string) ([]byte, error) {
	f.requests = append(f.requests, append([]string{executable}, args...))
	cmd := strings.Join(args, " ")
	encode := func(v any) ([]byte, error) { return json.Marshal(v) }
	if strings.Contains(cmd, "account get") {
		return encode([]any{map[string]any{"uuid": f.account}})
	}
	if strings.Contains(cmd, "account info") {
		return encode(map[string]any{"account": map[string]any{"email": f.account}})
	}
	if strings.Contains(cmd, "profile view") {
		return encode([]any{map[string]any{"uid": 42, "username": f.account}})
	}
	if strings.Contains(cmd, "iam tenancy get") {
		return encode(map[string]any{"data": map[string]any{"id": "tenancy-1"}})
	}
	if strings.Contains(cmd, "compute size list") {
		return []byte(`[{"slug":"s-1vcpu-1gb","memory":1024,"vcpus":1,"disk":25,"transfer":1,"price_monthly":6,"available":true,"regions":["sgp1"]}]`), nil
	}
	if strings.Contains(cmd, "plans list") {
		return []byte(`{"plans":[{"id":"vc2-1c-1gb","ram":1024,"vcpu_count":1,"disk":25,"bandwidth":1024,"monthly_cost":5,"locations":["sgp1"]}],"meta":{"links":{"next":""}}}`), nil
	}
	if strings.Contains(cmd, "os list") {
		return []byte(`{"os":[{"id":2284,"name":"Ubuntu 24.04 LTS x64"}],"meta":{"links":{"next":""}}}`), nil
	}
	if strings.Contains(cmd, "linodes types") {
		return []byte(`[{"id":"g6-nanode-1","memory":1024,"vcpus":1,"disk":25600,"transfer":1000,"price":{"monthly":5}}]`), nil
	}
	if strings.Contains(cmd, "iam region-subscription list") {
		return []byte(`{"data":[{"region-name":"sgp1","is-home-region":true}]}`), nil
	}
	if strings.Contains(cmd, "compute image get") {
		return []byte(`{"data":{"id":"image-1","operating-system":"Canonical Ubuntu","operating-system-version":"24.04","compartment-id":null}}`), nil
	}
	if strings.Contains(cmd, "image-shape-compatibility-entry list") {
		return []byte(`{"data":[{"shape":"VM.Standard.A1.Flex"}]}`), nil
	}
	if strings.Contains(cmd, "firewall add-droplets") {
		return nil, nil
	}
	if strings.Contains(cmd, "network subnet get") {
		return []byte(`{"data":{"id":"subnet-1","prohibit-public-ip-on-vnic":false}}`), nil
	}
	if strings.Contains(cmd, "iam compartment list") || strings.Contains(cmd, "bv volume list") || strings.Contains(cmd, "bv boot-volume list") {
		return []byte(`{"data":[]}`), nil
	}
	if strings.Contains(cmd, "iam availability-domain list") {
		return []byte(`{"data":[{"name":"ad-1"}]}`), nil
	}
	if strings.Contains(cmd, "usage-api usage-summary") {
		return []byte(`{"data":{"items":[]}}`), nil
	}
	if strings.Contains(cmd, "compute instance list-vnics") {
		return []byte(`{"data":[{"public-ip":"203.0.113.10"}]}`), nil
	}
	isCreate := strings.Contains(cmd, "droplet create") || strings.Contains(cmd, "instance create") || strings.Contains(cmd, "linodes create") || strings.Contains(cmd, "instance launch")
	if isCreate {
		f.createCalls++
		if f.beforeCreate != nil {
			f.beforeCreate()
		}
		f.created = true
		f.mutations = append(f.mutations, cmd)
		for i, arg := range args {
			if (arg == "--tag-names" || arg == "--tags") && i+1 < len(args) {
				f.tag = args[i+1]
			}
			if arg == "--freeform-tags" && i+1 < len(args) {
				var tags map[string]string
				if err := json.Unmarshal([]byte(args[i+1]), &tags); err != nil {
					f.t.Fatal(err)
				}
				f.tag = tags["lazyclash-operation"]
			}
		}
		if f.createError {
			return nil, context.DeadlineExceeded
		}
	}
	if strings.Contains(cmd, "droplet list") || strings.Contains(cmd, "instance list") || strings.Contains(cmd, "linodes list") {
		if !f.created || f.deleted {
			return []byte(`{"data":[],"instances":[],"meta":{"links":{"next":""}}}`), nil
		}
		return encode(map[string]any{"data": []any{f.remote()}, "instances": []any{f.remote()}, "meta": map[string]any{"links": map[string]any{"next": ""}}})
	}
	if isCreate || strings.Contains(cmd, "droplet get") || strings.Contains(cmd, "instance get") || strings.Contains(cmd, "linodes view") {
		switch f.provider {
		case "digitalocean", "linode":
			return encode([]any{f.remote()})
		case "vultr":
			return encode(map[string]any{"instance": f.remote()})
		case "oracle":
			return encode(map[string]any{"data": f.remote()})
		}
	}
	if strings.Contains(cmd, " delete ") || strings.Contains(cmd, " terminate ") || strings.Contains(cmd, " stop ") || strings.Contains(cmd, " shutdown ") || strings.Contains(cmd, " action ") || strings.Contains(cmd, "power-on") || strings.Contains(cmd, " boot ") || strings.Contains(cmd, " restart ") || strings.Contains(cmd, " reboot ") {
		f.mutations = append(f.mutations, cmd)
		if strings.Contains(cmd, " delete ") || strings.Contains(cmd, " terminate ") {
			f.deleted = true
			if f.deleteError {
				return nil, context.DeadlineExceeded
			}
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected fake CLI command %s %s", executable, cmd)
}

func TestDeleteTimeoutReconcilesAbsenceAndCannotReviveCreate(t *testing.T) {
	s, f, req := testService(t, "digitalocean")
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(context.Background(), req, p.Digest); err != nil {
		t.Fatal(err)
	}
	p, err = s.PlanAction(context.Background(), req.ID, "delete")
	if err != nil {
		t.Fatal(err)
	}
	f.deleteError = true
	if _, err = s.Action(context.Background(), req.ID, "delete", p.Digest); err == nil {
		t.Fatal("delete timeout was hidden")
	}
	inv, _ := s.store.Load()
	h, _ := inv.Host(req.ID)
	if h.Status != "delete-pending" {
		t.Fatalf("delete intent missing: %#v", h)
	}
	count := len(f.mutations)
	p, err = s.PlanAction(context.Background(), req.ID, "delete")
	if err != nil {
		t.Fatal(err)
	}
	if p.Host.Status != "cleanup-required" {
		t.Fatalf("absence not reconciled: %#v", p)
	}
	h, err = s.Action(context.Background(), req.ID, "delete", p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != count {
		t.Fatal("absent VM deletion retried")
	}
	if h.Status != "deleted" || h.Owned {
		t.Fatalf("cleanup did not close host: %#v", h)
	}
	if _, err = s.PlanResume(context.Background(), req.ID); err == nil {
		t.Fatal("deleted host can be resumed")
	}
	if _, err = s.Resume(context.Background(), req.ID); err == nil {
		t.Fatal("deleted host resumed")
	}
	op, err := s.readOperation(h.OperationID)
	if err != nil || op.State != "deleted" {
		t.Fatalf("terminal phase not persisted: %#v %v", op, err)
	}
}

func TestSSHKeyContentChangeInvalidatesPreview(t *testing.T) {
	s, f, req := testService(t, "linode")
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(req.SSHKey, []byte("ssh-ed25519 AAAAdifferent-public-key key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(context.Background(), req, p.Digest); err == nil {
		t.Fatal("changed SSH key was accepted")
	}
	if len(f.mutations) > 0 {
		t.Fatal("key mismatch mutated provider")
	}
}

func TestServiceReadOnlyGuardsAllMutations(t *testing.T) {
	s, f, req := testService(t, "oracle")
	s.options.ReadOnly = true
	if _, err := s.Create(context.Background(), req, "digest"); err == nil {
		t.Fatal("read-only create allowed")
	}
	if _, err := s.Action(context.Background(), req.ID, "stop", "digest"); err == nil {
		t.Fatal("read-only power allowed")
	}
	if _, err := s.Resume(context.Background(), req.ID); err == nil {
		t.Fatal("read-only resume allowed")
	}
	if _, err := s.Register(serverstate.Host{ID: "host", SSHHost: "host", PublicHost: "host.example"}); err == nil {
		t.Fatal("read-only registration allowed")
	}
	if len(f.requests) > 0 {
		t.Fatal("read-only rejection contacted provider")
	}
}

func TestMalformedCloudListDoesNotProveAbsence(t *testing.T) {
	s, _, req := testService(t, "digitalocean")
	s.options.Run = func(context.Context, string, []string) ([]byte, error) { return []byte(`{"unexpected":[]}`), nil }
	if _, err := s.lookupRemote(context.Background(), req, "lc-operation", "123"); err == nil {
		t.Fatal("malformed provider list was treated as absence")
	}
}

func TestUnknownCreateCannotEnterDeletionBeforeReconciliation(t *testing.T) {
	s, f, req := testService(t, "digitalocean")
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	f.createError = true
	h, err := s.Create(context.Background(), req, p.Digest)
	if err == nil {
		t.Fatal("expected create timeout")
	}
	op, err := s.readOperation(h.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	h.Resources = append(h.Resources, serverstate.Resource{Kind: "firewall", ID: "owned-firewall", Owned: true})
	op.Host = h
	if err = s.writeOperation(op); err != nil {
		t.Fatal(err)
	}
	if err = s.saveHost(h); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PlanAction(context.Background(), h.ID, "delete"); err == nil || !strings.Contains(err.Error(), "unconfirmed") {
		t.Fatalf("uncertain VM entered deletion: %v", err)
	}
	inv, _ := s.store.Load()
	h, _ = inv.Host(h.ID)
	if h.Status != "creating" {
		t.Fatalf("preview changed phase: %#v", h)
	}
	if _, err = s.Resume(context.Background(), h.ID); err != nil {
		t.Fatal(err)
	}
	if f.createCalls != 1 {
		t.Fatal("reconciliation launched another VM")
	}
}

func TestReconcileOnlyDoesNotFinishPreparedCreate(t *testing.T) {
	s, f, req := testService(t, "digitalocean")
	account, err := s.accountIdentity(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	op := operation{Version: 1, ID: "lc-prepared", AccountID: account, Request: req, State: "firewall", Host: serverstate.Host{ID: req.ID, Provider: req.Provider, Region: req.Region, Owned: true, Status: "creating", OperationID: "lc-prepared"}}
	if err = s.writeOperation(op); err != nil {
		t.Fatal(err)
	}
	if err = s.saveHost(op.Host); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Resume(context.Background(), req.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations) != 0 || f.createCalls != 0 {
		t.Fatal("reconcile-only provisioned resources")
	}
}
func (f *fakeCloud) remote() map[string]any {
	return map[string]any{"id": "123", "status": "running", "main_ip": "203.0.113.10", "networks": map[string]any{"v4": []any{map[string]any{"type": "public", "ip_address": "203.0.113.10"}}}, "ipv4": []any{"192.168.1.1", "203.0.113.10"}, "tags": []any{f.tag}, "lifecycle-state": "RUNNING", "shape": "VM.Standard.A1.Flex", "shape-config": map[string]any{"ocpus": 1, "memory-in-gbs": 6}, "freeform-tags": map[string]any{"lazyclash-operation": f.tag}}
}

func testService(t *testing.T, provider string) (*Service, *fakeCloud, CreateRequest) {
	t.Helper()
	dir := t.TempDir()
	store := serverstate.Store{Path: filepath.Join(dir, "servers.toml"), StateDir: filepath.Join(dir, "state")}
	fake := &fakeCloud{t: t, provider: provider, account: "account-one"}
	key := filepath.Join(dir, "id_ed25519.pub")
	if err := os.WriteFile(key, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMtestfixture key"), 0600); err != nil {
		t.Fatal(err)
	}
	req := CreateRequest{ID: "test", Provider: provider, Region: "sgp1", SSHKey: "key-id"}
	if provider != "oracle" {
		req.FirewallID = "shared-firewall"
	}
	switch provider {
	case "vultr":
		req.Image = "2284"
	case "linode":
		req.SSHKey = key
	case "oracle":
		req.Image = "image-1"
		req.SSHKey = key
		req.TenancyID = "tenancy-1"
		req.CompartmentID = "tenancy-1"
		req.SubnetID = "subnet-1"
		req.AvailabilityDomain = "ad-1"
	}
	s := New(store, Options{Run: fake.run, Now: func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }})
	return s, fake, req
}

func TestCreateAdaptersPersistIntentAndReconcile(t *testing.T) {
	for _, provider := range []string{"digitalocean", "vultr", "linode", "oracle"} {
		t.Run(provider, func(t *testing.T) {
			s, f, req := testService(t, provider)
			p, err := s.PlanCreate(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.mutations) != 0 {
				t.Fatal("preview mutated cloud")
			}
			if _, e := os.Stat(s.store.Path); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("preview wrote inventory: %v", e)
			}
			f.beforeCreate = func() {
				inv, e := s.store.Load()
				if e != nil {
					t.Fatal(e)
				}
				h, e := inv.Host(req.ID)
				if e != nil || h.OperationID == "" {
					t.Fatalf("missing durable intent: %#v %v", h, e)
				}
				op, e := s.readOperation(h.OperationID)
				if e != nil || op.State != "submitted" {
					t.Fatalf("missing submitted intent: %s %v", op.State, e)
				}
			}
			f.createError = true
			h, err := s.Create(context.Background(), req, p.Digest)
			if err == nil || h.OperationID == "" {
				t.Fatalf("missing uncertain create result: %#v %v", h, err)
			}
			h, err = s.Resume(context.Background(), req.ID)
			if err != nil {
				t.Fatal(err)
			}
			if h.ResourceID != "123" || h.PublicHost != "203.0.113.10" {
				t.Fatalf("wrong reconciliation: %#v", h)
			}
			if f.createCalls != 1 {
				t.Fatalf("create retried %d times", f.createCalls)
			}
			if _, err = s.Create(context.Background(), req, p.Digest); err == nil {
				t.Fatal("duplicate create allowed")
			}
			plan, err := s.PlanAction(context.Background(), req.ID, "delete")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Action(context.Background(), req.ID, "delete", plan.Digest); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccountOrDigestChangeNeverCreates(t *testing.T) {
	s, f, req := testService(t, "digitalocean")
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	f.account = "different-account"
	if _, err = s.Create(context.Background(), req, p.Digest); err == nil {
		t.Fatal("account switch was accepted")
	}
	if f.createCalls != 0 {
		t.Fatal("account switch created VM")
	}
	if _, err = os.Stat(s.store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected create wrote inventory")
	}
}

func TestUnownedOrChangedMarkerPreventsDelete(t *testing.T) {
	s, f, req := testService(t, "digitalocean")
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Create(context.Background(), req, p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	f.tag = "somebody-elses-vm"
	if _, err = s.PlanAction(context.Background(), h.ID, "delete"); err == nil {
		t.Fatal("changed ownership marker accepted")
	}
	if err = s.store.Update(func(inv *serverstate.Inventory) error { h.Owned = false; return inv.UpsertHost(h) }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PlanAction(context.Background(), h.ID, "delete"); err == nil {
		t.Fatal("unowned delete allowed")
	}
}

func TestReadOnlyStatusDoesNotWrite(t *testing.T) {
	s, _, req := testService(t, "digitalocean")
	p, err := s.PlanCreate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Create(context.Background(), req, p.Digest); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.store.Path)
	if err != nil {
		t.Fatal(err)
	}
	s.options.ReadOnly = true
	s.options.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err = s.Status(context.Background(), req.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.store.Path)
	if string(before) != string(after) {
		t.Fatal("read-only status changed inventory")
	}
}

func TestRunCLIWithExecutableWithholdsSecretErrorOutput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "provider-cli")
	if err := os.WriteFile(file, []byte("#!/bin/sh\nprintf 'secret-cloud-token'\nprintf 'secret-cloud-password' >&2\nexit 17\n"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := runCLI(context.Background(), file, nil)
	if err == nil || strings.Contains(err.Error(), "secret-cloud") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestPrivateKeyRejectedBeforeCloudCalls(t *testing.T) {
	s, f, req := testService(t, "linode")
	if err := os.WriteFile(req.SSHKey, []byte("-----BEGIN OPENSSH PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PlanCreate(context.Background(), req); err == nil {
		t.Fatal("private key accepted")
	}
	if len(f.requests) != 0 {
		t.Fatal("invalid key contacted cloud")
	}
}
