package vps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func TestCloudDraftRejectsUnsupportedOverrides(t *testing.T) {
	for _, req := range []CreateRequest{
		{Provider: "azure", Profile: "personal"},
		{Provider: "aws-ec2", SubscriptionID: "subscription"},
		{Provider: "aws-lightsail", DiskGB: 20},
		{Provider: "azure", SubnetID: "existing"},
		{Provider: "aws-ec2", FirewallID: "existing"},
		{Provider: "azure", SubscriptionID: "tab\tinjection"},
		{Provider: "digitalocean", Architecture: "arm64"},
		{Provider: "vultr", AvailabilityZone: "zone"},
		{Provider: "oracle", DiskGB: 20},
		{Architecture: "typo"},
	} {
		if err := ValidateDraft(req); err == nil {
			t.Fatalf("accepted unsupported override: %+v", req)
		}
	}
	if err := ValidateDraft(CreateRequest{Provider: "digitalocean", Architecture: "auto"}); err != nil {
		t.Fatalf("new CLI flag default broke legacy provider: %v", err)
	}
}

func TestCloudKeyPathAndFingerprintStayPinnedAcrossResumeDirectories(t *testing.T) {
	t.Chdir(t.TempDir())
	file := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(file, []byte("ssh-ed25519 AAAA fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, file)
	if err != nil {
		t.Fatal(err)
	}
	req, err := normalizeCloud(CreateRequest{ID: "key-fixture", Provider: "aws-ec2", Region: "us-east-1", SSHKey: relative, SSHCIDR: "192.0.2.1/24"})
	if err != nil || !filepath.IsAbs(req.SSHKey) || req.SSHCIDR != "192.0.2.0/24" || req.SSHKeyFingerprint == "" {
		t.Fatalf("unresolved key or network: %+v %v", req, err)
	}
	if err := os.WriteFile(file, []byte("ssh-ed25519 BBBB changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reviewedPublicKey(req); err == nil {
		t.Fatal("changed key accepted after review")
	}
}

func TestDeletedCloudStatusDoesNotContactProvider(t *testing.T) {
	for _, provider := range []string{"azure", "aws-ec2", "aws-lightsail"} {
		s := New(serverstate.Store{Path: filepath.Join(t.TempDir(), "servers.toml")}, Options{Run: func(context.Context, string, []string) ([]byte, error) {
			t.Fatal("deleted status should not contact the provider")
			return nil, nil
		}})
		if err := s.saveHost(serverstate.Host{ID: "deleted", Provider: provider, ResourceID: "retained-receipt-id", Status: "deleted"}); err != nil {
			t.Fatal(err)
		}
		h, err := s.Status(context.Background(), "deleted")
		if err != nil || h.Status != "deleted" || h.Owned {
			t.Fatalf("deleted cloud observation: %+v %v", h, err)
		}
	}
}

func TestCatalogIncludesCloudFixedCostBaselines(t *testing.T) {
	found := map[string]bool{}
	for _, q := range Catalog() {
		if isCloudProvider(q.Provider) {
			found[q.Provider] = true
			if q.Region == "" || q.CLI == "" || q.Architecture == "" || q.MemoryMiB < 1024 || q.DiskGB < 20 || q.MonthlyUSD <= 0 || q.Checked == "" || q.Source == "" {
				t.Fatalf("cloud catalog lacks a usable dated baseline: %+v", q)
			}
		}
	}
	if len(found) != 3 {
		t.Fatalf("missing cloud providers: %v", found)
	}
}
