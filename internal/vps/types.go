// Package vps manages cloud virtual machines through their official CLIs.
// Cloud credentials remain in those CLIs; the inventory contains no API tokens.
package vps

import (
	"context"
	"encoding/json"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type Options struct {
	Run      func(context.Context, string, []string) ([]byte, error)
	Now      func() time.Time
	ReadOnly bool
	HTTPGet  func(context.Context, string) ([]byte, error)
}

type CreateRequest struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Profile            string `json:"profile,omitempty"`
	SubscriptionID     string `json:"subscription_id,omitempty"`
	Architecture       string `json:"architecture,omitempty"`
	AvailabilityZone   string `json:"availability_zone,omitempty"`
	DiskGB             int    `json:"disk_gb,omitempty"`
	ImageVersion       string `json:"image_version,omitempty"`
	Region             string `json:"region"`
	Plan               string `json:"plan"`
	Image              string `json:"image"`
	SSHKey             string `json:"ssh_key"`
	SSHKeyFingerprint  string `json:"ssh_key_fingerprint,omitempty"`
	SSHUser            string `json:"ssh_user"`
	SSHCIDR            string `json:"ssh_cidr"`
	FirewallID         string `json:"firewall_id,omitempty"`
	TenancyID          string `json:"tenancy_id,omitempty"`
	CompartmentID      string `json:"compartment_id,omitempty"`
	SubnetID           string `json:"subnet_id,omitempty"`
	AvailabilityDomain string `json:"availability_domain,omitempty"`
	InitializerVersion string `json:"initializer_version,omitempty"`
	InitializerSHA256  string `json:"initializer_sha256,omitempty"`
}

type Offering struct {
	Provider     string  `json:"provider"`
	Plan         string  `json:"plan"`
	CLI          string  `json:"cli,omitempty"`
	Region       string  `json:"region,omitempty"`
	Architecture string  `json:"architecture,omitempty"`
	MonthlyUSD   float64 `json:"monthly_usd"`
	MemoryMiB    int     `json:"memory_mib"`
	VCPUs        int     `json:"vcpus"`
	DiskGB       int     `json:"disk_gb"`
	TransferGB   int     `json:"transfer_gb"`
	TransferUnit string  `json:"transfer_unit,omitempty"`
	Notes        string  `json:"notes"`
	Source       string  `json:"source"`
	Checked      string  `json:"checked"`
}

type Quote struct {
	Provider          string           `json:"provider"`
	Plan              string           `json:"plan"`
	Region            string           `json:"region,omitempty"`
	MonthlyUSD        float64          `json:"monthly_usd"`
	MemoryMiB         int              `json:"memory_mib"`
	VCPUs             int              `json:"vcpus"`
	DiskGB            int              `json:"disk_gb"`
	TransferGB        int              `json:"transfer_gb"`
	TransferUnit      string           `json:"transfer_unit"`
	Live              bool             `json:"live"`
	Notes             []string         `json:"notes"`
	Architecture      string           `json:"architecture,omitempty"`
	Components        []CostComponent  `json:"components,omitempty"`
	TransferPricing   *TransferPricing `json:"transfer_pricing,omitempty"`
	StoppedMonthlyUSD *float64         `json:"stopped_monthly_usd,omitempty"`
}

type CostComponent struct {
	Name       string  `json:"name"`
	MonthlyUSD float64 `json:"monthly_usd"`
	Unit       string  `json:"unit,omitempty"`
	UnitUSD    float64 `json:"unit_usd,omitempty"`
	Quantity   float64 `json:"quantity,omitempty"`
	Source     string  `json:"source,omitempty"`
}

// Tiers describe paid outbound units after a per-instance allowance. Account-
// wide free allocations are descriptive only and are never subtracted here.
type PriceTier struct {
	From float64 `json:"from"`
	To   float64 `json:"to,omitempty"` // zero means unbounded
	USD  float64 `json:"usd"`
}
type TransferPricing struct {
	Basis             string      `json:"basis"` // outbound or combined (Lightsail)
	Tiers             []PriceTier `json:"tiers"`
	Source            string      `json:"source"`
	Checked           string      `json:"checked"`
	SharedAllowanceGB float64     `json:"shared_allowance_gb,omitempty"`
}

type Preview struct {
	OperationDigest string            `json:"operation_digest,omitempty"`
	AccountID       string            `json:"account_id,omitempty"`
	Action          string            `json:"action"`
	ID              string            `json:"id"`
	Request         *CreateRequest    `json:"request,omitempty"`
	Host            *serverstate.Host `json:"host,omitempty"`
	Quote           *Quote            `json:"quote,omitempty"`
	Warnings        []string          `json:"warnings"`
	Digest          string            `json:"digest"`
}

type operation struct {
	AccountID           string                     `json:"account_id"`
	Version             int                        `json:"version"`
	ID                  string                     `json:"id"`
	Request             CreateRequest              `json:"request"`
	State               string                     `json:"state"`
	Host                serverstate.Host           `json:"host"`
	CreatedAt           time.Time                  `json:"created_at"`
	UpdatedAt           time.Time                  `json:"updated_at"`
	PendingResourceKind string                     `json:"pending_resource_kind,omitempty"`
	CloudResources      []cloudResource            `json:"cloud_resources,omitempty"`
	PrivateData         map[string]json.RawMessage `json:"private_data,omitempty"`
	Quote               *Quote                     `json:"quote,omitempty"`
}

func Catalog() []Offering {
	offerings := []Offering{
		{Provider: "oracle", Plan: "VM.Standard.A1.Flex", CLI: "oci", VCPUs: 1, MemoryMiB: 6144, DiskGB: 50, TransferGB: 10000, Notes: "Always Free only; home region, tenancy-wide allowance and usage checks required; limited capacity and idle reclamation. Conservative current allowance: 2 OCPUs / 12 GB / 200 GB combined volumes.", Source: "https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm", Checked: "2026-09-21"},
		{Provider: "racknerd", Plan: "1gb-kvm", MonthlyUSD: 21.99 / 12, VCPUs: 1, MemoryMiB: 1024, DiskGB: 20, TransferGB: 3000, Notes: "$21.99/year advertised special; purchase separately, then vps register over SSH; availability varies.", Source: "https://www.racknerd.com/specials/", Checked: "2026-09-21"},
		{Provider: "vultr", Plan: "vc2-1c-1gb", CLI: "vultr-cli", MonthlyUSD: 5, VCPUs: 1, MemoryMiB: 1024, DiskGB: 25, TransferGB: 1024, Notes: "Snapshot, region availability and transfer pricing must be checked; stopped instances still bill.", Source: "https://api.vultr.com/v2/plans", Checked: "2026-09-21"},
		{Provider: "linode", Plan: "g6-nanode-1", CLI: "linode-cli", MonthlyUSD: 5, VCPUs: 1, MemoryMiB: 1024, DiskGB: 25, TransferGB: 1000, Notes: "Snapshot; region premiums and transfer overages may apply; shutdown does not release resources.", Source: "https://www.akamai.com/cloud/pricing", Checked: "2026-09-21"},
		{Provider: "digitalocean", Plan: "s-1vcpu-1gb", CLI: "doctl", MonthlyUSD: 6, VCPUs: 1, MemoryMiB: 1024, DiskGB: 25, TransferGB: 1000, Notes: "Recommended balanced baseline. Transfer is advertised in GiB; smaller 512 MiB plan is for one lightweight native service.", Source: "https://www.digitalocean.com/pricing/droplets", Checked: "2026-09-21"},
		{Provider: "digitalocean", Plan: "s-1vcpu-512mb-10gb", CLI: "doctl", MonthlyUSD: 4, VCPUs: 1, MemoryMiB: 512, DiskGB: 10, TransferGB: 500, Notes: "Lightweight native service only; transfer advertised in GiB. Validate actual memory and throughput.", Source: "https://www.digitalocean.com/pricing/droplets", Checked: "2026-09-21"},
		{Provider: "aws-lightsail", Plan: "micro_3_0", CLI: "aws", Region: "us-east-1", Architecture: "amd64", MonthlyUSD: 7, VCPUs: 2, MemoryMiB: 1024, DiskGB: 40, TransferGB: 2048, Notes: "Linux public-IPv4 bundle snapshot, not a capacity guarantee; discover current regional bundle IDs. Inbound and outbound share the allowance; some regions have half the transfer. Stopping still bills; static IP must remain attached.", Source: "https://aws.amazon.com/lightsail/pricing/", Checked: "2026-09-21"},
		{Provider: "aws-ec2", Plan: "t4g.micro", CLI: "aws", Region: "us-east-1", Architecture: "arm64", MonthlyUSD: 11.382, VCPUs: 2, MemoryMiB: 1024, DiskGB: 20, Notes: "730-hour snapshot: compute $6.132 + 20 GiB gp3 $1.60 + one IPv4 $3.65. Standard CPU credits avoid unlimited-credit charges. Outbound is additional; no account-wide free tier is deducted. Use live quote for your region.", Source: "https://aws.amazon.com/ec2/pricing/on-demand/", Checked: "2026-09-21"},
		{Provider: "azure", Plan: "Standard_B2pts_v2", CLI: "az", Region: "eastus", Architecture: "arm64", MonthlyUSD: 12.182, VCPUs: 2, MemoryMiB: 1024, DiskGB: 32, Notes: "730-hour snapshot: compute $6.132 + E4 Standard SSD $2.40 + Standard Static IPv4 $3.65. Outbound and storage transactions are additional; deallocate stops compute only. Use live quote for regional price, architecture and quota checks.", Source: "https://prices.azure.com/api/retail/prices", Checked: "2026-09-21"},
	}
	for i := range offerings {
		offerings[i].TransferUnit = "GB"
		if offerings[i].Provider == "digitalocean" {
			offerings[i].TransferUnit = "GiB"
		}
	}
	return offerings
}
