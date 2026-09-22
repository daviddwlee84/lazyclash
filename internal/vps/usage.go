package vps

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

// UsageReport keeps network observations separate from provider billing meters.
// Neither source establishes a remaining shared allowance or a spending cap.
type UsageReport struct {
	HostID      string              `json:"host_id"`
	ServerID    string              `json:"server_id,omitempty"`
	Provider    string              `json:"provider"`
	ResourceID  string              `json:"resource_id"`
	Region      string              `json:"region"`
	ObservedAt  time.Time           `json:"observed_at"`
	PeriodStart time.Time           `json:"period_start"`
	PeriodEnd   time.Time           `json:"period_end"`
	Observed    TransferObservation `json:"observed"`
	Billing     BillingObservation  `json:"billing"`
	Warnings    []string            `json:"warnings,omitempty"`
}

type TransferObservation struct {
	InboundBytes   *float64  `json:"inbound_bytes,omitempty"`
	OutboundBytes  *float64  `json:"outbound_bytes,omitempty"`
	Source         string    `json:"source"`
	LatestAt       time.Time `json:"latest_at,omitempty"`
	ExpectedPoints int       `json:"expected_points"`
	InboundPoints  int       `json:"inbound_points"`
	OutboundPoints int       `json:"outbound_points"`
	Partial        bool      `json:"partial"`
}

type BillingObservation struct {
	Source             string       `json:"source"`
	Scope              string       `json:"scope"`
	Status             string       `json:"status"`
	Meters             []UsageMeter `json:"meters"`
	PublishedAllowance string       `json:"published_allowance,omitempty"`
	LatestAt           time.Time    `json:"latest_at,omitempty"`
	Warnings           []string     `json:"warnings,omitempty"`
}

type UsageMeter struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Unit     string    `json:"unit"`
	Currency string    `json:"currency,omitempty"`
	Quantity float64   `json:"quantity"`
	Cost     *float64  `json:"cost,omitempty"`
	LatestAt time.Time `json:"latest_at,omitempty"`
}

// Usage reads the current UTC month without saving inventory, histories or
// counters. Monitoring survives lazyclash restarts because the provider stores it.
func (s *Service) Usage(ctx context.Context, id string) (UsageReport, error) {
	return s.UsageMonth(ctx, id, "")
}

// UsageMonth accepts a UTC calendar month. An empty month selects the current
// month; a window outside provider retention is rejected before cloud queries.
func (s *Service) UsageMonth(ctx context.Context, id, month string) (UsageReport, error) {
	inv, err := s.store.Load()
	if err != nil {
		return UsageReport{}, err
	}
	h, err := inv.Host(id)
	if err != nil {
		return UsageReport{}, err
	}
	b, err := s.usageBinding(h)
	if err != nil {
		return UsageReport{}, err
	}
	if err = validateObservationRequest(b); err != nil {
		return UsageReport{}, err
	}
	now := s.options.Now().UTC()
	start, end, err := usageWindow(now, month, b.Provider)
	if err != nil {
		return UsageReport{}, err
	}
	account, err := s.observationIdentity(ctx, b)
	if err != nil {
		return UsageReport{}, err
	}
	if account != b.AccountID {
		return UsageReport{}, fmt.Errorf("cloud account changed since the observation binding was verified; review vps bind-cloud again")
	}
	r := UsageReport{HostID: h.ID, Provider: b.Provider, ResourceID: b.ResourceID, Region: b.Region, ObservedAt: now, PeriodStart: start, PeriodEnd: end}
	r.Observed.ExpectedPoints = int(math.Ceil(end.Sub(start).Hours()))
	r.Billing.Meters = []UsageMeter{}
	r.Warnings = []string{"VM network bytes include traffic that may not consume the provider's billable internet-egress allowance. Shared allowance remaining and overage are not calculated."}
	switch b.Provider {
	case "oracle":
		return s.oracleUsage(ctx, h, b, r)
	case "azure":
		return s.azureUsage(ctx, h, b, r)
	default:
		return UsageReport{}, fmt.Errorf("usage monitoring is not supported for provider %q", b.Provider)
	}
}

func (s *Service) UsageForServer(ctx context.Context, id string) (UsageReport, error) {
	return s.UsageForServerMonth(ctx, id, "")
}

func (s *Service) UsageForServerMonth(ctx context.Context, id, month string) (UsageReport, error) {
	inv, err := s.store.Load()
	if err != nil {
		return UsageReport{}, err
	}
	d, err := inv.Deployment(id)
	if err != nil {
		return UsageReport{}, err
	}
	r, err := s.UsageMonth(ctx, d.HostID, month)
	r.ServerID = id
	return r, err
}

func usageWindow(now time.Time, month, provider string) (time.Time, time.Time, error) {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if month != "" {
		parsed, err := time.Parse("2006-01", month)
		if err != nil || parsed.Format("2006-01") != month {
			return time.Time{}, time.Time{}, fmt.Errorf("--month must be a UTC calendar month in YYYY-MM format")
		}
		if parsed.After(start) {
			return time.Time{}, time.Time{}, fmt.Errorf("usage cannot query a future month")
		}
		start = parsed
	}
	retention := 90
	if provider == "azure" {
		retention = 93
	}
	if start.Before(now.AddDate(0, 0, -retention)) {
		return time.Time{}, time.Time{}, fmt.Errorf("the requested full month begins outside %s Monitoring's %d-day retention; incomplete older history is not treated as zero", provider, retention)
	}
	end := start.AddDate(0, 1, 0)
	if end.After(now) {
		end = now
	}
	if !end.After(start) {
		return time.Time{}, time.Time{}, fmt.Errorf("the current UTC month has no elapsed observation window yet")
	}
	return start, end, nil
}

func (s *Service) usageBinding(h serverstate.Host) (serverstate.CloudObservationBinding, error) {
	if h.Observation != nil {
		return *h.Observation, nil
	}
	if h.Owned && h.ResourceID != "" && (h.Provider == "oracle" || h.Provider == "azure") {
		op, err := s.readOperation(h.OperationID)
		if err != nil {
			return serverstate.CloudObservationBinding{}, err
		}
		if op.Host.ID != h.ID || op.Host.ResourceID != h.ResourceID || op.Request.Provider != h.Provider || op.Request.Region != h.Region || op.Request.Profile != h.Profile || op.Request.SubscriptionID != h.SubscriptionID {
			return serverstate.CloudObservationBinding{}, fmt.Errorf("host differs from its saved cloud resource record")
		}
		return serverstate.CloudObservationBinding{Provider: h.Provider, Profile: h.Profile, Region: h.Region, ResourceID: h.ResourceID, TenancyID: op.Request.TenancyID, CompartmentID: op.Request.CompartmentID, SubscriptionID: h.SubscriptionID, AccountID: op.AccountID, VerifiedAt: h.CreatedAt}, nil
	}
	return serverstate.CloudObservationBinding{}, fmt.Errorf("host %q has no verified cloud observation binding; use vps bind-cloud %s", h.ID, h.ID)
}
