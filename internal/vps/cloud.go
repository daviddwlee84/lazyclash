package vps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func isCloudProvider(p string) bool { return p == "azure" || p == "aws-lightsail" || p == "aws-ec2" }
func (s *Service) cloudAdapter(p string) cloudAdapter {
	switch p {
	case "azure":
		return azureAdapter{s: s}
	case "aws-ec2":
		return ec2Adapter{s: s}
	case "aws-lightsail":
		return lightsailAdapter{s: s}
	}
	panic("unsupported cloud adapter")
}
func (s *Service) hasCloudHost(id string) bool {
	inv, err := s.store.Load()
	if err != nil {
		return false
	}
	h, err := inv.Host(id)
	return err == nil && h.Owned && isCloudProvider(h.Provider)
}

func validateCloudDraft(r CreateRequest) error {
	if !isCloudProvider(r.Provider) {
		return errors.New("unsupported cloud provider")
	}
	if r.ID != "" && !safeID.MatchString(r.ID) {
		return errors.New("invalid host ID")
	}
	for _, v := range []string{r.Name, r.Profile, r.Region, r.Plan, r.Image, r.ImageVersion, r.SubscriptionID, r.AvailabilityZone, r.SSHKey, r.SSHUser, r.SSHCIDR} {
		if strings.IndexFunc(v, unicode.IsControl) >= 0 || strings.HasPrefix(v, "-") {
			return errors.New("cloud fields cannot contain controls or start with '-'")
		}
	}
	if r.Architecture != "" && r.Architecture != "auto" && r.Architecture != "amd64" && r.Architecture != "arm64" {
		return errors.New("architecture must be auto, amd64 or arm64")
	}
	if r.DiskGB < 0 || r.DiskGB > 1024 {
		return errors.New("disk-gb must be between 0 (provider baseline) and 1024")
	}
	if r.FirewallID != "" || r.SubnetID != "" || r.TenancyID != "" || r.CompartmentID != "" || r.AvailabilityDomain != "" {
		return errors.New("these cloud providers create an owned network; existing network adoption is not supported")
	}
	if r.Provider != "azure" && r.SubscriptionID != "" {
		return errors.New("--subscription applies only to Azure")
	}
	if r.Provider == "azure" && r.Profile != "" {
		return errors.New("Azure uses --subscription, not --profile")
	}
	if r.Provider == "aws-lightsail" && r.DiskGB != 0 {
		return errors.New("Lightsail storage is fixed by its bundle; omit --disk-gb")
	}
	return nil
}
func normalizeCloud(r CreateRequest) (CreateRequest, error) {
	if err := validateCloudDraft(r); err != nil {
		return r, err
	}
	if !safeID.MatchString(r.ID) {
		return r, errors.New("host ID is required")
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if !safeID.MatchString(r.Name) {
		return r, errors.New("invalid host name")
	}
	if r.Region == "" || r.SSHKey == "" {
		return r, errors.New("--region and --ssh-key public key file are required")
	}
	if r.Architecture == "" {
		r.Architecture = "auto"
	}
	if r.SSHUser == "" {
		r.SSHUser = "ubuntu"
	}
	if r.SSHUser != "ubuntu" {
		return r, errors.New("the reviewed Ubuntu cloud recipes use SSH user ubuntu")
	}
	if r.SSHCIDR == "" {
		r.SSHCIDR = "0.0.0.0/0"
	}
	ip, cidr, err := net.ParseCIDR(r.SSHCIDR)
	if err != nil || ip.To4() == nil {
		return r, errors.New("--ssh-cidr must be an IPv4 CIDR for the public IPv4 recipe")
	}
	r.SSHCIDR = cidr.String()
	if strings.HasPrefix(r.SSHKey, "~/") {
		homeDir, e := os.UserHomeDir()
		if e != nil {
			return r, e
		}
		r.SSHKey = filepath.Join(homeDir, strings.TrimPrefix(r.SSHKey, "~/"))
	}
	r.SSHKey, err = filepath.Abs(r.SSHKey)
	if err != nil {
		return r, err
	}
	key, err := publicKey(r.SSHKey)
	if err != nil {
		return r, err
	}
	kind := strings.Fields(key)[0]
	if kind != "ssh-rsa" && kind != "ssh-ed25519" {
		return r, errors.New("cloud SSH keys must be RSA or Ed25519 public keys")
	}
	r.SSHKeyFingerprint = digest(key)
	return r, nil
}

func (s *Service) cloudHTTPJSON(ctx context.Context, endpoint string) (any, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host != "prices.azure.com" || u.User != nil || u.Path != "/api/retail/prices" {
		return nil, errors.New("untrusted cloud pricing endpoint")
	}
	var data []byte
	if s.options.HTTPGet != nil {
		data, err = s.options.HTTPGet(ctx, endpoint)
	} else {
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		req, e := http.NewRequestWithContext(c, http.MethodGet, endpoint, nil)
		if e != nil {
			return nil, e
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("pricing redirects are not accepted") }}
		resp, e := client.Do(req)
		if e != nil {
			return nil, errors.New("Azure retail pricing is unavailable")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Azure retail pricing returned HTTP %d", resp.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 8<<20 {
		return nil, errors.New("cloud price page exceeds 8 MiB")
	}
	var v any
	if json.Unmarshal(data, &v) != nil {
		return nil, errors.New("cloud pricing returned invalid JSON")
	}
	return v, nil
}

func validateCloudQuote(q Quote) error {
	if q.MonthlyUSD <= 0 || math.IsNaN(q.MonthlyUSD) || math.IsInf(q.MonthlyUSD, 0) {
		return errors.New("mandatory fixed cloud costs are not fully priced")
	}
	if q.MemoryMiB < 1024 {
		return errors.New("cloud proxy baseline requires at least 1 GiB RAM")
	}
	var sum float64
	for _, c := range q.Components {
		if c.MonthlyUSD < 0 || math.IsNaN(c.MonthlyUSD) || math.IsInf(c.MonthlyUSD, 0) {
			return errors.New("invalid cloud cost component")
		}
		sum += c.MonthlyUSD
	}
	if len(q.Components) == 0 || math.Abs(sum-q.MonthlyUSD) > 0.011 {
		return errors.New("cloud quote must itemize all required fixed costs")
	}
	return nil
}
func (s *Service) cloudPlanCreate(ctx context.Context, req CreateRequest) (Preview, error) {
	req, err := normalizeCloud(req)
	if err != nil {
		return Preview{}, err
	}
	inv, err := s.store.Load()
	if err != nil {
		return Preview{}, err
	}
	if _, e := inv.Host(req.ID); e == nil {
		return Preview{}, fmt.Errorf("host %q already exists; use vps resume", req.ID)
	}
	adapter := s.cloudAdapter(req.Provider)
	req, q, err := adapter.Resolve(ctx, req)
	if err != nil {
		return Preview{}, err
	}
	if err = validateCloudQuote(q); err != nil {
		return Preview{}, err
	}
	if req.Architecture == "" || req.Architecture == "auto" || req.Plan == "" || req.Image == "" {
		return Preview{}, errors.New("cloud preview did not pin its machine, architecture and image")
	}
	identity, err := adapter.Identity(ctx, req)
	if err != nil {
		return Preview{}, err
	}
	if identity == "" {
		return Preview{}, errors.New("cloud account identity is unavailable")
	}
	p := Preview{Action: "create", ID: req.ID, Request: &req, Quote: &q, AccountID: identity, Warnings: []string{
		"Creates one owned Ubuntu server and its dedicated network/static IPv4 resources; no NAT Gateway, IAM role, trial-credit or Spot fallback.",
		"Monthly USD includes required compute, disk and one public IPv4; usage charges and taxes remain additional.",
		"Machine, region, image, architecture and public-key fingerprint are fixed by this preview. Capacity shortages require a new review.",
		"SSH ingress: " + req.SSHCIDR + "; standard proxy ingress: TCP 80/443 and UDP 443.",
	}}
	p.Warnings = append(p.Warnings, q.Notes...)
	p.Digest = digest(p)
	return p, nil
}
func applyCloudQuote(h *serverstate.Host, q Quote) {
	h.MonthlyUSD = q.MonthlyUSD
	h.Transfer = q.TransferGB
	h.TransferUnit = q.TransferUnit
	h.ComputeMonthlyUSD, h.DiskMonthlyUSD, h.IPv4MonthlyUSD = 0, 0, 0
	for _, c := range q.Components {
		switch c.Name {
		case "compute", "bundle":
			h.ComputeMonthlyUSD += c.MonthlyUSD
		case "disk":
			h.DiskMonthlyUSD += c.MonthlyUSD
		case "ipv4":
			h.IPv4MonthlyUSD += c.MonthlyUSD
		}
	}
	h.BillingBasis = "required fixed monthly USD; 730 hours where hourly; usage and tax additional"
}
func (s *Service) cloudCreate(ctx context.Context, req CreateRequest, expected string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, errors.New("VPS creation is disabled in read-only mode")
	}
	unlock, err := s.lockHost(req.ID)
	if err != nil {
		return serverstate.Host{}, err
	}
	defer unlock()
	p, err := s.cloudPlanCreate(ctx, req)
	if err != nil {
		return serverstate.Host{}, err
	}
	if err = verify(p, expected); err != nil {
		return serverstate.Host{}, err
	}
	req = *p.Request
	var token [12]byte
	if _, err = rand.Read(token[:]); err != nil {
		return serverstate.Host{}, err
	}
	now := s.options.Now().UTC()
	op := operation{Version: 1, ID: "lc-" + hex.EncodeToString(token[:]), Request: req, AccountID: p.AccountID, State: "intent", CreatedAt: now, PrivateData: map[string]json.RawMessage{}, Quote: p.Quote}
	op.Host = serverstate.Host{ID: req.ID, Name: req.Name, Provider: req.Provider, Profile: req.Profile, SubscriptionID: req.SubscriptionID, Architecture: req.Architecture, AvailabilityZone: req.AvailabilityZone, DiskGB: p.Quote.DiskGB, Region: req.Region, Plan: req.Plan, Status: "creating", Owned: true, OperationID: op.ID, CreatedAt: now, UpdatedAt: now, PriceCheckedAt: now}
	applyCloudQuote(&op.Host, *p.Quote)
	if err = s.writeOperation(op); err != nil {
		return op.Host, err
	}
	if err = s.store.Update(func(i *serverstate.Inventory) error {
		if _, e := i.Host(req.ID); e == nil {
			return errors.New("host was concurrently registered")
		}
		return i.UpsertHost(op.Host)
	}); err != nil {
		return op.Host, err
	}
	return s.cloudProvision(ctx, &op, true)
}
func (s *Service) cloudProvision(ctx context.Context, op *operation, allowWrites bool) (serverstate.Host, error) {
	adapter := s.cloudAdapter(op.Request.Provider)
	identity, err := adapter.Identity(ctx, op.Request)
	if err != nil {
		return op.Host, err
	}
	if identity != op.AccountID {
		return op.Host, errors.New("cloud account changed; no mutation performed")
	}
	if allowWrites {
		if _, err = reviewedPublicKey(op.Request); err != nil {
			return op.Host, err
		}
	}
	if err = adapter.Provision(ctx, op, allowWrites); err != nil {
		return op.Host, fmt.Errorf("cloud operation retained for vps resume %s: %w", op.Request.ID, err)
	}
	if err = s.cloudPersist(op); err != nil {
		return op.Host, err
	}
	return op.Host, nil
}
func (s *Service) loadCloudHost(id string, reconciling ...bool) (operation, error) {
	inv, err := s.store.Load()
	if err != nil {
		return operation{}, err
	}
	h, err := inv.Host(id)
	if err != nil {
		return operation{}, err
	}
	if !h.Owned || !isCloudProvider(h.Provider) {
		return operation{}, errors.New("host is not an owned cloud operation")
	}
	op, err := s.readOperation(h.OperationID)
	if err != nil {
		return op, err
	}
	// The journal is durable before the public inventory is updated. A crash
	// between those writes is recoverable only through explicit reconciliation;
	// never accept replacement of a previously recorded public instance ID.
	journalAhead := len(reconciling) > 0 && reconciling[0] && h.ResourceID == "" && op.Host.ResourceID != ""
	if op.Host.ID != h.ID || op.ID != h.OperationID || op.Host.Provider != h.Provider || op.Host.Profile != h.Profile || op.Host.Region != h.Region || (op.Host.ResourceID != h.ResourceID && !journalAhead) || op.Host.Plan != h.Plan || op.Host.DiskGB != h.DiskGB || op.Request.SubscriptionID != h.SubscriptionID || op.Request.Architecture != h.Architecture || op.Request.AvailabilityZone != h.AvailabilityZone {
		return op, errors.New("cloud inventory differs from private ownership; reconcile before changing it")
	}
	return op, nil
}
func (s *Service) cloudVerifyAccount(ctx context.Context, op operation) error {
	account, err := s.cloudAdapter(op.Request.Provider).Identity(ctx, op.Request)
	if err != nil {
		return err
	}
	if account != op.AccountID {
		return errors.New("cloud account differs from this operation")
	}
	return nil
}
func (s *Service) cloudPlanResume(ctx context.Context, id string) (Preview, error) {
	op, err := s.loadCloudHost(id, true)
	if err != nil {
		return Preview{}, err
	}
	if op.State == "deleted" || op.State == "delete-pending" || op.Host.Status == "cleanup-required" {
		return Preview{}, errors.New("operation is being deleted; use vps resume --reconcile-only to synchronize its inventory, then vps delete for remaining cleanup")
	}
	if err = s.cloudVerifyAccount(ctx, op); err != nil {
		return Preview{}, err
	}
	p := Preview{Action: "resume", ID: id, Request: &op.Request, Host: &op.Host, AccountID: op.AccountID, OperationDigest: digest(op), Warnings: []string{"Reconcile submitted resources before continuing. Unknown create outcomes are never blindly repeated."}}
	if op.Host.ResourceID == "" {
		resolved, q, e := s.cloudAdapter(op.Request.Provider).Resolve(ctx, op.Request)
		if e != nil {
			return Preview{}, e
		}
		if resolved != op.Request {
			return Preview{}, errors.New("the saved cloud request can no longer be resolved unchanged; inspect retained resources before creating a new operation")
		}
		if e = validateCloudQuote(q); e != nil {
			return Preview{}, e
		}
		p.Quote = &q
	}
	p.Digest = digest(p)
	return p, nil
}
func (s *Service) cloudResume(ctx context.Context, id string, expected ...string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, errors.New("VPS recovery is disabled in read-only mode")
	}
	unlock, err := s.lockHost(id)
	if err != nil {
		return serverstate.Host{}, err
	}
	defer unlock()
	op, err := s.loadCloudHost(id, true)
	if err != nil {
		return serverstate.Host{}, err
	}
	if op.State == "deleted" || op.State == "delete-pending" || op.Host.Status == "cleanup-required" {
		if len(expected) > 0 {
			return op.Host, errors.New("use vps resume --reconcile-only to synchronize deletion state, then vps delete for remaining cleanup")
		}
		if err = s.cloudVerifyAccount(ctx, op); err != nil {
			return op.Host, err
		}
		if op.State == "deleted" {
			if op.Host.Owned || op.Host.Status != "deleted" {
				return op.Host, errors.New("inconsistent deleted operation receipt")
			}
			for _, r := range op.CloudResources {
				if !r.Deleted {
					return op.Host, errors.New("deleted operation has outstanding resource receipts")
				}
			}
			return op.Host, s.cloudPersist(&op)
		}
		// Only restore already-recorded receipts. Deletion itself remains a
		// separately reviewed action with fresh remote ownership checks.
		err = s.cloudPersist(&op)
		return op.Host, errors.Join(errors.New("inventory synchronized; use vps delete to finish cleanup"), err)
	}
	if len(expected) > 0 {
		p, e := s.cloudPlanResume(ctx, id)
		if e != nil {
			return op.Host, e
		}
		if e = verify(p, expected[0]); e != nil {
			return op.Host, e
		}
		if p.Quote != nil {
			op.Quote = p.Quote
			applyCloudQuote(&op.Host, *p.Quote)
			op.Host.PriceCheckedAt = s.options.Now().UTC()
		}
	}
	return s.cloudProvision(ctx, &op, len(expected) > 0)
}
func (s *Service) cloudStatus(ctx context.Context, id string) (serverstate.Host, error) {
	if !s.options.ReadOnly {
		unlock, err := s.lockHost(id)
		if err != nil {
			return serverstate.Host{}, err
		}
		defer unlock()
	}
	op, err := s.loadCloudHost(id)
	if err != nil {
		return serverstate.Host{}, err
	}
	if err = s.cloudVerifyAccount(ctx, op); err != nil {
		return op.Host, err
	}
	if op.Host.ResourceID == "" {
		return op.Host, nil
	}
	h, err := s.cloudAdapter(op.Request.Provider).Observe(ctx, op)
	if err != nil {
		return op.Host, err
	}
	if h.ID == "" {
		h = mergeRemote(op.Host, h, op.Request.SSHUser)
	}
	// Observation does not rewrite private resource identity or create receipts.
	if !s.options.ReadOnly {
		if err = s.saveHost(h); err != nil {
			return h, err
		}
	}
	return h, nil
}
func (s *Service) cloudPlanAction(ctx context.Context, id, action string) (Preview, error) {
	if action != "start" && action != "stop" && action != "reboot" && action != "delete" {
		return Preview{}, errors.New("unknown VPS action")
	}
	op, err := s.loadCloudHost(id)
	if err != nil {
		return Preview{}, err
	}
	if err = s.cloudVerifyAccount(ctx, op); err != nil {
		return Preview{}, err
	}
	if action == "delete" {
		inv, e := s.store.Load()
		if e != nil {
			return Preview{}, e
		}
		for _, d := range inv.Deployments {
			if d.HostID == id && d.Status != "removed" {
				return Preview{}, fmt.Errorf("remove server deployment %s before deleting its VM", d.ID)
			}
		}
	}
	if action != "delete" && (op.State == "delete-pending" || op.Host.Status == "cleanup-required") {
		return Preview{}, errors.New("finish pending deletion before power operations")
	}
	if err = s.cloudAdapter(op.Request.Provider).ValidateAction(ctx, op, action); err != nil {
		return Preview{}, err
	}
	warnings := []string{"Power actions are separate from proxy services. Disks and public IPv4 can remain billable while stopped."}
	if op.Request.Provider == "aws-lightsail" {
		warnings = append(warnings, "Stopping Lightsail does not stop instance bundle billing.")
	}
	if op.Request.Provider == "azure" && action == "stop" {
		warnings = append(warnings, "Stop deallocates the VM; storage and reserved public IPv4 remain billable.")
	}
	if action == "stop" && op.Quote != nil && op.Quote.StoppedMonthlyUSD != nil {
		warnings = append(warnings, fmt.Sprintf("Estimated retained fixed cost after stopping: $%.2f/month from the saved quote; usage and tax are additional.", *op.Quote.StoppedMonthlyUSD))
	}
	if action == "delete" {
		warnings = []string{"Delete only verified owned resources; preserve foreign attachments and report any retained billable resources."}
	}
	p := Preview{Action: action, ID: id, Host: &op.Host, AccountID: op.AccountID, OperationDigest: digest(op), Warnings: warnings}
	p.Digest = digest(p)
	return p, nil
}
func (s *Service) cloudAction(ctx context.Context, id, action, expected string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, errors.New("VPS cloud changes are disabled in read-only mode")
	}
	unlock, err := s.lockHost(id)
	if err != nil {
		return serverstate.Host{}, err
	}
	defer unlock()
	p, err := s.cloudPlanAction(ctx, id, action)
	if err != nil {
		return serverstate.Host{}, err
	}
	if err = verify(p, expected); err != nil {
		return *p.Host, err
	}
	op, err := s.loadCloudHost(id)
	if err != nil {
		return serverstate.Host{}, err
	}
	if action == "delete" {
		op.State = "delete-pending"
		op.Host.Status = "delete-pending"
		if err = s.cloudPersist(&op); err != nil {
			return op.Host, err
		}
	}
	err = s.cloudAdapter(op.Request.Provider).Action(ctx, &op, action)
	if err != nil {
		if action == "delete" {
			op.Host.Status = "cleanup-required"
		}
		saveErr := s.cloudPersist(&op)
		return op.Host, errors.Join(err, saveErr)
	}
	if action == "delete" {
		op.State = "deleted"
		op.Host.Status = "deleted"
		op.Host.Owned = false
	}
	return op.Host, s.cloudPersist(&op)
}
