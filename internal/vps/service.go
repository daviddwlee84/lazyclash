package vps

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

type Service struct {
	store   serverstate.Store
	options Options
}

func New(store serverstate.Store, opts Options) *Service {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Run == nil {
		opts.Run = runCLI
	}
	return &Service{store: store, options: opts}
}

// Provider output can include passwords and tokens. Only successfully decoded,
// explicitly selected fields may leave this package.
func runCLI(ctx context.Context, executable string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	var stdout boundedOutput
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s exited with status %d (provider output withheld; inspect the provider CLI privately)", executable, ee.ExitCode())
		}
		return nil, fmt.Errorf("cannot execute %s: %w", executable, err)
	}
	return stdout.Bytes(), nil
}

type boundedOutput struct{ buffer bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 8<<20 {
		return 0, fmt.Errorf("provider output exceeds 8 MiB")
	}
	return b.buffer.Write(p)
}
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }

var safeID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func normalize(req CreateRequest) (CreateRequest, error) {
	if !safeID.MatchString(req.ID) {
		return req, fmt.Errorf("host ID must be 1–63 letters, digits, dots, underscores or hyphens, starting with a letter or digit")
	}
	if req.Name == "" {
		req.Name = req.ID
	}
	if !safeID.MatchString(req.Name) {
		return req, fmt.Errorf("cloud name must be 1–63 letters, digits, dots, underscores or hyphens")
	}
	switch req.Provider {
	case "digitalocean", "vultr", "linode", "oracle":
	default:
		return req, fmt.Errorf("provider must be digitalocean, vultr, linode, or oracle; use vps register for existing SSH hosts")
	}
	for _, v := range []string{req.Profile, req.Region, req.Plan, req.Image, req.SSHKey, req.FirewallID, req.TenancyID, req.CompartmentID, req.SubnetID, req.AvailabilityDomain} {
		if strings.ContainsAny(v, "\x00\r\n") || strings.HasPrefix(v, "-") {
			return req, fmt.Errorf("cloud fields must not contain control characters or begin with '-' ")
		}
	}
	if req.Region == "" || req.SSHKey == "" {
		return req, fmt.Errorf("--region and --ssh-key are required")
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
		if req.Provider == "oracle" {
			req.SSHUser = "ubuntu"
		}
	}
	if req.SSHCIDR == "" {
		req.SSHCIDR = "0.0.0.0/0"
	}
	if _, _, err := net.ParseCIDR(req.SSHCIDR); err != nil {
		return req, fmt.Errorf("--ssh-cidr requires an IP CIDR")
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(req.SSHUser) {
		return req, fmt.Errorf("invalid SSH username")
	}
	if req.Plan == "" {
		switch req.Provider {
		case "digitalocean":
			req.Plan = "s-1vcpu-1gb"
		case "vultr":
			req.Plan = "vc2-1c-1gb"
		case "linode":
			req.Plan = "g6-nanode-1"
		case "oracle":
			req.Plan = "VM.Standard.A1.Flex"
		}
	}
	if req.Image == "" {
		switch req.Provider {
		case "digitalocean":
			req.Image = "ubuntu-24-04-x64"
		case "linode":
			req.Image = "linode/ubuntu24.04"
		case "vultr":
			return req, fmt.Errorf("--image requires the Ubuntu 24.04 OS ID from vultr-cli os list")
		case "oracle":
			return req, fmt.Errorf("--image requires an official Ubuntu 24.04 arm64 image OCID")
		}
	}
	if req.Provider == "oracle" {
		req.InitializerVersion = oracleInitializerVersion
		req.InitializerSHA256 = oracleInitializerSHA256()
		if req.Plan != "VM.Standard.A1.Flex" {
			return req, fmt.Errorf("Oracle creation is limited to the Always Free A1 shape")
		}
		if req.TenancyID == "" || req.CompartmentID == "" || req.AvailabilityDomain == "" {
			return req, fmt.Errorf("Oracle requires --tenancy, --compartment and --availability-domain")
		}
	} else {
		req.InitializerVersion = ""
		req.InitializerSHA256 = ""
	}
	if req.Provider == "linode" || req.Provider == "oracle" {
		key, err := publicKey(req.SSHKey)
		if err != nil {
			return req, err
		}
		req.SSHKeyFingerprint = digest(key)
	}
	return req, nil
}

func publicKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read SSH public key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 16384 {
		return "", fmt.Errorf("SSH public key must be a regular file smaller than 16 KiB")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read SSH public key: %w", err)
	}
	s := strings.TrimSpace(string(b))
	p := strings.Fields(s)
	if len(p) < 2 || len(b) > 16384 || strings.ContainsAny(s, "\n\r") || !(strings.HasPrefix(p[0], "ssh-") || strings.HasPrefix(p[0], "ecdsa-")) {
		return "", fmt.Errorf("--ssh-key must name a single SSH public key file, never a private key")
	}
	return s, nil
}

func (s *Service) List() ([]serverstate.Host, error) {
	inv, err := s.store.Load()
	return inv.Hosts, err
}
func (s *Service) Register(host serverstate.Host) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return host, fmt.Errorf("VPS registration is disabled in read-only mode")
	}
	if !safeID.MatchString(host.ID) {
		return host, fmt.Errorf("invalid host ID")
	}
	if host.SSHHost == "" || host.PublicHost == "" {
		return host, fmt.Errorf("SSH management host and public client host are required")
	}
	if strings.HasPrefix(host.SSHHost, "-") || strings.ContainsAny(host.SSHHost, "\x00\r\n\t ") || strings.ContainsAny(host.PublicHost, "\x00\r\n\t /@") {
		return host, fmt.Errorf("invalid management or public host")
	}
	if host.Name == "" {
		host.Name = host.ID
	}
	if host.Provider == "" {
		host.Provider = "ssh"
	}
	host.Owned = false
	host.Status = "registered"
	host.CreatedAt = s.options.Now().UTC()
	host.UpdatedAt = host.CreatedAt
	err := s.store.Update(func(inv *serverstate.Inventory) error {
		if _, e := inv.Host(host.ID); e == nil {
			return fmt.Errorf("host %q is already registered", host.ID)
		}
		return inv.UpsertHost(host)
	})
	return host, err
}

func (s *Service) PlanCreate(ctx context.Context, req CreateRequest) (Preview, error) {
	req, err := normalize(req)
	if err != nil {
		return Preview{}, err
	}
	inv, err := s.store.Load()
	if err != nil {
		return Preview{}, err
	}
	if _, err := inv.Host(req.ID); err == nil {
		return Preview{}, fmt.Errorf("host %q already exists; use vps resume for an incomplete create", req.ID)
	}
	q, err := s.Quote(ctx, req)
	if err != nil {
		return Preview{}, err
	}
	if err = s.validateImage(ctx, req); err != nil {
		return Preview{}, err
	}
	if req.Provider == "oracle" {
		if err := s.oracleFree(ctx, req); err != nil {
			return Preview{}, err
		}
	}
	account, err := s.accountIdentity(ctx, req)
	if err != nil {
		return Preview{}, err
	}
	p := Preview{Action: "create", ID: req.ID, Request: &req, Quote: &q, Warnings: []string{"Cloud CLI credentials are reused; no credentials are copied into lazyclash.", "Powering off a VM generally does not stop billing. Destroy owned cloud resources to release charges.", "Plan pricing excludes taxes, transfer overage and optional resources. Check regional network performance before committing."}}
	p.AccountID = account
	if req.FirewallID == "" {
		p.Warnings = append(p.Warnings, "Create an owned cloud firewall (or Oracle subnet security list) allowing SSH from the reviewed CIDR, TCP 80/443 and UDP 443.")
	} else {
		p.Warnings = append(p.Warnings, "Existing firewall is reused unchanged and never deleted. Its rules must already allow SSH, TCP 80/443 and UDP 443; coverage is not automatically rewritten.")
	}
	if req.Provider == "oracle" {
		if req.SubnetID != "" {
			p.Warnings = append(p.Warnings, "Existing subnet, VCN and gateways remain user-owned.")
		} else {
			p.Warnings = append(p.Warnings, "Create an owned public VCN, Internet gateway, route and subnet; no paid NAT gateway.")
		}
		p.Warnings = append(p.Warnings, "New owned OCI Ubuntu VM only: install the reviewed cloud-init/systemd initializer to allow host INPUT TCP 80/443 and UDP 443 at boot, preserving all existing firewall rules. Initializer: "+req.InitializerVersion+" SHA256 "+req.InitializerSHA256)
	}
	p.Warnings = append(p.Warnings, "SSH ingress CIDR: "+req.SSHCIDR+". Public proxy ports: TCP 80/443 and UDP 443.")
	p.Digest = digest(p)
	return p, nil
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func verify(p Preview, expected string) error {
	if expected == "" || expected != p.Digest {
		return fmt.Errorf("preview changed or --expect is missing; inspect a fresh preview and use its digest")
	}
	return nil
}

func (s *Service) Create(ctx context.Context, req CreateRequest, expected string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, fmt.Errorf("VPS creation is disabled in read-only mode")
	}
	unlock, err := s.lockHost(req.ID)
	if err != nil {
		return serverstate.Host{}, err
	}
	defer unlock()
	p, err := s.PlanCreate(ctx, req)
	if err != nil {
		return serverstate.Host{}, err
	}
	if err = verify(p, expected); err != nil {
		return serverstate.Host{}, err
	}
	req = *p.Request
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		return serverstate.Host{}, err
	}
	op := operation{Version: 1, ID: "lc-" + hex.EncodeToString(random[:]), Request: req, State: "intent", CreatedAt: s.options.Now().UTC()}
	op.AccountID = p.AccountID
	op.Host = serverstate.Host{ID: req.ID, Name: req.Name, Provider: req.Provider, Profile: req.Profile, Region: req.Region, Plan: req.Plan, Status: "creating", Owned: true, OperationID: op.ID, CreatedAt: op.CreatedAt, UpdatedAt: op.CreatedAt}
	op.Host.MonthlyUSD = p.Quote.MonthlyUSD
	op.Host.Transfer = p.Quote.TransferGB
	op.Host.TransferUnit = p.Quote.TransferUnit
	op.Host.PriceCheckedAt = op.CreatedAt
	op.Host.BillingBasis = "monthly base USD; excludes overages and tax"
	if req.Provider == "oracle" {
		op.Host.BillingBasis = "conditional Always Free; conservative allocation and usage checks passed"
	}
	// Persist intent before any provider write. The inventory reservation makes
	// concurrent attempts for the same ID fail without creating two machines.
	if err = s.writeOperation(op); err != nil {
		return op.Host, err
	}
	if err = s.store.Update(func(inv *serverstate.Inventory) error {
		if _, e := inv.Host(req.ID); e == nil {
			return fmt.Errorf("host %q was concurrently registered", req.ID)
		}
		return inv.UpsertHost(op.Host)
	}); err != nil {
		return op.Host, err
	}
	if req.Provider == "oracle" {
		if err = s.prepareOracleNetwork(ctx, &op); err != nil {
			return op.Host, fmt.Errorf("Oracle networking incomplete; run vps resume %s: %w", req.ID, err)
		}
		req = op.Request
	}
	if err = s.prepareFirewall(ctx, &op); err != nil {
		return op.Host, fmt.Errorf("cloud firewall incomplete; preview vps resume %s: %w", req.ID, err)
	}
	req = op.Request
	if err = s.verifyLaunch(ctx, op); err != nil {
		return op.Host, err
	}
	op.State = "submitted"
	if err = s.writeOperation(op); err != nil {
		return op.Host, err
	}
	created, err := s.createRemote(ctx, req, op.ID)
	if err != nil {
		op.State = "uncertain"
		_ = s.writeOperation(op)
		return op.Host, fmt.Errorf("cloud create outcome is unconfirmed (operation %s); run vps resume %s; do not retry creation: %w", op.ID, req.ID, err)
	}
	op.Host = mergeRemote(op.Host, created, req.SSHUser)
	op.State = "created"
	if err = s.writeOperation(op); err != nil {
		return op.Host, fmt.Errorf("VM %s exists but saving operation failed: %w", op.Host.ResourceID, err)
	}
	if err = s.saveHost(op.Host); err != nil {
		return op.Host, fmt.Errorf("VM %s exists; run vps resume %s to repair inventory: %w", op.Host.ResourceID, req.ID, err)
	}
	if err = s.attachFirewall(ctx, &op); err != nil {
		return op.Host, fmt.Errorf("VM exists but firewall attachment needs recovery: %w", err)
	}
	return op.Host, nil
}

func mergeRemote(host, remote serverstate.Host, user string) serverstate.Host {
	host.ResourceID = remote.ResourceID
	host.Status = remote.Status
	if remote.PublicHost != "" {
		host.PublicHost = remote.PublicHost
		host.SSHHost = user + "@" + remote.PublicHost
	}
	found := false
	for _, r := range host.Resources {
		if r.Kind == "instance" && r.ID == host.ResourceID {
			found = true
		}
	}
	if !found {
		host.Resources = append(host.Resources, serverstate.Resource{Kind: "instance", ID: host.ResourceID, Owned: true})
	}
	return host
}
func (s *Service) saveHost(host serverstate.Host) error {
	host.UpdatedAt = s.options.Now().UTC()
	return s.store.Update(func(inv *serverstate.Inventory) error {
		if old, err := inv.Host(host.ID); err == nil && old.PublicHost != "" && host.PublicHost != "" && old.PublicHost != host.PublicHost {
			for i := range inv.Deployments {
				d := &inv.Deployments[i]
				if d.HostID == host.ID && d.Status != "removed" {
					d.Status = "endpoint-changed"
				}
			}
		}
		return inv.UpsertHost(host)
	})
}
func (s *Service) lockHost(id string) (func(), error) {
	if !safeID.MatchString(id) {
		return nil, fmt.Errorf("invalid host ID")
	}
	root, err := s.store.StateRoot()
	if err != nil {
		return nil, err
	}
	return serverstate.Lock(filepath.Join(root, "vps", id+".lock"))
}
func (s *Service) operationPath(id string) (string, error) {
	if !safeID.MatchString(id) {
		return "", fmt.Errorf("invalid operation ID")
	}
	root, err := s.store.StateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "vps", id+".json"), nil
}
func (s *Service) writeOperation(op operation) error {
	path, err := s.operationPath(op.ID)
	if err != nil {
		return err
	}
	op.UpdatedAt = s.options.Now().UTC()
	b, err := json.MarshalIndent(op, "", "  ")
	if err != nil {
		return err
	}
	return serverstate.WritePrivate(path, b)
}
func (s *Service) readOperation(id string) (operation, error) {
	path, err := s.operationPath(id)
	if err != nil {
		return operation{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return operation{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 2<<20 {
		return operation{}, fmt.Errorf("private operation must be a regular owner-only file smaller than 2 MiB")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return operation{}, err
	}
	var op operation
	err = json.Unmarshal(b, &op)
	if err == nil && (op.Version != 1 || op.ID != id) {
		err = fmt.Errorf("unsupported or mismatched private operation record")
	}
	return op, err
}

// Resume only reconciles; an uncertain create is never automatically repeated.
func (s *Service) Resume(ctx context.Context, id string, expected ...string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, fmt.Errorf("VPS recovery is disabled in read-only mode")
	}
	unlock, err := s.lockHost(id)
	if err != nil {
		return serverstate.Host{}, err
	}
	defer unlock()
	inv, err := s.store.Load()
	if err != nil {
		return serverstate.Host{}, err
	}
	host, err := inv.Host(id)
	if err != nil {
		return host, err
	}
	if !host.Owned || host.Status == "deleted" || host.Status == "cleanup-required" || host.Status == "delete-pending" {
		return host, fmt.Errorf("this operation is closed or being deleted; use reviewed vps delete to finish cleanup")
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		return host, err
	}
	account, err := s.accountIdentity(ctx, op.Request)
	if err != nil {
		return host, err
	}
	if account != op.AccountID {
		return host, fmt.Errorf("cloud account differs from the saved create operation")
	}
	if len(expected) > 0 {
		p, e := s.PlanResume(ctx, id)
		if e != nil {
			return host, e
		}
		if e = verify(p, expected[0]); e != nil {
			return host, e
		}
		if p.Quote != nil {
			op.Host.MonthlyUSD = p.Quote.MonthlyUSD
			op.Host.PriceCheckedAt = s.options.Now().UTC()
		}
	}
	if op.PendingResourceKind != "" {
		if strings.HasPrefix(op.PendingResourceKind, "firewall") {
			err = s.resumeFirewall(ctx, &op)
		} else {
			err = s.resumeOracleNetwork(ctx, &op)
		}
		if err != nil {
			return op.Host, err
		}
		host = op.Host
	}
	if op.State == "intent" || op.State == "network" || op.State == "firewall" {
		if len(expected) == 0 {
			return op.Host, s.saveHost(op.Host)
		}
		if err = s.prepareOracleNetwork(ctx, &op); err != nil {
			return op.Host, err
		}
		if err = s.prepareFirewall(ctx, &op); err != nil {
			return op.Host, err
		}
		if err = s.verifyLaunch(ctx, op); err != nil {
			return op.Host, err
		}
		op.State = "submitted"
		if err = s.writeOperation(op); err != nil {
			return op.Host, err
		}
		remote, e := s.createRemote(ctx, op.Request, op.ID)
		if e != nil {
			return op.Host, fmt.Errorf("cloud create outcome is unconfirmed; resume will only reconcile: %w", e)
		}
		op.Host = mergeRemote(op.Host, remote, op.Request.SSHUser)
		op.State = "created"
		if err = s.writeOperation(op); err != nil {
			return op.Host, err
		}
		if err = s.saveHost(op.Host); err != nil {
			return op.Host, err
		}
		if err = s.attachFirewall(ctx, &op); err != nil {
			return op.Host, err
		}
		return op.Host, nil
	}
	if op.Host.ResourceID != "" {
		host = op.Host
		remote, e := s.getRemote(ctx, op.Request, host.ResourceID)
		if e != nil {
			return host, e
		}
		host = mergeRemote(host, remote, op.Request.SSHUser)
	} else {
		remote, e := s.findRemote(ctx, op.Request, op.ID)
		if e != nil {
			return host, e
		}
		host = mergeRemote(host, remote, op.Request.SSHUser)
	}
	op.Host = host
	op.State = "created"
	if err = s.writeOperation(op); err != nil {
		return host, err
	}
	if err = s.saveHost(host); err != nil {
		return host, err
	}
	if len(expected) > 0 {
		if err = s.attachFirewall(ctx, &op); err != nil {
			return op.Host, err
		}
	}
	return op.Host, nil
}

func (s *Service) PlanResume(ctx context.Context, id string) (Preview, error) {
	inv, err := s.store.Load()
	if err != nil {
		return Preview{}, err
	}
	host, err := inv.Host(id)
	if err != nil {
		return Preview{}, err
	}
	if !host.Owned || host.Status == "deleted" || host.Status == "cleanup-required" || host.Status == "delete-pending" {
		return Preview{}, fmt.Errorf("this operation is closed or being deleted; use reviewed vps delete to finish cleanup")
	}
	op, err := s.readOperation(host.OperationID)
	if err != nil {
		return Preview{}, err
	}
	account, err := s.accountIdentity(ctx, op.Request)
	if err != nil {
		return Preview{}, err
	}
	if account != op.AccountID {
		return Preview{}, fmt.Errorf("cloud account differs from the saved create operation")
	}
	p := Preview{Action: "resume", ID: id, Host: &op.Host, Request: &op.Request, Warnings: []string{"Reconcile the saved operation. An already-submitted VM create will never be repeated."}}
	p.AccountID = account
	if op.State == "intent" || op.State == "network" || op.State == "firewall" {
		if op.Request.Provider == "oracle" {
			if err := validateOracleInitializer(op.Request); err != nil {
				return p, err
			}
		}
		q, e := s.Quote(ctx, op.Request)
		if e != nil {
			return p, e
		}
		p.Quote = &q
		if op.Request.Provider == "oracle" {
			if e = s.oracleFree(ctx, op.Request); e != nil {
				return p, e
			}
		}
		p.Warnings = append(p.Warnings, "After resolving all pending network writes, finish the reviewed network and submit the original VM create once.")
	}
	p.Digest = digest(p)
	return p, nil
}

func (s *Service) Status(ctx context.Context, id string) (serverstate.Host, error) {
	if !s.options.ReadOnly {
		unlock, err := s.lockHost(id)
		if err != nil {
			return serverstate.Host{}, err
		}
		defer unlock()
	}
	inv, err := s.store.Load()
	if err != nil {
		return serverstate.Host{}, err
	}
	host, err := inv.Host(id)
	if err != nil {
		return host, err
	}
	if host.ResourceID == "" {
		return host, nil
	}
	if host.Owned {
		if _, err = s.verifyOwned(ctx, host); err != nil {
			return host, err
		}
	}
	if host.Status == "delete-pending" || host.Status == "cleanup-required" {
		op, e := s.readOperation(host.OperationID)
		if e != nil {
			return host, e
		}
		remote, e := s.lookupRemote(ctx, op.Request, op.ID, host.ResourceID)
		if e != nil {
			return host, e
		}
		if remote == nil {
			host.Status = "cleanup-required"
		}
		if s.options.ReadOnly {
			return host, nil
		}
		return host, s.saveHost(host)
	}
	req := CreateRequest{Provider: host.Provider, Profile: host.Profile, Region: host.Region}
	remote, err := s.getRemote(ctx, req, host.ResourceID)
	if err != nil {
		return host, err
	}
	user := "root"
	if at := strings.IndexByte(host.SSHHost, '@'); at > 0 {
		user = host.SSHHost[:at]
	}
	host = mergeRemote(host, remote, user)
	if s.options.ReadOnly {
		return host, nil
	}
	return host, s.saveHost(host)
}

func (s *Service) PlanAction(ctx context.Context, id, action string) (Preview, error) {
	switch action {
	case "start", "stop", "reboot", "delete":
	default:
		return Preview{}, fmt.Errorf("unknown VPS action %q", action)
	}
	inv, err := s.store.Load()
	if err != nil {
		return Preview{}, err
	}
	host, err := inv.Host(id)
	if err != nil {
		return Preview{}, err
	}
	ownedResource := hasOracleNetwork(host)
	for _, r := range host.Resources {
		if r.Owned && (r.Kind == "firewall" || r.Kind == "cloud-tag") {
			ownedResource = true
		}
	}
	if !host.Owned || (host.ResourceID == "" && !(action == "delete" && ownedResource)) {
		return Preview{}, fmt.Errorf("host %q is not a cloud VM owned by lazyclash; manage the provider directly", id)
	}
	if action == "delete" {
		for _, d := range inv.Deployments {
			if d.HostID == id && d.Status != "removed" {
				return Preview{}, fmt.Errorf("host has deployment %q; remove the server deployment before deleting its VM", d.ID)
			}
		}
	}
	op, err := s.verifyOwned(ctx, host)
	if err != nil {
		return Preview{}, err
	}
	if action == "delete" && (op.PendingResourceKind != "" || (host.ResourceID == "" && (op.State == "submitted" || op.State == "uncertain"))) {
		return Preview{}, fmt.Errorf("resource creation is unconfirmed; run vps resume %s --reconcile-only before reviewing deletion", id)
	}
	if host.Status == "delete-pending" || host.Status == "cleanup-required" {
		if action != "delete" {
			return Preview{}, fmt.Errorf("VM deletion is pending; finish reviewed vps delete before other lifecycle actions")
		}
		if host.ResourceID != "" {
			remote, e := s.lookupRemote(ctx, op.Request, op.ID, host.ResourceID)
			if e != nil {
				return Preview{}, e
			}
			if remote == nil {
				host.Status = "cleanup-required"
			} else {
				host.Status = "delete-pending"
			}
		}
	}
	p := Preview{Action: action, ID: id, Host: &host, Warnings: []string{"VM power operations are separate from proxy service operations. Powered-off VMs can still incur charges."}}
	p.AccountID = op.AccountID
	if action == "delete" {
		p.Warnings = []string{"Permanently destroys the owned VM and its provider-managed boot disk. Shared firewalls, networks, keys and pre-existing resources are preserved."}
	}
	p.Digest = digest(p)
	return p, nil
}

func (s *Service) Action(ctx context.Context, id, action, expected string) (serverstate.Host, error) {
	if s.options.ReadOnly {
		return serverstate.Host{}, fmt.Errorf("VPS cloud changes are disabled in read-only mode")
	}
	unlock, err := s.lockHost(id)
	if err != nil {
		return serverstate.Host{}, err
	}
	defer unlock()
	p, err := s.PlanAction(ctx, id, action)
	if err != nil {
		return serverstate.Host{}, err
	}
	if err = verify(p, expected); err != nil {
		return *p.Host, err
	}
	host := *p.Host
	if action == "delete" && host.Status != "cleanup-required" {
		op, e := s.readOperation(host.OperationID)
		if e != nil {
			return host, e
		}
		op.State = "delete-submitted"
		host.Status = "delete-pending"
		op.Host = host
		if e = s.writeOperation(op); e != nil {
			return host, e
		}
		if e = s.saveHost(host); e != nil {
			return host, e
		}
	}
	if host.ResourceID != "" && !(action == "delete" && host.Status == "cleanup-required") {
		if err = s.actionRemote(ctx, host, action); err != nil {
			return host, fmt.Errorf("%s outcome is unconfirmed; inspect vps status before retrying: %w", action, err)
		}
	}
	if action == "delete" {
		host.Status = "cleanup-required"
		if err = s.saveHost(host); err != nil {
			return host, err
		}
		cleanupErr := s.cleanupFirewall(ctx, host)
		if latest, e := s.store.Load(); e == nil {
			if saved, e := latest.Host(id); e == nil {
				host = saved
			}
		}
		if cleanupErr != nil {
			host.Status = "cleanup-required"
			_ = s.saveHost(host)
			return host, cleanupErr
		}
		if host.Provider == "oracle" {
			if err = s.cleanupOracleNetwork(ctx, host); err != nil {
				host.Status = "cleanup-required"
				_ = s.saveHost(host)
				return host, err
			}
		}
		host.Status = "deleted"
		host.Owned = false
		op, e := s.readOperation(host.OperationID)
		if e != nil {
			return host, e
		}
		op.State = "deleted"
		op.Host = host
		if e = s.writeOperation(op); e != nil {
			return host, e
		}
	} else {
		host.Status = action + "-requested"
	}
	return host, s.saveHost(host)
}
