package tailnet

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

//go:embed host.py
var hostScript string

type snapshot struct {
	Self       Peer              `json:"self"`
	Peers      []Peer            `json:"peers"`
	Prefs      prefs             `json:"prefs"`
	Forwarding map[string]string `json:"forwarding"`
	OS         string            `json:"os"`
	Core       map[string]any    `json:"core"`
}
type prefs struct {
	ExitNode  string `json:"exit_node"`
	AllowLAN  bool   `json:"allow_lan"`
	Advertise bool   `json:"advertise"`
}
type receipt struct {
	OwnerToken string    `json:"owner_token"`
	PeerID     string    `json:"peer_id"`
	SSHHost    string    `json:"ssh_host"`
	Status     string    `json:"status"`
	Guard      string    `json:"guard,omitempty"`
	AckToken   string    `json:"ack_token,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}
type response struct {
	Error      string    `json:"error"`
	Status     string    `json:"status"`
	Message    string    `json:"message"`
	Guard      string    `json:"guard"`
	AckToken   string    `json:"ack_token"`
	IP         string    `json:"ip"`
	NodeID     string    `json:"node_id"`
	PeerID     string    `json:"peer_id"`
	TUNPaused  bool      `json:"tun_paused"`
	VerifiedAt time.Time `json:"verified_at"`
}

func fullScript() string {
	defs, _, ok := strings.Cut(hostScript, "\n# TAILNET_ENTRYPOINT\n")
	if !ok {
		panic("tailnet helper entrypoint missing")
	}
	worker := defs + "\nworker(sys.argv[1])\n"
	return "WORKER_SOURCE=" + strconv.Quote(worker) + "\n" + hostScript
}
func (s Service) now() time.Time {
	if s.Options.Now != nil {
		return s.Options.Now().UTC()
	}
	return time.Now().UTC()
}
func (s Service) call(ctx context.Context, host string, privileged bool, request any, result any) error {
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	var out []byte
	if s.Options.Execute != nil {
		out, err = s.Options.Execute(ctx, host, privileged, b)
	} else {
		out, err = ExecuteHelper(ctx, host, fullScript(), b, privileged, s.Options.Foreground)
	}
	if err != nil {
		return err
	}
	var check response
	if json.Unmarshal(out, &check) != nil {
		return errors.New("tailnet host returned an invalid response")
	}
	if check.Error != "" {
		return fmt.Errorf("tailnet: %s", check.Error)
	}
	if result != nil {
		return json.Unmarshal(out, result)
	}
	return nil
}
func (s Service) inspect(ctx context.Context, host string, r Request) (snapshot, error) {
	request := map[string]any{"op": "inspect"}
	if host == "" && r.Controller != "" {
		request["controller"] = r.Controller
		request["secret"] = r.ControllerSecret
	}
	var result snapshot
	err := s.call(ctx, host, false, request, &result)
	return result, err
}
func (s Service) Peers(ctx context.Context) ([]Peer, error) {
	state, err := s.inspect(ctx, "", Request{})
	return state.Peers, err
}
func (s Service) resolved(ctx context.Context, r Request) (Request, error) {
	if r.LocalTarget != nil {
		secret, err := connection.LocalControllerCredentials(ctx, *r.LocalTarget)
		if err != nil {
			return r, err
		}
		r.Controller = r.LocalTarget.Controller
		r.ControllerSecret = secret
	}
	if r.ProbeProxy != "" {
		u, err := url.Parse(r.ProbeProxy)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return r, errors.New("probe proxy must be a credential-free loopback endpoint")
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return r, errors.New("probe proxy must use HTTP, HTTPS or SOCKS5")
		}
		address, e := netip.ParseAddr(u.Hostname())
		if u.Hostname() != "localhost" && (e != nil || !address.IsLoopback()) {
			return r, errors.New("probe proxy must be a credential-free loopback endpoint")
		}
		if u.Port() == "" {
			return r, errors.New("probe proxy requires an explicit port")
		}
	}
	return r, nil
}
func (s Service) nodeFor(ctx context.Context, id, host string) (serverstate.TailnetNode, Peer, snapshot, error) {
	if err := serverstate.ValidateID(id); err != nil {
		return serverstate.TailnetNode{}, Peer{}, snapshot{}, err
	}
	inv, err := s.Store.Load()
	if err != nil {
		return serverstate.TailnetNode{}, Peer{}, snapshot{}, err
	}
	node, foundErr := inv.TailnetNode(id)
	if host == "" {
		if foundErr != nil {
			return node, Peer{}, snapshot{}, foundErr
		}
		host = node.SSHHost
	} else if foundErr == nil && node.SSHHost != host {
		return node, Peer{}, snapshot{}, errors.New("registered SSH host differs; remove the registration before rebinding its identity")
	}
	remote, err := s.inspect(ctx, host, Request{})
	if err != nil {
		return node, Peer{}, snapshot{}, err
	}
	local, err := s.inspect(ctx, "", Request{})
	if err != nil {
		return node, Peer{}, snapshot{}, err
	}
	var match Peer
	for _, p := range local.Peers {
		if p.ID == remote.Self.ID {
			match = p
			break
		}
	}
	if match.ID == "" || match.ID == local.Self.ID {
		return node, Peer{}, snapshot{}, errors.New("SSH host identity does not match an existing peer in the local tailnet")
	}
	if foundErr == nil && node.PeerID != match.ID {
		return node, Peer{}, snapshot{}, errors.New("Tailscale peer identity changed; registration cannot be silently rebound")
	}
	if foundErr != nil {
		node = serverstate.TailnetNode{ID: id, PeerID: match.ID, SSHHost: host, CreatedAt: s.now()}
	}
	node.Hostname = match.Hostname
	node.IPs = append([]string(nil), match.IPs...)
	node.OS = match.OS
	node.UpdatedAt = s.now()
	return node, match, remote, nil
}

// Register explicitly remembers an existing SSH host after checking its stable
// peer identity against the local tailnet. Preview never calls this mutator.
func (s Service) Register(ctx context.Context, id, host string) (serverstate.TailnetNode, error) {
	if s.Options.ReadOnly {
		return serverstate.TailnetNode{}, errors.New("read-only mode forbids tailnet registration")
	}
	n, _, _, err := s.nodeFor(ctx, id, host)
	if err != nil {
		return n, err
	}
	err = s.Store.Update(func(i *serverstate.Inventory) error {
		if old, e := i.TailnetNode(n.ID); e == nil {
			if old.PeerID != n.PeerID || old.SSHHost != n.SSHHost {
				return errors.New("tailnet registration identity changed during discovery")
			}
			n.CreatedAt = old.CreatedAt
			n.ExitManaged = old.ExitManaged
			n.ExitStatus = old.ExitStatus
			n.VerifiedAt = old.VerifiedAt
		}
		return i.UpsertTailnetNode(n)
	})
	return n, err
}
func (s Service) scope() (string, error) {
	root, err := s.Store.StateRoot()
	if err != nil {
		return "", err
	}
	return digestBytes([]byte(root))[:24], nil
}
func (s Service) receiptPath(id string) (string, error) {
	dir, err := s.Store.PrivateDir("tailnet-exit", id)
	return filepath.Join(dir, "receipt.json"), err
}
func (s Service) readReceipt(id string) (receipt, error) {
	path, err := s.receiptPath(id)
	if err != nil {
		return receipt{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return receipt{}, err
	}
	var r receipt
	if json.Unmarshal(b, &r) != nil {
		return r, errors.New("invalid private exit receipt")
	}
	return r, nil
}
func (s Service) saveReceipt(id string, r receipt) error {
	p, err := s.receiptPath(id)
	if err != nil {
		return err
	}
	r.UpdatedAt = s.now()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return serverstate.WritePrivate(p, b)
}
func (s Service) Preview(ctx context.Context, r Request) (Plan, error) {
	var err error
	r, err = s.resolved(ctx, r)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{Request: r, Changes: []string{}, Warnings: []string{}, Blockers: []string{}}
	switch r.Action {
	case "register", "setup", "enable", "disable", "remove", "use", "release":
	default:
		return p, errors.New("unknown exit action")
	}
	if r.Action == "release" {
		state, e := s.inspect(ctx, "", Request{})
		if e != nil {
			return p, e
		}
		p.snapshot = state
		p.Changes = append(p.Changes, "Restore the saved exit preference and runtime TUN only if their expected values and core process still match")
	} else {
		node, peer, remote, e := s.nodeFor(ctx, r.ID, r.SSHHost)
		if e != nil {
			return p, e
		}
		p.Peer = peer
		p.Request.SSHHost = node.SSHHost
		if !peer.Online {
			p.Blockers = append(p.Blockers, "Tailscale peer is offline")
		}
		if r.Action == "register" {
			p.snapshot = remote
			p.Changes = append(p.Changes, "Register the verified existing Tailscale peer and SSH host without changing its settings")
		} else if r.Action == "use" {
			if !peer.ExitAvailable {
				p.Blockers = append(p.Blockers, "Exit is not selectable: advertise it, approve it in the Tailscale admin console, and grant exit-node access")
			}
			p.snapshot, err = s.inspect(ctx, "", r)
			if err != nil {
				return p, err
			}
			device, _ := p.snapshot.Core["device"].(string)
			enabled, _ := p.snapshot.Core["enabled"].(bool)
			blocked, err := s.networkConflicts(ctx, device, enabled)
			if err != nil {
				return p, err
			}
			p.Blockers = append(p.Blockers, blocked...)
			p.Changes = append(p.Changes, "Select this peer as the system exit; keep DNS and application proxy preferences unchanged")
			if enabled {
				p.Changes = append(p.Changes, "Pause the confirmed local Mihomo TUN at runtime before selecting the exit")
			}
			p.Warnings = append(p.Warnings, "Runtime TUN handoff can become stale after Mihomo or its owning app restarts; inspect status before reusing it", "No automatic direct fallback is performed when the exit becomes unavailable", "Egress comparison verifies IPv4; IPv6 reachability is not independently verified")
		} else {
			p.snapshot = remote
			p.NeedsPrivilege = true
			if remote.OS != "linux" {
				p.Blockers = append(p.Blockers, "Managed exit setup supports Linux hosts")
			}
			saved, e := s.readReceipt(r.ID)
			if e == nil && (saved.PeerID != peer.ID || saved.SSHHost != node.SSHHost) {
				p.Blockers = append(p.Blockers, "Private ownership receipt does not match this peer")
			}
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return p, e
			}
			if r.Action != "setup" && e != nil {
				p.Blockers = append(p.Blockers, "No private owned exit setup receipt exists; run setup first")
			}
			if r.Action == "setup" && remote.Prefs.Advertise && e != nil {
				p.Blockers = append(p.Blockers, "Peer already advertises an unmanaged exit; existing ownership cannot be adopted implicitly")
			}
			if r.Action == "enable" && e == nil && saved.Status == "removed" {
				p.Blockers = append(p.Blockers, "Exit setup was removed; run setup before enabling it")
			}
			if r.Action == "enable" && (remote.Forwarding["ipv4"] != "1" || remote.Forwarding["ipv6"] != "1") {
				p.Blockers = append(p.Blockers, "IP forwarding is disabled; run setup to restore it")
			}
			p.Changes = append(p.Changes, map[string]string{"setup": "Create an owned persistent Linux forwarding file and advertise an exit node", "enable": "Enable the owned exit-node advertisement", "disable": "Disable only the owned exit-node advertisement", "remove": "Disable the owned advertisement and remove its persistent forwarding file; retain current shared kernel forwarding"}[r.Action])
			if r.Action == "setup" || r.Action == "enable" {
				p.Warnings = append(p.Warnings, "Tailscale administrator approval or an existing auto-approver is required before clients can select the exit")
			}
		}
	}
	// Transient peer connectivity and timestamps are excluded; actual preference,
	// forwarding, core identity and runtime config changes invalidate this plan.
	material := struct {
		Request    Request
		PeerID     string
		Snapshot   snapshot
		SecretHash string
	}{p.Request, p.Peer.ID, p.snapshot, digestBytes([]byte(r.ControllerSecret))}
	material.Snapshot.Peers = nil
	material.Snapshot.Self.Connection = ""
	material.Snapshot.Self.Online = false
	b, _ := json.Marshal(material)
	p.Digest = digestBytes(b)
	return p, nil
}
func (s Service) networkConflicts(ctx context.Context, device string, enabled bool) ([]string, error) {
	if s.Options.NetworkCheck != nil {
		return s.Options.NetworkCheck(ctx, device, enabled, "")
	}
	report, err := networkcheck.Inspect(ctx, "")
	if err != nil {
		return nil, err
	}
	report = networkcheck.WithCoreTUNDevice(report, enabled, device)
	var blockers []string
	tsInterfaces := map[string]bool{}
	for _, iface := range report.Interfaces {
		for _, raw := range iface.Addresses {
			addr, err := netip.ParseAddr(strings.Split(raw, "/")[0])
			if err == nil && (netip.MustParsePrefix("100.64.0.0/10").Contains(addr) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(addr)) {
				tsInterfaces[iface.Name] = true
			}
		}
	}
	for _, capability := range report.Capabilities {
		if !capability.Available && (strings.HasPrefix(capability.Name, "routes-") || capability.Name == "platform") {
			blockers = append(blockers, "Cannot verify competing VPN routes: "+capability.Name)
		}
	}
	for _, f := range report.Conflicts {
		if f.Code == "vpn-default-route" {
			own := enabled && device != "" && len(f.Evidence) > 0 && f.Evidence[0] == device
			ts := len(f.Evidence) > 0 && (strings.Contains(strings.ToLower(f.Evidence[0]), "tailscale") || tsInterfaces[f.Evidence[0]])
			if !own && !ts {
				blockers = append(blockers, "Another VPN owns broad/default routes: "+strings.Join(f.Evidence, ", "))
			}
		}
	}
	return blockers, nil
}
func (s Service) Apply(ctx context.Context, plan Plan, expected string) (Result, error) {
	if s.Options.ReadOnly {
		return Result{}, errors.New("read-only mode forbids exit-node mutations")
	}
	if expected == "" || expected != plan.Digest {
		return Result{}, errors.New("reviewed exit preview digest is required")
	}
	root, err := s.Store.StateRoot()
	if err != nil {
		return Result{}, err
	}
	unlock, err := serverstate.Lock(filepath.Join(root, "tailnet-exit-operation.lock"))
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	fresh, err := s.Preview(ctx, plan.Request)
	if err != nil {
		return Result{}, err
	}
	if fresh.Digest != expected {
		return Result{}, errors.New("exit plan changed since preview; review a fresh preview")
	}
	if len(fresh.Blockers) > 0 {
		return Result{}, errors.New(strings.Join(fresh.Blockers, "; "))
	}
	plan = fresh
	scope, err := s.scope()
	if err != nil {
		return Result{}, err
	}
	r := plan.Request
	request := map[string]any{"op": "apply", "action": r.Action, "scope": scope, "id": r.ID, "peer_id": plan.Peer.ID, "expected": plan.snapshot, "self_id": plan.snapshot.Self.ID}
	if r.Action == "release" {
		request["id"] = "selection"
		var out response
		err = s.call(ctx, "", false, request, &out)
		result := Result{Status: out.Status, Message: out.Message}
		if out.Status == "released_tun_preserved" {
			result.Warnings = []string{out.Message}
		}
		return result, err
	}
	if r.Action == "register" {
		node, err := s.Register(ctx, r.ID, r.SSHHost)
		return Result{ID: node.ID, Status: "registered", Peer: plan.Peer, Message: "Existing peer identity and SSH host registered"}, err
	}
	local := r.Action == "use"
	host := r.SSHHost
	var saved receipt
	result := Result{ID: r.ID, Peer: plan.Peer, Warnings: plan.Warnings}
	if local {
		host = ""
		request["id"] = "selection"
		request["node_id"] = r.ID
		request["allow_lan"] = r.AllowLAN
		request["controller"] = r.Controller
		request["secret"] = r.ControllerSecret
		ip := ""
		for _, value := range plan.Peer.IPs {
			a, e := netip.ParseAddr(value)
			if e == nil && a.Is4() {
				ip = value
				break
			}
		}
		if ip == "" {
			return result, errors.New("peer has no Tailscale IPv4 address")
		}
		request["exit_ip"] = ip
		remoteIP, e := s.probe(ctx, r.SSHHost, "")
		if e != nil {
			return result, fmt.Errorf("exit host has no verified direct OS egress: %w", e)
		}
		result.DirectIP = remoteIP
	} else {
		if r.Action == "setup" || r.Action == "enable" {
			if _, e := s.probe(ctx, r.SSHHost, ""); e != nil {
				return result, fmt.Errorf("exit host has no verified direct OS egress: %w", e)
			}
		}
		saved, err = s.readReceipt(r.ID)
		if errors.Is(err, os.ErrNotExist) {
			bytes := make([]byte, 32)
			if _, err = rand.Read(bytes); err != nil {
				return result, err
			}
			saved = receipt{OwnerToken: hex.EncodeToString(bytes), PeerID: plan.Peer.ID, SSHHost: r.SSHHost, Status: "prepared"}
		} else if err != nil {
			return result, err
		}
		request["owner_token"] = saved.OwnerToken
		if err = s.saveReceipt(r.ID, saved); err != nil {
			return result, err
		}
	}
	var applied response
	if err = s.call(ctx, host, !local, request, &applied); err != nil {
		result.NeedsPrivilege = isAuthorization(err)
		return result, err
	}
	if applied.Status != "verification_pending" {
		return result, errors.New("exit mutation returned no armed verification receipt")
	}
	if !local {
		saved.Status = applied.Status
		saved.Guard = applied.Guard
		saved.AckToken = applied.AckToken
		if err = s.saveReceipt(r.ID, saved); err != nil {
			return result, err
		}
	}
	freshSSH := s.Options.FreshManagement
	if freshSSH == nil {
		freshSSH = connection.VerifyFreshSSH
	}
	if err = freshSSH(ctx, r.SSHHost); err != nil {
		return result, fmt.Errorf("fresh SSH failed; detached rollback remains armed: %w", err)
	}
	directIP := ""
	if r.Action != "disable" && r.Action != "remove" {
		directIP, err = s.probe(ctx, host, "")
	}
	if err != nil {
		return result, fmt.Errorf("HTTPS/DNS egress verification failed; detached rollback remains armed: %w", err)
	}
	if local && directIP != result.DirectIP {
		return result, errors.New("local HTTPS egress differs from the selected exit host; detached rollback remains armed")
	}
	result.DirectIP = directIP
	if local && r.ProbeProxy != "" {
		result.ProxyIP, err = s.probe(ctx, "", r.ProbeProxy)
		if err != nil {
			return result, fmt.Errorf("existing local proxy egress failed; detached rollback remains armed: %w", err)
		}
		if result.ProxyIP != directIP {
			return result, errors.New("existing proxy uses a different egress from the selected exit; detached rollback remains armed")
		}
	}
	ack := map[string]any{"op": "ack", "scope": scope, "id": r.ID, "guard": applied.Guard, "ack_token": applied.AckToken, "remote": !local}
	if local {
		ack["id"] = "selection"
	}
	var acknowledged response
	if err = s.call(ctx, host, false, ack, &acknowledged); err != nil {
		return result, err
	}
	if acknowledged.Status != "acknowledged" {
		return result, fmt.Errorf("exit verification acknowledgement was not completed (%s)", acknowledged.Status)
	}
	result.VerifiedAt = s.now()
	result.Status = "enabled"
	result.Message = "Fresh SSH, HTTPS egress and DNS resolution verified"
	if local {
		result.Status = "selected"
		result.Selected = true
		result.TUNPaused, _ = plan.snapshot.Core["enabled"].(bool)
		return result, nil
	}
	switch r.Action {
	case "disable":
		result.Status = "disabled"
		result.Message = "Fresh SSH verified; owned exit advertisement disabled"
	case "remove":
		result.Status = "removed"
		result.Message = "Fresh SSH verified; owned advertisement and persistent forwarding file removed; shared kernel forwarding retained"
	default:
		result.Status = "approval_pending"
		result.Message = "Exit advertised and host egress verified; client approval availability requires inspection"
		peers, e := s.Peers(ctx)
		if e == nil {
			for _, p := range peers {
				if p.ID == plan.Peer.ID {
					result.Peer = p
					if p.ExitAvailable {
						result.Status = "enabled"
						result.Message = "Exit is selectable; fresh SSH, IPv4 HTTPS egress and DNS resolution verified"
					}
					if !p.ExitAvailable {
						result.Status = "approval_pending"
						result.Message = "Exit advertised and host egress verified; approve this exit in https://login.tailscale.com/admin/machines and grant access before selecting it"
					}
				}
			}
		}
	}
	saved.Status = result.Status
	if err = s.saveReceipt(r.ID, saved); err != nil {
		return result, err
	}
	node := serverstate.TailnetNode{ID: r.ID, PeerID: plan.Peer.ID, SSHHost: r.SSHHost, Hostname: plan.Peer.Hostname, IPs: plan.Peer.IPs, OS: plan.Peer.OS, ExitManaged: r.Action != "remove", ExitStatus: result.Status, CreatedAt: s.now(), UpdatedAt: s.now(), VerifiedAt: result.VerifiedAt}
	err = s.Store.Update(func(i *serverstate.Inventory) error {
		if old, e := i.TailnetNode(r.ID); e == nil {
			node.CreatedAt = old.CreatedAt
		}
		return i.UpsertTailnetNode(node)
	})
	return result, err
}
func isAuthorization(err error) bool { var e *AuthorizationRequiredError; return errors.As(err, &e) }
func (s Service) probe(ctx context.Context, host, proxy string) (string, error) {
	var r response
	err := s.call(ctx, host, false, map[string]any{"op": "probe", "probe_proxy": proxy}, &r)
	return r.IP, err
}
func (s Service) Status(ctx context.Context, id string) (Result, error) {
	scope, err := s.scope()
	if err != nil {
		return Result{}, err
	}
	var selected response
	if err = s.call(ctx, "", false, map[string]any{"op": "selection_status", "scope": scope, "id": "selection"}, &selected); err != nil {
		return Result{}, err
	}
	if id == "" && selected.NodeID != "" {
		id = selected.NodeID
	}
	if id == "" {
		return Result{Status: selected.Status, Message: selected.Message, TUNPaused: selected.TUNPaused}, nil
	}
	inv, err := s.Store.Load()
	if err != nil {
		return Result{}, err
	}
	node, err := inv.TailnetNode(id)
	if err != nil {
		return Result{}, err
	}
	peers, err := s.Peers(ctx)
	if err != nil {
		return Result{}, err
	}
	result := Result{ID: id, Status: node.ExitStatus, VerifiedAt: node.VerifiedAt}
	for _, p := range peers {
		if p.ID == node.PeerID {
			result.Peer = p
			result.Selected = p.Selected
			break
		}
	}
	switch {
	case result.Peer.ID == "":
		result.Status = "peer_missing"
	case !result.Peer.Online:
		result.Status = "offline"
	default:
		remoteCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		remote, e := s.inspect(remoteCtx, node.SSHHost, Request{})
		cancel()
		if e != nil {
			result.Status = "inspection_failed"
			result.Message = "Could not verify current SSH host advertisement and forwarding"
		} else if remote.Self.ID != node.PeerID {
			result.Status = "identity_changed"
		} else if !node.ExitManaged {
			result.Status = "registered"
		} else if !remote.Prefs.Advertise {
			result.Status = "disabled"
		} else if remote.Forwarding["ipv4"] != "1" || remote.Forwarding["ipv6"] != "1" {
			result.Status = "forwarding_disabled"
		} else if result.Peer.ExitAvailable {
			result.Status = "available"
		} else {
			result.Status = "approval_pending"
		}
	}
	if selected.NodeID == id && selected.Status != "restored" && selected.Status != "released_tun_preserved" {
		result.TUNPaused = selected.TUNPaused
		if !selected.VerifiedAt.IsZero() {
			result.VerifiedAt = selected.VerifiedAt
		}
		// A saved successful selection is not current online/reachability evidence.
		if result.Status != "offline" && result.Status != "peer_missing" && result.Status != "identity_changed" && result.Status != "inspection_failed" && result.Status != "forwarding_disabled" {
			if selected.Status != "acknowledged" {
				result.Status = selected.Status
			} else if result.Selected {
				result.Status = "selected"
			}
		}
		if selected.Message != "" {
			result.Message = selected.Message
		}
	}
	result.Warnings = []string{"Runtime TUN pause is not persistent across core/app restart; use status to detect stale handoff"}
	return result, nil
}
