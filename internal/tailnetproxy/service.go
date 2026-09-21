package tailnetproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverprobe"
	"go.yaml.in/yaml/v3"
)

func mergeRequest(r Request, previous Request) Request {
	if r.NodeID == "" {
		r.NodeID = previous.NodeID
	}
	if r.Name == "" {
		r.Name = previous.Name
	}
	if r.Mode == "" {
		r.Mode = previous.Mode
	}
	if r.Backend == "" {
		r.Backend = previous.Backend
	}
	if r.Port == 0 {
		r.Port = previous.Port
	}
	if r.LocalPort == 0 {
		r.LocalPort = previous.LocalPort
	}
	if r.ControllerPort == 0 {
		r.ControllerPort = previous.ControllerPort
	}
	if r.Egress == "" {
		r.Egress = previous.Egress
		if r.Upstream == "" {
			r.Upstream = previous.Upstream
		}
	} else if r.Egress == previous.Egress && r.Upstream == "" {
		r.Upstream = previous.Upstream
	}
	if r.Egress == "direct" {
		r.Upstream = ""
	}
	if !r.UDPSet && !r.UDP {
		r.UDP = previous.UDP
	}
	return r
}
func planDigest(p Plan, upstream string) string {
	p.Digest = ""
	data, _ := json.Marshal(struct {
		Plan     Plan
		Upstream string
	}{p, upstream})
	return hash(data)
}
func (s Service) Preview(ctx context.Context, r Request) (Plan, error) {
	i, err := s.Options.Store.Load()
	if err != nil {
		return Plan{}, err
	}
	old, loadErr := s.load(r.ID)
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return Plan{}, loadErr
	}
	existing := loadErr == nil
	if existing {
		if old.Phase == "removed" {
			return Plan{}, errors.New("removed proxy ID cannot be reused; choose a new ID")
		}
		r = mergeRequest(r, old.Request)
	}
	node, err := i.TailnetNode(r.NodeID)
	if err != nil {
		return Plan{}, err
	}
	r, err = normalize(r, node)
	if err != nil {
		return Plan{}, err
	}
	ip, err := tailnetIP(node.IPs)
	if err != nil {
		return Plan{}, err
	}
	j := journal{Request: r, PeerID: node.PeerID, SSHHost: node.SSHHost, ListenIP: ip, CoreID: coreID(r.ID), Username: "gateway", Password: "__LAZYCLASH_GENERATED_PROXY_PASSWORD__"}
	if existing {
		if old.PeerID != node.PeerID || old.SSHHost != node.SSHHost || old.ListenIP != ip {
			return Plan{}, errors.New("registered peer identity or address changed; review a new proxy deployment")
		}
		a, b := old.Request, r
		if a.NodeID != b.NodeID || a.Mode != b.Mode || a.Backend != b.Backend || a.Port != b.Port || a.LocalPort != b.LocalPort || a.ControllerPort != b.ControllerPort || (a.Egress == "existing") != (b.Egress == "existing") {
			return Plan{}, errors.New("configure retains node, exposure, backend, ports and ownership kind; deploy a new ID to migrate")
		}
		j = old
		j.Request = r
	}
	for _, p := range i.TailnetProxies {
		if p.ID != r.ID && p.PeerID == node.PeerID && p.Status != "removed" && (p.Port == r.Port || p.LocalPort == r.LocalPort || p.Port == r.LocalPort || p.LocalPort == r.Port) {
			return Plan{}, errors.New("another owned Tailnet proxy already uses this port")
		}
	}
	facts, err := s.execute(ctx, node.SSHHost, remote(j, "inspect"))
	if err != nil {
		return Plan{}, err
	}
	if facts.PeerID != node.PeerID {
		return Plan{}, errors.New("SSH host no longer matches the registered Tailscale peer")
	}
	j.HostOS = facts.OS
	p := Plan{ID: r.ID, Action: "deploy", Request: r, PeerID: node.PeerID, SSHHost: node.SSHHost, ListenIP: ip, Upstream: redactedUpstream(r.Upstream), Mapping: facts.Mapping, Summary: fmt.Sprintf("Share %s through %s on %s", r.Name, r.Mode, node.Hostname), Steps: []string{"Verify peer identity and exact listener exposure", "Start only the owned gateway and per-port Serve mapping", "Verify authenticated HTTPS egress through the exported client node"}, Warnings: facts.Warnings}
	if existing {
		p.Action = "configure"
		data, _ := json.Marshal(old)
		p.StateDigest = hash(data)
	}
	if !facts.Running || !contains(facts.IPs, ip) {
		p.Blockers = append(p.Blockers, "Tailscale peer address is currently unavailable")
	}
	if r.Mode == "serve" && facts.Mapping != "" && (!existing || !facts.Owned || !ownedMapping(facts.Mapping, r.LocalPort)) {
		p.Blockers = append(p.Blockers, "Serve port has a foreign or changed mapping")
	}
	if r.UDP {
		p.Warnings = append(p.Warnings, "SOCKS UDP is restricted by the Tailnet address and access policy; UDP datagrams do not carry the TCP username/password. HTTPS verification does not establish UDP egress.")
	}
	if r.Mode == "serve" {
		p.Warnings = append(p.Warnings, "Tailscale Serve shares TCP only and requires tailnet access permission.")
	}
	if r.Egress == "existing" {
		p.Warnings = append(p.Warnings, "The existing proxy process remains externally managed; only its owned Serve mapping is controlled.")
	} else {
		opts, e := s.coreOptions()
		if e != nil {
			return p, e
		}
		req, e := gatewayRequest(j)
		if e != nil {
			return p, e
		}
		var corePlan managedcore.Plan
		_, coreErr := managedcore.GetInstance(j.CoreID, opts)
		if coreErr != nil && !errors.Is(coreErr, os.ErrNotExist) {
			return p, coreErr
		}
		if coreErr == nil {
			corePlan, e = managedcore.PreviewConfigure(ctx, j.CoreID, req, opts)
		} else {
			corePlan, e = managedcore.Preview(ctx, req, opts)
		}
		if e != nil {
			return p, e
		}
		p.Core = &corePlan
		p.Warnings = append(p.Warnings, corePlan.Warnings...)
		p.Blockers = append(p.Blockers, corePlan.Blockers...)
	}
	p.Digest = planDigest(p, r.Upstream)
	return p, nil
}

func (s Service) Apply(ctx context.Context, r Request, expected string) (Result, error) {
	if s.Options.ReadOnly {
		return Result{}, errors.New("Tailnet proxy changes are disabled in read-only mode")
	}
	unlock, err := s.lock(r.ID)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	p, err := s.Preview(ctx, r)
	if err != nil {
		return Result{}, err
	}
	if expected == "" || p.Digest != expected {
		return Result{}, errors.New("Tailnet proxy preview changed; review the current digest")
	}
	if len(p.Blockers) > 0 {
		return Result{}, fmt.Errorf("Tailnet proxy blocked: %s", strings.Join(p.Blockers, "; "))
	}
	r = p.Request
	j, e := s.load(r.ID)
	existing := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return Result{}, e
	}
	if !existing {
		token, e := randomSecret()
		if e != nil {
			return Result{}, e
		}
		password, e := randomSecret()
		if e != nil {
			return Result{}, e
		}
		j = journal{Request: r, PeerID: p.PeerID, SSHHost: p.SSHHost, ListenIP: p.ListenIP, CoreID: coreID(r.ID), Token: token, Username: "gateway", Password: password, Phase: "installing", CreatedAt: s.now()}
		if r.Egress == "existing" {
			u, _ := upstreamURL(r.Upstream)
			j.Username = u.User.Username()
			j.Password, _ = u.User.Password()
			j.CoreID = ""
		}
		if err = s.save(j); err != nil {
			return Result{}, err
		}
	} else {
		j.Request = r
		if r.Egress == "existing" {
			u, _ := upstreamURL(r.Upstream)
			j.Username = u.User.Username()
			j.Password, _ = u.User.Password()
		}
	}
	observation, err := s.execute(ctx, j.SSHHost, remote(j, "inspect"))
	if err != nil {
		return s.fail(j, "core_unverified", err)
	}
	j.HostOS = observation.OS
	if r.Egress != "existing" {
		opts, e := s.coreOptions()
		if e != nil {
			return Result{}, e
		}
		// The final probe crosses the Tailnet endpoint. The managed core still
		// authenticates and verifies its loopback controller independently.
		opts.Probe = func(context.Context, config.Target) error { return nil }
		req, e := gatewayRequest(j)
		if e != nil {
			return Result{}, e
		}
		var cp managedcore.Plan
		_, coreErr := managedcore.GetInstance(j.CoreID, opts)
		if coreErr != nil && !errors.Is(coreErr, os.ErrNotExist) {
			return s.fail(j, "core_unverified", coreErr)
		}
		coreExists := coreErr == nil
		if coreExists {
			cp, e = managedcore.PreviewConfigure(ctx, j.CoreID, req, opts)
		} else {
			cp, e = managedcore.Preview(ctx, req, opts)
		}
		if e != nil {
			return s.fail(j, "core_unverified", e)
		}
		if p.Core == nil || !reflect.DeepEqual(p.Core.Artifact, cp.Artifact) {
			return s.fail(j, "core_unverified", errors.New("gateway artifact changed since review"))
		}
		j.HostOS = cp.Host.OS
		j.DockerEndpoint = cp.Host.DockerEndpoint
		if coreExists {
			_, e = managedcore.Configure(ctx, j.CoreID, req, cp.Digest, opts)
		} else {
			_, e = managedcore.Apply(ctx, req, cp.Digest, opts)
		}
		if e != nil {
			return s.fail(j, "core_unverified", e)
		}
	}
	j.Phase = "gateway_ready"
	if err = s.save(j); err != nil {
		return Result{}, err
	}
	call := remote(j, "start")
	call.Expected = p.Mapping
	if _, err = s.execute(ctx, j.SSHHost, call); err != nil {
		return s.fail(j, "mapping_unverified", err)
	}
	j.Phase = "running_unverified"
	if err = s.save(j); err != nil {
		return Result{}, err
	}
	return s.verify(ctx, j)
}
func (s Service) fail(j journal, phase string, cause error) (Result, error) {
	j.Phase = phase
	if err := s.save(j); err != nil {
		return Result{ID: j.Request.ID, Status: phase}, errors.Join(cause, err)
	}
	return Result{ID: j.Request.ID, Status: phase, Message: "Operation is recorded; inspect status before retrying."}, cause
}
func (s Service) verify(ctx context.Context, j journal) (Result, error) {
	if j.Request.Egress != "existing" {
		opts, e := s.coreOptions()
		if e != nil {
			return Result{}, e
		}
		status, e := managedcore.GetStatus(ctx, j.CoreID, opts)
		if e != nil {
			return s.fail(j, "core_unverified", e)
		}
		if !status.Running || !status.ControllerHealthy {
			return s.fail(j, "core_unverified", errors.New("owned gateway is not healthy"))
		}
	}
	observation, err := s.execute(ctx, j.SSHHost, remote(j, "audit"))
	if err != nil {
		return s.fail(j, "exposure_unverified", err)
	}
	if !observation.Running || !contains(observation.IPs, j.ListenIP) || !observation.ListenerSafe || !observation.ListenerActive || (j.Request.Mode == "serve" && (!observation.Owned || !ownedMapping(observation.Mapping, j.Request.LocalPort))) {
		return s.fail(j, "exposure_unverified", errors.New("Tailnet proxy exposure could not be verified"))
	}
	node, err := yaml.Marshal(clientMap(j))
	if err != nil {
		return Result{}, err
	}
	probe := s.Options.Probe
	if probe == nil {
		probe = serverprobe.Probe
	}
	ip, err := probe(ctx, node)
	if err != nil {
		return s.fail(j, "running_unverified", err)
	}
	j.Phase = "running_verified"
	j.ObservedExitIP = ip
	j.VerifiedAt = s.now()
	if err = s.save(j); err != nil {
		return Result{}, err
	}
	return Result{ID: j.Request.ID, Status: j.Phase, Message: "Authenticated HTTPS egress verified through the Tailnet endpoint.", ObservedExitIP: ip, VerifiedAt: j.VerifiedAt}, nil
}
func ownedMapping(value string, port int) bool {
	var v struct {
		TCP        map[string]any `json:"TCP"`
		Web        map[string]any `json:"Web"`
		Funnel     map[string]any `json:"Funnel"`
		Foreground map[string]any `json:"Foreground"`
	}
	if json.Unmarshal([]byte(value), &v) != nil {
		return false
	}
	return len(v.TCP) == 1 && v.TCP["TCPForward"] == fmt.Sprintf("127.0.0.1:%d", port) && len(v.Web) == 0 && len(v.Funnel) == 0 && len(v.Foreground) == 0
}
