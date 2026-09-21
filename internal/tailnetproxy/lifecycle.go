package tailnetproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

func (s Service) checkRegistration(j journal) error {
	i, err := s.Options.Store.Load()
	if err != nil {
		return err
	}
	n, err := i.TailnetNode(j.Request.NodeID)
	if err != nil {
		return err
	}
	if n.PeerID != j.PeerID || n.SSHHost != j.SSHHost {
		return errors.New("Tailnet node registration changed; refusing another peer")
	}
	return nil
}
func (s Service) Status(ctx context.Context, id string) (Status, error) {
	j, err := s.load(id)
	if err != nil {
		return Status{}, err
	}
	result := Status{ID: id, NodeID: j.Request.NodeID, Mode: j.Request.Mode, Status: j.Phase, Endpoint: endpoint(j), ObservedExitIP: j.ObservedExitIP, VerifiedAt: j.VerifiedAt}
	if j.Phase == "removed" {
		return result, nil
	}
	if err = s.checkRegistration(j); err != nil {
		return result, err
	}
	facts, err := s.execute(ctx, j.SSHHost, remote(j, "audit"))
	if err != nil {
		return result, err
	}
	result.AddressPresent = facts.Running && contains(facts.IPs, j.ListenIP)
	result.MappingOwned = facts.Owned && (j.Request.Mode == "direct" || ownedMapping(facts.Mapping, j.Request.LocalPort))
	result.Running = result.AddressPresent && facts.ListenerActive && facts.ListenerSafe && result.MappingOwned
	if j.Request.Egress != "existing" {
		opts, e := s.coreOptions()
		if e != nil {
			return result, e
		}
		core, e := managedcore.GetStatus(ctx, j.CoreID, opts)
		if e != nil {
			return result, e
		}
		result.Running = result.Running && core.Running && core.ControllerHealthy
	}
	if !result.AddressPresent {
		result.Status = "address_unavailable"
		result.Message = "Exact Tailnet address is unavailable; start/restart is blocked and no wildcard fallback is configured."
	} else if !facts.ListenerSafe && facts.ListenerActive {
		result.Status = "exposure_conflict"
		result.Message = "Listener exposure differs from the owned private gateway."
	} else if !result.Running {
		result.Status = "stopped_or_changed"
	}
	return result, nil
}
func (s Service) PreviewAction(ctx context.Context, id, action string) (Plan, error) {
	if action != "start" && action != "stop" && action != "restart" && action != "remove" {
		return Plan{}, errors.New("proxy action must be start, stop, restart or remove")
	}
	j, err := s.load(id)
	if err != nil {
		return Plan{}, err
	}
	if j.Phase == "removed" && action == "remove" {
		data, _ := json.Marshal(j)
		p := Plan{ID: id, Action: action, Request: j.Request, PeerID: j.PeerID, SSHHost: j.SSHHost, ListenIP: j.ListenIP, StateDigest: hash(data), Summary: "Finish local inventory cleanup for the removed proxy", Steps: []string{"Remove the already retired proxy registration"}}
		p.Digest = planDigest(p, j.Request.Upstream)
		return p, nil
	}
	if err = s.checkRegistration(j); err != nil {
		return Plan{}, err
	}
	if j.Phase == "removed" {
		return Plan{}, errors.New("Tailnet proxy was removed")
	}
	facts, err := s.execute(ctx, j.SSHHost, remote(j, "inspect"))
	if err != nil {
		return Plan{}, err
	}
	data, _ := json.Marshal(j)
	p := Plan{ID: id, Action: action, Request: j.Request, PeerID: j.PeerID, SSHHost: j.SSHHost, ListenIP: j.ListenIP, Upstream: redactedUpstream(j.Request.Upstream), Mapping: facts.Mapping, StateDigest: hash(data), Summary: fmt.Sprintf("%s owned Tailnet proxy %s", action, id), Steps: []string{"Verify the recorded peer and per-port ownership", "Change only the owned proxy service and Serve mapping"}}
	if (action == "start" || action == "restart") && (!facts.Running || !contains(facts.IPs, j.ListenIP)) {
		p.Blockers = append(p.Blockers, "Tailscale address is unavailable; no listener will be started")
	}
	if facts.Mapping != "" && (!facts.Owned || !ownedMapping(facts.Mapping, j.Request.LocalPort)) {
		p.Blockers = append(p.Blockers, "Serve mapping changed outside this tool; it will not be overwritten")
	}
	if j.Request.Egress != "existing" {
		opts, e := s.coreOptions()
		if e != nil {
			return p, e
		}
		instance, instanceErr := managedcore.GetInstance(j.CoreID, opts)
		if action == "remove" && instanceErr == nil && instance.Removed {
			p.Warnings = append(p.Warnings, "Gateway service is already removed; finish only owned sharing cleanup.")
			p.Digest = planDigest(p, j.Request.Upstream)
			return p, nil
		}
		cp, e := managedcore.PreviewAction(ctx, j.CoreID, action, opts)
		if e != nil {
			if errors.Is(e, os.ErrNotExist) && (action == "remove" || action == "stop") {
				p.Warnings = append(p.Warnings, "Gateway installation did not complete; only the owned sharing record will be cleaned up.")
				p.Digest = planDigest(p, j.Request.Upstream)
				return p, nil
			}
			return p, e
		}
		// Bind the independently reviewed service ownership to this plan.
		p.Steps = append(p.Steps, "Managed gateway action digest: "+cp.Digest)
	}
	p.Digest = planDigest(p, j.Request.Upstream)
	return p, nil
}
func (s Service) Action(ctx context.Context, id, action, expected string) (Result, error) {
	if s.Options.ReadOnly {
		return Result{}, errors.New("Tailnet proxy changes are disabled in read-only mode")
	}
	unlock, err := s.lock(id)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	p, err := s.PreviewAction(ctx, id, action)
	if err != nil {
		return Result{}, err
	}
	if expected == "" || expected != p.Digest {
		return Result{}, errors.New("Tailnet proxy action preview changed; review the current digest")
	}
	if len(p.Blockers) > 0 {
		return Result{}, errors.New(strings.Join(p.Blockers, "; "))
	}
	j, err := s.load(id)
	if err != nil {
		return Result{}, err
	}
	if j.Phase == "removed" && action == "remove" {
		err = s.Options.Store.Update(func(i *serverstate.Inventory) error { return i.RemoveTailnetProxy(id) })
		return Result{ID: id, Status: "removed", Message: "Removed proxy inventory cleanup completed."}, err
	}
	if action == "stop" || action == "remove" || action == "restart" {
		r := remote(j, "stop")
		r.Expected = p.Mapping
		if _, err = s.execute(ctx, j.SSHHost, r); err != nil {
			return s.fail(j, "mapping_unverified", err)
		}
	}
	if j.Request.Egress != "existing" {
		opts, e := s.coreOptions()
		if e != nil {
			return Result{}, e
		}
		instance, instanceErr := managedcore.GetInstance(j.CoreID, opts)
		alreadyRemoved := action == "remove" && instanceErr == nil && instance.Removed
		var cp managedcore.ActionPlan
		if !alreadyRemoved {
			cp, e = managedcore.PreviewAction(ctx, j.CoreID, action, opts)
		}
		if e != nil {
			if !(errors.Is(e, os.ErrNotExist) && (action == "remove" || action == "stop")) {
				return s.fail(j, "core_unverified", e)
			}
		}
		if e == nil && !alreadyRemoved {
			if _, e = managedcore.ApplyAction(ctx, j.CoreID, action, cp.Digest, opts); e != nil {
				return s.fail(j, "core_unverified", e)
			}
		}
	}
	if action == "stop" {
		j.Phase = "stopped"
		err = s.save(j)
		return Result{ID: id, Status: j.Phase, Message: "Owned proxy sharing stopped; Tailscale and foreign services remain running."}, err
	}
	if action == "remove" {
		r := remote(j, "remove")
		if _, err = s.execute(ctx, j.SSHHost, r); err != nil {
			return s.fail(j, "mapping_unverified", err)
		}
		j.Phase = "removed"
		if err = s.save(j); err != nil {
			return Result{}, err
		}
		err = s.Options.Store.Update(func(i *serverstate.Inventory) error { return i.RemoveTailnetProxy(id) })
		return Result{ID: id, Status: "removed", Message: "Owned sharing removed; private recovery data preserved."}, err
	}
	r := remote(j, "start")
	if action == "start" {
		r.Expected = p.Mapping
	}
	if _, err = s.execute(ctx, j.SSHHost, r); err != nil {
		return s.fail(j, "mapping_unverified", err)
	}
	return s.verify(ctx, j)
}
