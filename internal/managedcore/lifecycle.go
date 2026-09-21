package managedcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
)

type ActionPlan struct {
	ID             string   `json:"id"`
	Operation      string   `json:"operation"`
	Digest         string   `json:"digest"`
	Root           string   `json:"root"`
	Service        string   `json:"service"`
	NeedsPrivilege bool     `json:"needs_privilege"`
	Running        bool     `json:"running"`
	DataPreserved  bool     `json:"data_preserved"`
	Warnings       []string `json:"warnings"`
	proxyPlan      *networkcheck.SystemProxyPlan
	hostInstance   Instance
	hostDigest     string
}

func GetInstance(id string, opts Options) (Instance, error) { return loadInstance(id, opts) }
func GetStatus(ctx context.Context, id string, opts Options) (Status, error) {
	instance, err := loadInstance(id, opts)
	if err != nil {
		return Status{}, err
	}
	request, err := LoadRequest(id, opts)
	if err != nil {
		return Status{}, err
	}
	hostReq := lifecycleRequest(instance, request, "status")
	hostReq.Expected = ""
	response, err := callHost(ctx, instance.SSHHost, false, hostReq, opts)
	result := Status{Instance: instance, State: "unknown"}
	if err != nil {
		result.Message = "Host ownership/service status could not be inspected"
		return result, err
	}
	result.Instance.Digest = response.Digest
	if data, e := json.Marshal(response.Manifest["network"]); e == nil && string(data) != "null" {
		_ = json.Unmarshal(data, &result.Instance.Network)
	}
	if hash, ok := response.Manifest["profile_sha256"].(string); ok {
		result.Instance.ProfileSHA256 = hash
	}
	if ref, ok := response.Manifest["network_guard"].(string); ok {
		result.Instance.CoreGuardRef = ref
	}

	result.Running = response.Running
	result.State = "stopped"
	if response.Running {
		result.State = "running"
	}
	if instance.Removed {
		result.State = "removed_data_preserved"
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	client, closer, e := open(ctx, instance.Target, true)
	if e == nil {
		_, healthErr := client.Version(ctx)
		result.ControllerHealthy = healthErr == nil
		client.Close()
		if closer != nil {
			closer.Close()
		}
	}
	return result, nil
}

func lifecycleRequest(instance Instance, request Request, op string) hostRequest {
	return hostRequest{Op: op, ID: instance.ID, Root: instance.Root, Backend: instance.Backend, Version: instance.Version, ServiceScope: instance.ServiceScope, DockerContext: instance.DockerContext, DockerEndpoint: instance.DockerEndpoint, OwnerToken: instance.OwnerToken, Expected: instance.Digest, Image: instance.Artifact.Image, Platform: instance.Artifact.Platform, GuardRef: instance.CoreGuardRef, Network: instance.Network, Boot: instance.Boot, Ports: []int{request.ControllerPort, request.MixedPort}, ProxyListen: request.ProxyListen, ProxyUDP: request.ProxyUDP}
}

func PreviewAction(ctx context.Context, id, operation string, opts Options) (ActionPlan, error) {
	switch operation {
	case "start", "stop", "restart", "remove":
	default:
		return ActionPlan{}, errors.New("unknown managed lifecycle operation")
	}
	status, err := GetStatus(ctx, id, opts)
	if err != nil {
		return ActionPlan{}, err
	}
	if status.Instance.Removed {
		return ActionPlan{}, errors.New("this instance was removed; its preserved files are not a live service")
	}
	plan := ActionPlan{ID: id, Operation: operation, Root: status.Instance.Root, Service: status.Instance.Service, NeedsPrivilege: status.Instance.ServiceScope == "system", Running: status.Running, DataPreserved: true, Warnings: []string{}, hostDigest: status.Instance.Digest, hostInstance: status.Instance}
	if operation == "remove" {
		plan.Warnings = append(plan.Warnings, "Stop and remove only this owned service/project. Private configuration, nodes, state and receipts remain on disk.")
	}
	if status.Instance.Network.TUN || status.Instance.Network.SystemProxy {
		plan.Warnings = append(plan.Warnings, "Network state belongs to this managed instance; external VPN or proxy changes must never be overwritten.")
	}
	if (operation == "start" || operation == "restart") && status.Instance.Network.SystemProxy {
		reader := opts.ReadSystemProxy
		if reader == nil {
			reader = networkcheck.ReadSystemProxy
		}
		snapshot, e := reader(ctx, status.Instance.SSHHost, status.Instance.Network.Services)
		if e != nil {
			return plan, e
		}
		saved, e := LoadRequest(id, opts)
		if e != nil {
			return plan, e
		}
		proxy, e := networkcheck.PlanSystemProxyWithSOCKS(snapshot, status.Instance.Target.ProbeProxy, fmt.Sprintf("socks5://127.0.0.1:%d", saved.MixedPort), status.Instance.Network.ProxyExceptions)
		if e != nil {
			return plan, e
		}
		plan.proxyPlan = &proxy
	}
	data, _ := json.Marshal(struct {
		Plan     ActionPlan
		Instance Instance
		Proxy    *networkcheck.SystemProxyPlan
	}{plan, status.Instance, plan.proxyPlan})
	plan.Digest = hashBytes(data)
	return plan, nil
}

func ApplyAction(ctx context.Context, id, operation, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("managed lifecycle changes are disabled in read-only mode")
	}
	unlock, err := mutationLock(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	plan, err := PreviewAction(ctx, id, operation, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || expected != plan.Digest {
		return Receipt{}, errors.New("lifecycle preview changed; review its current digest before applying")
	}
	instance, err := loadInstance(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	request, err := LoadRequest(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	instance = plan.hostInstance
	request.Network = instance.Network
	instance.Digest = plan.hostDigest
	receipt := newReceipt(instance, operation, plan.Digest, opts)
	receipt.Status = "operation_started"
	_ = saveReceipt(receipt, opts)
	if (operation == "stop" || operation == "remove") && instance.ProxyGuardRef != "" {
		restore := lifecycleRequest(instance, request, "restore-proxy")
		restore.GuardRef = instance.ProxyGuardRef
		restore.Expected = ""
		outcome, e := callHost(ctx, instance.SSHHost, instance.OS == "darwin", restore, opts)
		if e != nil || outcome.Status != "restored" {
			receipt.Status = "proxy_restore_incomplete"
			receipt.Message = "System proxy restoration was not complete; the core remains running for inspection."
			_ = saveReceipt(receipt, opts)
			if e == nil {
				e = errors.New(receipt.Message)
			}
			return receipt, e
		}
	}
	response, err := callHost(ctx, instance.SSHHost, plan.NeedsPrivilege, lifecycleRequest(instance, request, operation), opts)
	if err != nil {
		receipt.Status = "unknown_host_result"
		receipt.Message = "Lifecycle result is unconfirmed; inspect before retrying."
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	if response.GuardRef != "" {
		instance.CoreGuardRef = response.GuardRef
	}
	response.ProxyPlan = plan.proxyPlan
	instance.Removed = operation == "remove"
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	receipt.Status = response.Status
	if operation == "start" || operation == "restart" {
		return finishActivation(ctx, instance, request, response, receipt, opts)
	}
	if operation == "remove" && opts.Unregister != nil {
		if err = opts.Unregister(instance.ID); err != nil {
			receipt.Status = "removed_registration_pending"
			receipt.Message = "The owned service is removed; local target cleanup still needs attention."
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
	}
	_ = saveReceipt(receipt, opts)
	return receipt, nil
}

func PreviewConfigure(ctx context.Context, id string, request Request, opts Options) (Plan, error) {
	status, err := GetStatus(ctx, id, opts)
	instance := status.Instance
	if err != nil {
		return Plan{}, err
	}
	if instance.Removed {
		return Plan{}, errors.New("removed instance cannot be configured")
	}
	if request.ID == "" {
		request.ID = id
	}
	if request.ID != id {
		return Plan{}, errors.New("configure cannot rename a managed core")
	}
	saved, e := LoadRequest(id, opts)
	if e != nil {
		return Plan{}, e
	}
	if request.InputKind == saved.InputKind && request.InputBaseDir == saved.InputBaseDir && bytes.Equal(request.Input, saved.Input) {
		snapshot, e := callHost(ctx, instance.SSHHost, instance.ServiceScope == "system", lifecycleRequest(instance, saved, "snapshot"), opts)
		if e != nil {
			return Plan{}, e
		}
		request.Input = snapshot.Profile
		request.InputKind = "yaml"
		request.InputBaseDir = ""
		home := filepath.Join(instance.Root, "home")
		if instance.Backend == "docker" {
			home = "/root/.config/mihomo"
		}
		ctx = context.WithValue(ctx, profileSnapshotKey{}, profileSnapshot{Home: home, Files: snapshot.Resources})
	}
	return preview(ctx, request, opts, &instance)
}

func Configure(ctx context.Context, id string, request Request, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("managed configuration changes are disabled in read-only mode")
	}
	unlock, err := mutationLock(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	plan, err := PreviewConfigure(ctx, id, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || plan.Digest != expected {
		return Receipt{}, errors.New("configuration preview changed; review the current digest before applying")
	}
	if len(plan.Blockers) > 0 {
		return Receipt{}, fmt.Errorf("configuration blocked: %s", strings.Join(plan.Blockers, "; "))
	}
	instance := *plan.current
	secret, err := os.ReadFile(instance.Target.SecretFile)
	if err != nil {
		return Receipt{}, errors.New("managed controller secret is unavailable")
	}
	profile, err := injectControllerSecret(plan.profile, strings.TrimSpace(string(secret)))
	if err != nil {
		return Receipt{}, err
	}
	receipt := newReceipt(instance, "configure", plan.Digest, opts)
	receipt.Status = "operation_started"
	_ = saveReceipt(receipt, opts)
	hostReq := lifecycleRequest(instance, plan.Request, "configure")
	hostReq.Profile, hostReq.ProfileSHA256, hostReq.Resources = profile, hashBytes(profile), plan.resources
	hostReq.Network, hostReq.Boot = plan.Request.Network, plan.Request.Boot
	response, err := callHost(ctx, instance.SSHHost, instance.ServiceScope == "system", hostReq, opts)
	if err != nil {
		receipt.Status = "unknown_host_result"
		receipt.Message = "Configuration result is unconfirmed; inspect the host before retrying."
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	if response.Status == "configure_failed_restored" {
		receipt.Status = response.Status
		_ = saveReceipt(receipt, opts)
		return receipt, errors.New("new configuration failed; previous owned configuration was restored")
	}
	instance.Name = plan.Request.Name
	if plan.Request.Preset == "cn-split" || plan.Request.Preset == "simple" {
		instance.ActivePreset = plan.Request.Preset
	}
	previousSystemProxy := instance.Network.SystemProxy
	instance.ResourceInventory = plan.ResourceInventory
	instance.Digest, instance.ProfileSHA256, instance.Network, instance.Boot, instance.RulesVersion = response.Digest, hashBytes(profile), plan.Request.Network, plan.Request.Boot, plan.RulesVersion
	if response.GuardRef != "" {
		instance.CoreGuardRef = response.GuardRef
	}
	response.ProxyPlan = plan.systemProxy
	if previousSystemProxy && !plan.Request.Network.SystemProxy && instance.ProxyGuardRef != "" {
		restore := lifecycleRequest(instance, plan.Request, "restore-proxy")
		restore.GuardRef = instance.ProxyGuardRef
		outcome, e := callHost(ctx, instance.SSHHost, instance.OS == "darwin", restore, opts)
		if e != nil || outcome.Status != "restored" {
			return receipt, errors.New("core configuration changed but system proxy restoration requires inspection")
		}
	}
	instance.Target = targetForInstance(instance, plan, instance.Target.SecretFile)
	savedRequest, err := persistProfileSnapshot(instance, plan.Request, profile, plan.resources, opts)
	if err != nil {
		return receipt, err
	}
	plan.Request = savedRequest
	if err = saveInstance(instance, plan.Request, opts); err != nil {
		return receipt, err
	}
	receipt.Target = instance.Target
	return finishActivation(ctx, instance, plan.Request, response, receipt, opts)
}
