package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"go.yaml.in/yaml/v3"
)

func normalizeWindows(r Request) (Request, error) {
	if r.Client == "" {
		r.Client = "mihomo"
	}
	if r.Client != "mihomo" && r.Client != "verge" {
		return r, errors.New("Windows client must be mihomo or verge")
	}
	if r.Network.TUN || r.ServiceScope == "system" || r.Backend == "docker" || r.ProxyGateway || r.ProxyListen != "" {
		return r, errors.New("Windows initial clients use a user InteractiveToken task, loopback ports and TUN off")
	}
	if r.Client == "verge" {
		if r.Version != "" && r.Version != DefaultVersion {
			return r, errors.New("Verge uses the core bundled in its reviewed installer; --core-version cannot replace it")
		}
		if r.ClientVersion == "" {
			r.ClientVersion = WindowsVergeVersion
		}
		if r.ClientVersion == "2.5.2" {
			r.ClientVersion = WindowsVergeVersion
		}
		if r.ClientVersion != WindowsVergeVersion {
			return r, errors.New("owned Windows Verge requires reviewed version v2.5.2")
		}
	}
	r.HostOS = "windows"
	r.ServiceScope = "user"
	r.Backend = "native"
	var err error
	r, err = normalize(r)
	if err != nil {
		return r, err
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if err = config.ValidateDiagnosticChecks(r.CloneChecks); err != nil {
		return r, err
	}
	return r, nil
}

func PreviewWindows(ctx context.Context, request Request, opts Options) (Plan, error) {
	ctx, cleanup, err := withDownloadClient(ctx, request, opts)
	if err != nil {
		return Plan{}, err
	}
	defer cleanup()
	request, err = normalizeWindows(request)
	if err != nil {
		return Plan{}, err
	}
	response, err := callWindows(ctx, request.SSHHost, windowsRequest{Op: "facts", ID: request.ID, Client: request.Client, ControllerPort: request.ControllerPort, MixedPort: request.MixedPort}, opts)
	if err != nil {
		return Plan{}, err
	}
	host := response.Facts
	p := Plan{windowsProxy: host.WindowsProxy, ID: request.ID, Request: request, Host: host, Root: winJoin(host.LocalAppData, "lazyclash", "cores", request.ID), Service: "lazyclash-" + request.ID, Controller: fmt.Sprintf("http://127.0.0.1:%d", request.ControllerPort), ProbeProxy: fmt.Sprintf("http://127.0.0.1:%d", request.MixedPort), InputSHA256: hashBytes(request.Input), Warnings: []string{}, Blockers: []string{}, Changes: []string{}}
	// Keep registry values private: PAC URLs and bypass strings may contain credentials.
	p.Host.WindowsProxy = windowsPublicProxy(host.WindowsProxy)
	if host.OS != "windows" || host.Arch != "amd64" {
		p.Blockers = append(p.Blockers, "This Windows backend requires an amd64 Windows host")
	}
	if host.UserSID == "" || host.InteractiveSession <= 0 || !host.TaskScheduler {
		p.Blockers = append(p.Blockers, "The selected user must have one interactive desktop session and Task Scheduler available")
	}
	if host.Existing {
		p.Blockers = append(p.Blockers, "Instance directory already exists; inspect/resume the owned instance instead of overwriting it")
	}
	if len(host.BusyPorts) > 0 {
		p.Blockers = append(p.Blockers, "A reviewed loopback controller or data port is in use")
	}
	if request.Client == "verge" && host.VergeExisting {
		p.Blockers = append(p.Blockers, "An existing Verge app/profile is not owned by this new instance; automatic adoption is refused")
	}
	if request.Client == "verge" && !host.IsRoot {
		p.Blockers = append(p.Blockers, "The pinned Verge per-machine installer requires an existing administrator token")
	}
	resolver := opts.ResolveArtifact
	if resolver == nil {
		resolver = resolveWindowsArtifact
	}
	p.Artifact, err = resolver(ctx, request, host)
	if err != nil {
		return p, err
	}
	p.ResourceOrigins = map[string]string{}
	profileCtx := context.WithValue(ctx, profileOriginsKey{}, p.ResourceOrigins)
	p.profile, p.resources, p.RulesVersion, p.Warnings, err = buildProfile(profileCtx, request)
	if err != nil {
		return p, err
	}
	if err = validateWindowsProfile(p.profile); err != nil {
		return p, err
	}
	p.ProfileSHA256 = hashBytes(p.profile)
	p.ResourceInventory = sortedResourceNames(p.resources)
	p.ResourceSHA256 = map[string]string{}
	for name, data := range p.resources {
		p.ResourceSHA256[name] = hashBytes(data)
	}
	if request.Client == "verge" && !request.Network.SystemProxy && host.WindowsProxy != nil && (host.WindowsProxy.Enabled != 0 || host.WindowsProxy.AutoConfigURL != "" || host.WindowsProxy.Flags&14 != 0) {
		p.Blockers = append(p.Blockers, "Verge startup refreshes Windows proxy settings; an active prior proxy/PAC requires the reviewed --system-proxy takeover")
	}
	if request.Client == "verge" && host.WindowsRASEntries > 0 {
		p.Blockers = append(p.Blockers, "Verge changes per-connection proxy settings; RAS/VPN entries require an explicit snapshot strategy before managed GUI activation")
	}
	p.NeedsPrivilege = request.Client == "verge"
	p.Changes = []string{"Create only the new owned Windows instance " + p.Root, "Stage the verified Mihomo executable in Rule mode with TUN off and private loopback ports, retaining the existing Windows proxy", "Install the exact verified artifact and a user InteractiveToken task; no password or SYSTEM principal", "Validate the private profile, launch into the reviewed interactive session, and verify controller plus proxy before registration"}
	if request.Client == "verge" {
		p.Changes = append(p.Changes, "Cold-seed a fresh native Verge profile and companions; first verify its bundled core alone, then activate the GUI after arming takeover recovery")
	}
	if request.Network.SystemProxy {
		p.Changes = append(p.Changes, "After successful proxy verification, stop only the reviewed CFW executable identity and transfer this user's system proxy with a two-minute rollback task")
	}
	p.Warnings = append(p.Warnings, "The task runs at user logon when boot is enabled; it does not run under SYSTEM or before user login.", "The existing CFW app and system proxy are retained throughout staging. A partial installer outcome is never blindly retried.")
	copy := p
	copy.Digest = ""
	data, _ := json.Marshal(copy)
	p.Digest = hashBytes(data)
	return p, nil
}

func ApplyWindows(ctx context.Context, request Request, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("Windows installation is disabled in read-only mode")
	}
	ctx, cleanup, err := withDownloadClient(ctx, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer cleanup()
	p, err := PreviewWindows(ctx, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || expected != p.Digest {
		return Receipt{}, errors.New("Windows setup preview changed; review a new digest")
	}
	if len(p.Blockers) > 0 {
		return Receipt{}, fmt.Errorf("Windows setup blocked: %s", strings.Join(p.Blockers, "; "))
	}
	request = p.Request
	unlock, err := mutationLock(request.ID, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	if _, err = loadInstance(request.ID, opts); err == nil {
		return Receipt{}, errors.New("managed ID is already recorded; use resume")
	} else if !os.IsNotExist(err) {
		return Receipt{}, errors.New("saved Windows ownership state is invalid; inspect it before installation")
	}
	secret, err := randomHex(32)
	if err != nil {
		return Receipt{}, err
	}
	owner, err := randomHex(24)
	if err != nil {
		return Receipt{}, err
	}
	profile, err := injectControllerSecret(p.profile, secret)
	if err != nil {
		return Receipt{}, err
	}
	var artifact []byte
	if request.ArtifactFile != "" {
		info, e := os.Stat(request.ArtifactFile)
		if e != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return Receipt{}, errors.New("Windows artifact must be a bounded regular release file")
		}
		artifact, err = os.ReadFile(request.ArtifactFile)
	} else {
		fetch := opts.FetchArtifact
		if fetch == nil {
			fetch = fetchWindowsArtifact
		}
		artifact, err = fetch(ctx, p.Artifact)
	}
	if err != nil {
		return Receipt{}, err
	}
	if hashBytes(artifact) != p.Artifact.SHA256 || int64(len(artifact)) != p.Artifact.Size {
		return Receipt{}, errors.New("Windows artifact differs from reviewed size/SHA256")
	}
	state, err := instanceDir(request.ID, opts)
	if err != nil {
		return Receipt{}, err
	}
	secretPath := filepath.Join(state, "controller.secret")
	if err = writePrivate(secretPath, []byte(secret+"\n")); err != nil {
		return Receipt{}, err
	}
	instance := Instance{ID: request.ID, Name: request.Name, SSHHost: request.SSHHost, Backend: "native", Client: request.Client, ClientVersion: request.ClientVersion, Version: request.Version, Artifact: p.Artifact, Root: p.Root, Service: p.Service, ServiceScope: "user", OS: "windows", UserSID: p.Host.UserSID, OwnerToken: owner, ProfileSHA256: hashBytes(profile), ResourceInventory: p.ResourceInventory, RulesVersion: p.RulesVersion, Network: request.Network, Boot: request.Boot, CreatedAt: opts.now()}
	if request.Client == "verge" {
		instance.AppRoot = winJoin(p.Host.ProgramFiles, "lazyclash", request.ID, "Clash Verge")
		instance.ProfileUID = "lc_" + strings.ReplaceAll(request.ID, "-", "_")
	}
	instance.Target = windowsTarget(instance, p, secretPath)
	files := map[string][]byte{}
	if instance.Client == "verge" {
		files, err = windowsVergeFiles(request, profile, secret, instance.ProfileUID, p.windowsProxy)
		if err != nil {
			return Receipt{}, err
		}
	}
	request, err = persistProfileSnapshot(instance, request, profile, p.resources, opts)
	if err != nil {
		return Receipt{}, err
	}
	receipt := newReceipt(instance, "install", p.Digest, opts)
	receipt.Status = "operation_started"
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	if err = saveReceipt(receipt, opts); err != nil {
		return receipt, err
	}
	hostReq := windowsHostRequest(instance, request, "install")
	hostReq.Expected = p.Host.WindowsStateDigest
	if err = yaml.Unmarshal(profile, &hostReq.ProfileDocument); err != nil {
		return receipt, errors.New("invalid Windows profile document")
	}
	hostReq.Profile = profile
	hostReq.Resources = p.resources
	hostReq.Files = files
	hostReq.Selections = request.CloneSelections
	hostReq.Artifact = artifact
	hostReq.ArtifactSHA256 = p.Artifact.SHA256
	hostReq.ArtifactKind = p.Artifact.Kind
	hostReq.AppliedBypass = windowsAppliedBypass(instance.Client, p.windowsProxy)
	hostReq.BeforeProxy = p.windowsProxy
	hostReq.BeforeCFW = p.Host.WindowsCFW
	hostReq.Helper = []byte(windowsHostScript)
	response, err := callWindows(ctx, instance.SSHHost, hostReq, opts)
	if err != nil {
		if response.Status == "not_installed" {
			receipt.Status = "not_installed"
			receipt.Message = "Private transfer failed before installation dispatch; no installer was started. The failed local draft is retained and a fresh reviewed setup may reuse this ID."
			root, archiveErr := stateRoot(opts)
			if archiveErr == nil {
				failed := filepath.Join(root, "failed", receipt.ID)
				archiveErr = os.MkdirAll(filepath.Dir(failed), 0700)
				if archiveErr == nil {
					archiveErr = os.Rename(state, failed)
				}
			}
			if archiveErr != nil {
				receipt.Message = "No installer was dispatched; private failed-draft archival needs inspection before reusing this ID."
			}
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		receipt.Status = "unknown_host_result"
		receipt.Message = "Windows staging is unconfirmed; inspect the private receipt and owned directory before resume. The previous proxy was not intentionally replaced."
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
	if response.CoreVersion != "" {
		instance.Version = response.CoreVersion
	}
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	return finishWindowsActivation(ctx, instance, request, receipt, opts)
}

func windowsHealth(ctx context.Context, instance Instance, request Request, initial bool, opts Options, receipt *Receipt) error {
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	readinessCtx, readinessCancel := context.WithTimeout(ctx, 35*time.Second)
	defer readinessCancel()
	defer cancel()
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	var last error
	for {
		client, closer, err := open(readinessCtx, instance.Target, false)
		if err == nil && client != nil {
			version, e := client.Version(readinessCtx)
			settings, ce := client.Config(readinessCtx)
			if e != nil {
				err = e
			} else if ce != nil {
				err = ce
			} else if version["version"] != instance.Version {
				err = errors.New("Windows controller version differs from the owned executable")
			} else if initial && settings["mode"] != "rule" {
				err = errors.New("Windows core is not in reviewed Rule mode")
			} else if tun, ok := settings["tun"].(map[string]any); initial && ok && tun["enable"] == true {
				err = errors.New("Windows initial core unexpectedly enabled TUN")
			}
			if err == nil && initial {
				proxies, e := client.Proxies(readinessCtx)
				err = e
				if e == nil {
					for group, member := range request.CloneSelections {
						p, ok := proxies[group]
						if !ok {
							err = fmt.Errorf("cloned group %q is absent", group)
							break
						}
						if p.Now != member {
							err = client.Select(readinessCtx, group, member)
							if err != nil {
								break
							}
						}
					}
				}
			}
			client.Close()
		}
		if closer != nil {
			closer.Close()
		}
		if err == nil && client != nil {
			break
		}
		last = err
		select {
		case <-readinessCtx.Done():
			return fmt.Errorf("Windows controller readiness unconfirmed: %w", last)
		case <-time.After(250 * time.Millisecond):
		}
	}
	proof := windowsHostRequest(instance, request, "verify-runtime")
	proof.Expected = ""
	proof.VerifyGenerated = initial && instance.Client == "verge" && instance.WindowsGUIActivated
	observed, err := callWindows(ctx, instance.SSHHost, proof, opts)
	if err != nil {
		return err
	}
	if verified, _ := observed.Manifest["loopback_listeners_verified"].(bool); !verified {
		return errors.New("Windows controller/data listeners were not verified as loopback and owned by the pinned core")
	}
	if proof.VerifyGenerated {
		if err = verifyWindowsGenerated(request.Input, observed.Source.File.Data); err != nil {
			return err
		}
	}
	probe := opts.Probe
	if probe == nil {
		probe = func(ctx context.Context, t config.Target) error {
			return windowsLifecycleProbe(ctx, t, receipt, func(ctx context.Context, t config.Target) (diagnostics.LatencyResult, error) {
				return diagnostics.Latency(ctx, t, diagnostics.Options{})
			})
		}
	}
	return probe(ctx, instance.Target)
}

// Only lifecycle's default website probes receive one warmup retry. Source
// validation, caller-provided probes and standalone diagnostics keep their
// existing semantics. Both attempts share the health/rollback deadline.
func windowsLifecycleProbe(ctx context.Context, target config.Target, receipt *Receipt, run func(context.Context, config.Target) (diagnostics.LatencyResult, error)) error {
	result, err := run(ctx, target)
	first := windowsProbeError(result, err)
	if receipt == nil || !errors.Is(err, diagnostics.ErrPartial) || ctx.Err() != nil {
		return first
	}
	index := len(receipt.Warnings)
	warning := "The first HTTPS verification attempt failed. " + first.Error()
	receipt.Warnings = append(receipt.Warnings, warning)
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		receipt.Warnings[index] = warning + " The verification deadline canceled the retry."
		return &windowsProbeFailure{summary: "Windows HTTPS verification deadline expired before retry; " + first.Error(), cause: ctx.Err()}
	case <-timer.C:
	}
	result, err = run(ctx, target)
	if err == nil {
		receipt.Warnings[index] = warning + " All sites passed on the single retry after a one-second warmup."
	} else {
		receipt.Warnings[index] = warning + " The single retry also failed."
	}
	return windowsProbeError(result, err)
}

type windowsProbeFailure struct {
	summary string
	cause   error
}

func (e *windowsProbeFailure) Error() string { return e.summary }
func (e *windowsProbeFailure) Unwrap() error { return e.cause }

// The fixed public probe names and diagnostics' classified errors are useful
// in a lifecycle receipt; URLs, routes and proxy credentials are omitted.
func windowsProbeError(result diagnostics.LatencyResult, err error) error {
	if err == nil || len(result.Sites) == 0 {
		return err
	}
	parts := make([]string, 0, len(result.Sites))
	for _, site := range result.Sites {
		outcome := fmt.Sprintf("HTTP %d", site.StatusCode)
		if site.Error != "" {
			outcome = site.Error
		}
		parts = append(parts, fmt.Sprintf("%s: %s (%.0f ms)", site.Name, outcome, site.Milliseconds))
	}
	return &windowsProbeFailure{summary: "Windows HTTPS verification incomplete: " + strings.Join(parts, "; "), cause: err}
}

func windowsProbeMessage(message string, err error) string {
	var failure *windowsProbeFailure
	if errors.As(err, &failure) {
		return message + " " + failure.Error()
	}
	return message
}

func verifyWindowsGenerated(expected, generated []byte) error {
	var a, b map[string]any
	if yaml.Unmarshal(expected, &a) != nil || yaml.Unmarshal(generated, &b) != nil {
		return errors.New("Windows generated profile is not valid YAML")
	}
	for _, key := range []string{"proxies", "proxy-groups", "rules"} {
		if !reflect.DeepEqual(a[key], b[key]) {
			return fmt.Errorf("Windows native-generated %s differs from the reviewed clone", key)
		}
	}
	return nil
}
func finishWindowsActivation(ctx context.Context, instance Instance, request Request, receipt Receipt, opts Options) (Receipt, error) {
	receipt.ProxyHealthy = false
	if err := windowsHealth(ctx, instance, request, !instance.WindowsInitialized, opts, &receipt); err != nil {
		receipt.Status = "running_proxy_unverified"
		receipt.Message = "The staged Windows client is unverified. Existing CFW/system proxy remain unchanged unless an earlier takeover is still awaiting rollback."
		if instance.WindowsInitialized {
			receipt.Message = "Windows client verification is incomplete after " + receipt.Operation + "; check the controller and per-site probe results."
		}
		receipt.Message = windowsProbeMessage(receipt.Message, err)
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	receipt.ProxyHealthy = true
	if instance.Network.SystemProxy {
		// The staged probe does not establish the post-handoff data route.
		receipt.ProxyHealthy = false
		r := windowsHostRequest(instance, request, "takeover")
		r.Expected = ""
		response, err := callWindows(ctx, instance.SSHHost, r, opts)
		if err != nil {
			receipt.Status = "proxy_takeover_unconfirmed"
			receipt.Message = "Inspect the Windows ownership receipt; any armed two-minute rollback task remains active."
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		instance.Digest = response.Digest
		instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
		receipt.NeedsACK, _ = response.Manifest["rollback_armed"].(bool)
		if receipt.NeedsACK {
			receipt.RollbackDeadline = opts.now().Add(2 * time.Minute)
			if deadline, ok := response.Manifest["rollback_deadline"].(string); ok {
				if parsed, e := time.Parse(time.RFC3339Nano, deadline); e == nil {
					receipt.RollbackDeadline = parsed
				}
			}
		}
		if err = saveInstance(instance, request, opts); err != nil {
			return receipt, err
		}
		if err = saveReceipt(receipt, opts); err != nil {
			return receipt, err
		}
		if instance.Client == "verge" && !instance.WindowsGUIActivated {
			return receipt, errors.New("Windows GUI takeover activation was not observed; inspect the armed recovery receipt")
		}
		verifyCtx, verifyCancel := windowsVerificationContext(ctx, receipt)
		defer verifyCancel()
		fresh := opts.FreshManagement
		if fresh == nil {
			fresh = connection.VerifyFreshWindowsSSH
		}
		if err = fresh(verifyCtx, instance.SSHHost); err != nil {
			return receipt, err
		}
		if err = windowsHealth(verifyCtx, instance, request, !instance.WindowsInitialized, opts, &receipt); err != nil {
			receipt.Status = "proxy_verification_failed"
			receipt.Message = "Post-takeover verification failed; inspect the saved ownership state before further control."
			if receipt.NeedsACK {
				receipt.Status = "proxy_pending_rollback"
				receipt.Message = "Post-takeover verification failed; the owned rollback task remains armed."
			}
			receipt.Message = windowsProbeMessage(receipt.Message, err)
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		receipt.ProxyHealthy = true
	}
	if instance.Client == "verge" && !instance.Network.SystemProxy && !instance.WindowsGUIActivated {
		receipt.ProxyHealthy = false
		response, err := callWindows(ctx, instance.SSHHost, windowsHostRequest(instance, request, "activate-gui"), opts)
		if err != nil {
			receipt.Status = "gui_activation_unconfirmed"
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		instance.Digest = response.Digest
		instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
		receipt.NeedsACK, _ = response.Manifest["rollback_armed"].(bool)
		if deadline, ok := response.Manifest["rollback_deadline"].(string); ok {
			receipt.RollbackDeadline, _ = time.Parse(time.RFC3339Nano, deadline)
		}
		if err = saveInstance(instance, request, opts); err != nil {
			return receipt, err
		}
		if err = saveReceipt(receipt, opts); err != nil {
			return receipt, err
		}
		if !instance.WindowsGUIActivated {
			return receipt, errors.New("Windows GUI activation was not observed")
		}
		verifyCtx, verifyCancel := windowsVerificationContext(ctx, receipt)
		defer verifyCancel()
		if err = windowsHealth(verifyCtx, instance, request, !instance.WindowsInitialized, opts, &receipt); err != nil {
			receipt.Status = "gui_running_unverified"
			receipt.Message = windowsProbeMessage("Native GUI verification is incomplete; inspect the owned recovery receipt.", err)
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		receipt.ProxyHealthy = true
	}
	ackCtx := ctx
	if receipt.NeedsACK && !receipt.RollbackDeadline.IsZero() {
		var cancel context.CancelFunc
		ackCtx, cancel = context.WithDeadline(ctx, receipt.RollbackDeadline.Add(-2*time.Second))
		defer cancel()
	}
	response, err := callWindows(ackCtx, instance.SSHHost, windowsHostRequest(instance, request, "ack"), opts)
	if err != nil {
		receipt.Status = "activation_ack_unconfirmed"
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	instance.WindowsInitialized = true
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	receipt.Status = "running_verified"
	receipt.NeedsACK = false
	receipt.Message = "Owned Windows client, cloned configuration and explicit proxy verified. User task and system-proxy ownership were recorded."
	if opts.Register != nil && !instance.WindowsRegistered {
		if err = opts.Register(instance.Target); err != nil {
			receipt.Status = "installed_unregistered"
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		instance.WindowsRegistered = true
		if err = saveInstance(instance, request, opts); err != nil {
			return receipt, err
		}
	}
	return receipt, saveReceipt(receipt, opts)
}

func WindowsStatus(ctx context.Context, id string, opts Options) (Status, error) {
	instance, err := loadInstance(id, opts)
	if err != nil {
		return Status{}, err
	}
	if instance.OS != "windows" {
		return Status{}, errors.New("instance is not Windows")
	}
	request, err := LoadRequest(id, opts)
	if err != nil {
		return Status{}, err
	}
	r := windowsHostRequest(instance, request, "status")
	r.Expected = ""
	response, err := callWindows(ctx, instance.SSHHost, r, opts)
	result := Status{Instance: instance, State: "unknown"}
	if err != nil {
		return result, err
	}
	result.Instance.Digest = response.Digest
	result.Instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
	result.Running = response.Running
	result.State = response.Status
	if response.Running {
		healthCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		open := opts.Open
		if open == nil {
			open = connection.Open
		}
		client, closer, e := open(healthCtx, instance.Target, true)
		if closer != nil {
			defer closer.Close()
		}
		if e == nil && client != nil {
			defer client.Close()
			version, ve := client.Version(healthCtx)
			_, ce := client.Config(healthCtx)
			result.ControllerHealthy = ve == nil && ce == nil && version["version"] == response.CoreVersion
		}
		if !result.ControllerHealthy {
			result.Message = "Owned core process was observed; its authenticated controller is not verified."
		}
	}
	return result, nil
}
func WindowsPreviewAction(ctx context.Context, id, operation string, opts Options) (ActionPlan, error) {
	switch operation {
	case "start", "stop", "restart", "remove":
	default:
		return ActionPlan{}, errors.New("unsupported Windows lifecycle operation")
	}
	status, err := WindowsStatus(ctx, id, opts)
	if err != nil {
		return ActionPlan{}, err
	}
	if status.Instance.Removed {
		return ActionPlan{}, errors.New("Windows instance was removed")
	}
	p := ActionPlan{ID: id, Operation: operation, Root: status.Instance.Root, Service: status.Instance.Service, Running: status.Running, DataPreserved: true, Warnings: []string{"Control only the pinned user task/executables; retain profiles and the previous CFW installation."}, hostInstance: status.Instance, hostDigest: status.Instance.Digest}
	raw, _ := json.Marshal(struct {
		Plan       ActionPlan
		HostDigest string
	}{p, p.hostDigest})
	p.Digest = hashBytes(raw)
	return p, nil
}
func WindowsLifecycle(ctx context.Context, id, operation, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("Windows lifecycle is disabled in read-only mode")
	}
	unlock, err := mutationLock(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	p, err := WindowsPreviewAction(ctx, id, operation, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || expected != p.Digest {
		return Receipt{}, errors.New("Windows action preview changed")
	}
	instance := p.hostInstance
	request, err := LoadRequest(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	receipt := newReceipt(instance, operation, p.Digest, opts)
	receipt.Status = "operation_started"
	if err = saveReceipt(receipt, opts); err != nil {
		return receipt, err
	}
	response, err := callWindows(ctx, instance.SSHHost, windowsHostRequest(instance, request, operation), opts)
	if err != nil {
		receipt.Status = "unknown_host_result"
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
	instance.Removed = operation == "remove"
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	if operation == "start" || operation == "restart" {
		return finishWindowsActivation(ctx, instance, request, receipt, opts)
	}
	receipt.Status = response.Status
	if operation == "remove" && opts.Unregister != nil {
		if err = opts.Unregister(id); err != nil {
			receipt.Status = "removed_registration_pending"
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
	}
	return receipt, saveReceipt(receipt, opts)
}
func ResumeWindows(ctx context.Context, id string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("Windows resume is disabled in read-only mode")
	}
	unlock, err := mutationLock(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	instance, err := loadInstance(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	request, err := LoadRequest(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	receipt := newReceipt(instance, "resume", instance.Digest, opts)
	receipt.Status = "operation_started"
	if err = saveReceipt(receipt, opts); err != nil {
		return receipt, err
	}
	r := windowsHostRequest(instance, request, "resume")
	r.Expected = ""
	response, err := callWindows(ctx, instance.SSHHost, r, opts)
	if err != nil {
		receipt.Status = "resume_requires_inspection"
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
	if response.CoreVersion != "" {
		instance.Version = response.CoreVersion
	}
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	return finishWindowsActivation(ctx, instance, request, receipt, opts)
}
func WindowsSourceOperation(ctx context.Context, target config.Target, source configwork.HostRequest, opts Options) (configwork.HostResponse, error) {
	if sourceMutation(source.Op) && opts.ReadOnly {
		return configwork.HostResponse{}, errors.New("Windows source writes disabled in read-only mode")
	}
	if sourceMutation(source.Op) {
		unlock, e := mutationLock(target.ManagedCoreID, opts)
		if e != nil {
			return configwork.HostResponse{}, e
		}
		defer unlock()
	}
	instance, err := loadInstance(target.ManagedCoreID, opts)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	if instance.OS != "windows" || instance.Removed || target.ID != instance.Target.ID || target.SSHHost != instance.SSHHost || target.Controller != instance.Target.Controller || !reflect.DeepEqual(target.ConfigSource, instance.Target.ConfigSource) {
		return configwork.HostResponse{}, errors.New("Windows source binding differs from its owned instance")
	}
	request, err := LoadRequest(instance.ID, opts)
	if err != nil {
		return configwork.HostResponse{}, err
	}
	if err = validateSourceResourceOperation(instance, source); err != nil {
		return configwork.HostResponse{}, err
	}

	if source.Op == "write" {
		if err = windowsValidateSourceWrite(ctx, instance, request, &source, opts); err != nil {
			return configwork.HostResponse{}, err
		}
	}
	if source.Op == "validate" {
		staged, e := stagedSourceInventory(instance, source.Resources)
		if e != nil {
			return configwork.HostResponse{}, e
		}
		if err = validateWindowsOwnedResources(source.Document, staged); err != nil {
			return configwork.HostResponse{}, err
		}
	}
	r := windowsHostRequest(instance, request, "source")
	r.Expected = ""
	r.Source = &source
	response, err := callWindows(ctx, instance.SSHHost, r, opts)
	if err == nil && sourceMutation(source.Op) {
		instance.Digest = response.Digest
		if err = updateSourceResourceInventory(&instance, source); err != nil {
			return response.Source, err
		}
		err = saveInstance(instance, request, opts)
	}
	return response.Source, err
}
func WindowsActivateSource(ctx context.Context, target config.Target, opts Options) error {
	if opts.ReadOnly {
		return errors.New("Windows source activation disabled in read-only mode")
	}
	unlock, err := mutationLock(target.ManagedCoreID, opts)
	if err != nil {
		return err
	}
	defer unlock()
	instance, err := loadInstance(target.ManagedCoreID, opts)
	if err != nil {
		return err
	}
	if instance.OS != "windows" || instance.Removed || target.ID != instance.Target.ID || target.Controller != instance.Target.Controller || target.SSHHost != instance.SSHHost || !reflect.DeepEqual(target.ConfigSource, instance.Target.ConfigSource) {
		return errors.New("Windows activation binding changed")
	}
	request, err := LoadRequest(instance.ID, opts)
	if err != nil {
		return err
	}
	r := windowsHostRequest(instance, request, "activate-source")
	r.Expected = ""
	response, err := callWindows(ctx, instance.SSHHost, r, opts)
	if err != nil {
		return err
	}
	instance.Digest = response.Digest
	if err = saveInstance(instance, request, opts); err != nil {
		return err
	}
	return windowsHealth(ctx, instance, request, false, opts, nil)
}

// Verification never consumes the time reserved for the guarded ACK. The
// independent host rollback task remains authoritative if the budget expires.
func windowsVerificationContext(ctx context.Context, receipt Receipt) (context.Context, context.CancelFunc) {
	if receipt.NeedsACK && !receipt.RollbackDeadline.IsZero() {
		return context.WithDeadline(ctx, receipt.RollbackDeadline.Add(-20*time.Second))
	}
	return context.WithCancel(ctx)
}
