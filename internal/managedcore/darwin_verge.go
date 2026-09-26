package managedcore

import (
	"context"
	_ "embed"
	"encoding/base64"
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
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

//go:embed darwin_verge_host.py
var darwinVergeHostScript string

const darwinVergeApp = "/Applications/Clash Verge.app"

type darwinVergeRequest struct {
	Op              string `json:"op"`
	ID              string `json:"id"`
	OwnerToken      string `json:"owner_token,omitempty"`
	Expected        string `json:"expected,omitempty"`
	ControllerPort  int    `json:"controller_port"`
	MixedPort       int    `json:"mixed_port"`
	Ports           []int  `json:"ports,omitempty"`
	TransferID      string `json:"transfer_id,omitempty"`
	DMGSHA256       string `json:"dmg_sha256,omitempty"`
	DMGSize         int64  `json:"dmg_size,omitempty"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
	AckToken        string `json:"ack_token,omitempty"`
	DeadlineSeconds int    `json:"deadline_seconds,omitempty"`
	HelperSource    string `json:"helper_source,omitempty"`
}

type darwinVergeFacts struct {
	OS                 string   `json:"os"`
	Arch               string   `json:"arch"`
	Home               string   `json:"home"`
	UID                int      `json:"uid"`
	User               string   `json:"user"`
	ConsoleUser        string   `json:"console_user"`
	BusyPorts          []int    `json:"busy_ports"`
	Launchd            bool     `json:"launchd"`
	AppExisting        bool     `json:"app_existing"`
	ServiceExisting    bool     `json:"service_existing"`
	DataDir            string   `json:"data_dir"`
	DataDirExisting    bool     `json:"data_dir_existing"`
	Existing           bool     `json:"existing"`
	HDIUtil            bool     `json:"hdiutil"`
	SudoNonInteractive bool     `json:"sudo_noninteractive"`
	MacOSVersion       string   `json:"macos_version"`
	CFWRunning         bool     `json:"cfw_running"`
	CFWDaemons         []string `json:"cfw_daemons"`
	StateDigest        string   `json:"state_digest"`
}

type darwinVergeResponse struct {
	Facts        darwinVergeFacts `json:"facts"`
	Status       string           `json:"status"`
	Digest       string           `json:"digest"`
	Running      bool             `json:"running"`
	CoreVersion  string           `json:"core_version,omitempty"`
	TransferPath string           `json:"transfer_path,omitempty"`
	AckToken     string           `json:"ack_token,omitempty"`
	Deadline     int64            `json:"deadline,omitempty"`
	Generated    string           `json:"generated,omitempty"`
	Manifest     map[string]any   `json:"manifest,omitempty"`
	Error        string           `json:"error,omitempty"`
}

// Operations that change root-owned state, launchd jobs or other users'
// processes run under native sudo; everything else runs as the SSH user.
var darwinVergePrivileged = map[string]bool{"privilege-check": true, "install": true, "launch-staged": true, "verify-runtime": true, "takeover": true, "ack": true, "stop": true, "start": true, "restart": true, "remove": true, "rollback": true}

func callDarwinVerge(ctx context.Context, host string, r darwinVergeRequest, opts Options) (darwinVergeResponse, error) {
	switch r.Op {
	case "launch-staged", "takeover", "start", "restart":
		r.HelperSource = darwinVergeHostScript
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return darwinVergeResponse{}, err
	}
	timeout := 90 * time.Second
	if r.Op == "install" || r.Op == "remove" {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	privileged := darwinVergePrivileged[r.Op]
	var output []byte
	switch {
	case opts.Execute != nil:
		output, err = opts.Execute(ctx, host, privileged, raw)
	case privileged:
		output, err = runPrivilegedScript(ctx, host, compactHostScript(darwinVergeHostScript), raw, opts)
	default:
		output, err = connection.ExecutePython(ctx, host, compactHostScript(darwinVergeHostScript), raw, 32<<20)
	}
	if err != nil {
		return darwinVergeResponse{}, err
	}
	var response darwinVergeResponse
	marker := "LAZYCLASH_MANAGED_RESULT="
	found := false
	for _, line := range strings.Split(string(output), "\n") {
		if at := strings.Index(line, marker); at >= 0 {
			decoded, e := base64.StdEncoding.DecodeString(strings.TrimSpace(line[at+len(marker):]))
			if e == nil && json.Unmarshal(decoded, &response) == nil {
				found = true
			}
		}
	}
	if !found && json.Unmarshal(output, &response) != nil {
		return response, errors.New("macOS Verge helper returned an invalid response")
	}
	if response.Error != "" {
		return response, fmt.Errorf("macOS Verge: %s", response.Error)
	}
	return response, nil
}

func darwinVergeHostRequest(instance Instance, request Request, op string) darwinVergeRequest {
	return darwinVergeRequest{Op: op, ID: instance.ID, OwnerToken: instance.OwnerToken, Expected: instance.Digest, ControllerPort: request.ControllerPort, MixedPort: request.MixedPort}
}

func isDarwinVerge(instance Instance) bool {
	return instance.OS == "darwin" && instance.Client == "verge"
}

func normalizeDarwinVerge(r Request) (Request, error) {
	if r.Version != "" && r.Version != DefaultVersion {
		return r, errors.New("Verge uses the core bundled in its reviewed disk image; --core-version cannot replace it")
	}
	if r.ClientVersion == "" || r.ClientVersion == "2.5.2" {
		r.ClientVersion = WindowsVergeVersion
	}
	if r.ClientVersion != WindowsVergeVersion {
		return r, errors.New("owned macOS Verge requires reviewed version v2.5.2")
	}
	if r.CloneMode != "" && r.CloneMode != "native" && r.CloneMode != "portable" {
		return r, errors.New("clone mode must be native or portable")
	}
	if r.Backend == "docker" || r.ProxyGateway || r.ProxyListen != "" {
		return r, errors.New("macOS Verge is a native desktop client with loopback listeners")
	}
	if r.SSHHost == "" {
		return r, errors.New("macOS Verge deployment targets an SSH host; use the Verge app directly on this Mac")
	}
	r.HostOS, r.Backend, r.ServiceScope = "darwin", "native", "system"
	var err error
	if r, err = normalize(r); err != nil {
		return r, err
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	return r, config.ValidateDiagnosticChecks(r.CloneChecks)
}

func PreviewDarwinVerge(ctx context.Context, request Request, opts Options) (Plan, error) {
	ctx, cleanup, err := withDownloadClient(ctx, request, opts)
	if err != nil {
		return Plan{}, err
	}
	defer cleanup()
	if request, err = normalizeDarwinVerge(request); err != nil {
		return Plan{}, err
	}
	response, err := callDarwinVerge(ctx, request.SSHHost, darwinVergeRequest{Op: "facts", ID: request.ID, Ports: []int{request.ControllerPort, request.MixedPort}}, opts)
	if err != nil {
		return Plan{}, err
	}
	f := response.Facts
	host := HostFacts{OS: f.OS, Arch: f.Arch, Home: f.Home, UID: f.UID, Launchd: f.Launchd, BusyPorts: f.BusyPorts, Existing: f.Existing, VergeExisting: f.AppExisting, VergeDataDir: f.DataDir, DarwinUser: f.User, DarwinConsoleUser: f.ConsoleUser, DarwinVersion: f.MacOSVersion, DarwinServiceExisting: f.ServiceExisting, DarwinDataDirExisting: f.DataDirExisting, DarwinCFWRunning: f.CFWRunning, DarwinCFWJobs: f.CFWDaemons, DarwinStateDigest: f.StateDigest, SudoNonInteractive: f.SudoNonInteractive}
	p := Plan{ID: request.ID, Request: request, Host: host, Root: "/Library/Application Support/lazyclash/verge/" + request.ID, Service: "io.github.clash-verge-rev.clash-verge-rev.service", Controller: fmt.Sprintf("http://127.0.0.1:%d", request.ControllerPort), ProbeProxy: fmt.Sprintf("http://127.0.0.1:%d", request.MixedPort), InputSHA256: hashBytes(request.Input), Warnings: []string{}, Blockers: []string{}, Changes: []string{}, NeedsPrivilege: true}
	if f.OS != "darwin" || f.Arch != "arm64" {
		p.Blockers = append(p.Blockers, "This macOS Verge backend requires an Apple silicon (arm64) Mac")
	}
	if f.User == "" || f.ConsoleUser != f.User {
		p.Blockers = append(p.Blockers, "The SSH user must own the active macOS console session so Verge runs in its desktop")
	}
	if !f.Launchd || !f.HDIUtil {
		p.Blockers = append(p.Blockers, "launchd and hdiutil are required")
	}
	if f.Existing {
		p.Blockers = append(p.Blockers, "Managed Verge state for this ID already exists; inspect it with cores status instead of reinstalling")
	}
	if f.AppExisting || f.ServiceExisting {
		p.Blockers = append(p.Blockers, "An existing Verge app or service is not owned by this new instance; automatic adoption is refused")
	}
	if len(f.BusyPorts) > 0 {
		p.Blockers = append(p.Blockers, "A reviewed loopback controller or data port is in use; choose ports that differ from the current client")
	}
	resolver := opts.ResolveArtifact
	if resolver == nil {
		resolver = resolveDarwinVergeArtifact
	}
	if p.Artifact, err = resolver(ctx, request, host); err != nil {
		return p, err
	}
	p.ResourceOrigins = map[string]string{}
	profileCtx := context.WithValue(ctx, profileOriginsKey{}, p.ResourceOrigins)
	if p.profile, p.resources, p.RulesVersion, p.Warnings, err = buildProfile(profileCtx, request); err != nil {
		return p, err
	}
	if p.Warnings == nil {
		p.Warnings = []string{}
	}
	if !f.SudoNonInteractive {
		p.Warnings = append(p.Warnings, "sudo -n is refused on this host; apply prompts for the administrator password in this terminal (or fails without one) before anything is changed.")
	}
	p.ProfileSHA256 = hashBytes(p.profile)
	p.ResourceInventory = sortedResourceNames(p.resources)
	p.ResourceSHA256 = map[string]string{}
	for name, data := range p.resources {
		p.ResourceSHA256[name] = hashBytes(data)
	}
	mirror, native := nativeMirrorFrom(ctx)
	if request.CloneMode == "native" && !native {
		return p, errors.New("native clone mode requires --from-target bound to a Verge data directory")
	}
	if native {
		p.NativeSHA256 = mirror.SHA256
		p.nativeFiles = mirror.Files
		p.Warnings = append(p.Warnings, mirror.Warnings...)
	}
	p.Changes = []string{
		"Install the verified Clash Verge Rev " + request.ClientVersion + " disk image to " + darwinVergeApp + " and its privileged service helper",
		"Seed the Verge data directory with a new controller secret, loopback ports and Tailnet TUN exclusions",
		"Launch Verge staged (TUN, system proxy and autostart off) beside the current client under a 3-minute launchd rollback watchdog",
		"After controller, selections and proxy verification, stop and disable Clash for Windows (files kept) and apply the final Verge settings",
		"Acknowledge only after a fresh SSH login and egress checks; otherwise the watchdog restores CFW and the previous system proxy",
	}
	if native {
		p.Changes[1] = fmt.Sprintf("Mirror %d Verge data files from %s (all profiles and companions; cache, logs and runtime YAML excluded) with a new controller secret, loopback ports and Tailnet TUN exclusions", len(mirror.SHA256), mirror.SourceID)
	}
	if f.DataDirExisting {
		p.Changes = append(p.Changes, "Rename the existing Verge data directory to a timestamped backup; it is never deleted")
	}
	if f.CFWRunning || len(f.CFWDaemons) > 0 {
		p.Warnings = append(p.Warnings, "Clash for Windows keeps running during staging; stop/remove of this instance restores it.")
	}
	if request.Network.TUN {
		p.Warnings = append(p.Warnings, "TUN changes host routing; SSH over Tailscale is excluded from TUN and verified with a fresh login before acknowledgement.")
	}
	copy := p
	copy.Digest = ""
	copy.Host.BusyPorts = nil
	data, _ := json.Marshal(copy)
	p.Digest = hashBytes(data)
	return p, nil
}

func ApplyDarwinVerge(ctx context.Context, request Request, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("macOS Verge installation is disabled in read-only mode")
	}
	ctx, cleanup, err := withDownloadClient(ctx, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer cleanup()
	p, err := PreviewDarwinVerge(ctx, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || expected != p.Digest {
		return Receipt{}, errors.New("macOS Verge setup preview changed; review a new digest")
	}
	if len(p.Blockers) > 0 {
		return Receipt{}, fmt.Errorf("macOS Verge setup blocked: %s", strings.Join(p.Blockers, "; "))
	}
	request = p.Request
	unlock, err := mutationLock(request.ID, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	if _, err = loadInstance(request.ID, opts); err == nil {
		return Receipt{}, errors.New("managed ID is already recorded; use cores status")
	} else if !os.IsNotExist(err) {
		return Receipt{}, errors.New("saved ownership state is invalid; inspect it before installation")
	}
	// Prove administrator authorization before any local or remote state exists.
	if _, err = callDarwinVerge(ctx, request.SSHHost, darwinVergeRequest{Op: "privilege-check", ID: request.ID}, opts); err != nil {
		if errors.Is(err, ErrSudoRefused) {
			return Receipt{}, fmt.Errorf("sudo was refused on %s; enable noninteractive sudo or rerun in a terminal. Nothing was changed", request.SSHHost)
		}
		return Receipt{}, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return Receipt{}, err
	}
	owner, err := randomHex(24)
	if err != nil {
		return Receipt{}, err
	}
	var artifact []byte
	if request.ArtifactFile != "" {
		info, e := os.Stat(request.ArtifactFile)
		if e != nil || !info.Mode().IsRegular() || info.Size() > darwinVergeArtifactLimit {
			return Receipt{}, errors.New("macOS Verge artifact must be a bounded regular disk image")
		}
		artifact, err = os.ReadFile(request.ArtifactFile)
	} else {
		fetch := opts.FetchArtifact
		if fetch == nil {
			fetch = fetchDarwinVergeArtifact
		}
		artifact, err = fetch(ctx, p.Artifact)
	}
	if err != nil {
		return Receipt{}, err
	}
	if hashBytes(artifact) != p.Artifact.SHA256 || int64(len(artifact)) != p.Artifact.Size {
		return Receipt{}, errors.New("macOS Verge artifact differs from reviewed size/SHA256")
	}
	profileUID := "lc_" + strings.ReplaceAll(request.ID, "-", "_")
	source := p.nativeFiles
	if source == nil {
		profile, e := injectControllerSecret(p.profile, secret)
		if e != nil {
			return Receipt{}, e
		}
		if source, e = windowsVergeFiles(request, profile, secret, profileUID, nil); e != nil {
			return Receipt{}, e
		}
	} else {
		mirror, _ := nativeMirrorFrom(ctx)
		profileUID = mirror.ProfileUID
		for name, data := range source {
			if p.NativeSHA256[name] != hashBytes(data) {
				return Receipt{}, errors.New("mirrored Verge data changed after review")
			}
		}
	}
	files, staged, final, warnings, err := darwinVergeFiles(request, source, secret)
	if err != nil {
		return Receipt{}, err
	}
	payload, err := json.Marshal(map[string]any{"files": files, "verge_staged": staged, "verge_final": final})
	if err != nil {
		return Receipt{}, err
	}
	state, err := instanceDir(request.ID, opts)
	if err != nil {
		return Receipt{}, err
	}
	secretPath := filepath.Join(state, "controller.secret")
	if err = writePrivate(secretPath, []byte(secret+"\n")); err != nil {
		return Receipt{}, err
	}
	instance := Instance{ID: request.ID, Name: request.Name, SSHHost: request.SSHHost, Backend: "native", Client: "verge", ClientVersion: request.ClientVersion, Version: request.Version, Artifact: p.Artifact, Root: p.Root, Service: p.Service, ServiceScope: "system", OS: "darwin", AppRoot: darwinVergeApp, ProfileUID: profileUID, OwnerToken: owner, ProfileSHA256: hashBytes(p.profile), ResourceInventory: p.ResourceInventory, RulesVersion: p.RulesVersion, Network: request.Network, Boot: request.Boot, CreatedAt: opts.now()}
	instance.Target = darwinVergeTarget(instance, p, secretPath)
	receipt := newReceipt(instance, "install", p.Digest, opts)
	receipt.Status = "operation_started"
	receipt.Warnings = append(receipt.Warnings, warnings...)
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	if err = saveReceipt(receipt, opts); err != nil {
		return receipt, err
	}
	notInstalled := func(message string, cause error) (Receipt, error) {
		receipt.Status = "not_installed"
		receipt.Message = message
		if root, e := stateRoot(opts); e == nil {
			failed := filepath.Join(root, "failed", receipt.ID)
			if e = os.MkdirAll(filepath.Dir(failed), 0700); e == nil {
				_ = os.Rename(state, failed)
			}
		}
		_ = saveReceipt(receipt, opts)
		return receipt, cause
	}
	nonce, err := randomHex(16)
	if err != nil {
		return notInstalled("No transfer was prepared.", err)
	}
	transfer := darwinVergeRequest{Op: "prepare-transfer", ID: request.ID, TransferID: nonce}
	prepared, err := callDarwinVerge(ctx, request.SSHHost, transfer, opts)
	if err != nil {
		return notInstalled("The private transfer directory could not be prepared; nothing was installed.", err)
	}
	if !strings.HasSuffix(prepared.TransferPath, "/.cache/lazyclash/managed-transfers/"+request.ID+"-"+nonce) {
		return notInstalled("The host returned an unexpected transfer directory; nothing was installed.", errors.New("macOS transfer path differs from its private directory"))
	}
	cleaned := false
	cleanupTransfer := func() {
		if cleaned {
			return
		}
		cleaned = true
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		transfer.Op = "cleanup-transfer"
		_, _ = callDarwinVerge(cleanupCtx, request.SSHHost, transfer, opts)
	}
	defer cleanupTransfer()
	upload := opts.Upload
	if upload == nil {
		upload = func(ctx context.Context, host, local, remote string) error {
			return connection.CopyPrivateFileOS(ctx, host, local, remote, "darwin")
		}
	}
	for name, data := range map[string][]byte{"verge.dmg": artifact, "payload.json": payload} {
		local := filepath.Join(state, "transfer-"+nonce+"-"+name)
		if err = writePrivate(local, data); err != nil {
			return notInstalled("A private local transfer file could not be written; nothing was installed.", err)
		}
		err = upload(ctx, request.SSHHost, local, prepared.TransferPath+"/"+name)
		_ = os.Remove(local)
		if err != nil {
			return notInstalled("The private SFTP transfer failed before installation; nothing was installed.", err)
		}
	}
	install := darwinVergeHostRequest(instance, request, "install")
	install.Expected = ""
	install.TransferID = nonce
	install.DMGSHA256, install.DMGSize = p.Artifact.SHA256, p.Artifact.Size
	install.PayloadSHA256 = hashBytes(payload)
	response, err := callDarwinVerge(ctx, request.SSHHost, install, opts)
	cleanupTransfer()
	if err != nil {
		receipt.Status = "unknown_host_result"
		receipt.Message = "macOS Verge installation is unconfirmed; inspect the host before retrying. Clash for Windows was not changed."
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	if response.CoreVersion != "" {
		instance.Version = response.CoreVersion
	}
	if svc, _ := response.Manifest["service_installed"].(bool); !svc {
		receipt.Warnings = append(receipt.Warnings, "The Verge service helper was not observed after installation; TUN needs it (install it from Verge settings if activation fails).")
	}
	if backup, _ := response.Manifest["data_backup"].(string); backup != "" {
		receipt.Warnings = append(receipt.Warnings, "The previous Verge data directory was kept at "+backup)
	}
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	return finishDarwinVergeActivation(ctx, instance, request, receipt, true, opts)
}

func darwinVergeTarget(instance Instance, p Plan, secretPath string) config.Target {
	data := p.Host.VergeDataDir
	target := config.Target{ID: instance.ID, Name: instance.Name, SSHHost: instance.SSHHost, Controller: p.Controller, ProbeProxy: p.ProbeProxy, SecretFile: secretPath, ManagedCoreID: instance.ID, HostOS: "darwin", Checks: append([]config.DiagnosticCheck(nil), p.Request.CloneChecks...)}
	target.SourceConfig = hostpath.Join("darwin", data, "clash-verge.yaml")
	target.Configs = []config.CoreConfig{{ID: "runtime", Name: "Runtime YAML", Path: target.SourceConfig}}
	binary := darwinVergeApp + "/Contents/MacOS/verge-mihomo"
	target.ConfigSource = &config.ConfigSource{Kind: "verge", Version: "2.5.2", DataDir: data, ProfileUID: instance.ProfileUID, Binary: binary, Home: data}
	target.RuleSource = &config.RuleSource{Kind: "verge", Version: "2.5.2", DataDir: data, ProfileUID: instance.ProfileUID}
	return target
}

// darwinHealth verifies the authenticated controller, reviewed selections,
// loopback listeners owned by the bundled core and one proxied probe.
func darwinHealth(ctx context.Context, instance Instance, request Request, staged bool, opts Options, receipt *Receipt) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	readinessCtx, readinessCancel := context.WithTimeout(ctx, 45*time.Second)
	defer readinessCancel()
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
			switch {
			case e != nil:
				err = e
			case ce != nil:
				err = ce
			case instance.Version != "" && strings.TrimPrefix(fmt.Sprint(version["version"]), "v") != strings.TrimPrefix(instance.Version, "v"):
				err = errors.New("Verge controller version differs from the bundled core")
			case staged && settings["mode"] != "rule":
				err = errors.New("staged Verge core is not in reviewed Rule mode")
			}
			if tun, ok := settings["tun"].(map[string]any); err == nil && staged && ok && tun["enable"] == true {
				err = errors.New("staged Verge core unexpectedly enabled TUN")
			}
			if err == nil && staged {
				proxies, pe := client.Proxies(readinessCtx)
				err = pe
				for group, member := range request.CloneSelections {
					if err != nil {
						break
					}
					current, ok := proxies[group]
					if !ok {
						err = fmt.Errorf("cloned group %q is absent", group)
					} else if current.Now != member {
						err = client.Select(readinessCtx, group, member)
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
			return fmt.Errorf("Verge controller readiness unconfirmed: %w", last)
		case <-time.After(500 * time.Millisecond):
		}
	}
	proof := darwinVergeHostRequest(instance, request, "verify-runtime")
	proof.Expected = ""
	observed, err := callDarwinVerge(ctx, instance.SSHHost, proof, opts)
	if err != nil {
		return err
	}
	if verified, _ := observed.Manifest["loopback_listeners_verified"].(bool); !verified {
		return errors.New("Verge controller/data listeners were not verified as loopback and owned by the bundled core")
	}
	if staged && len(request.Input) > 0 && observed.Generated != "" && receipt != nil {
		if generated, e := base64.StdEncoding.DecodeString(observed.Generated); e == nil {
			if e = verifyWindowsGenerated(request.Input, generated); e != nil {
				receipt.Warnings = append(receipt.Warnings, "Generated profile differs from the flattened source snapshot: "+e.Error())
			}
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

func darwinArmed(receipt *Receipt, response darwinVergeResponse, opts Options) {
	receipt.NeedsACK = response.AckToken != ""
	receipt.RollbackDeadline = opts.now().Add(3 * time.Minute)
	if response.Deadline > 0 {
		receipt.RollbackDeadline = time.Unix(response.Deadline, 0)
	}
}

// finishDarwinVergeActivation mirrors the Windows sequence: verify the staged
// client beside CFW, take over under the watchdog, prove a fresh SSH login and
// egress, then acknowledge and register last.
func finishDarwinVergeActivation(ctx context.Context, instance Instance, request Request, receipt Receipt, staged bool, opts Options) (Receipt, error) {
	save := func(status, message string, err error) (Receipt, error) {
		receipt.Status, receipt.Message = status, windowsProbeMessage(message, err)
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	if staged {
		launched, err := callDarwinVerge(ctx, instance.SSHHost, darwinVergeHostRequest(instance, request, "launch-staged"), opts)
		if err != nil {
			return save("gui_activation_unconfirmed", "Staged Verge launch is unconfirmed; the rollback watchdog, if armed, restores the previous state.", err)
		}
		instance.Digest = launched.Digest
		instance.WindowsGUIActivated, _ = launched.Manifest["gui_activated"].(bool)
		darwinArmed(&receipt, launched, opts)
		if err = saveInstance(instance, request, opts); err != nil {
			return receipt, err
		}
		verifyCtx, cancel := windowsVerificationContext(ctx, receipt)
		err = darwinHealth(verifyCtx, instance, request, true, opts, &receipt)
		cancel()
		if err != nil {
			return save("running_proxy_unverified", "The staged Verge client is unverified. Clash for Windows was not stopped; the watchdog quits Verge at its deadline.", err)
		}
	}
	r := darwinVergeHostRequest(instance, request, "takeover")
	r.Expected = ""
	if !staged {
		r.Op = receipt.Operation
	}
	response, err := callDarwinVerge(ctx, instance.SSHHost, r, opts)
	if err != nil {
		return save("proxy_takeover_unconfirmed", "Inspect the host; any armed rollback watchdog remains active.", err)
	}
	instance.Digest = response.Digest
	instance.WindowsGUIActivated, _ = response.Manifest["gui_activated"].(bool)
	darwinArmed(&receipt, response, opts)
	if pending, _ := response.Manifest["takeover_warnings"].([]any); len(pending) > 0 {
		receipt.Warnings = append(receipt.Warnings, fmt.Sprintf("Takeover left items for inspection: %v (cfw-login-item: remove Clash for Windows from Login Items manually)", pending))
	}
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	if err = saveReceipt(receipt, opts); err != nil {
		return receipt, err
	}
	if !instance.WindowsGUIActivated {
		return save("gui_activation_unconfirmed", "Verge was not observed after takeover; the rollback watchdog remains armed.", errors.New("Verge GUI was not observed after takeover"))
	}
	verifyCtx, cancel := windowsVerificationContext(ctx, receipt)
	defer cancel()
	fresh := opts.FreshManagement
	if fresh == nil {
		fresh = connection.VerifyFreshSSH
	}
	if err = fresh(verifyCtx, instance.SSHHost); err != nil {
		return save("proxy_pending_rollback", "A fresh SSH login failed after takeover; the rollback watchdog remains armed.", err)
	}
	if err = darwinHealth(verifyCtx, instance, request, false, opts, &receipt); err != nil {
		return save("proxy_pending_rollback", "Post-takeover verification failed; the rollback watchdog remains armed.", err)
	}
	egress, err := callDarwinVerge(verifyCtx, instance.SSHHost, darwinVergeRequest{Op: "verify-egress", ID: instance.ID, MixedPort: request.MixedPort}, opts)
	if err != nil {
		return save("proxy_pending_rollback", "Egress verification failed; the rollback watchdog remains armed.", err)
	}
	if code, _ := egress.Manifest["via_proxy"].(string); code != "204" {
		return save("proxy_pending_rollback", "The data proxy did not reach the public probe; the rollback watchdog remains armed.", fmt.Errorf("proxied egress returned %q", code))
	}
	if instance.Network.TUN {
		if code, _ := egress.Manifest["direct"].(string); code != "204" {
			receipt.Warnings = append(receipt.Warnings, fmt.Sprintf("Unproxied egress through TUN returned %q; applications without proxy settings may not get out.", code))
		}
	}
	ackCtx := ctx
	if !receipt.RollbackDeadline.IsZero() {
		var ackCancel context.CancelFunc
		ackCtx, ackCancel = context.WithDeadline(ctx, receipt.RollbackDeadline.Add(-2*time.Second))
		defer ackCancel()
	}
	ackReq := darwinVergeHostRequest(instance, request, "ack")
	ackReq.Expected = ""
	ackReq.AckToken = response.AckToken
	acked, err := callDarwinVerge(ackCtx, instance.SSHHost, ackReq, opts)
	if err != nil {
		return save("activation_ack_unconfirmed", "The rollback acknowledgement is unconfirmed; inspect the host watchdog.", err)
	}
	instance.Digest = acked.Digest
	instance.WindowsInitialized = true
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	receipt.Status, receipt.NeedsACK, receipt.ProxyHealthy = "running_verified", false, true
	receipt.RollbackDeadline = time.Time{}
	receipt.Message = "Owned macOS Verge, mirrored configuration and egress verified; Clash for Windows is stopped and kept for restore."
	if opts.Register != nil && !instance.WindowsRegistered {
		if err = opts.Register(instance.Target); err != nil {
			return save("installed_unregistered", "Installation succeeded but local target registration failed.", err)
		}
		instance.WindowsRegistered = true
		if err = saveInstance(instance, request, opts); err != nil {
			return receipt, err
		}
	}
	return receipt, saveReceipt(receipt, opts)
}

func DarwinVergeStatus(ctx context.Context, id string, opts Options) (Status, error) {
	instance, err := loadInstance(id, opts)
	if err != nil {
		return Status{}, err
	}
	request, err := LoadRequest(id, opts)
	if err != nil {
		return Status{}, err
	}
	r := darwinVergeHostRequest(instance, request, "status")
	r.Expected = ""
	response, err := callDarwinVerge(ctx, instance.SSHHost, r, opts)
	result := Status{Instance: instance, State: "unknown"}
	if err != nil {
		return result, err
	}
	result.Instance.Digest = response.Digest
	result.Running, result.State = response.Running, response.Status
	if response.Running {
		healthCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
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
			_, ve := client.Version(healthCtx)
			_, ce := client.Config(healthCtx)
			result.ControllerHealthy = ve == nil && ce == nil
		}
		if !result.ControllerHealthy {
			result.Message = "Verge is running; its authenticated controller is not verified."
		}
	}
	if pending, _ := response.Manifest["restore_incomplete"].([]any); len(pending) > 0 {
		result.Message = strings.TrimSpace(result.Message + fmt.Sprintf(" Last restore left %d item(s) for manual inspection.", len(pending)))
	}
	return result, nil
}

func DarwinVergePreviewAction(ctx context.Context, id, operation string, opts Options) (ActionPlan, error) {
	switch operation {
	case "start", "stop", "restart", "remove":
	default:
		return ActionPlan{}, errors.New("unsupported macOS Verge lifecycle operation")
	}
	status, err := DarwinVergeStatus(ctx, id, opts)
	if err != nil {
		return ActionPlan{}, err
	}
	if status.Instance.Removed {
		return ActionPlan{}, errors.New("macOS Verge instance was removed")
	}
	warnings := []string{"Verge profiles, the app bundle and Clash for Windows files are retained."}
	switch operation {
	case "stop", "remove":
		warnings = append(warnings, "Stopping restores the recorded system proxy and re-enables Clash for Windows.")
	case "start", "restart":
		warnings = append(warnings, "Start/restart runs under the rollback watchdog and re-verifies SSH and egress before acknowledgement.")
	}
	p := ActionPlan{ID: id, Operation: operation, Root: status.Instance.Root, Service: status.Instance.Service, Running: status.Running, DataPreserved: true, Warnings: warnings, hostInstance: status.Instance, hostDigest: status.Instance.Digest}
	raw, _ := json.Marshal(struct {
		Plan       ActionPlan
		HostDigest string
	}{p, p.hostDigest})
	p.Digest = hashBytes(raw)
	return p, nil
}

func DarwinVergeLifecycle(ctx context.Context, id, operation, expected string, opts Options) (Receipt, error) {
	if opts.ReadOnly {
		return Receipt{}, errors.New("macOS Verge lifecycle is disabled in read-only mode")
	}
	unlock, err := mutationLock(id, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	p, err := DarwinVergePreviewAction(ctx, id, operation, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || expected != p.Digest {
		return Receipt{}, errors.New("macOS Verge action preview changed")
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
	if operation == "start" || operation == "restart" {
		return finishDarwinVergeActivation(ctx, instance, request, receipt, false, opts)
	}
	response, err := callDarwinVerge(ctx, instance.SSHHost, darwinVergeHostRequest(instance, request, operation), opts)
	if err != nil {
		receipt.Status = "unknown_host_result"
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	instance.Removed = operation == "remove"
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	receipt.Status = response.Status
	if pending, _ := response.Manifest["restore_incomplete"].([]any); len(pending) > 0 {
		receipt.Warnings = append(receipt.Warnings, fmt.Sprintf("Restore left %d item(s) for manual inspection: %v", len(pending), pending))
	}
	if operation == "remove" && opts.Unregister != nil {
		if err = opts.Unregister(id); err != nil {
			receipt.Status = "removed_registration_pending"
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
	}
	return receipt, saveReceipt(receipt, opts)
}

// darwinVergeSourceOperation edits the owned Verge data directory as the SSH
// user. Every path and guard must stay inside the recorded data directory.
func darwinVergeSourceOperation(ctx context.Context, target config.Target, instance Instance, operation configwork.HostRequest, opts Options) (configwork.HostResponse, error) {
	if instance.Removed || target.ID != instance.Target.ID || target.SSHHost != instance.SSHHost || target.Controller != instance.Target.Controller || !reflect.DeepEqual(target.ConfigSource, instance.Target.ConfigSource) {
		return configwork.HostResponse{}, errors.New("macOS Verge source binding differs from its owned instance")
	}
	data := instance.Target.ConfigSource.DataDir
	within := func(p string) bool { return p == "" || hostpath.Within("darwin", data, hostpath.Clean("darwin", p)) }
	if !within(operation.Path) {
		return configwork.HostResponse{}, errors.New("owned Verge source operations are limited to its data directory")
	}
	for _, guard := range operation.Guards {
		if !within(guard.Path) {
			return configwork.HostResponse{}, errors.New("owned Verge source guards are limited to its data directory")
		}
	}
	return configwork.DefaultHostOperation(ctx, target, operation)
}

func darwinActivateSource(ctx context.Context, instance Instance, opts Options) error {
	request, err := LoadRequest(instance.ID, opts)
	if err != nil {
		return err
	}
	response, err := callDarwinVerge(ctx, instance.SSHHost, darwinVergeRequest{Op: "activate-source", ID: instance.ID}, opts)
	if err != nil {
		return err
	}
	if !response.Running {
		return errors.New("Verge did not relaunch after the source change")
	}
	return darwinHealth(ctx, instance, request, false, opts, nil)
}
