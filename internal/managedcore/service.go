package managedcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

func normalize(request Request) (Request, error) {
	if request.Client != "" && request.Client != "mihomo" && request.Client != "verge" {
		return request, errors.New("client must be mihomo or verge")
	}
	if request.HostOS != "" && request.HostOS != "windows" && request.HostOS != "linux" && request.HostOS != "darwin" {
		return request, errors.New("host OS must be windows, linux or darwin")
	}
	if !idPattern.MatchString(request.ID) {
		return request, errors.New("core ID must be 1..48 lowercase letters, numbers, '-' or '_', starting with a letter or number")
	}
	if request.Backend == "" {
		request.Backend = "native"
	}
	if request.Backend != "native" && request.Backend != "docker" {
		return request, errors.New("backend must be native or docker")
	}
	if request.Version == "" {
		request.Version = DefaultVersion
	}
	if request.InputKind == "" {
		request.InputKind = "links"
	}
	if request.Preset == "" || request.Preset == "auto" {
		if request.InputKind == "yaml" {
			request.Preset = "preserve"
		} else {
			request.Preset = "cn-split"
		}
	}
	if request.ControllerPort == 0 {
		request.ControllerPort = 9090
	}
	if request.MixedPort == 0 {
		request.MixedPort = 7890
	}
	if request.ControllerPort < 1024 || request.ControllerPort > 65535 || request.MixedPort < 1024 || request.MixedPort > 65535 || request.ControllerPort == request.MixedPort {
		return request, errors.New("choose distinct controller and mixed ports in 1024..65535")
	}
	if request.ServiceScope == "" {
		request.ServiceScope = "user"
		if request.Network.TUN {
			request.ServiceScope = "system"
		}
	}
	if request.ServiceScope != "user" && request.ServiceScope != "system" {
		return request, errors.New("service scope must be user or system")
	}
	if request.Network.TUN && request.ServiceScope != "system" {
		return request, errors.New("host TUN requires a system-owned installation; select --service-scope system")
	}
	if request.ProxyListen != "" {
		ip, e := netip.ParseAddr(request.ProxyListen)
		if e != nil || !(netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)) {
			return request, errors.New("private gateway listener must be an explicit Tailscale IP")
		}
		if request.Network.TUN || request.Network.SystemProxy {
			return request, errors.New("a private gateway cannot own host TUN or system proxy settings")
		}
	}
	if request.ProxyGateway && (request.Network.TUN || request.Network.SystemProxy) {
		return request, errors.New("a private gateway cannot own host TUN or system proxy settings")
	}
	if err := config.ValidateTarget(config.Target{Controller: "http://127.0.0.1:9090", SSHHost: request.SSHHost}); err != nil {
		return request, err
	}
	return request, nil
}

func Preview(ctx context.Context, request Request, opts Options) (Plan, error) {
	if request.HostOS == "windows" {
		return PreviewWindows(ctx, request, opts)
	}
	if request.Client == "verge" {
		return Plan{}, errors.New("managed Verge deployment requires a Windows host")
	}
	return preview(ctx, request, opts, nil)
}

func preview(ctx context.Context, request Request, opts Options, current *Instance) (Plan, error) {
	var cleanup func()
	var routeErr error
	ctx, cleanup, routeErr = withDownloadClient(ctx, request, opts)
	if routeErr != nil {
		return Plan{}, routeErr
	}
	defer cleanup()
	request, err := normalize(request)
	if err != nil {
		return Plan{}, err
	}
	response, err := callHost(ctx, request.SSHHost, false, hostRequest{Op: "facts", ID: request.ID, Backend: request.Backend, ServiceScope: request.ServiceScope, DockerContext: request.DockerContext, DockerArchive: request.DockerArchive, Ports: []int{request.ControllerPort, request.MixedPort}}, opts)
	if err != nil {
		return Plan{}, err
	}
	host := response.Facts
	if request.DockerArchive != "" && (request.Backend != "docker" || !digestPattern.MatchString(request.DockerArchiveSHA256) || request.DockerArchiveSHA256 != host.ArchiveSHA256) {
		return Plan{}, errors.New("Docker archive on the selected host must match the explicit --docker-archive-sha256")
	}

	plan := Plan{current: current, ID: request.ID, Request: request, Host: host, Controller: fmt.Sprintf("http://127.0.0.1:%d", request.ControllerPort), ProbeProxy: fmt.Sprintf("http://127.0.0.1:%d", request.MixedPort), InputSHA256: hashBytes(request.Input), Warnings: []string{}, Blockers: []string{}, Changes: []string{}, NeedsPrivilege: request.ServiceScope == "system"}
	if request.ProxyListen != "" {
		plan.ProbeProxy = "http://" + net.JoinHostPort(request.ProxyListen, fmt.Sprint(request.MixedPort))
	}
	if host.OS != "darwin" && host.OS != "linux" {
		plan.Blockers = append(plan.Blockers, "managed clients support macOS and Linux")
	}
	if host.Arch != "amd64" && host.Arch != "arm64" {
		plan.Blockers = append(plan.Blockers, "managed native platforms are amd64 and arm64")
	}
	if current == nil && host.Existing {
		plan.Blockers = append(plan.Blockers, "installation ID/path already exists; an external or existing instance will not be overwritten")
	}
	if len(host.BusyPorts) > 0 && current == nil {
		plan.Blockers = append(plan.Blockers, "one or more selected ports are in use; choose unused ports without stopping the current owner")
	}
	if request.Backend == "native" {
		if host.OS == "linux" && !host.Systemd || host.OS == "darwin" && !host.Launchd {
			plan.Blockers = append(plan.Blockers, "the selected native service manager is unavailable")
		}
		if !host.Sandbox {
			plan.Blockers = append(plan.Blockers, "isolated native validation requires bubblewrap on Linux or sandbox-exec on macOS")
		}
	} else {
		if !host.Docker {
			plan.Blockers = append(plan.Blockers, "an existing accessible Docker daemon and Compose plugin are required")
		}
		if !strings.HasPrefix(host.DockerEndpoint, "unix://") {
			plan.Blockers = append(plan.Blockers, "select a local Unix Docker daemon on this host, not a daemon on another host")
		}
		if request.Network.TUN && (host.OS != "linux" || host.DockerRootless || host.DockerOS != "linux") {
			plan.Blockers = append(plan.Blockers, "host Docker TUN requires rootful Docker Engine on Linux; use native for macOS TUN")
		}
	}
	root := filepath.Join(host.Home, ".local", "share", "lazyclash", "cores", request.ID)
	if request.ServiceScope == "system" {
		if host.OS == "darwin" {
			root = filepath.Join("/Library/Application Support/lazyclash/cores", request.ID)
		} else {
			root = filepath.Join("/var/lib/lazyclash/cores", request.ID)
		}
	}
	plan.Root = root
	plan.Service = "lazyclash-mihomo-" + request.ID + ".service"
	if host.OS == "darwin" {
		plan.Service = "io.lazyclash.mihomo." + request.ID
	}
	if request.Backend == "docker" {
		plan.Service = "lazyclash_" + request.ID
	}
	if opts.NetworkPlan != nil {
		network, warnings, blockers, e := opts.NetworkPlan(ctx, request.SSHHost, request.Network)
		if e != nil {
			return plan, e
		}
		request.Network = network
		plan.Warnings = append(plan.Warnings, warnings...)
		plan.Blockers = append(plan.Blockers, blockers...)
	} else {
		report, e := networkcheck.Inspect(ctx, request.SSHHost)
		if e != nil {
			return plan, e
		}
		if request.Network.TUN {
			if current != nil && current.Network.TUN {
				open := opts.Open
				if open == nil {
					open = connection.Open
				}
				client, closer, e := open(ctx, current.Target, true)
				if e == nil {
					settings, e := client.Config(ctx)
					if e == nil {
						tun, _ := settings["tun"].(map[string]any)
						enabled, _ := tun["enable"].(bool)
						device, _ := tun["device"].(string)
						report = networkcheck.WithCoreTUNDevice(report, enabled, device)
					}
					client.Close()
					if closer != nil {
						closer.Close()
					}
				}
			}
			tun, e := networkcheck.PlanTUN(report, request.Network.ExcludedRoutes, current != nil && current.Network.TUN)
			if e != nil {
				return plan, e
			}
			if tun.Blocked {
				plan.Blockers = append(plan.Blockers, "another VPN/default-route owner conflicts with TUN; choose and remediate one owner before activation")
			}
			request.Network.ExcludedRoutes, _ = tun.Settings["route-exclude-address"].([]string)
			request.Network.DNSPolicies = tun.DNSPolicies
			request.Network.FakeIPFilter = tun.FakeIPFilter
		} else {
			request.Network.ExcludedRoutes = append(request.Network.ExcludedRoutes, report.ExcludedRoutes...)
			request.Network.DNSPolicies = report.DNSPolicies
			request.Network.FakeIPFilter = report.FakeIPFilter
		}
		for _, finding := range report.Conflicts {
			if finding.Level != "information" {
				plan.Warnings = append(plan.Warnings, finding.Message)
			}
		}
	}
	request.Network.ExcludedRoutes = uniqueStrings(request.Network.ExcludedRoutes)
	request.Network.FakeIPFilter = uniqueStrings(request.Network.FakeIPFilter)
	if request.Network.SystemProxy {
		request.Network.ProxyExceptions = append(request.Network.ProxyExceptions, "localhost", "127.0.0.1", "::1")
		request.Network.ProxyExceptions = append(request.Network.ProxyExceptions, request.Network.ExcludedRoutes...)
		for _, suffix := range request.Network.FakeIPFilter {
			request.Network.ProxyExceptions = append(request.Network.ProxyExceptions, "*."+strings.TrimPrefix(suffix, "+."))
		}
		request.Network.ProxyExceptions = uniqueStrings(request.Network.ProxyExceptions)
		reader := opts.ReadSystemProxy
		if reader == nil {
			reader = networkcheck.ReadSystemProxy
		}
		snapshot, e := reader(ctx, request.SSHHost, request.Network.Services)
		if e != nil {
			return plan, e
		}
		proxy, e := networkcheck.PlanSystemProxyWithSOCKS(snapshot, plan.ProbeProxy, fmt.Sprintf("socks5://127.0.0.1:%d", request.MixedPort), request.Network.ProxyExceptions)
		if e != nil {
			plan.Blockers = append(plan.Blockers, e.Error())
		} else {
			plan.systemProxy = &proxy
			redacted := proxy.Redacted()
			plan.SystemProxy = &redacted
			if proxy.Backend == "macos-networksetup" {
				plan.NeedsPrivilege = true
			}
		}
	}
	plan.Request = request
	if current != nil {
		old, e := LoadRequest(current.ID, opts)
		if e != nil {
			return plan, e
		}
		if old.ControllerPort != request.ControllerPort || old.MixedPort != request.MixedPort || old.Boot != request.Boot || old.SSHHost != request.SSHHost || old.DockerContext != request.DockerContext || old.ProxyListen != request.ProxyListen || old.ProxyGateway != request.ProxyGateway {
			plan.Blockers = append(plan.Blockers, "configure retains host, ports, boot policy and Docker context; create a separately reviewed instance to migrate them")
		}
	}
	if current != nil && (current.Backend != request.Backend || current.ServiceScope != request.ServiceScope || current.Version != request.Version) {
		plan.Blockers = append(plan.Blockers, "configure retains backend, service scope and core version; create a separately reviewed instance to migrate them")
	}
	resolver := opts.ResolveArtifact
	if resolver == nil {
		resolver = resolveOfficialArtifact
	}
	if current != nil {
		plan.Artifact = current.Artifact
	} else {
		plan.Artifact, err = resolver(ctx, request, host)
		if err != nil {
			return plan, err
		}
	}
	plan.ResourceOrigins = map[string]string{}
	profileCtx := context.WithValue(ctx, profileOriginsKey{}, plan.ResourceOrigins)
	profile, resources, rulesVersion, warnings, err := buildProfile(profileCtx, request)
	if err != nil {
		return plan, err
	}
	plan.profile, plan.resources, plan.RulesVersion = profile, resources, rulesVersion
	plan.ProfileSHA256 = hashBytes(profile)
	plan.ResourceInventory = sortedResourceNames(resources)
	plan.ResourceSHA256 = map[string]string{}
	for name, data := range resources {
		plan.ResourceSHA256[name] = hashBytes(data)
	}
	plan.Warnings = append(plan.Warnings, warnings...)
	plan.Changes = []string{"Create or update only this explicitly owned instance: " + root, "Listen on loopback controller and data-proxy ports with a generated private API secret", "Validate the candidate in isolated storage before starting its service", "Verify API authentication and record explicit proxy connectivity separately"}
	if request.ProxyListen != "" {
		plan.Changes[1] = "Listen on the explicit Tailscale data-proxy address with required authentication; keep the controller private"
	}
	if current != nil {
		plan.Changes[0] = "Configure owned instance: " + root
	}
	if request.Network.TUN {
		plan.Warnings = append(plan.Warnings, "TUN changes host routing. Coexistence exclusions are separate from DNS policy and proxy bypass; strict routing and automatic TCP redirection remain disabled.")
	}
	if request.Boot && request.ServiceScope == "user" {
		plan.Warnings = append(plan.Warnings, "User services require the user's service session; Linux boot without login also requires an existing linger policy. No login policy is changed automatically.")
	}
	if request.Network.TUN || request.Network.SystemProxy {
		plan.Warnings = append(plan.Warnings, "Network activation arms a host-side rollback deadline; a new authenticated management read must succeed before acknowledgement.")
	}
	copy := plan
	copy.Digest = ""
	copy.Host.BusyPorts = nil
	if current != nil {
		copy.Host.ExistingDigest = current.Digest
	}
	data, _ := json.Marshal(copy)
	plan.Digest = hashBytes(data)
	return plan, nil
}

func Apply(ctx context.Context, request Request, expected string, opts Options) (Receipt, error) {
	if request.HostOS == "windows" {
		return ApplyWindows(ctx, request, expected, opts)
	}
	if opts.ReadOnly {
		return Receipt{}, errors.New("managed installation is disabled in read-only mode")
	}
	ctx, cleanup, err := withDownloadClient(ctx, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer cleanup()
	plan, err := Preview(ctx, request, opts)
	if err != nil {
		return Receipt{}, err
	}
	if expected == "" || plan.Digest != expected {
		return Receipt{}, errors.New("setup preview changed; review the current digest before applying")
	}
	if len(plan.Blockers) > 0 {
		return Receipt{}, fmt.Errorf("setup blocked: %s", strings.Join(plan.Blockers, "; "))
	}
	request = plan.Request
	unlock, err := mutationLock(request.ID, opts)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()

	if _, err := loadInstance(request.ID, opts); err == nil {
		return Receipt{}, errors.New("managed ID is already recorded locally")
	}
	secret, err := randomHex(32)
	if err != nil {
		return Receipt{}, err
	}
	owner, err := randomHex(24)
	if err != nil {
		return Receipt{}, err
	}
	state, err := instanceDir(request.ID, opts)
	if err != nil {
		return Receipt{}, err
	}
	secretPath := filepath.Join(state, "controller.secret")
	profile, err := injectControllerSecret(plan.profile, secret)
	if err != nil {
		return Receipt{}, err
	}
	var artifact []byte
	if request.Backend == "native" {
		if request.ArtifactFile != "" {
			info, e := os.Stat(request.ArtifactFile)
			if e != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
				return Receipt{}, errors.New("offline artifact must be a bounded regular compressed release file")
			}
			artifact, err = os.ReadFile(request.ArtifactFile)
		} else {
			fetch := opts.FetchArtifact
			if fetch == nil {
				fetch = fetchOfficialArtifact
			}
			artifact, err = fetch(ctx, plan.Artifact)
		}
		if err != nil {
			return Receipt{}, err
		}
		if hashBytes(artifact) != plan.Artifact.SHA256 {
			return Receipt{}, errors.New("Mihomo artifact does not match the verified official release")
		}
	}
	if err = writePrivate(secretPath, []byte(secret+"\n")); err != nil {
		return Receipt{}, err
	}
	instance := Instance{ID: request.ID, Name: request.Name, SSHHost: request.SSHHost, Backend: request.Backend, Version: request.Version, Artifact: plan.Artifact, Root: plan.Root, Service: plan.Service, ServiceScope: request.ServiceScope, DockerContext: request.DockerContext, DockerEndpoint: plan.Host.DockerEndpoint, OS: plan.Host.OS, ResourceInventory: plan.ResourceInventory, OwnerToken: owner, ProfileSHA256: hashBytes(profile), RulesVersion: plan.RulesVersion, Network: request.Network, Boot: request.Boot, CreatedAt: opts.now()}
	if request.Preset == "cn-split" || request.Preset == "simple" {
		instance.ActivePreset = request.Preset
	}
	instance.Target = targetForInstance(instance, plan, secretPath)
	request, err = persistProfileSnapshot(instance, request, profile, plan.resources, opts)
	if err != nil {
		return Receipt{}, err
	}
	receipt := newReceipt(instance, "install", plan.Digest, opts)
	receipt.Status = "operation_started"
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	if err = saveReceipt(receipt, opts); err != nil {
		return receipt, err
	}
	response, err := callHost(ctx, request.SSHHost, request.ServiceScope == "system", hostRequest{Op: "install", ID: request.ID, Root: plan.Root, Backend: request.Backend, Version: request.Version, ServiceScope: request.ServiceScope, DockerEndpoint: plan.Host.DockerEndpoint, Ports: []int{request.ControllerPort, request.MixedPort}, ProxyListen: request.ProxyListen, ProxyUDP: request.ProxyUDP, OwnerToken: owner, Profile: profile, ProfileSHA256: hashBytes(profile), Resources: plan.resources, Artifact: artifact, ArtifactSHA256: plan.Artifact.SHA256, DockerArchive: request.DockerArchive, DockerArchiveSHA256: request.DockerArchiveSHA256, ConfigSHA256: plan.Artifact.ConfigSHA256, Image: plan.Artifact.Image, Platform: plan.Artifact.Platform, Network: request.Network, Boot: request.Boot}, opts)
	if err != nil {
		if response.Status == "not_installed" {
			receipt.Status = "not_installed"
			receipt.Message = "Host confirmed no managed instance was created. The failed private draft is retained; fix the input and retry this ID."
			root, e := stateRoot(opts)
			if e == nil {
				failed := filepath.Join(root, "failed", receipt.ID)
				e = os.MkdirAll(filepath.Dir(failed), 0700)
				if e == nil {
					e = os.Rename(state, failed)
				}
			}
			if e != nil {
				receipt.Message = "Host confirmed no managed instance was created; local failed-draft cleanup requires inspection before reusing this ID."
			}
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
		receipt.Status = "unknown_host_result"
		receipt.Message = "Host operation did not return a confirmed result; inspect the managed instance before retrying."
		_ = saveReceipt(receipt, opts)
		return receipt, err
	}
	instance.Digest = response.Digest
	instance.CoreGuardRef = response.GuardRef
	response.ProxyPlan = plan.systemProxy
	if err = saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}
	receipt.Status = response.Status
	receipt.Target = instance.Target
	if response.Status == "installed_start_failed" {
		_ = saveReceipt(receipt, opts)
		return receipt, errors.New("Mihomo was installed but its service did not start; private files were retained")
	}
	return finishActivation(ctx, instance, request, response, receipt, opts)
}

func targetForInstance(instance Instance, plan Plan, secretPath string) config.Target {
	target := config.Target{Checks: plan.Request.CloneChecks, ID: instance.ID, Name: instance.Name, SSHHost: instance.SSHHost, Controller: plan.Controller, ProbeProxy: plan.ProbeProxy, SecretFile: secretPath, ManagedCoreID: instance.ID}
	corePath := filepath.Join(instance.Root, "home", "config.yaml")
	binary := filepath.Join(instance.Root, "bin", "mihomo")
	home := filepath.Join(instance.Root, "home")
	source := &config.ConfigSource{Kind: "native", ConfigID: "managed", Binary: binary, Home: home}
	if instance.Backend == "docker" {
		corePath = "/root/.config/mihomo/config.yaml"
		source = &config.ConfigSource{Kind: "docker", ConfigID: "managed", HostPath: filepath.Join(instance.Root, "home", "config.yaml"), CorePath: corePath, Binary: "/mihomo", Home: "/root/.config/mihomo", Container: "lazyclash_" + instance.ID + "-mihomo-1"}
	}
	target.Configs = []config.CoreConfig{{ID: "managed", Name: "Managed source", Path: corePath}}
	target.ConfigSource = source
	// New installations own this exact profile for both editing capabilities.
	// Existing saved targets are not migrated by read operations.
	target.RuleSource, _ = config.RuleSourceFromConfigSource(target)
	return target
}

func finishActivation(ctx context.Context, instance Instance, request Request, response hostResponse, receipt Receipt, opts Options) (Receipt, error) {
	if response.AckToken != "" || response.ProxyPlan != nil {
		if err := verifyFreshManagement(ctx, instance.SSHHost, opts); err != nil {
			return activationFailure(receipt, response, "Fresh management transport could not be confirmed; rollback remains armed.", err, opts)
		}
	}
	healthCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	var healthErr error
	for {
		client, closer, err := open(healthCtx, instance.Target, true)
		healthErr = err
		if err == nil {
			version, e := client.Version(healthCtx)
			_, configErr := client.Config(healthCtx)
			client.Close()
			if closer != nil {
				closer.Close()
			}
			if version["version"] != instance.Version {
				healthErr = errors.New("running core version differs from the installed artifact")
			} else if e != nil {
				healthErr = e
			} else {
				healthErr = configErr
			}
			if healthErr == nil {
				break
			}
		}
		select {
		case <-healthCtx.Done():
			healthErr = healthCtx.Err()
		case <-time.After(250 * time.Millisecond):
			continue
		}
		break
	}
	if healthErr != nil {
		receipt.Status = "running_management_unverified"
		receipt.NeedsACK = response.AckToken != ""
		receipt.RollbackDeadline = time.Unix(response.Deadline, 0)
		receipt.Message = "Management verification failed; any armed host rollback remains active."
		_ = saveReceipt(receipt, opts)
		return receipt, healthErr
	}
	if receipt.Operation == "install" && len(request.CloneSelections) > 0 {
		if err := applyCloneSelections(healthCtx, instance.Target, request.CloneSelections, opts); err != nil {
			receipt.Status = "running_clone_selections_unverified"
			receipt.Message = "The client started, but the reviewed manual selections could not be verified."
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
	}
	probe := opts.Probe
	if probe == nil {
		probe = func(ctx context.Context, target config.Target) error {
			_, e := diagnostics.Latency(ctx, target, diagnostics.Options{})
			return e
		}
	}
	probeErr := probe(healthCtx, instance.Target)
	receipt.ProxyHealthy = probeErr == nil
	if response.AckToken != "" {
		ackReq := lifecycleRequest(instance, request, "ack")
		ackReq.AckToken = response.AckToken
		ackReq.GuardRef = response.GuardRef
		ackReq.Expected = ""
		ack, err := callHost(ctx, instance.SSHHost, false, ackReq, opts)
		if err != nil || ack.Status != "acknowledged" {
			if err == nil {
				err = errors.New("host rollback worker has not acknowledged connectivity")
			}
			return activationFailure(receipt, response, "Host network acknowledgement remains pending.", err, opts)
		}
	}
	if response.ProxyPlan != nil {
		proxyRequest := lifecycleRequest(instance, request, "activate-proxy")
		proxyRequest.SystemProxy = response.ProxyPlan
		proxyRequest.PreviousGuardRef = instance.ProxyGuardRef
		proxyRequest.Expected = ""
		proxyResponse, err := callHost(ctx, instance.SSHHost, instance.OS == "darwin", proxyRequest, opts)
		if err != nil {
			return activationFailure(receipt, proxyResponse, "System proxy activation is unconfirmed; inspect the owned network receipt.", err, opts)
		}
		instance.ProxyGuardRef = proxyResponse.GuardRef
		if err = saveInstance(instance, request, opts); err != nil {
			return receipt, err
		}
		if proxyResponse.Status != "applied" {
			return activationFailure(receipt, proxyResponse, "System proxy changed partially or conflicted; rollback remains armed.", errors.New("system proxy was not fully applied"), opts)
		}
		if err = verifyFreshManagement(ctx, instance.SSHHost, opts); err != nil {
			return activationFailure(receipt, proxyResponse, "Fresh management transport after system proxy change failed.", err, opts)
		}
		client, closer, err := open(ctx, instance.Target, true)
		if err == nil {
			_, err = client.Config(ctx)
			client.Close()
			if closer != nil {
				closer.Close()
			}
		}
		if err != nil {
			return activationFailure(receipt, proxyResponse, "Controller read after system proxy change failed.", err, opts)
		}
		proxyRequest.Op = "ack-proxy"
		proxyRequest.GuardRef = proxyResponse.GuardRef
		proxyRequest.AckToken = proxyResponse.AckToken
		proxyRequest.SystemProxy = nil
		ack, err := callHost(ctx, instance.SSHHost, false, proxyRequest, opts)
		if err != nil || ack.Status != "acknowledged" {
			if err == nil {
				err = errors.New("system proxy acknowledgement remains pending")
			}
			return activationFailure(receipt, proxyResponse, "System proxy rollback remains active.", err, opts)
		}
	}
	if request.Boot {
		finalized, err := callHost(ctx, instance.SSHHost, instance.ServiceScope == "system", lifecycleRequest(instance, request, "finalize"), opts)
		if err != nil || finalized.Status != "finalized" {
			if err == nil {
				err = errors.New("boot policy could not be finalized")
			}
			return activationFailure(receipt, hostResponse{}, "Service is verified; boot policy still needs inspection.", err, opts)
		}
	}
	if err := saveInstance(instance, request, opts); err != nil {
		return receipt, err
	}

	receipt.Status = "running_verified"
	if probeErr != nil {
		receipt.Status = "running_proxy_unverified"
		receipt.Message = "The authenticated controller is reachable; one or more outbound probes failed. Inspect nodes, DNS and the explicit proxy route."
	}
	if opts.Register != nil {
		if err := opts.Register(instance.Target); err != nil {
			receipt.Status = "installed_unregistered"
			receipt.Message = "Installation succeeded but local target registration failed; no other saved target was overwritten."
			_ = saveReceipt(receipt, opts)
			return receipt, err
		}
	}
	_ = saveReceipt(receipt, opts)
	return receipt, nil
}

func randomHex(n int) (string, error) {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func newReceipt(instance Instance, operation, digest string, opts Options) Receipt {
	id, _ := randomHex(12)
	return Receipt{ID: id, InstanceID: instance.ID, Operation: operation, Digest: digest, CreatedAt: opts.now(), Target: instance.Target, DataPreserved: true}
}

func activationFailure(receipt Receipt, response hostResponse, message string, err error, opts Options) (Receipt, error) {
	receipt.Status = "running_pending_verification"
	receipt.NeedsACK = response.AckToken != ""
	if response.Deadline > 0 {
		receipt.RollbackDeadline = time.Unix(response.Deadline, 0)
	}
	receipt.Message = message
	if e := saveReceipt(receipt, opts); e != nil {
		return receipt, e
	}
	return receipt, err
}
func verifyFreshManagement(ctx context.Context, host string, opts Options) error {
	if host == "" {
		return nil
	}
	if opts.FreshManagement != nil {
		return opts.FreshManagement(ctx, host)
	}
	err := connection.VerifyFreshSSH(ctx, host)
	if err == nil {
		return nil
	}
	if !connection.IsAuthRequired(err) || opts.Foreground == nil {
		return err
	}
	cmd, e := connection.FreshSSHAuthenticationCommand(ctx, host)
	if e != nil {
		return e
	}
	return opts.Foreground(cmd)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
