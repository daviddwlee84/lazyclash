// Package doctor aggregates passive, local-only proxy evidence. It never tests
// egress, changes state, opens SSH, or treats controller access as a data test.
package doctor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/networkcheck"
	"github.com/daviddwlee84/lazyclash/internal/proxyenv"
)

const DefaultTimeout = 10 * time.Second

type Status string

const (
	Pass    Status = "pass"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Unknown Status = "unknown"
	Skip    Status = "skip"
)

type Check struct {
	ID         string `json:"id"`
	Status     Status `json:"status"`
	Required   bool   `json:"required"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

type Selection struct {
	Source     string   `json:"source"`
	TargetID   string   `json:"target_id,omitempty"`
	Controller string   `json:"controller,omitempty"`
	Local      bool     `json:"local"`
	Candidates []string `json:"candidates,omitempty"`
}

type Runtime struct {
	IdentityVerified bool   `json:"identity_verified"`
	Mode             string `json:"mode,omitempty"`
	MixedPort        int    `json:"mixed_port"`
	HTTPPort         int    `json:"http_port"`
	SOCKSPort        int    `json:"socks_port"`
	TUNKnown         bool   `json:"tun_known"`
	TUNEnabled       bool   `json:"tun_enabled"`
	TUNDevice        string `json:"tun_device,omitempty"`
}

type Environment struct {
	Variables  map[string]string `json:"variables"`
	NoProxySet bool              `json:"no_proxy_set"`
}

type DataEndpoint struct {
	Source string `json:"source"`
	HTTP   string `json:"http,omitempty"`
	SOCKS  string `json:"socks,omitempty"`
	Tested bool   `json:"tested"`
}

// SystemService deliberately excludes PAC URLs and exception lists. Their
// paths/queries may carry tokens; neither is needed for passive comparison.
type SystemService struct {
	Name          string `json:"name"`
	HTTP          string `json:"http,omitempty"`
	HTTPS         string `json:"https,omitempty"`
	SOCKS         string `json:"socks,omitempty"`
	PACEnabled    bool   `json:"pac_enabled"`
	AutoDiscovery bool   `json:"auto_discovery"`
}

type SystemProxy struct {
	Available bool            `json:"available"`
	Backend   string          `json:"backend,omitempty"`
	Services  []SystemService `json:"services"`
}

type Network struct {
	OS            string                    `json:"os"`
	Capabilities  []networkcheck.Capability `json:"capabilities"`
	Interfaces    []string                  `json:"interfaces"`
	DefaultRoutes []networkcheck.Route      `json:"default_routes"`
	DNSServers    []string                  `json:"dns_servers"`
}

type Summary struct {
	Pass     int  `json:"pass"`
	Warn     int  `json:"warn"`
	Fail     int  `json:"fail"`
	Unknown  int  `json:"unknown"`
	Skip     int  `json:"skip"`
	Complete bool `json:"complete"`
	Canceled bool `json:"canceled"`
	TimedOut bool `json:"timed_out"`
	ExitCode int  `json:"exit_code"`
}

type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Scope         string       `json:"scope"`
	Selection     Selection    `json:"selection"`
	Checks        []Check      `json:"checks"`
	Environment   Environment  `json:"environment"`
	DataEndpoint  DataEndpoint `json:"data_endpoint"`
	Runtime       *Runtime     `json:"runtime,omitempty"`
	SystemProxy   *SystemProxy `json:"system_proxy,omitempty"`
	Network       *Network     `json:"network,omitempty"`
	Summary       Summary      `json:"summary"`
	Suggestions   []string     `json:"suggestions"`
}

type Request struct {
	SettingsPath     string
	ExplicitSettings bool
	TargetID         string
	Controller       string
	SSHHost          string
	SecretEnv        string
	SecretFile       string
	CAFile           string
	Timeout          time.Duration
}

// Collectors must honor context and return sanitized/typed evidence. Run also
// bounds waiting, so a slow optional collector cannot withhold the whole report.
// DiscoverLocal is a separate seam: general discovery must never be injected here.
type Options struct {
	Load            func(string, bool) (config.Config, error)
	Open            func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
	DiscoverLocal   func(context.Context) ([]config.Target, error)
	Environment     func() map[string]any
	ReadSystemProxy func(context.Context, string, []string) (networkcheck.SystemProxySnapshot, error)
	Inspect         func(context.Context, string, networkcheck.InspectOptions) (networkcheck.Report, error)
	Getenv          func(string) string
}

func (o Options) defaults() Options {
	if o.Load == nil {
		o.Load = config.Load
	}
	if o.Open == nil {
		o.Open = connection.Open
	}
	if o.DiscoverLocal == nil {
		o.DiscoverLocal = connection.DiscoverLocal
	}
	if o.Environment == nil {
		o.Environment = proxyenv.EnvironmentStatus
	}
	if o.ReadSystemProxy == nil {
		o.ReadSystemProxy = networkcheck.ReadSystemProxy
	}
	if o.Inspect == nil {
		o.Inspect = networkcheck.InspectWithOptions
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	return o
}

// Run always returns a report, including when settings, authentication, or the
// controller are unavailable. Only explicit CLI syntax validation precedes it.
func Run(parent context.Context, request Request, opts Options) Report {
	opts = opts.defaults()
	if request.Timeout <= 0 {
		request.Timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, request.Timeout)
	defer cancel()
	r := Report{SchemaVersion: 1, Scope: "local-passive", Selection: Selection{Source: "local-auto"},
		Environment: Environment{Variables: map[string]string{}}, Suggestions: []string{}}
	for _, id := range []string{"settings", "selection", "controller", "runtime", "environment", "system_proxy", "network", "consistency", "egress"} {
		r.Checks = append(r.Checks, Check{ID: id, Status: Unknown, Required: id == "settings" || id == "selection" || id == "controller" || id == "runtime", Message: "Not collected; a prerequisite was unavailable or the diagnostic deadline was reached."})
	}
	// Each worker publishes small immutable snapshots as they become available;
	// the receiver alone owns the report. Buffered sends cannot strand a worker
	// if the caller stops waiting on cancellation.
	updates := make(chan func(*Report), 16)
	done := make(chan struct{}, 4)
	go func() { defer func() { done <- struct{}{} }(); collectController(ctx, request, opts, updates) }()
	go func() { defer func() { done <- struct{}{} }(); collectSystem(ctx, opts, updates) }()
	go func() { defer func() { done <- struct{}{} }(); collectNetwork(ctx, opts, updates) }()
	go func() {
		defer func() { done <- struct{}{} }()
		env := opts.Environment()
		result := Environment{Variables: map[string]string{}}
		if vars, ok := env["variables"].(map[string]string); ok {
			for _, key := range proxyenv.Variables {
				if value := vars[key]; value != "" {
					result.Variables[key] = safeEndpoint(value)
				}
			}
		}
		result.NoProxySet, _ = env["no_proxy_set"].(bool)
		updates <- func(r *Report) {
			r.Environment = result
			r.set(Check{ID: "environment", Status: Pass, Message: "Process proxy variables read; applications may ignore them or apply NO_PROXY differently. No variables is not a failure."})
		}
	}()
	remaining := 4
collect:
	for remaining > 0 {
		select {
		case update := <-updates:
			update(&r)
		case <-done:
			remaining--
		case <-ctx.Done():
			break collect
		}
	}
	for {
		select {
		case update := <-updates:
			update(&r)
		default:
			goto collected
		}
	}
collected:
	r.set(Check{ID: "egress", Status: Skip, Message: "Egress connectivity not tested. Controller reachability does not prove the proxy data path works.", Suggestion: "For an explicit active test, use proxy test or diagnostics url after choosing the intended scope."})
	compare(&r)
	r.Summary.Canceled = errors.Is(parent.Err(), context.Canceled)
	r.Summary.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	r.summarize()
	return r
}

func (r *Report) set(check Check) {
	for i := range r.Checks {
		if r.Checks[i].ID == check.ID {
			check.Required = r.Checks[i].Required
			r.Checks[i] = check
			return
		}
	}
}

func publish(updates chan<- func(*Report), check Check) {
	updates <- func(r *Report) { r.set(check) }
}

func collectController(ctx context.Context, request Request, opts Options, updates chan<- func(*Report)) {
	if ctx.Err() != nil {
		return
	}
	data := DataEndpoint{}
	if request.TargetID == "" && request.Controller == "" && opts.Getenv("LOCAL_PROXY_URL") != "" {
		data = DataEndpoint{Source: "LOCAL_PROXY_URL", HTTP: safeEndpoint(opts.Getenv("LOCAL_PROXY_URL")), SOCKS: safeEndpoint(opts.Getenv("LOCAL_PROXY_SOCKS_URL"))}
		initialData := data
		updates <- func(r *Report) { r.DataEndpoint = initialData }
	}
	explicitUnsupported := request.SSHHost != "" || (request.Controller != "" && !proxyenv.IsLocalTarget(config.Target{Controller: request.Controller}))
	if explicitUnsupported {
		source := "explicit-controller"
		if request.SSHHost != "" {
			source = "explicit-ssh"
		}
		unsupported(updates, source)
	}
	// Load explicitly to retain the distinction between an absent default file
	// (normal, no registrations) and an explicitly missing settings file.
	path := request.SettingsPath
	var cfg config.Config
	var err error
	if path == "" {
		path, err = config.DefaultPath()
	}
	if err == nil {
		cfg, err = opts.Load(path, true)
	}
	settingsOK := err == nil
	if err != nil && !request.ExplicitSettings && errors.Is(err, os.ErrNotExist) {
		settingsOK = true
		publish(updates, Check{ID: "settings", Status: Warn, Message: "Default settings file is absent; checking local discovery without creating it."})
	} else if err != nil {
		publish(updates, Check{ID: "settings", Status: Fail, Message: "Settings could not be read or validated.", Suggestion: "Check settings path and TOML syntax with settings path / settings edit; doctor did not change the file."})
	} else {
		publish(updates, Check{ID: "settings", Status: Pass, Message: "Settings loaded and validated."})
	}
	if !settingsOK {
		cfg = config.Config{}
	}
	if ctx.Err() != nil || explicitUnsupported {
		return
	}
	var target config.Target
	source := "local-auto"
	switch {
	case request.Controller != "":
		source = "explicit-controller"
		target = config.Target{Controller: request.Controller, ID: "temporary"}
	case request.TargetID != "":
		source = "explicit-target"
		for _, candidate := range cfg.Targets {
			if candidate.ID == request.TargetID {
				target = candidate
				break
			}
		}
		if target.Controller == "" {
			publish(updates, Check{ID: "selection", Status: Fail, Message: "Explicit target could not be resolved; no local fallback was attempted.", Suggestion: "Check settings and targets list, then select --target LOCAL."})
			updates <- func(r *Report) { r.Selection.Source = source }
			return
		}
	default:
		// Do not use the global remote default, or general (possibly remote)
		// discovery. The safety restriction is inside DiscoverLocal, before I/O.
		target, err = proxyenv.SelectLocalTarget(ctx, cfg, proxyenv.Options{Discover: func(ctx context.Context, host string) ([]config.Target, error) {
			return opts.DiscoverLocal(ctx)
		}})
		if err != nil {
			check := Check{ID: "selection", Status: Fail, Message: "No local controller candidate was identified; this does not mean there is no proxy.", Suggestion: "Select --target LOCAL or --controller LOOPBACK; check whether its controller API is enabled."}
			var ambiguous *proxyenv.AmbiguousError
			if errors.As(err, &ambiguous) {
				check.Message = "Multiple local controllers are available; none was selected."
				check.Suggestion = "Select one with --target LOCAL or --controller LOOPBACK."
				ids := []string{}
				for _, candidate := range ambiguous.Targets {
					ids = append(ids, safeText(candidate.ID))
				}
				updates <- func(r *Report) { r.Selection.Candidates = ids }
			}
			publish(updates, check)
			return
		}
		if target.ID == cfg.DefaultTarget {
			source = "local-default"
		} else {
			source = "sole-local-candidate"
		}
	}
	if !proxyenv.IsLocalTarget(target) {
		unsupported(updates, source)
		return
	}
	if request.SecretEnv != "" {
		target.SecretEnv, target.SecretFile, target.Secret = request.SecretEnv, "", ""
	}
	if request.SecretFile != "" {
		target.SecretFile, target.SecretEnv, target.Secret = request.SecretFile, "", ""
	}
	if request.CAFile != "" {
		target.CAFile = request.CAFile
	}
	if request.Controller != "" && target.SecretEnv == "" && target.SecretFile == "" && opts.Getenv("CLASH_SECRET") != "" {
		target.SecretEnv = "CLASH_SECRET"
	}
	selection := Selection{Source: source, TargetID: safeText(target.ID), Controller: safeEndpoint(target.Controller), Local: true}
	// Endpoint intent is independent from the controller. Explicit target or
	// controller selection takes precedence over LOCAL_PROXY_URL.
	if data.Source == "" && target.ProbeProxy != "" {
		data = DataEndpoint{Source: "registered data proxy", HTTP: safeEndpoint(target.ProbeProxy)}
	}
	initialData := data
	updates <- func(r *Report) {
		r.Selection = selection
		r.DataEndpoint = initialData
		r.set(Check{ID: "selection", Status: Pass, Message: "Selected a local controller; controller and data endpoint selection are independent."})
	}
	if ctx.Err() != nil {
		return
	}
	client, closer, err := opts.Open(ctx, target, true)
	if closer != nil {
		defer closer.Close()
	}
	if client != nil {
		defer client.Close()
	}
	if err != nil || client == nil {
		message := "Controller could not be opened; check its credential references and availability. Proxy data connectivity is unknown."
		var controllerErr *core.Error
		if errors.As(err, &controllerErr) {
			switch controllerErr.Kind {
			case core.KindAuth:
				message = "Controller authentication rejected (401/403); data proxy authentication is separate."
			case core.KindUnreachable:
				message = "Controller is offline or timed out; proxy data connectivity remains unknown."
			case core.KindTLS:
				message = "Controller TLS verification failed; check the configured CA certificate."
			}
		}
		publish(updates, Check{ID: "controller", Status: Fail, Message: message, Suggestion: "Check the selected controller URL and secret_env/secret_file; doctor never starts or repairs services."})
		return
	}
	updates <- func(r *Report) {
		r.Runtime = &Runtime{IdentityVerified: true}
		r.set(Check{ID: "controller", Status: Pass, Message: "Local controller identity and access verified with GET /version."})
	}
	runtime, err := client.Config(ctx)
	if err != nil {
		publish(updates, Check{ID: "runtime", Status: Fail, Message: "Controller runtime settings could not be read with GET /configs.", Suggestion: "Check controller API compatibility and authentication; host evidence is still available."})
		return
	}
	snapshot := runtimeSnapshot(runtime)
	if data.Source == "" {
		data = runtimeEndpoint(target, snapshot)
	}
	updates <- func(r *Report) {
		r.Runtime, r.DataEndpoint = &snapshot, data
		r.set(Check{ID: "runtime", Status: Pass, Message: "Read runtime mode, listener ports and TUN state. Direct mode, TUN-only operation and absent proxy variables are not failures."})
	}
}

func unsupported(updates chan<- func(*Report), source string) {
	updates <- func(r *Report) {
		r.Selection = Selection{Source: source}
		r.set(Check{ID: "selection", Status: Fail, Message: "Remote/SSH scope is not supported by doctor; no connection or local fallback was attempted.", Suggestion: "Use doctor with a local target/controller, or run it on the remote host yourself."})
		r.set(Check{ID: "controller", Status: Skip, Message: "Remote controller access is outside doctor's local-only scope."})
		r.set(Check{ID: "runtime", Status: Skip, Message: "Remote runtime settings were not requested."})
	}
}

func runtimeSnapshot(value core.Object) Runtime {
	r := Runtime{IdentityVerified: true, MixedPort: port(value["mixed-port"]), HTTPPort: port(value["port"]), SOCKSPort: port(value["socks-port"])}
	if mode, ok := value["mode"].(string); ok {
		switch strings.ToLower(mode) {
		case "rule", "global", "direct":
			r.Mode = strings.ToLower(mode)
		}
	}
	if tun, ok := value["tun"].(map[string]any); ok {
		r.TUNEnabled, r.TUNKnown = tun["enable"].(bool)
		if name, ok := tun["device"].(string); ok {
			r.TUNDevice = safeText(name)
		}
	}
	return r
}

func port(value any) int {
	n := 0
	switch v := value.(type) {
	case float64:
		if v == float64(int(v)) {
			n = int(v)
		}
	case int:
		n = v
	}
	if n < 1 || n > 65535 {
		return 0
	}
	return n
}

func runtimeEndpoint(target config.Target, r Runtime) DataEndpoint {
	host := "127.0.0.1"
	u, err := url.Parse(target.Controller)
	if err == nil && u.Hostname() == "::1" {
		host = "::1"
	}
	http, socks := r.HTTPPort, r.SOCKSPort
	if r.MixedPort != 0 {
		http, socks = r.MixedPort, r.MixedPort
	}
	d := DataEndpoint{Source: "core runtime ports"}
	if http != 0 {
		d.HTTP = "http://" + net.JoinHostPort(host, strconv.Itoa(http))
	}
	if socks != 0 {
		d.SOCKS = "socks5h://" + net.JoinHostPort(host, strconv.Itoa(socks))
	}
	return d
}

func safeText(s string) string {
	s = strings.Join(strings.Fields(core.Sanitize(s)), " ")
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

func safeEndpoint(value string) string {
	if value == "" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil {
		return "<set; unrecognized>"
	}
	if u.Scheme == "unix" {
		return "unix://<local socket>"
	}
	if u.Hostname() == "" {
		return "<set; unrecognized>"
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "<set; unrecognized>"
	}
	return safeText((&url.URL{Scheme: u.Scheme, Host: u.Host}).String())
}

func (r *Report) summarize() {
	r.Summary.Complete = true
	for _, check := range r.Checks {
		switch check.Status {
		case Pass:
			r.Summary.Pass++
		case Warn:
			r.Summary.Warn++
		case Fail:
			r.Summary.Fail++
		case Unknown:
			r.Summary.Unknown++
		case Skip:
			r.Summary.Skip++
		}
		if check.Required && (check.Status == Unknown || check.Status == Skip) {
			r.Summary.Complete = false
		}
		if check.Suggestion != "" {
			r.Suggestions = append(r.Suggestions, check.Suggestion)
		}
	}
	if r.Summary.Fail != 0 || !r.Summary.Complete {
		r.Summary.ExitCode = 1
	}
	if r.Summary.Canceled {
		r.Summary.ExitCode = 130
	}
}
