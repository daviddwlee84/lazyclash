package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type CheckOptions struct {
	Options
	Timeout time.Duration // per check, including its optional policy comparison
}

type CheckRoute struct {
	Status      string   `json:"status"`
	Rule        string   `json:"rule,omitempty"`
	RulePayload string   `json:"rule_payload,omitempty"`
	Chains      []string `json:"chains"`
	Reason      string   `json:"reason"`
}

type CheckResult struct {
	ID                    string               `json:"id"`
	Name                  string               `json:"name,omitempty"`
	URL                   string               `json:"url"`
	ExpectedStatuses      []int                `json:"expected_statuses,omitempty"`
	Status                string               `json:"status"`
	TransportReachable    bool                 `json:"transport_reachable"`
	ExpectedStatusMatched *bool                `json:"expected_status_matched,omitempty"`
	ApplicationAccess     string               `json:"application_access"`
	Request               RequestEvidence      `json:"request"`
	Route                 CheckRoute           `json:"route"`
	Connections           []ConnectionEvidence `json:"connections"`
	PolicyComparison      *OutboundEvidence    `json:"policy_comparison,omitempty"`
	Warnings              []string             `json:"warnings,omitempty"`
}

type CheckReport struct {
	TargetID    string        `json:"target_id"`
	SampledAt   time.Time     `json:"sampled_at"`
	FinishedAt  time.Time     `json:"finished_at"`
	CoreAtStart CoreEvidence  `json:"core_at_start"`
	Checks      []CheckResult `json:"checks"`
	Completed   int           `json:"completed"`
	Passed      int           `json:"passed"`
	Canceled    bool          `json:"canceled"`
	Warnings    []string      `json:"warnings,omitempty"`
}

// RunChecks sends one unauthenticated HEAD through the configured data proxy
// per check, sequentially. It never changes core modes, selectors or rules.
// Unlike RunURL it does not test every host, resolver and DIRECT context.
func RunChecks(ctx context.Context, target config.Target, checks []config.DiagnosticCheck, opts CheckOptions) (CheckReport, error) {
	if opts.ReadOnly {
		return CheckReport{}, ErrReadOnly
	}
	if err := config.ValidateDiagnosticChecks(checks); err != nil {
		return CheckReport{}, err
	}
	if len(checks) == 0 {
		return CheckReport{}, errors.New("no saved connectivity checks selected")
	}
	if target.ProbeProxy == "" {
		return CheckReport{}, ErrNoProxy
	}
	if err := config.ValidateProbe(target); err != nil {
		return CheckReport{}, err
	}
	limit := opts.Timeout
	if limit <= 0 {
		limit = 10 * time.Second
		if target.SSHHost != "" {
			// The data-plane SSH tunnel opens within each check. Allow its
			// setup, the HEAD request and optional URLTest their bounded work.
			limit = 30 * time.Second
		}
	}
	if limit > 30*time.Second {
		return CheckReport{}, errors.New("check timeout must not exceed 30 seconds")
	}
	ctx, cancelBatch := context.WithTimeout(ctx, time.Duration(len(checks))*limit+15*time.Second)
	defer cancelBatch()
	report := CheckReport{TargetID: target.ID, SampledAt: opts.now().UTC(), Checks: make([]CheckResult, 0, len(checks)), Warnings: []string{"Checks test unauthenticated HTTP headers through this target's explicit data proxy. They do not prove login, API entitlement, a Claude model call or full application usability."}}
	for _, check := range checks {
		report.Checks = append(report.Checks, CheckResult{ID: check.ID, Name: check.Name, URL: check.URL, ExpectedStatuses: append([]int(nil), check.ExpectedStatuses...), Status: "not-run", ApplicationAccess: "not-tested", Request: RequestEvidence{Source: "explicit data proxy", Status: "not-run"}, Route: CheckRoute{Status: "unknown", Chains: []string{}, Reason: "No uniquely observed connection for this request."}, Connections: []ConnectionEvidence{}})
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	compare := false
	for _, check := range checks {
		compare = compare || check.Via != ""
	}
	// The opener's context owns SSH forwarding for its entire lifetime. Do not
	// cancel an initialization-only context and accidentally close that tunnel.
	client, closer, openErr := open(ctx, target, !compare)
	if closer != nil {
		defer closer.Close()
	}
	if client != nil {
		defer client.Close()
	}
	controllerCtx, stopController := context.WithTimeout(ctx, 3*time.Second)
	var proxies map[string]core.Proxy
	if openErr == nil && client != nil {
		report.CoreAtStart.Available = true
		settings, e := client.Config(controllerCtx)
		if e != nil {
			report.CoreAtStart.Error = "runtime settings unavailable"
		} else {
			report.CoreAtStart.Mode = evidenceText(settings["mode"])
			if tun, ok := settings["tun"].(map[string]any); ok {
				report.CoreAtStart.TUNEnabled, report.CoreAtStart.TUNKnown = tun["enable"].(bool)
			}
		}
		if compare {
			proxies, _ = client.Proxies(controllerCtx)
		}
	} else {
		report.CoreAtStart.Error = "controller unavailable; explicit proxy requests are tested independently"
		if connection.IsAuthRequired(openErr) {
			stopController()
			return report, openErr
		}
		client = nil
	}
	stopController()
	failed := false
	for i, check := range checks {
		if ctx.Err() != nil {
			report.Canceled = true
			break
		}
		checkCtx, cancel := context.WithTimeout(ctx, limit)
		u, _ := diagnosticURL(check.URL)
		var capture *urlCapture
		captureCtx, stopCapture := context.WithCancel(checkCtx)
		if client != nil {
			capture = beginCheckCapture(captureCtx, client, u.Hostname())
		}
		result := &report.Checks[i]
		result.Request = explicitURLRequest(checkCtx, target, check.URL, opts.Options)
		stopCapture()
		if capture != nil {
			capture.wait()
			result.Connections, _ = correlateURL(capture, URLResult{ExplicitProxy: result.Request}, target.SSHHost != "")
			result.Route = observedCheckRoute(result.Connections)
			if capture.failed {
				result.Warnings = append(result.Warnings, "Connection observation was incomplete; uncaptured rule/chain remains unknown.")
			}
		}
		result.TransportReachable = result.Request.Status == "http-response"
		result.Status = "failed"
		if result.TransportReachable {
			matched := matchesExpectedStatus(result.Request.HTTPStatus, check.ExpectedStatuses)
			result.ExpectedStatusMatched = &matched
			if matched {
				result.Status = "passed"
			} else {
				result.Status = "unexpected-status"
			}
		}
		if check.Via != "" {
			comparison := OutboundEvidence{Policy: check.Via, Status: "unavailable", Error: "controller or policy unavailable", Note: "Optional core URLTest comparison; it does not provide HTTP status or send selector/mode settings."}
			if client != nil && checkCtx.Err() == nil {
				comparison = outboundURLTest(checkCtx, client, proxies, check.Via, check.URL)
			}
			if comparison.Status != "response-sample" && errors.Is(checkCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				comparison.Status = "timeout"
				comparison.Error = "Per-check time budget expired before the optional policy comparison completed; the HTTP result is retained."
			}
			comparison.Note += " Resolved leaf/chain reflect the batch-start selector snapshot. Health-based selections can change during URLTests."
			result.PolicyComparison = &comparison
			if result.Status == "passed" && comparison.Status != "response-sample" {
				result.Status = "comparison-failed"
				if comparison.Status == "timeout" {
					result.Status = "comparison-timeout"
				}
			}
		}
		if ctx.Err() != nil {
			result.Status = "canceled"
			report.Canceled = true
		}
		cancel()
		report.Completed++
		if result.Status == "passed" {
			report.Passed++
		} else {
			failed = true
		}
	}
	report.FinishedAt = opts.now().UTC()
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if failed {
		return report, ErrPartial
	}
	return report, nil
}

// The check capture deliberately omits logs: host mentions in raw log messages
// cannot prove that this probe used a rule. Structured connections are bounded
// and short-lived; a fast request may finish before any matching event appears.
func beginCheckCapture(ctx context.Context, client *core.Client, host string) *urlCapture {
	c := &urlCapture{host: host, connections: map[string]capturedConnection{}, logs: []LogEvidence{}}
	c.read(ctx, client, true)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(75 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.read(ctx, client, false)
			}
		}
	}()
	return c
}

func observedCheckRoute(connections []ConnectionEvidence) CheckRoute {
	route := CheckRoute{Status: "unknown", Chains: []string{}, Reason: "No unique connection matched this request's host, time and local source address/port. SSH forwarding or fast requests can prevent exact correlation."}
	var observed []ConnectionEvidence
	for _, c := range connections {
		if c.Confidence == "observed" && c.RequestSource == "explicit data proxy" {
			observed = append(observed, c)
		}
	}
	if len(observed) != 1 {
		return route
	}
	c := observed[0]
	if c.Rule == "" && len(c.Chains) == 0 {
		return route
	}
	route.Status = "observed"
	route.Rule = c.Rule
	route.RulePayload = c.RulePayload
	route.Chains = append([]string{}, c.Chains...)
	route.Reason = c.Reason
	return route
}

func matchesExpectedStatus(status int, expected []int) bool {
	if len(expected) == 0 {
		return status >= 200 && status < 400
	}
	for _, code := range expected {
		if code == status {
			return true
		}
	}
	return false
}

func FormatChecks(report CheckReport) string {
	lines := []string{fmt.Sprintf("Connectivity checks · %s · %d/%d passed · %d/%d completed", core.Sanitize(report.TargetID), report.Passed, len(report.Checks), report.Completed, len(report.Checks))}
	for _, check := range report.Checks {
		name := check.Name
		if name == "" {
			name = check.ID
		}
		transport := "not reached"
		if check.TransportReachable {
			transport = "reachable"
		}
		if check.Status == "not-run" {
			transport = "not run"
		}
		httpStatus := "unknown"
		if check.Request.HTTPStatus != 0 {
			httpStatus = fmt.Sprintf("%d", check.Request.HTTPStatus)
		}
		expected := "unknown"
		if check.ExpectedStatusMatched != nil {
			if *check.ExpectedStatusMatched {
				expected = "matched"
			} else {
				expected = "unexpected"
			}
		}
		lines = append(lines, fmt.Sprintf("%s [%s]: transport %s · HTTP %s (%s) · %.0f ms", core.Sanitize(name), core.Sanitize(check.Status), transport, httpStatus, expected, check.Request.Milliseconds))
		if check.Route.Status == "observed" {
			lines = append(lines, "  Observed rule: "+core.Sanitize(strings.TrimSpace(check.Route.Rule+" "+check.Route.RulePayload))+" · core chain (leaf first): "+core.Sanitize(strings.Join(check.Route.Chains, " → ")))
		} else {
			lines = append(lines, "  Rule / chain: unknown (no unique observed connection)")
			possible := []ConnectionEvidence{}
			for _, event := range check.Connections {
				if event.Confidence == "probable" && event.RequestSource == "explicit data proxy" {
					possible = append(possible, event)
				}
			}
			if len(possible) == 1 {
				event := possible[0]
				lines = append(lines, "  Possible connection (not confirmed for this probe): rule "+core.Sanitize(strings.TrimSpace(event.Rule+" "+event.RulePayload))+" · core chain (leaf first): "+core.Sanitize(strings.Join(event.Chains, " → ")))
			} else if len(check.Connections) > 0 {
				lines = append(lines, fmt.Sprintf("  %d matching-host core connections; request association remains unknown.", len(check.Connections)))
			}
		}
		if check.PolicyComparison != nil {
			p := check.PolicyComparison
			lines = append(lines, fmt.Sprintf("  Policy comparison %s: %s · %.0f ms (URLTest, not HTTP status)", core.Sanitize(p.Policy), core.Sanitize(p.Status), p.Milliseconds))
			if p.Status == "timeout" && p.Error != "" {
				lines = append(lines, "  "+core.Sanitize(p.Error))
			}
			if len(p.Chain) > 0 {
				lines = append(lines, "  Selection at batch start: "+core.Sanitize(strings.Join(p.Chain, " → ")))
			}
		}
		if check.Request.Error != "" {
			lines = append(lines, "  "+core.Sanitize(check.Request.Error))
		}
	}
	if report.Canceled {
		lines = append(lines, "Canceled; unstarted checks are marked not-run.")
	}
	lines = append(lines, "Authentication / application access: not tested. No mode, selector or rule settings were sent.")
	return strings.Join(lines, "\n")
}
