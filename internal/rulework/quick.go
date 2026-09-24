package rulework

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"go.yaml.in/yaml/v3"
)

func quickTargets(targets []config.Target, all bool) ([]config.Target, error) {
	if len(targets) == 0 || !all && len(targets) != 1 {
		return nil, errors.New("select one saved target or all saved targets")
	}
	items := append([]config.Target(nil), targets...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	for i, t := range items {
		if t.ID == "" || t.Transient || t.TransportOverride {
			return nil, errors.New("rule operations require saved targets without transport overrides")
		}
		if i > 0 && items[i-1].ID == t.ID {
			return nil, errors.New("duplicate selected target")
		}
	}
	return items, nil
}

func finding(severity, code, message string) rulecheck.Finding {
	return rulecheck.Finding{Severity: severity, Code: code, Index: -1, Message: core.Sanitize(message)}
}

func hashQuick(v any) string { b, _ := json.Marshal(v); return sha(b) }

// PreviewRules validates every reachable candidate before any source is written.
func PreviewRules(ctx context.Context, targets []config.Target, raw string, all bool, opts Options) (QuickPlan, error) {
	p := QuickPlan{Status: "ready", Targets: []QuickTargetPlan{}}
	rule, err := rulecheck.Parse(raw)
	if err != nil {
		return p, err
	}
	p.Rule = rule.String()
	items, err := quickTargets(targets, all)
	if err != nil {
		return p, err
	}
	usable, blocked := 0, false
	for _, t := range items {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		item := previewQuickTarget(ctx, t, rule, opts)
		if item.Status == "skipped_unavailable" && !all {
			item.Status = "blocked"
		}
		blocked = blocked || item.Status == "blocked"
		if item.Status == "ready" || item.Status == "skipped_existing" {
			usable++
		}
		p.Targets = append(p.Targets, item)
	}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	// Skip reasons can vary with transport diagnostics; bind only stable identity,
	// disposition and each source plan, never volatile counters or messages.
	ids := []any{p.Rule, all}
	for i, t := range items {
		ids = append(ids, binding(t), p.Targets[i].Status, p.Targets[i].Digest)
	}
	p.Digest = hashQuick(ids)
	if blocked {
		p.Status = "blocked"
		causes := []error{errors.New("rule preflight found errors; no targets were changed")}
		for _, t := range p.Targets {
			if t.Status == "blocked" && t.cause != nil {
				causes = append(causes, t.cause)
			}
		}
		return p, errors.Join(causes...)
	}
	if usable == 0 {
		p.Status = "unavailable"
		return p, errors.New("no selected target is available; no targets were changed")
	}
	if !p.HasChanges() {
		p.Status = "no_changes"
	}
	return p, nil
}

func previewQuickTarget(ctx context.Context, t config.Target, rule rulecheck.Rule, opts Options) QuickTargetPlan {
	p := QuickTargetPlan{TargetID: t.ID, Status: "blocked", Findings: []rulecheck.Finding{}}
	fail := func(err error, unavailable bool) QuickTargetPlan {
		p.cause = err
		p.Message = core.Sanitize(err.Error())
		if unavailable {
			p.Status = "skipped_unavailable"
		} else {
			p.Findings = append(p.Findings, finding("error", "preflight_failed", p.Message))
		}
		return p
	}
	if t.RuleSource == nil {
		return fail(errors.New("bind a persistent rule source with rules source set (or --from-config-source)"), true)
	}
	source, err := inspectSource(ctx, t, opts)
	if err != nil {
		return fail(err, errors.Is(err, ErrSourceUnavailable))
	}
	p.Owner = &source
	rules, err := sourceRuleList(source)
	if err != nil {
		return fail(err, false)
	}
	client, cleanup, err := openCore(ctx, t, true, opts)
	if err != nil {
		return fail(err, unavailableCore(err))
	}
	defer cleanup()
	proxies, err := client.Proxies(ctx)
	if err != nil {
		return fail(err, unavailableCore(err))
	}
	policies := policyNames(proxies)
	version, err := client.Version(ctx)
	if err != nil {
		return fail(err, unavailableCore(err))
	}
	runtime, err := client.Rules(ctx)
	if err != nil {
		return fail(err, unavailableCore(err))
	}
	runtimeDigest, err := rulesDigest(runtime)
	if err != nil {
		return fail(err, false)
	}
	runtimeList, err := runtimeRuleList(runtime)
	if err != nil {
		return fail(err, false)
	}
	base := rulecheck.Analyze(rules, policies)
	p.Findings = append(p.Findings, base.Findings...)
	p.Findings = append(p.Findings, sourceReferenceFindings(source, rules, policies)...)
	p.Limitations = append(p.Limitations, base.Limitations...)
	duplicate := false
	for _, old := range rules {
		duplicate = duplicate || old.Equal(rule)
	}
	if !duplicate {
		rule.Index = -1
		report := rulecheck.Analyze(append([]rulecheck.Rule{rule}, rules...), policies)
		// Keep each original finding once, plus findings involving the new rule.
		for _, f := range report.Findings {
			if f.Index == -1 || f.RelatedIndex != nil && *f.RelatedIndex == -1 {
				p.Findings = append(p.Findings, f)
			}
		}
	}
	if !policies[rule.Policy] {
		p.Findings = append(p.Findings, finding("error", "policy_missing", "requested policy does not exist on this target: "+rule.Policy))
	}
	// Runtime is a separate list: an old runtime policy is drift, not a
	// contradiction with the source candidate that is about to replace it.
	runtimeReport := rulecheck.Analyze(runtimeList, policies)
	for _, f := range runtimeReport.Findings {
		f.Message = "Runtime: " + f.Message
		p.Findings = append(p.Findings, f)
	}
	p.Limitations = append(p.Limitations, runtimeReport.Limitations...)
	p.Limitations = append(p.Limitations, "Runtime checks confirm enabled selector/policy entries; the API does not expose every source option, including no-resolve.")
	if source.Kind == "verge" {
		p.Limitations = append(p.Limitations, "Persistent checks cover the Rules companion prepend/append; base profile and later Merge/Script effects are represented only by the runtime snapshot.")
	}
	if !duplicate {
		incoming := rule
		incoming.Index = -1
		report := rulecheck.Analyze(append([]rulecheck.Rule{incoming}, runtimeList...), policies)
		for _, f := range report.Findings {
			if f.Index != -1 && (f.RelatedIndex == nil || *f.RelatedIndex != -1) {
				continue
			}
			if f.Code == "duplicate" {
				continue
			}
			if f.Severity == "error" && source.Kind != "verge" {
				f.Severity = "warning"
				f.Code = "runtime_policy_drift"
			}
			f.Message = "Current runtime vs proposed source: " + f.Message
			p.Findings = append(p.Findings, f)
		}
	}
	for _, warning := range source.Warnings {
		p.Findings = append(p.Findings, finding("warning", "owner_reload", warning))
	}
	runtimeMode := ""
	if cfg, e := client.Config(ctx); e == nil {
		runtimeMode, _ = cfg["mode"].(string)
		if mode := runtimeMode; mode != "" && mode != "rule" {
			p.Findings = append(p.Findings, finding("warning", "runtime_mode", "Runtime mode is "+mode+"; routing rules may not determine traffic."))
		}
	} else {
		p.Limitations = append(p.Limitations, "Runtime mode could not be read.")
	}
	for _, f := range p.Findings {
		if f.Severity == "error" {
			p.Message = "Resolve rule errors before applying."
			return p
		}
	}
	coreVersion, _ := version["version"].(string)
	after := source.file.Data
	if !duplicate {
		after, err = prependQuickRule(source, rule.String())
		if err != nil {
			return fail(err, false)
		}
		if err = validateOwnerCandidate(ctx, t, source, after, coreVersion, opts); err != nil {
			return fail(err, false)
		}
	}
	p.plan = Plan{TargetID: t.ID, Owner: source, Rule: rule.String(), Policy: rule.Policy, CoreVersion: coreVersion, NoChange: duplicate, after: after, beforeRuntimeDigest: runtimeDigest}
	if rule.Type == "IP-CIDR" || rule.Type == "IP-CIDR6" {
		p.plan.Prefix = rule.Payload
	} else {
		p.plan.Domain = rule.Payload
	}
	p.Digest = hashQuick([]any{binding(t), rule.String(), coreVersion, sha(after), runtimeDigest, runtimeMode, source.guards, sourceOwnerIdentity(source), t.Service, policies})
	p.plan.Digest = p.Digest
	p.RuntimeVerified = runtimeHasRule(runtimeList, rule)
	if duplicate {
		p.Status = "skipped_existing"
		p.Message = "The same rule already exists in the persistent source; no write or reload."
		if !p.RuntimeVerified {
			p.Findings = append(p.Findings, finding("warning", "source_runtime_drift", "Persistent rule is not enabled in the current runtime; activate the owner and inspect routing."))
		}
	} else {
		p.Status = "ready"
		p.Diff = "+ [0] " + rule.String() + "\nAll existing rules retain their order."
		p.plan.Diff = p.Diff
	}
	return p
}

func unavailableCore(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var api *core.Error
	if errors.As(err, &api) {
		return api.Kind == core.KindUnreachable || api.Kind == core.KindAuth || api.Kind == core.KindTLS || api.Kind == core.KindUnsupported || api.Kind == core.KindRejected
	}
	return true
}

func policyNames(proxies map[string]core.Proxy) map[string]bool {
	names := map[string]bool{}
	for name := range proxies {
		names[name] = true
	}
	// These core-built-in actions are valid even when omitted from /proxies.
	for _, name := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS"} {
		names[name] = true
	}
	return names
}

func sourceRuleList(source Source) ([]rulecheck.Rule, error) {
	doc, err := decodeYAML(source.file.Data)
	if err != nil {
		return nil, err
	}
	keys := []string{"rules"}
	if source.Kind == "verge" {
		keys = []string{"prepend", "append"}
		if deleted := mappingValue(doc.Content[0], "delete"); deleted != nil {
			if deleted.Kind != yaml.SequenceNode {
				return nil, errors.New("Verge delete must be a YAML sequence of strings")
			}
			for _, entry := range deleted.Content {
				if entry.Kind != yaml.ScalarNode || entry.Tag != "!!str" {
					return nil, errors.New("Verge delete must contain strings")
				}
			}
		}
	}
	result := []rulecheck.Rule{}
	for _, key := range keys {
		seq := mappingValue(doc.Content[0], key)
		if seq == nil {
			continue
		}
		if seq.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s must be a YAML sequence", key)
		}
		for _, item := range seq.Content {
			if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
				return nil, fmt.Errorf("%s entries must be rule strings", key)
			}
			result = append(result, rulecheck.ParseExisting(item.Value, len(result)))
		}
	}
	return result, nil
}

func prependQuickRule(source Source, rule string) ([]byte, error) {
	doc, err := decodeYAML(source.file.Data)
	if err != nil {
		return nil, err
	}
	key := "rules"
	if source.Kind == "verge" {
		key = "prepend"
	}
	root := doc.Content[0]
	seq := mappingValue(root, key)
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, seq)
	}
	if seq.Kind != yaml.SequenceNode {
		return nil, errors.New("rule source list must be a sequence")
	}
	seq.Content = append([]*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: rule}}, seq.Content...)
	seq.Style = 0
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if out.Len() > 8<<20 {
		return nil, errors.New("candidate exceeds 8 MiB")
	}
	return out.Bytes(), nil
}

func runtimeRuleList(object core.Object) ([]rulecheck.Rule, error) {
	if _, err := rulesDigest(object); err != nil {
		return nil, err
	}
	result := []rulecheck.Rule{}
	kinds := map[string]string{"domain": "DOMAIN", "domainsuffix": "DOMAIN-SUFFIX", "domainkeyword": "DOMAIN-KEYWORD", "ipcidr": "IP-CIDR", "srcipcidr": "IP-CIDR", "match": "MATCH", "ruleset": "RULE-SET", "geoip": "GEOIP", "geosite": "GEOSITE"}
	for i, raw := range object["rules"].([]any) {
		row := raw.(map[string]any)
		kind := strings.ToLower(row["type"].(string))
		typ := kinds[kind]
		if typ == "" {
			typ = strings.ToUpper(row["type"].(string))
		}
		expression := typ + "," + row["payload"].(string) + "," + row["proxy"].(string)
		if typ == "MATCH" {
			expression = "MATCH," + row["proxy"].(string)
		}
		if kind == "srcipcidr" {
			expression += ",src"
		}
		r := rulecheck.ParseExisting(expression, i)
		if extra, ok := row["extra"].(map[string]any); ok {
			if d, present := extra["disabled"]; present && d != false {
				r.Disabled = true
			}
		}
		result = append(result, r)
	}
	return result, nil
}

func runtimeHasRule(rules []rulecheck.Rule, want rulecheck.Rule) bool {
	for _, r := range rules {
		if !r.Disabled && r.SelectorKey() == want.SelectorKey() && r.Policy == want.Policy {
			return true
		}
	}
	return false
}

// ApplyRules requires the internal preview fingerprint even when the CLI's
// --yes obtains it in the same invocation. No mutation is retried.
func ApplyRules(ctx context.Context, targets []config.Target, raw string, all bool, expected string, opts Options) (QuickResult, error) {
	r := QuickResult{Digest: expected, Status: "stopped", Results: []QuickTargetResult{}}
	if opts.ReadOnly {
		return r, errors.New("rule writes are disabled in read-only mode")
	}
	if len(expected) != 64 {
		return r, errors.New("apply requires a fresh preview digest")
	}
	p, err := PreviewRules(ctx, targets, raw, all, opts)
	r.Rule = p.Rule
	for _, t := range p.Targets {
		status := "unattempted"
		if strings.HasPrefix(t.Status, "skipped_") {
			status = t.Status
		}
		r.Results = append(r.Results, QuickTargetResult{TargetID: t.TargetID, Status: status, Message: t.Message, Findings: t.Findings, RuntimeVerified: t.RuntimeVerified})
	}
	if err != nil {
		return r, err
	}
	if p.Digest != expected {
		return r, errors.New("rule source or target availability changed; review a new preview")
	}
	items, _ := quickTargets(targets, all)
	for i, t := range items {
		if strings.HasPrefix(p.Targets[i].Status, "skipped_") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return r, err
		}
		fresh := previewQuickTarget(ctx, t, mustQuickRule(p.Rule), opts)
		if fresh.Status != "ready" || fresh.Digest != p.Targets[i].Digest {
			r.Results[i].Status = "failed"
			r.Results[i].Message = "Source or runtime changed before this write."
			return r, fmt.Errorf("target %s changed before apply; inspect results before retrying", t.ID)
		}
		receipt, e := applyQuickPlan(ctx, t, fresh.plan, opts)
		r.Results[i].Status = "failed"
		if receipt.ID != "" {
			r.Results[i].Receipt = &receipt
			r.Results[i].Status = receipt.Status
			r.Results[i].Message = receipt.Message
			r.Results[i].RuntimeVerified = receipt.RuntimeVerified
		}
		if e != nil {
			return r, fmt.Errorf("target %s: %w", t.ID, e)
		}
		if receipt.Status != "applied_verified" && receipt.Status != "persisted_pending_owner_reload" {
			return r, fmt.Errorf("target %s has an unverified result; inspect its receipt", t.ID)
		}
	}
	r.Status = "completed"
	for _, t := range r.Results {
		if t.Status == "skipped_unavailable" {
			r.Status = "completed_with_skips"
		}
	}
	return r, nil
}

func mustQuickRule(raw string) rulecheck.Rule { r, _ := rulecheck.Parse(raw); return r }

func applyQuickPlan(ctx context.Context, t config.Target, p Plan, opts Options) (Receipt, error) {
	if _, err := sourceHostCall(ctx, t, hostRequest{Op: "check", Guards: p.Owner.guards}, opts); err != nil {
		return Receipt{}, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Receipt{}, err
	}
	now := time.Now().UTC()
	r := Receipt{ID: hex.EncodeToString(id), TargetID: t.ID, Owner: p.Owner.Kind, File: p.Owner.File, Rule: p.Rule, Domain: p.Domain, Prefix: p.Prefix, Policy: p.Policy, Status: "prepared", CreatedAt: now, UpdatedAt: now, Digest: p.Digest, BeforeSHA256: p.Owner.file.SHA256, AfterSHA256: sha(p.after), Binding: binding(t), ProfileUID: p.Owner.ProfileUID, BeforeRuntimeDigest: p.beforeRuntimeDigest}
	r.OwnerIdentity = sourceOwnerIdentity(p.Owner)
	if err := prepareReceipt(opts, r, p.Owner.file.Data); err != nil {
		return Receipt{}, err
	}
	written, err := sourceHostCall(ctx, t, hostRequest{Op: "write", Path: r.File, Data: p.after, Guards: p.Owner.guards}, opts)
	if err != nil {
		r.Status = "write_result_unknown"
		r.Message = "The source write was not confirmed. Verify this receipt before retrying."
		_ = saveReceipt(opts, r)
		return r, fmt.Errorf("%w: %w", &core.Error{Kind: core.KindUnknownWrite, Operation: "write persistent rule source"}, err)
	}
	r.AfterFingerprint = written.Fingerprint
	r.Status = "persisted_pending_owner_reload"
	r.Message = "Rule saved. Activate its owner and verify this receipt."
	if err = saveReceipt(opts, r); err != nil {
		return r, err
	}
	if t.RuleSource.Kind == "verge" {
		r.Message = "Rule saved. Reactivate Profiles in Clash Verge, then verify this receipt."
		if err = saveReceipt(opts, r); err != nil {
			return r, err
		}
		if t.ManagedCoreID == "" || opts.ActivateOwner == nil {
			return r, nil
		}
		if err = opts.ActivateOwner(ctx, t); err != nil {
			return r, err
		}
		return Verify(ctx, t, r.ID, opts)
	}
	ready, restarted, err := activateOwnerSource(ctx, t, p.Owner, r.AfterSHA256, opts)
	if err == nil && restarted {
		err = waitForOwnerCore(ctx, t, opts)
	}
	if err != nil {
		r.Status = "runtime_result_unknown"
		r.Message = "Source saved; owner activation could not be confirmed."
		_ = saveReceipt(opts, r)
		return r, err
	}
	if !ready {
		return r, nil
	}
	client, cleanup, err := openCore(ctx, t, false, opts)
	if err == nil {
		_, err = client.ApplyConfig(ctx, sourceReloadPath(p.Owner))
		cleanup()
	}
	if err != nil {
		r.Status = "runtime_result_unknown"
		r.Message = "Source saved; reload was not confirmed. Verify before retrying."
		_ = saveReceipt(opts, r)
		return r, err
	}
	return Verify(ctx, t, r.ID, opts)
}
