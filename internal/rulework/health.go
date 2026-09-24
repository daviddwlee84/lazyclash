package rulework

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"go.yaml.in/yaml/v3"
)

// Healthcheck observes source and runtime separately. It never refreshes
// providers, evaluates scripts, reloads owners or generates test traffic.
func Healthcheck(ctx context.Context, targets []config.Target, all bool, opts Options) (HealthReport, error) {
	report := HealthReport{Status: "completed", Targets: []TargetHealth{}}
	items, err := quickTargets(targets, all)
	if err != nil {
		return report, err
	}
	usable, hasErrors := 0, false
	for _, t := range items {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		h := healthTarget(ctx, t, opts)
		report.Targets = append(report.Targets, h)
		if h.Runtime != nil || h.Source != nil {
			usable++
		}
		if h.Status == "errors" {
			hasErrors = true
		}
		if h.Status == "skipped_unavailable" || h.Status == "partial" {
			report.Status = "completed_with_skips"
		}
	}
	if hasErrors {
		report.Status = "errors"
		return report, errors.New("rule healthcheck found errors; inspect findings")
	}
	if usable == 0 {
		report.Status = "unavailable"
		return report, errors.New("no selected target could be inspected")
	}
	return report, nil
}

func healthTarget(ctx context.Context, t config.Target, opts Options) TargetHealth {
	h := TargetHealth{TargetID: t.ID, Status: "checked", ObservedAt: time.Now().UTC().Format(time.RFC3339), Findings: []rulecheck.Finding{}}
	var sourceRules []rulecheck.Rule
	if t.RuleSource != nil {
		source, err := inspectSource(ctx, t, opts)
		if err == nil {
			h.Owner = &source
			sourceRules, err = sourceRuleList(source)
			if err == nil {
				r := rulecheck.Analyze(sourceRules, nil)
				r.Findings = append(r.Findings, sourceReferenceFindings(source, sourceRules, nil)...)
				h.Source = &r
			}
			for _, w := range source.Warnings {
				h.Findings = append(h.Findings, finding("warning", "owner_context", w))
			}
			if source.Kind == "verge" {
				h.Limitations = append(h.Limitations, "Source analysis covers the bound Rules companion prepend/append; base profile, Merge and Script composition is represented only by the separate runtime snapshot.")
			}
		}
		if err != nil {
			severity := "error"
			if errors.Is(err, ErrSourceUnavailable) {
				severity = "warning"
				h.Status = "partial"
			}
			h.Findings = append(h.Findings, finding(severity, "source_unavailable", err.Error()))
		}
	} else {
		h.Limitations = append(h.Limitations, "No persistent rule source is bound; original configuration syntax cannot be verified.")
	}
	client, cleanup, err := openCore(ctx, t, true, opts)
	if err != nil {
		h.Message = core.Sanitize(err.Error())
		h.Status = "skipped_unavailable"
		if h.Source != nil {
			h.Status = "partial"
		}
		return finalizeHealth(h)
	}
	defer cleanup()
	var policies map[string]bool
	if proxies, e := client.Proxies(ctx); e == nil {
		policies = policyNames(proxies)
	} else {
		h.Limitations = append(h.Limitations, "Policy availability could not be checked.")
	}
	if h.Source != nil {
		r := rulecheck.Analyze(sourceRules, policies)
		r.Findings = append(r.Findings, sourceReferenceFindings(*h.Owner, sourceRules, policies)...)
		h.Source = &r
	}
	if object, e := client.Rules(ctx); e == nil {
		list, e := runtimeRuleList(object)
		if e != nil {
			h.Findings = append(h.Findings, finding("error", "invalid_runtime", e.Error()))
		} else {
			r := rulecheck.Analyze(list, policies)
			h.Runtime = &r
			h.Limitations = append(h.Limitations, "Runtime rules do not expose all source options (including no-resolve); matching entries do not prove identical source semantics.")
			for _, rule := range sourceRules {
				if rule.Invalid == "" && !rule.Opaque && !runtimeHasRule(list, rule) {
					h.Findings = append(h.Findings, rulecheck.Finding{Severity: "warning", Code: "source_runtime_drift", Index: rule.Index, Message: "Source rule is absent or disabled in runtime: " + rule.String()})
				}
			}
		}
	} else {
		h.Message = core.Sanitize(e.Error())
		h.Status = "partial"
		h.Limitations = append(h.Limitations, "Runtime rules could not be read.")
	}
	if c, e := client.Config(ctx); e == nil {
		h.Mode, _ = c["mode"].(string)
		if h.Mode != "" && h.Mode != "rule" {
			h.Findings = append(h.Findings, finding("warning", "runtime_mode", "Runtime mode is "+h.Mode+"; routing rules may not determine traffic."))
		}
	}
	if object, e := client.Providers(ctx, "rules"); e == nil {
		if providers, ok := object["providers"].(map[string]any); ok {
			h.Providers = len(providers)
		}
	} else {
		h.Limitations = append(h.Limitations, "Rule provider metadata could not be read.")
	}
	return finalizeHealth(h)
}

// These references have a known flat grammar even though the provider/geodata
// matching contents remain opaque. Verge companion files do not own providers.
func sourceReferenceFindings(source Source, rules []rulecheck.Rule, policies map[string]bool) []rulecheck.Finding {
	var out []rulecheck.Finding
	providers := map[string]bool{}
	if source.Kind != "verge" {
		doc, err := decodeYAML(source.file.Data)
		if err != nil {
			return out
		}
		if n := mappingValue(doc.Content[0], "rule-providers"); n != nil && n.Tag != "!!null" {
			if n.Kind != yaml.MappingNode {
				return []rulecheck.Finding{finding("error", "invalid_providers", "rule-providers must be a YAML mapping")}
			}
			for i := 0; i+1 < len(n.Content); i += 2 {
				providers[n.Content[i].Value] = true
			}
		}
	}
	for _, r := range rules {
		if r.Invalid != "" || r.Disabled {
			continue
		}
		if r.Type == "RULE-SET" && r.Payload != "" && source.Kind != "verge" && !providers[r.Payload] {
			out = append(out, rulecheck.Finding{Severity: "error", Code: "provider_missing", Index: r.Index, Rule: r.String(), Message: "Rule provider is not declared in this source: " + r.Payload})
		}
		if r.Opaque && (r.Type == "RULE-SET" || r.Type == "GEOSITE" || r.Type == "GEOIP") && r.Policy != "" && policies != nil && !policies[r.Policy] {
			out = append(out, rulecheck.Finding{Severity: "error", Code: "policy_missing", Index: r.Index, Rule: r.String(), Message: "Rule policy is unavailable on this target: " + r.Policy})
		}
	}
	return out
}

func finalizeHealth(h TargetHealth) TargetHealth {
	for _, f := range h.Findings {
		if f.Severity == "error" {
			h.Status = "errors"
		}
	}
	if h.Source != nil && h.Source.HasErrors() || h.Runtime != nil && h.Runtime.HasErrors() {
		h.Status = "errors"
	}
	if h.Source == nil && h.Runtime == nil && h.Status != "errors" {
		h.Status = "skipped_unavailable"
	}
	return h
}

// Summary functions are shared by CLI and embedded TUI workbench adapters.
func FormatQuickPlan(p QuickPlan) string {
	text := fmt.Sprintf("Rule: %s\nStatus: %s\nDigest: %s\n", p.Rule, p.Status, p.Digest)
	for _, t := range p.Targets {
		text += fmt.Sprintf("\n%s: %s\n", t.TargetID, t.Status)
		if t.Owner != nil {
			text += "Source: " + t.Owner.File + " (" + t.Owner.Kind + ")\n"
		}
		if t.Diff != "" {
			text += t.Diff + "\n"
		}
		if t.Message != "" {
			text += t.Message + "\n"
		}
		for _, f := range t.Findings {
			where := ""
			if f.Index >= 0 {
				where = fmt.Sprintf(" rule #%d", f.Index+1)
			} else if f.Rule != "" {
				where = " proposed rule"
			}
			text += fmt.Sprintf("  %s [%s]%s: %s\n", f.Severity, f.Code, where, f.Message)
			if f.Rule != "" {
				text += "    " + f.Rule + "\n"
			}
			if f.RelatedRule != "" {
				label := "Proposed rule"
				if f.RelatedIndex != nil && *f.RelatedIndex >= 0 {
					label = fmt.Sprintf("Related rule #%d", *f.RelatedIndex+1)
				}
				text += fmt.Sprintf("    %s: %s\n", label, f.RelatedRule)
			}
		}
		for _, l := range t.Limitations {
			text += "  Analysis limit: " + l + "\n"
		}
	}
	return text
}
