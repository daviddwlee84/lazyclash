package rulework

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
)

func snapshotInfo(s RulesSnapshot) RuleTargetInfo {
	return RuleTargetInfo{TargetID: s.TargetID, ObservedAt: s.ObservedAt, Version: s.Version, Mode: s.Mode, SourceBinding: s.SourceBinding, Owner: s.Owner, Limitations: s.Limitations}
}

// DiffRules compares each destination against one snapshot of the baseline.
// Source read authorization is independent of the persistent write binding.
func DiffRules(ctx context.Context, baseline config.Target, targets []config.Target, scope string, opts Options) (RuleDiffReport, error) {
	r := RuleDiffReport{Status: "invalid", Targets: []TargetRuleDiff{}}
	var err error
	r.Scope, err = NormalizeRulesScope(scope)
	if err != nil {
		return r, err
	}
	if _, err = quickTargets([]config.Target{baseline}, false); err != nil {
		return r, err
	}
	items, err := quickTargets(targets, true)
	if err != nil {
		return r, err
	}
	for _, t := range items {
		if t.ID == baseline.ID {
			return r, errors.New("choose a destination different from the baseline")
		}
	}
	opts.ReadOnly = true
	r.Status, r.Complete = "completed", true
	left, _ := ReadRulesSnapshot(ctx, baseline, r.Scope, opts)
	r.Baseline = snapshotInfo(left)
	usable := 0
	for _, t := range items {
		if err := ctx.Err(); err != nil {
			r.Status, r.Complete = "interrupted", false
			return r, err
		}
		right, _ := ReadRulesSnapshot(ctx, t, r.Scope, opts)
		item := TargetRuleDiff{Target: snapshotInfo(right)}
		if r.Scope != "runtime" {
			item.Source = compareRuleViews(left.Source, right.Source, false)
			if viewAvailable(left.Source) && viewAvailable(right.Source) {
				usable++
			}
			if item.Source.Status != "equal" && item.Source.Status != "different" {
				r.Complete = false
			}
		}
		if r.Scope != "source" {
			item.Runtime = compareRuleViews(left.Runtime, right.Runtime, true)
			if viewAvailable(left.Runtime) && viewAvailable(right.Runtime) {
				usable++
			}
			if item.Runtime.Status != "equal" && item.Runtime.Status != "different" {
				r.Complete = false
			}
		}
		r.Targets = append(r.Targets, item)
	}
	if err := ctx.Err(); err != nil {
		r.Status, r.Complete = "interrupted", false
		return r, err
	}
	if !r.Complete {
		r.Status = "incomplete"
	}
	if usable == 0 {
		r.Status = "unavailable"
		return r, errors.New("no requested rule layers could be read on both sides")
	}
	return r, nil
}

func viewAvailable(v *RulesView) bool { return v != nil && v.Status == "available" }
func compareRuleViews(left, right *RulesView, reported bool) *RuleLayerDiff {
	r := &RuleLayerDiff{Status: "unavailable"}
	if left != nil {
		r.LeftShape = left.Shape
		r.Limitations = append(r.Limitations, left.Limitations...)
	}
	if right != nil {
		r.RightShape = right.Shape
		r.Limitations = append(r.Limitations, right.Limitations...)
	}
	if !viewAvailable(left) || !viewAvailable(right) {
		messages := []string{}
		for _, v := range []struct {
			name string
			view *RulesView
		}{{"Baseline", left}, {"Destination", right}} {
			if !viewAvailable(v.view) {
				message := "not available"
				if v.view != nil {
					message = v.view.Message
					if v.view.Status == "error" {
						r.Status = "error"
					}
				}
				messages = append(messages, v.name+": "+message)
			}
		}
		r.Message = strings.Join(messages, "; ")
		return r
	}
	if !reported && left.Shape != right.Shape {
		r.Status = "incomparable"
		r.Message = "Source scopes differ: a complete rules list cannot be equated with a Verge Rules companion. Compare runtime or query each source separately."
		return r
	}
	diff := rulecheck.CompareEntries(left.Entries, right.Entries, reported)
	r.Result = &diff
	r.Status = "different"
	if diff.Equal {
		r.Status = "equal"
	}
	r.Limitations = append(r.Limitations, "Equality covers this ordered rule list only; referenced provider contents and proxy definitions are not compared.")
	return r
}

func FindRules(ctx context.Context, targets []config.Target, raw, scope string, opts Options) (RuleFindReport, error) {
	r := RuleFindReport{Status: "invalid", Targets: []TargetRuleFind{}}
	query, err := rulecheck.ParseQuery(raw)
	if err != nil {
		return r, err
	}
	r.Query = query.String()
	r.Scope, err = NormalizeRulesScope(scope)
	if err != nil {
		return r, err
	}
	items, err := quickTargets(targets, true)
	if err != nil {
		return r, err
	}
	opts.ReadOnly = true
	r.Status, r.Complete = "completed", true
	usable := 0
	for _, t := range items {
		if err := ctx.Err(); err != nil {
			r.Status, r.Complete = "interrupted", false
			return r, err
		}
		s, _ := ReadRulesSnapshot(ctx, t, r.Scope, opts)
		item := TargetRuleFind{Target: snapshotInfo(s)}
		if r.Scope != "runtime" {
			item.Source = findRuleView(s.Source, query, false)
			if viewAvailable(s.Source) {
				usable++
			} else {
				r.Complete = false
			}
		}
		if r.Scope != "source" {
			item.Runtime = findRuleView(s.Runtime, query, true)
			if viewAvailable(s.Runtime) {
				usable++
			} else {
				r.Complete = false
			}
		}
		r.Targets = append(r.Targets, item)
	}
	if err := ctx.Err(); err != nil {
		r.Status, r.Complete = "interrupted", false
		return r, err
	}
	if !r.Complete {
		r.Status = "incomplete"
	}
	if usable == 0 {
		r.Status = "unavailable"
		return r, errors.New("no requested rule layer could be inspected")
	}
	return r, nil
}

func findRuleView(view *RulesView, query rulecheck.Rule, reported bool) *RuleLayerFind {
	r := &RuleLayerFind{Status: "unavailable", Message: "Rule layer is unavailable; presence cannot be determined."}
	if view == nil {
		return r
	}
	r.Status, r.Shape, r.Message, r.Limitations = view.Status, view.Shape, view.Message, append([]string(nil), view.Limitations...)
	if !viewAvailable(view) {
		return r
	}
	result := rulecheck.FindEntries(view.Entries, query, reported)
	r.Result = &result
	if !result.Found {
		r.Message = "No identical rule was found in this inspected list; selector variants, if any, are listed separately."
	}
	return r
}

func LookupRules(ctx context.Context, targets []config.Target, input, scope string, opts Options) (RuleLookupReport, error) {
	r := RuleLookupReport{Status: "invalid", Targets: []TargetRuleLookup{}}
	var err error
	r.Input, err = rulecheck.ParseLookup(input)
	if err != nil {
		return r, err
	}
	r.Scope, err = NormalizeRulesScope(scope)
	if err != nil {
		return r, err
	}
	items, err := quickTargets(targets, true)
	if err != nil {
		return r, err
	}
	opts.ReadOnly = true
	r.Status, r.Complete = "completed", true
	usable := 0
	for _, t := range items {
		if err := ctx.Err(); err != nil {
			r.Status, r.Complete = "interrupted", false
			return r, err
		}
		s, _ := ReadRulesSnapshot(ctx, t, r.Scope, opts)
		item := TargetRuleLookup{Target: snapshotInfo(s)}
		if r.Scope != "runtime" {
			item.Source = lookupRuleView(s.Source, r.Input)
			if viewAvailable(s.Source) {
				usable++
			} else {
				r.Complete = false
			}
		}
		if r.Scope != "source" {
			item.Runtime = lookupRuleView(s.Runtime, r.Input)
			if viewAvailable(s.Runtime) {
				usable++
			} else {
				r.Complete = false
			}
		}
		r.Targets = append(r.Targets, item)
	}
	if err := ctx.Err(); err != nil {
		r.Status, r.Complete = "interrupted", false
		return r, err
	}
	if !r.Complete {
		r.Status = "incomplete"
	}
	if usable == 0 {
		r.Status = "unavailable"
		return r, errors.New("no requested rule layer could be inspected")
	}
	return r, nil
}

func lookupRuleView(view *RulesView, input rulecheck.LookupInput) *RuleLayerLookup {
	r := &RuleLayerLookup{Status: "unavailable", Message: "Rule layer is unavailable; coverage cannot be determined."}
	if view == nil {
		return r
	}
	r.Status, r.Shape, r.Message, r.Limitations = view.Status, view.Shape, view.Message, append([]string(nil), view.Limitations...)
	if !viewAvailable(view) {
		return r
	}
	result := rulecheck.LookupEntries(view.Entries, input)
	if view.Shape == "verge-companion" {
		result.Winner = nil
		result.Status = "unknown"
		result.Limitations = append(result.Limitations, "This companion omits the base profile and later Merge/Script composition; matches are declarations, not an effective routing order.")
	}
	r.Result = &result
	return r
}

func entryLabel(e *rulecheck.Entry) string {
	if e == nil {
		return ""
	}
	state := ""
	if e.Rule.Disabled {
		state = " [disabled]"
	}
	return fmt.Sprintf("%s #%d: %s%s", e.Section, e.Rule.Index+1, e.Rule.String(), state)
}

func FormatRuleDiff(r RuleDiffReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Baseline: %s\nScope: %s · %s\n", r.Baseline.TargetID, r.Scope, r.Status)
	writeRuleEvidence(&b, r.Baseline)
	for _, t := range r.Targets {
		fmt.Fprintf(&b, "\n%s → %s\n", r.Baseline.TargetID, t.Target.TargetID)
		writeRuleEvidence(&b, t.Target)
		for _, l := range []struct {
			name string
			v    *RuleLayerDiff
		}{{"runtime", t.Runtime}, {"source", t.Source}} {
			if l.v == nil {
				continue
			}
			fmt.Fprintf(&b, "  %s: %s\n", l.name, l.v.Status)
			if l.v.Message != "" {
				fmt.Fprintf(&b, "    %s\n", l.v.Message)
			}
			if l.v.Result != nil {
				for _, c := range l.v.Result.Changes {
					fmt.Fprintf(&b, "    %s %s\n", c.Kind, strings.Join(c.Fields, ", "))
					if c.Left != nil {
						fmt.Fprintf(&b, "      - %s\n", entryLabel(c.Left))
					}
					if c.Right != nil {
						fmt.Fprintf(&b, "      + %s\n", entryLabel(c.Right))
					}
				}
				writeRuleLimits(&b, l.v.Result.Limitations)
			}
			writeRuleLimits(&b, l.v.Limitations)
		}
	}
	return b.String()
}

func FormatRuleFind(r RuleFindReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule: %s\nScope: %s · %s\n", r.Query, r.Scope, r.Status)
	for _, t := range r.Targets {
		fmt.Fprintf(&b, "\n%s\n", t.Target.TargetID)
		writeRuleEvidence(&b, t.Target)
		for _, l := range []struct {
			name string
			v    *RuleLayerFind
		}{{"runtime", t.Runtime}, {"source", t.Source}} {
			if l.v == nil {
				continue
			}
			fmt.Fprintf(&b, "  %s: %s", l.name, l.v.Status)
			if l.v.Result != nil {
				fmt.Fprintf(&b, " · found=%t", l.v.Result.Found)
			}
			b.WriteByte('\n')
			if l.v.Message != "" {
				fmt.Fprintf(&b, "    %s\n", l.v.Message)
			}
			if l.v.Result != nil {
				for _, m := range l.v.Result.Matches {
					fmt.Fprintf(&b, "    %s: %s", m.Kind, entryLabel(&m.Entry))
					if len(m.Differences) > 0 {
						fmt.Fprintf(&b, " (%s)", strings.Join(m.Differences, ", "))
					}
					b.WriteByte('\n')
				}
				writeRuleLimits(&b, l.v.Result.Limitations)
			}
			writeRuleLimits(&b, l.v.Limitations)
		}
	}
	return b.String()
}

func FormatRuleLookup(r RuleLookupReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Lookup: %s (%s)\nScope: %s · %s\n", r.Input.Value, r.Input.Kind, r.Scope, r.Status)
	for _, t := range r.Targets {
		fmt.Fprintf(&b, "\n%s\n", t.Target.TargetID)
		writeRuleEvidence(&b, t.Target)
		for _, l := range []struct {
			name string
			v    *RuleLayerLookup
		}{{"runtime", t.Runtime}, {"source", t.Source}} {
			if l.v == nil {
				continue
			}
			fmt.Fprintf(&b, "  %s: %s\n", l.name, l.v.Status)
			if l.v.Message != "" {
				fmt.Fprintf(&b, "    %s\n", l.v.Message)
			}
			if l.v.Result != nil {
				fmt.Fprintf(&b, "    Static result: %s\n", l.v.Result.Status)
				for _, s := range l.v.Result.Steps {
					if s.Outcome == "miss" {
						continue
					}
					fmt.Fprintf(&b, "    %s: %s — %s\n", s.Outcome, entryLabel(&s.Entry), s.Reason)
				}
				writeRuleLimits(&b, l.v.Result.Limitations)
			}
			writeRuleLimits(&b, l.v.Limitations)
		}
	}
	return b.String()
}

func writeRuleEvidence(b *strings.Builder, t RuleTargetInfo) {
	fmt.Fprintf(b, "  Observed: %s\n", t.ObservedAt)
	if t.Version != "" {
		fmt.Fprintf(b, "  Core: %s\n", t.Version)
	}
	if t.Mode != "" {
		fmt.Fprintf(b, "  Runtime mode: %s\n", t.Mode)
	}
	if t.Owner != nil {
		fmt.Fprintf(b, "  Source: %s (%s; %s)\n", t.Owner.File, t.Owner.Kind, t.SourceBinding)
	}
	writeRuleLimits(b, t.Limitations)
}

func writeRuleLimits(b *strings.Builder, limits []string) {
	for _, s := range limits {
		fmt.Fprintf(b, "    Limit: %s\n", s)
	}
}
