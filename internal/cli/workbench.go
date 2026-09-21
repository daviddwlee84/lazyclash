package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/compare"
	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
	"github.com/daviddwlee84/lazyclash/internal/tui"
)

func workJSON(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
func (o *options) runWorkbench(ctx context.Context, r tui.WorkRequest) (tui.WorkResult, error) {
	if strings.HasPrefix(r.Kind, "servers-") {
		return o.runServerWorkbench(ctx, r)
	}
	result := tui.WorkResult{}
	cmp := compare.Options{Open: o.deps.Open, ReadOnly: o.readOnly}
	rules := rulework.Options{Open: o.deps.Open, ReadOnly: o.readOnly}
	switch r.Kind {
	case "source-inspect":
		source, e := rulework.InspectSource(ctx, r.Target)
		return tui.WorkResult{Title: "Persistent source", Summary: workJSON(source)}, e
	case "diff":
		d, e := compare.Diff(ctx, r.Target, r.DestinationTarget, cmp)
		if e != nil {
			return result, e
		}
		result.Title = r.Source + " → " + r.Destination + " · runtime comparison"
		result.Summary = fmt.Sprintf("Core version: %s → %s\nRuntime only; secrets are not compared. Select fields, then p Preview.\nExcluded: %s", d.Source.Version, d.Destination.Version, strings.Join(d.NotCompared, ", "))
		for _, name := range []string{"log-level", "mode"} {
			a, aok := d.Source.General[name]
			b, bok := d.Destination.General[name]
			result.Rows = append(result.Rows, tui.WorkRow{ID: "field:" + name, Label: fmt.Sprintf("%s: %v → %v", name, b, a), Detail: "Destination current → source proposed\n" + workJSON(map[string]any{"source": a, "destination": b}), Selectable: aok && bok})
		}
		dest := map[string]compare.Group{}
		for _, g := range d.Destination.Groups {
			dest[g.Name] = g
		}
		for _, g := range d.Source.Groups {
			dg, ok := dest[g.Name]
			if g.Type != "Selector" {
				continue
			}
			member := false
			for _, s := range dg.Members {
				member = member || s == g.Selected
			}
			result.Rows = append(result.Rows, tui.WorkRow{ID: "group:" + g.Name, Label: fmt.Sprintf("%s: %s → %s", g.Name, dg.Selected, g.Selected), Detail: workJSON(map[string]any{"source": g, "destination": dg}), Selectable: ok && dg.Type == "Selector" && member})
		}
		for _, f := range d.Fields {
			if f.Path == "/mode" || f.Path == "/log-level" {
				continue
			}
			result.Rows = append(result.Rows, tui.WorkRow{ID: "diff:" + f.Path, Label: f.Path + " (compare only)", Detail: workJSON(f)})
		}
		for _, g := range d.Groups {
			result.Rows = append(result.Rows, tui.WorkRow{ID: "diff-group:" + g.Name, Label: g.Name + " · group differences", Detail: workJSON(g)})
		}
		return result, nil
	case "copy-preview":
		p, e := compare.Preview(ctx, r.Target, r.DestinationTarget, compare.Selection{Fields: r.Fields, Groups: r.Groups}, cmp)
		if e != nil {
			return result, e
		}
		result.Title = "Review copy · " + r.Source + " → " + r.Destination
		result.Summary = "Runtime changes; restart or native profile reload may replace them.\nDigest: " + p.Digest
		for _, s := range p.Steps {
			result.Rows = append(result.Rows, tui.WorkRow{ID: s.Kind + ":" + s.Name, Label: s.Name + ": " + s.Before + " → " + s.After, Detail: workJSON(s)})
			result.Summary += "\n" + s.Name + ": " + s.Before + " → " + s.After
		}
		r.Kind = "copy-apply"
		r.Digest = p.Digest
		result.Apply = &r
		return result, nil
	case "copy-apply":
		receipt, e := compare.Apply(ctx, r.Target, r.DestinationTarget, compare.Selection{Fields: r.Fields, Groups: r.Groups}, r.Digest, cmp)
		result.Title = "Copy · " + receipt.Status
		result.Summary = workJSON(receipt)
		return result, e
	case "url":
		d, e := diagnostics.RunURL(ctx, r.Target, r.URL, diagnostics.URLOptions{Options: o.diagnosticOptions(), Via: r.Via, ObserveOnly: r.ObserveOnly})
		result.Title = "URL diagnosis · " + d.Host
		result.Summary = diagnostics.FormatURL(d)
		for i, n := range d.Topology {
			result.Rows = append(result.Rows, tui.WorkRow{ID: fmt.Sprint(i), Label: n.Label + " [" + n.Confidence + "]", Detail: workJSON(n)})
		}
		for _, c := range d.Connections {
			result.Rows = append(result.Rows, tui.WorkRow{ID: "connection:" + c.ID, Label: c.Rule + " · " + c.Confidence, Detail: workJSON(c)})
		}
		result.Rows = append(result.Rows, tui.WorkRow{ID: "local", Label: "Local host evidence", Detail: workJSON(d.Local)}, tui.WorkRow{ID: "core", Label: "Core evidence", Detail: workJSON(d.Core)}, tui.WorkRow{ID: "proxy", Label: "Explicit data proxy", Detail: workJSON(d.ExplicitProxy)})
		if d.Remote != nil {
			result.Rows = append(result.Rows, tui.WorkRow{ID: "ssh", Label: "SSH session evidence", Detail: workJSON(d.Remote)})
		}
		if d.Recommendation != nil {
			result.Recommend = &tui.WorkRequest{Kind: "rule-preview", Source: r.Source, URL: d.Recommendation.Domain, Via: d.Recommendation.Policy}
		}
		return result, e
	case "rule-preview":
		p, e := rulework.Preview(ctx, r.Target, r.URL, r.Via, rules)
		if e != nil {
			return result, e
		}
		result.Title = "Review domain rule · " + p.Owner.Kind
		result.Summary = "File: " + p.Owner.File + "\n" + p.Diff + "\nDigest: " + p.Digest + "\n" + strings.Join(p.Owner.Warnings, "\n")
		if p.Owner.Kind == "verge" {
			result.Summary += "\nAfter saving, reactivate the profile in Clash Verge, then Verify."
		}
		if p.NoChange {
			result.Summary += "\nAlready present; no change needed."
		} else {
			r.Kind = "rule-apply"
			r.Digest = p.Digest
			result.Apply = &r
		}
		return result, nil
	case "rule-apply", "rule-verify", "rule-restore":
		var receipt rulework.Receipt
		var e error
		switch r.Kind {
		case "rule-apply":
			receipt, e = rulework.Apply(ctx, r.Target, r.URL, r.Via, r.Digest, rules)
		case "rule-verify":
			receipt, e = rulework.Verify(ctx, r.Target, r.Receipt, rules)
		case "rule-restore":
			receipt, e = rulework.Restore(ctx, r.Target, r.Receipt, rules)
		}
		result.Title = "Rule receipt · " + receipt.Status
		result.Summary = workJSON(receipt)
		if receipt.ID != "" {
			result.Verify = &tui.WorkRequest{Kind: "rule-verify", Source: r.Source, Receipt: receipt.ID}
		}
		return result, e
	}
	return result, usage("unknown workbench operation")
}
