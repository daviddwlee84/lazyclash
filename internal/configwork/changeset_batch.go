package configwork

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// ChangeSetDestination contains only identifiers and decisions in public JSON.
// Each resolved target retains its own connection and owner bindings.
type ChangeSetDestination struct {
	TargetID  string              `json:"target"`
	Selection StructuralSelection `json:"selection"`
	Target    config.Target       `json:"-"`
}

type ChangeSetBatchRequest struct {
	Source       config.Target          `json:"-"`
	Destinations []ChangeSetDestination `json:"destinations"`
	All          bool                   `json:"all,omitempty"`
}

type ChangeSetTargetPlan struct {
	TargetID string         `json:"target"`
	Status   string         `json:"status"`
	Message  string         `json:"message,omitempty"`
	Plan     *ChangeSetPlan `json:"plan,omitempty"`
}

type ChangeSetBatchPlan struct {
	SourceTargetID string                `json:"source_target_id"`
	Digest         string                `json:"digest"`
	Status         string                `json:"status"`
	Targets        []ChangeSetTargetPlan `json:"targets"`
}

type ChangeSetBatchResult struct {
	Digest  string              `json:"digest"`
	Status  string              `json:"status"`
	Results []DestinationResult `json:"results"`
}

type changeSetPreview func(context.Context, config.Target, config.Target, StructuralSelection, Options) (ChangeSetPlan, error)
type changeSetApply func(context.Context, config.Target, config.Target, StructuralSelection, string, Options) (ChangeSetReceipt, error)

func changeSetDestinations(req ChangeSetBatchRequest) ([]ChangeSetDestination, error) {
	if req.Source.ID == "" || req.Source.Transient || req.Source.TransportOverride {
		return nil, errors.New("configuration sync requires a saved source target")
	}
	if len(req.Destinations) == 0 {
		return nil, errors.New("select at least one destination")
	}
	items := append([]ChangeSetDestination(nil), req.Destinations...)
	sort.Slice(items, func(i, j int) bool { return items[i].TargetID < items[j].TargetID })
	for i, d := range items {
		if d.TargetID == "" || d.TargetID != d.Target.ID || d.Target.Transient || d.Target.TransportOverride {
			return nil, errors.New("each destination must resolve to its own saved target")
		}
		if d.TargetID == req.Source.ID {
			return nil, errors.New("source and destination must be different targets")
		}
		if i > 0 && items[i-1].TargetID == d.TargetID {
			return nil, fmt.Errorf("duplicate destination %q", d.TargetID)
		}
	}
	return items, nil
}

func PreviewChangeSetBatch(ctx context.Context, req ChangeSetBatchRequest, opts Options) (ChangeSetBatchPlan, error) {
	return previewChangeSetBatch(ctx, req, opts, PreviewChangeSet)
}

func previewChangeSetBatch(ctx context.Context, req ChangeSetBatchRequest, opts Options, preview changeSetPreview) (ChangeSetBatchPlan, error) {
	p := ChangeSetBatchPlan{SourceTargetID: req.Source.ID, Status: "blocked", Targets: []ChangeSetTargetPlan{}}
	destinations, err := changeSetDestinations(req)
	if err != nil {
		return p, err
	}
	p.Status = "no_changes"
	var failures []error
	selected, usable := 0, 0
	for _, d := range destinations {
		if err = ctx.Err(); err != nil {
			p.Status = "stopped"
			return p, err
		}
		item := ChangeSetTargetPlan{TargetID: d.TargetID, Status: "not_selected"}
		if len(d.Selection.Objects) == 0 {
			p.Targets = append(p.Targets, item)
			continue
		}
		selected++
		plan, e := preview(ctx, req.Source, d.Target, d.Selection, opts)
		item.Plan = &plan
		item.Status = plan.Status
		if e != nil {
			item.Message = core.Sanitize(e.Error())
			item.Status = "blocked"
			if req.All && errors.Is(e, ErrConfigUnavailable) {
				item.Status = "skipped_unavailable"
			} else {
				failures = append(failures, fmt.Errorf("target %q: %w", d.TargetID, e))
			}
		} else {
			usable++
			if plan.Status != "no_changes" {
				p.Status = "ready"
			}
		}
		p.Targets = append(p.Targets, item)
	}
	if selected == 0 {
		failures = append(failures, errors.New("select at least one object; use configs sync --interactive or a nonempty selection file"))
	}
	if selected > 0 && usable == 0 && len(failures) == 0 {
		failures = append(failures, errors.New("all selected destinations are unavailable"))
	}
	if len(failures) > 0 {
		p.Status = "blocked"
	}
	// Include all choices and skip states. A newly reachable target or a changed
	// source/owner invalidates the review before any destination is written.
	req.Destinations = destinations
	p.Digest = hashJSON(struct {
		Source, Choices string
		Targets         []ChangeSetTargetPlan
	}{Binding(req.Source), hashJSON(req), p.Targets})
	return p, errors.Join(failures...)
}

func ApplyChangeSetBatch(ctx context.Context, req ChangeSetBatchRequest, expected string, opts Options) (ChangeSetBatchResult, error) {
	return applyChangeSetBatch(ctx, req, expected, opts, PreviewChangeSet, ApplyChangeSet)
}

func applyChangeSetBatch(ctx context.Context, req ChangeSetBatchRequest, expected string, opts Options, preview changeSetPreview, apply changeSetApply) (ChangeSetBatchResult, error) {
	r := ChangeSetBatchResult{Digest: expected, Status: "stopped", Results: []DestinationResult{}}
	destinations, err := changeSetDestinations(req)
	if err != nil {
		return r, err
	}
	for _, d := range destinations {
		r.Results = append(r.Results, DestinationResult{TargetID: d.TargetID, Status: "unattempted"})
	}
	if opts.ReadOnly {
		return r, errors.New("configuration sync is disabled in read-only mode")
	}
	if len(expected) != 64 {
		return r, errors.New("configuration sync requires its reviewed digest")
	}
	p, err := previewChangeSetBatch(ctx, req, opts, preview)
	if err != nil {
		return r, err
	}
	if p.Digest != expected {
		return r, errors.New("configuration source, selection or destination changed; review a new preview")
	}
	skipped := false
	for i, d := range destinations {
		if err = ctx.Err(); err != nil {
			return r, err
		}
		item := &r.Results[i]
		targetPlan := p.Targets[i]
		if targetPlan.Status == "not_selected" || targetPlan.Status == "no_changes" || targetPlan.Status == "skipped_unavailable" {
			item.Status, item.Message = targetPlan.Status, targetPlan.Message
			skipped = skipped || item.Status == "skipped_unavailable"
			continue
		}
		receipt, e := apply(ctx, req.Source, d.Target, d.Selection, targetPlan.Plan.Digest, opts)
		item.Status = "failed"
		if receipt.ID != "" {
			item.Receipt, item.Status = &receipt, receipt.Status
		}
		if e != nil {
			item.Message = "Stopped; inspect the receipt before retrying. Completed changes are retained."
			return r, fmt.Errorf("target %q: %w", d.TargetID, e)
		}
		switch receipt.Status {
		case "source_and_structure_verified", "persisted_pending_owner_reload", "no_changes":
		default:
			item.Message = "Verification incomplete; later targets were not attempted."
			return r, fmt.Errorf("target %q has unverified result %q", d.TargetID, receipt.Status)
		}
	}
	r.Status = "complete"
	if skipped {
		r.Status = "completed_with_skips"
	}
	return r, nil
}

func FormatChangeSetBatch(p ChangeSetBatchPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Source: %s\nStatus: %s\nDigest: %s\n", p.SourceTargetID, p.Status, p.Digest)
	for _, t := range p.Targets {
		fmt.Fprintf(&b, "\n%s: %s\n", t.TargetID, t.Status)
		if t.Message != "" {
			fmt.Fprintln(&b, t.Message)
		}
		if t.Plan == nil {
			continue
		}
		p := t.Plan
		for _, id := range p.Composition.Selected {
			fmt.Fprintf(&b, "  selected: %s\n", id)
		}
		for _, id := range p.Composition.AutoSelected {
			fmt.Fprintf(&b, "  dependency: %s", id)
			if required := p.Composition.RequiredBy[id]; len(required) > 0 {
				fmt.Fprintf(&b, " (required by %s)", strings.Join(required, ", "))
			}
			fmt.Fprintln(&b)
		}
		for _, id := range p.Composition.Reused {
			fmt.Fprintf(&b, "  reuse destination: %s\n", id)
		}
		for _, c := range p.Changes {
			fmt.Fprintf(&b, "  %s: %s\n", c.Status, c.Path)
		}
		for _, resource := range p.Resources {
			role := "authoritative data"
			if resource.Mutable {
				role = "HTTP cache seed"
			}
			fmt.Fprintf(&b, "  resource: %s/%s → %s (%d bytes, %s)\n", resource.Section, resource.Provider, resource.CorePath, resource.Bytes, role)
		}
		if len(p.Composition.Diff.Objects) > 0 {
			fmt.Fprint(&b, FormatConfigDiff(p.Composition.Diff, "tree"))
		}
		for _, w := range p.Warnings {
			fmt.Fprintf(&b, "  warning: %s\n", w)
		}
		for _, blocker := range p.Composition.Blockers {
			fmt.Fprintf(&b, "  %s: %s\n", blocker.Code, blocker.Message)
		}
	}
	fmt.Fprintln(&b, "\nDestinations apply in ID order. A failure stops later targets; completed writes are retained.")
	return core.Sanitize(b.String())
}
