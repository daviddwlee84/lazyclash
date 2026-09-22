package configwork

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

// Destination is also the credential-free --destinations JSON entry. The CLI
// resolves each TargetID independently before calling the shared service.
type Destination struct {
	TargetID     string        `json:"target"`
	Groups       []string      `json:"groups,omitempty"`
	CreateGroups []string      `json:"create_groups,omitempty"`
	Target       config.Target `json:"-"`
}
type BatchRequest struct {
	Request      Request       `json:"request"`
	Destinations []Destination `json:"destinations"`
}
type BatchPlan struct {
	Digest string `json:"digest"`
	Plans  []Plan `json:"plans"`
}
type DestinationResult struct {
	TargetID string   `json:"target"`
	Status   string   `json:"status"`
	Receipt  *Receipt `json:"receipt,omitempty"`
	Message  string   `json:"message,omitempty"`
}
type BatchResult struct {
	Digest  string              `json:"digest"`
	Status  string              `json:"status"`
	Results []DestinationResult `json:"results"`
}

type batchPreview func(context.Context, config.Target, Request, Options) (Plan, error)
type batchApply func(context.Context, config.Target, Request, string, Options) (Receipt, error)

func batchDestinations(req BatchRequest) ([]Destination, error) {
	if req.Request.Kind != "proxy" || (req.Request.Action != "import" && req.Request.Action != "add") {
		return nil, errors.New("multiple destinations require adding or importing proxies")
	}
	if len(req.Destinations) == 0 {
		return nil, errors.New("select at least one destination")
	}
	if len(req.Request.Groups) != 0 || len(req.Request.CreateGroups) != 0 {
		return nil, errors.New("batch groups belong to each destination")
	}
	items := append([]Destination(nil), req.Destinations...)
	sort.Slice(items, func(i, j int) bool { return items[i].TargetID < items[j].TargetID })
	for i, d := range items {
		if d.TargetID == "" || d.TargetID != d.Target.ID || d.Target.Transient || d.Target.TransportOverride {
			return nil, errors.New("each destination must resolve to its own saved target")
		}
		if i > 0 && items[i-1].TargetID == d.TargetID {
			return nil, fmt.Errorf("duplicate destination %q", d.TargetID)
		}
	}
	return items, nil
}

func destinationRequest(req Request, d Destination) Request {
	req.Groups = append([]string(nil), d.Groups...)
	req.CreateGroups = append([]string(nil), d.CreateGroups...)
	return req
}

func PreviewBatch(ctx context.Context, req BatchRequest, opts Options) (BatchPlan, error) {
	return previewBatch(ctx, req, opts, Preview)
}
func previewBatch(ctx context.Context, req BatchRequest, opts Options, preview batchPreview) (BatchPlan, error) {
	p := BatchPlan{Plans: []Plan{}}
	destinations, err := batchDestinations(req)
	if err != nil {
		return p, err
	}
	for _, d := range destinations {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		plan, err := preview(ctx, d.Target, destinationRequest(req.Request, d), opts)
		if err != nil {
			return p, fmt.Errorf("target %q: %w", d.TargetID, err)
		}
		p.Plans = append(p.Plans, plan)
	}
	// Include the request as well as every target/source digest. Input remains a
	// private hash and is never serialized into the public batch plan.
	req.Destinations = destinations
	digests := []string{hash(req.Request.Input), hashJSON(req)}
	for _, plan := range p.Plans {
		digests = append(digests, plan.TargetID, plan.Digest)
	}
	p.Digest = hashJSON(digests)
	return p, nil
}

func ApplyBatch(ctx context.Context, req BatchRequest, expected string, opts Options) (BatchResult, error) {
	return applyBatch(ctx, req, expected, opts, Preview, Apply)
}
func applyBatch(ctx context.Context, req BatchRequest, expected string, opts Options, preview batchPreview, apply batchApply) (BatchResult, error) {
	r := BatchResult{Digest: expected, Status: "stopped", Results: []DestinationResult{}}
	destinations, err := batchDestinations(req)
	if err != nil {
		return r, err
	}
	for _, d := range destinations {
		r.Results = append(r.Results, DestinationResult{TargetID: d.TargetID, Status: "unattempted"})
	}
	if opts.ReadOnly {
		return r, errors.New("source edits are disabled in read-only mode")
	}
	if len(expected) != 64 {
		return r, errors.New("batch apply requires its reviewed digest")
	}
	// All destinations are checked again before the first write. Apply also
	// rechecks each individual digest immediately before its write.
	p, err := previewBatch(ctx, req, opts, preview)
	if err != nil {
		return r, err
	}
	if p.Digest != expected {
		return r, errors.New("batch source/context changed; review a new preview")
	}
	for i, d := range destinations {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		receipt, err := apply(ctx, d.Target, destinationRequest(req.Request, d), p.Plans[i].Digest, opts)
		item := &r.Results[i]
		item.Status = "failed"
		if receipt.ID != "" {
			item.Receipt = &receipt
			item.Status = receipt.Status
		}
		if err != nil {
			item.Message = "Operation stopped; inspect any receipt before retrying."
			return r, fmt.Errorf("target %q: %w", d.TargetID, err)
		}
		// A pending native owner reload is an explicit known state. An absent
		// verification/unknown write is not success and stops the batch.
		if receipt.Status != "source_and_structure_verified" && receipt.Status != "persisted_pending_owner_reload" {
			item.Message = "Verification incomplete; inspect this receipt before continuing."
			return r, fmt.Errorf("target %q has unverified result %q", d.TargetID, receipt.Status)
		}
	}
	r.Status = "complete"
	return r, nil
}

func BatchWarningsText(p BatchPlan) string {
	var b strings.Builder
	for _, item := range p.Plans {
		fmt.Fprintf(&b, "Target: %s\n%s\n\n", item.TargetID, WarningsText(item))
	}
	fmt.Fprintf(&b, "Digest: %s\nTargets apply in ID order. A failure stops later targets; completed writes are retained.", p.Digest)
	return b.String()
}
