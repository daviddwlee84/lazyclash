package configwork

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func changeSetBatchFixture() ChangeSetBatchRequest {
	request := ChangeSetBatchRequest{Source: config.Target{ID: "source"}, All: true}
	for _, id := range []string{"b", "a", "c"} {
		request.Destinations = append(request.Destinations, ChangeSetDestination{TargetID: id, Target: config.Target{ID: id}, Selection: StructuralSelection{Objects: []ObjectSelection{{ID: "proxy/node"}}}})
	}
	return request
}

func TestChangeSetBatchPreflightAllAndStopAfterUnknown(t *testing.T) {
	ctx := context.Background()
	req := changeSetBatchFixture()
	var read, written []string
	preview := func(_ context.Context, _, dst config.Target, _ StructuralSelection, _ Options) (ChangeSetPlan, error) {
		read = append(read, dst.ID)
		return ChangeSetPlan{TargetID: dst.ID, Digest: hash([]byte(dst.ID)), Status: "ready"}, nil
	}
	apply := func(_ context.Context, _, dst config.Target, _ StructuralSelection, _ string, _ Options) (ChangeSetReceipt, error) {
		if strings.Join(read, "") != "abc" {
			t.Errorf("write before complete preflight: %v", read)
		}
		written = append(written, dst.ID)
		if dst.ID == "b" {
			return Receipt{ID: "unknown-receipt", Status: "write_unknown"}, errors.New("unknown")
		}
		return Receipt{ID: dst.ID, Status: "source_and_structure_verified"}, nil
	}
	p, err := previewChangeSetBatch(ctx, req, Options{}, preview)
	if err != nil {
		t.Fatal(err)
	}
	read = nil
	r, err := applyChangeSetBatch(ctx, req, p.Digest, Options{}, preview, apply)
	if err == nil || strings.Join(written, "") != "ab" || r.Status != "stopped" || r.Results[2].Status != "unattempted" || r.Results[1].Receipt.ID != "unknown-receipt" {
		t.Fatalf("result=%+v writes=%v err=%v", r, written, err)
	}
}

func TestChangeSetBatchBlocksBeforeWriteAndChecksSkipDrift(t *testing.T) {
	ctx := context.Background()
	req := changeSetBatchFixture()
	offline, invalid := true, false
	writes := 0
	preview := func(_ context.Context, _, dst config.Target, _ StructuralSelection, _ Options) (ChangeSetPlan, error) {
		if dst.ID == "c" && offline {
			return ChangeSetPlan{}, ErrConfigUnavailable
		}
		if dst.ID == "b" && invalid {
			return ChangeSetPlan{}, errors.New("malformed configuration")
		}
		return ChangeSetPlan{TargetID: dst.ID, Digest: hash([]byte(dst.ID)), Status: "ready"}, nil
	}
	apply := func(_ context.Context, _, dst config.Target, _ StructuralSelection, _ string, _ Options) (ChangeSetReceipt, error) {
		writes++
		return Receipt{ID: dst.ID, Status: "source_and_structure_verified"}, nil
	}
	p, err := previewChangeSetBatch(ctx, req, Options{}, preview)
	if err != nil || p.Targets[2].Status != "skipped_unavailable" {
		t.Fatal(p, err)
	}
	offline = false
	if _, err = applyChangeSetBatch(ctx, req, p.Digest, Options{}, preview, apply); err == nil || writes != 0 {
		t.Fatal("skip-state drift wrote", err)
	}
	offline, invalid = true, true
	if _, err = applyChangeSetBatch(ctx, req, p.Digest, Options{}, preview, apply); err == nil || writes != 0 {
		t.Fatal("invalid target failed to block", err)
	}
	invalid = false
	r, err := applyChangeSetBatch(ctx, req, p.Digest, Options{}, preview, apply)
	if err != nil || writes != 2 || r.Status != "completed_with_skips" {
		t.Fatal(r, writes, err)
	}
}

func TestChangeSetBatchNeverPropagatesChoicesToUnselectedTarget(t *testing.T) {
	req := changeSetBatchFixture()
	req.Destinations[0].Selection = StructuralSelection{}
	var read []string
	preview := func(_ context.Context, _, dst config.Target, s StructuralSelection, _ Options) (ChangeSetPlan, error) {
		read = append(read, dst.ID)
		if len(s.Objects) != 1 {
			t.Error("wrong selection")
		}
		return ChangeSetPlan{TargetID: dst.ID, Digest: hash([]byte(dst.ID)), Status: "ready"}, nil
	}
	p, err := previewChangeSetBatch(context.Background(), req, Options{}, preview)
	if err != nil || strings.Join(read, "") != "ac" || p.Targets[1].Status != "not_selected" {
		t.Fatal(p, read, err)
	}
	req.Destinations[1].Selection = StructuralSelection{}
	req.Destinations[2].Selection = StructuralSelection{}
	if _, err := previewChangeSetBatch(context.Background(), req, Options{}, preview); err == nil {
		t.Fatal("empty selections accepted")
	}
}
