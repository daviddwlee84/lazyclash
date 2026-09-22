package configwork

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

func batchFixture() BatchRequest {
	return BatchRequest{Request: Request{Kind: "proxy", Action: "import", Input: []byte("trojan://PRIVATE@host:443#node")}, Destinations: []Destination{
		{TargetID: "b", Target: config.Target{ID: "b", SecretEnv: "B_SECRET"}, Groups: []string{"B, 東京"}},
		{TargetID: "a", Target: config.Target{ID: "a", SecretEnv: "A_SECRET"}, Groups: []string{"A"}},
		{TargetID: "c", Target: config.Target{ID: "c"}},
	}}
}

func TestBatchPreflightOrderAndStopOnUnknown(t *testing.T) {
	req := batchFixture()
	calls := []string{}
	preview := func(_ context.Context, target config.Target, r Request, _ Options) (Plan, error) {
		calls = append(calls, "preview:"+target.ID)
		if target.ID == "a" && (target.SecretEnv != "A_SECRET" || !reflect.DeepEqual(r.Groups, []string{"A"})) {
			t.Fatal("cross-target state")
		}
		if target.ID == "b" && !reflect.DeepEqual(r.Groups, []string{"B, 東京"}) {
			t.Fatal("group name split")
		}
		return Plan{TargetID: target.ID, Digest: hash([]byte(target.ID))}, nil
	}
	ctx := context.Background()
	p, err := previewBatch(ctx, req, Options{}, preview)
	if err != nil {
		t.Fatal(err)
	}
	reordered := req
	reordered.Destinations = []Destination{req.Destinations[1], req.Destinations[0], req.Destinations[2]}
	other, err := previewBatch(ctx, reordered, Options{}, preview)
	if err != nil || p.Digest != other.Digest {
		t.Fatal("input order changed canonical digest")
	}
	calls = nil
	apply := func(_ context.Context, target config.Target, r Request, expected string, _ Options) (Receipt, error) {
		calls = append(calls, "apply:"+target.ID)
		if expected != hash([]byte(target.ID)) {
			t.Fatal("wrong target digest")
		}
		if target.ID == "b" {
			return Receipt{ID: "receipt-b", Status: "runtime_result_unknown"}, errors.New("uncertain")
		}
		return Receipt{ID: "receipt-a", Status: "source_and_structure_verified"}, nil
	}
	r, err := applyBatch(ctx, req, p.Digest, Options{}, preview, apply)
	if err == nil || r.Results[1].Receipt.ID != "receipt-b" || r.Results[2].Status != "unattempted" || r.Status != "stopped" {
		t.Fatalf("%+v %v", r, err)
	}
	if !reflect.DeepEqual(calls, []string{"preview:a", "preview:b", "preview:c", "apply:a", "apply:b"}) {
		t.Fatalf("unsafe order: %v", calls)
	}
}

func TestBatchStalePreflightAndReadOnlyNeverWrite(t *testing.T) {
	req := batchFixture()
	revision := "old"
	preview := func(_ context.Context, target config.Target, _ Request, _ Options) (Plan, error) {
		return Plan{TargetID: target.ID, Digest: hash([]byte(target.ID + revision))}, nil
	}
	apply := func(context.Context, config.Target, Request, string, Options) (Receipt, error) {
		t.Fatal("unexpected write")
		return Receipt{}, nil
	}
	p, _ := previewBatch(context.Background(), req, Options{}, preview)
	revision = "new"
	r, err := applyBatch(context.Background(), req, p.Digest, Options{}, preview, apply)
	if err == nil || r.Results[0].Status != "unattempted" {
		t.Fatal("stale review accepted")
	}
	if _, err = applyBatch(context.Background(), req, p.Digest, Options{ReadOnly: true}, preview, apply); err == nil {
		t.Fatal("read-only accepted")
	}
	broken := func(context.Context, config.Target, Request, Options) (Plan, error) {
		return Plan{}, errors.New("validation failed")
	}
	if _, err = applyBatch(context.Background(), req, p.Digest, Options{}, broken, apply); err == nil {
		t.Fatal("failed preflight accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = applyBatch(ctx, req, p.Digest, Options{}, preview, apply); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestBatchRealSourcesAndDistinctGroups(t *testing.T) {
	a, b := newConfigFixture(t, false), newConfigFixture(t, false)
	a.target.ID, b.target.ID = "a", "b"
	req := BatchRequest{Request: Request{Kind: "proxy", Action: "import", Input: []byte("trojan://private@example.test:443#new")}, Destinations: []Destination{{TargetID: "a", Target: a.target, Groups: []string{"G1"}}, {TargetID: "b", Target: b.target, Groups: []string{"G2"}, CreateGroups: []string{"Private, 東京"}}}}
	p, err := PreviewBatch(context.Background(), req, a.opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ApplyBatch(context.Background(), req, p.Digest, a.opts)
	if err != nil || r.Status != "complete" {
		t.Fatalf("%+v %v", r, err)
	}
	for i, f := range []*configFixture{a, b} {
		catalog, err := Inspect(context.Background(), f.target, f.opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range catalog.Groups {
			if g.Name == "G1" || g.Name == "G2" {
				want := (i == 0 && g.Name == "G1") || (i == 1 && g.Name == "G2")
				found := false
				for _, name := range g.Members {
					found = found || name == "new"
				}
				if found != want {
					t.Fatalf("wrong membership: target %d %+v", i, g)
				}
			}
		}
	}
}

func TestBatchRealLateConflictPreventsEveryWrite(t *testing.T) {
	a, b := newConfigFixture(t, false), newConfigFixture(t, false)
	a.target.ID, b.target.ID = "a", "b"
	req := BatchRequest{Request: Request{Kind: "proxy", Action: "import", Input: []byte("trojan://private@example.test:443#new")}, Destinations: []Destination{{TargetID: "a", Target: a.target}, {TargetID: "b", Target: b.target}}}
	p, err := PreviewBatch(context.Background(), req, a.opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(b.base)
	os.WriteFile(b.base, append(raw, []byte("# concurrent edit\n")...), 0600)
	_, err = ApplyBatch(context.Background(), req, p.Digest, a.opts)
	if err == nil || a.writes.Load() != 0 || b.writes.Load() != 0 {
		t.Fatal("late destination was not preflighted")
	}
	raw, _ = os.ReadFile(a.base)
	if strings.Contains(string(raw), "name: new") {
		t.Fatal("earlier destination already changed")
	}
}
