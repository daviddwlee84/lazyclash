package rulework

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type inspectionReads struct{ opens, files map[string]int }

func TestRuntimeSnapshotPreservesOpaqueReportedFields(t *testing.T) {
	for _, tc := range []struct{ kind, payload string }{
		{"DomainRegex", `^(foo|bar){1,3}\.example$`},
		{"ProcessPath", "/applications/a,b/client"},
		{"And", "((DOMAIN,example.com),(NETWORK,tcp))"},
		{"FutureMatcher", "x),y"},
	} {
		rows, err := runtimeRuleList(core.Object{"rules": []any{map[string]any{"type": tc.kind, "payload": tc.payload, "proxy": "PROXY"}}})
		if err != nil || len(rows) != 1 || rows[0].Payload != tc.payload || rows[0].Policy != "PROXY" || !rows[0].Opaque || rows[0].Invalid != "" {
			t.Fatalf("opaque runtime fields were reinterpreted: %+v %v", rows, err)
		}
	}
}

func TestOpaqueSourceAndRuntimeProjectionDoNotInventDrift(t *testing.T) {
	for _, tc := range []struct{ expression, kind, payload string }{
		{`DOMAIN-REGEX,^a{1,3}\.example$,PROXY`, "DomainRegex", `^a{1,3}\.example$`},
		{`FUTURE-MATCHER,a,b,PROXY`, "FUTURE-MATCHER", "a,b"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			f := newFixture(t, false)
			quickSource(t, f, "rules:\n  - '"+tc.expression+"'\n  - MATCH,DIRECT\n")
			f.rules = []map[string]any{{"type": tc.kind, "payload": tc.payload, "proxy": "PROXY"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
			health, err := Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
			if err != nil || health.Targets[0].Drift == nil || !health.Targets[0].Drift.Equal {
				t.Fatal("opaque fields produced false drift", health, err)
			}
			found, err := FindRules(context.Background(), []config.Target{f.target}, tc.expression, "both", f.opts)
			if err != nil || !found.Targets[0].Source.Result.Found || !found.Targets[0].Runtime.Result.Found {
				t.Fatal("full expression could not be found", found, err)
			}
		})
	}
}

func TestVergeOpaqueDriftUsesQueryAliasesAndLiteralOnlyBoundary(t *testing.T) {
	f := newFixture(t, true)
	path := filepath.Join(f.target.RuleSource.DataDir, "profiles", "owned.yaml")
	raw := []byte("prepend:\n  - 'DOMAIN-REGEX,^a{1,3}\\.example$,PROXY'\n  - 'FUTURE-MATCHER,a,b,PROXY'\nappend: []\ndelete: []\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.rules = []map[string]any{{"type": "DomainRegex", "payload": `^a{1,3}\.example$`, "proxy": "PROXY"}, {"type": "FUTURE-MATCHER", "payload": "a,b", "proxy": "PROXY"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
	health, err := Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err != nil || health.Targets[0].Drift == nil || !health.Targets[0].Drift.Equal {
		t.Fatal("Verge opaque declarations produced false drift", health, err)
	}
}

func inspectionOptions(t *testing.T, f *fixture) (Options, *inspectionReads) {
	t.Helper()
	counts := &inspectionReads{opens: map[string]int{}, files: map[string]int{}}
	opts := f.opts
	opts.Open = func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		if !readOnly {
			t.Fatal("inspection requested writable controller")
		}
		counts.opens[target.ID]++
		client, err := core.New(core.Options{Endpoint: target.Controller, ReadOnly: readOnly})
		return client, nil, err
	}
	opts.Host = func(ctx context.Context, target config.Target, request HostRequest) (HostFile, error) {
		if request.Op != "read" {
			t.Fatalf("inspection attempted host operation %s", request.Op)
		}
		counts.files[target.ID]++
		return ReadHostFile(ctx, target.SSHHost, request.Path)
	}
	opts.Validate = func(context.Context, config.Target, []byte, string) error {
		t.Fatal("inspection validated a candidate")
		return nil
	}
	opts.ActivateOwner = func(context.Context, config.Target) error { t.Fatal("inspection activated an owner"); return nil }
	return opts, counts
}

func inspectionFallback(f *fixture) {
	s := f.target.RuleSource
	f.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: s.ConfigID, Binary: s.Binary, Home: s.Home}
	f.target.RuleSource = nil
}

func TestRuleInspectionDiffReadsBaselineOnceAndSortsDestinations(t *testing.T) {
	base, a, z := newFixture(t, false), newFixture(t, false), newFixture(t, false)
	base.target.ID, a.target.ID, z.target.ID = "baseline", "a", "z"
	for _, f := range []*fixture{base, a, z} {
		inspectionFallback(f)
	}
	opts, counts := inspectionOptions(t, base)
	r, err := DiffRules(context.Background(), base.target, []config.Target{z.target, a.target}, "both", opts)
	if err != nil || !r.Complete || r.Status != "completed" || len(r.Targets) != 2 || r.Targets[0].Target.TargetID != "a" || r.Targets[1].Target.TargetID != "z" {
		t.Fatal(r, err)
	}
	for _, id := range []string{"baseline", "a", "z"} {
		if counts.opens[id] != 1 || counts.files[id] != 1 {
			t.Fatal("snapshot reread", id, counts)
		}
	}
	for _, item := range r.Targets {
		if item.Source.Status != "equal" || item.Runtime.Status != "equal" || item.Target.SourceBinding != "config_source" {
			t.Fatal(item)
		}
	}
	for _, f := range []*fixture{base, a, z} {
		if f.target.RuleSource != nil {
			t.Fatal("inspection granted rule write ownership")
		}
	}
	quickAssertUnchanged(t, base, a, z)
	if _, err := os.Stat(opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("inspection wrote receipt state")
	}
}

func TestRuleInspectionFindAndLookupUseReadOnlyFallbackForBothLayers(t *testing.T) {
	f := newFixture(t, false)
	inspectionFallback(f)
	opts, _ := inspectionOptions(t, f)
	find, err := FindRules(context.Background(), []config.Target{f.target}, "MATCH,DIRECT", "both", opts)
	if err != nil || !find.Complete || !find.Targets[0].Source.Result.Found || !find.Targets[0].Runtime.Result.Found || find.Targets[0].Target.SourceBinding != "config_source" {
		t.Fatal(find, err)
	}
	lookup, err := LookupRules(context.Background(), []config.Target{f.target}, "api.example.com", "both", opts)
	if err != nil || !lookup.Complete || lookup.Targets[0].Source.Result.Status != "candidate" || lookup.Targets[0].Runtime.Result.Status != "candidate" {
		t.Fatal(lookup, err)
	}
	if f.target.RuleSource != nil {
		t.Fatal("read fallback granted a persistent rule binding")
	}
	quickAssertUnchanged(t, f)
}

func TestRuleInspectionSourceShapesRemainIncomparable(t *testing.T) {
	native, verge := newFixture(t, false), newFixture(t, true)
	native.target.ID, verge.target.ID = "native", "verge"
	r, err := DiffRules(context.Background(), native.target, []config.Target{verge.target}, "source", native.opts)
	if err != nil || r.Complete || r.Status != "incomplete" || r.Targets[0].Source.Status != "incomparable" || r.Targets[0].Source.Result != nil || r.Targets[0].Source.LeftShape != "complete" || r.Targets[0].Source.RightShape != "verge-companion" || r.Targets[0].Runtime != nil {
		t.Fatal(r, err)
	}
	if r.Targets[0].Source.Message == "" {
		t.Fatal("incomparable source looked empty/equal")
	}
	lookup, err := LookupRules(context.Background(), []config.Target{verge.target}, "example.com", "source", verge.opts)
	if err != nil || lookup.Targets[0].Source.Result.Status != "unknown" || lookup.Targets[0].Source.Result.Winner != nil {
		t.Fatal(lookup, err)
	}
}

func TestRuleInspectionKeepsPartialOfflineLayersDistinctFromAbsence(t *testing.T) {
	base, offline := newFixture(t, false), newFixture(t, false)
	base.target.ID, offline.target.ID = "base", "offline"
	opts, _ := inspectionOptions(t, base)
	open := opts.Open
	opts.Open = func(ctx context.Context, target config.Target, ro bool) (*core.Client, io.Closer, error) {
		if target.ID == "offline" {
			return nil, nil, &core.Error{Kind: core.KindUnreachable}
		}
		return open(ctx, target, ro)
	}
	diff, err := DiffRules(context.Background(), base.target, []config.Target{offline.target}, "both", opts)
	if err != nil || diff.Complete || diff.Status != "incomplete" || diff.Targets[0].Source.Status != "equal" || diff.Targets[0].Runtime.Status != "unavailable" || diff.Targets[0].Runtime.Result != nil {
		t.Fatal(diff, err)
	}
	find, err := FindRules(context.Background(), []config.Target{offline.target}, "DOMAIN,absent.example,DIRECT", "both", opts)
	if err != nil || find.Complete || find.Targets[0].Source.Status != "available" || find.Targets[0].Source.Result.Found || find.Targets[0].Runtime.Result != nil {
		t.Fatal(find, err)
	}
	if !strings.Contains(find.Targets[0].Source.Message, "No identical") || find.Targets[0].Runtime.Message == "" {
		t.Fatal("unavailable and absence lost distinction", find)
	}
	find, err = FindRules(context.Background(), []config.Target{offline.target}, "MATCH,DIRECT", "runtime", opts)
	if err == nil || find.Status != "unavailable" || find.Complete {
		t.Fatal(find, err)
	}
	lookup, err := LookupRules(context.Background(), []config.Target{offline.target}, "example.com", "both", opts)
	if err != nil || lookup.Complete || lookup.Targets[0].Source.Result == nil || lookup.Targets[0].Runtime.Result != nil {
		t.Fatal(lookup, err)
	}
	lookup, err = LookupRules(context.Background(), []config.Target{offline.target}, "example.com", "runtime", opts)
	if err == nil || lookup.Status != "unavailable" {
		t.Fatal(lookup, err)
	}
	diff, err = DiffRules(context.Background(), base.target, []config.Target{offline.target}, "runtime", opts)
	if err == nil || diff.Status != "unavailable" || diff.Complete {
		t.Fatal(diff, err)
	}
}

func TestRuleInspectionFindPolicyAlternativesAndReportedOptions(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n  - DOMAIN,example.com,PROXY\n  - IP-CIDR,203.0.113.0/24,DIRECT\n  - MATCH,DIRECT\n")
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "Domain", "payload": "example.com", "proxy": "PROXY"}, {"type": "IPCIDR", "payload": "203.0.113.0/24", "proxy": "DIRECT"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
	f.mu.Unlock()
	r, err := FindRules(context.Background(), []config.Target{f.target}, "DOMAIN,example.com,DIRECT", "both", f.opts)
	if err != nil || !r.Complete {
		t.Fatal(r, err)
	}
	for _, layer := range []*RuleLayerFind{r.Targets[0].Source, r.Targets[0].Runtime} {
		if layer.Result.Found || len(layer.Result.Matches) != 1 || layer.Result.Matches[0].Kind != "same_selector" || strings.Join(layer.Result.Matches[0].Differences, ",") != "policy" {
			t.Fatal(layer)
		}
	}
	r, err = FindRules(context.Background(), []config.Target{f.target}, "IP-CIDR,203.0.113.0/24,DIRECT,no-resolve", "both", f.opts)
	if err != nil || r.Targets[0].Source.Result.Found || !r.Targets[0].Runtime.Result.Found || r.Targets[0].Runtime.Result.Matches[0].Kind != "reported" {
		t.Fatal(r, err)
	}
	if !strings.Contains(strings.Join(r.Targets[0].Runtime.Result.Limitations, " "), "no-resolve") {
		t.Fatal("reported presence overclaims source equality", r)
	}
	r, err = FindRules(context.Background(), []config.Target{f.target}, "DOMAIN,missing.example,DIRECT", "both", f.opts)
	if err != nil || !r.Complete || r.Targets[0].Source.Result.Found || len(r.Targets[0].Source.Result.Matches) != 0 {
		t.Fatal(r, err)
	}
}

func TestRuleInspectionOpaqueQueriesAndTrailingDotsKeepLiteralIdentity(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n  - DOMAIN-REGEX,^one\\.example$,DIRECT\n  - DOMAIN-REGEX,^two\\.example$,DIRECT\n  - DOMAIN,example.com.,DIRECT\n  - MATCH,DIRECT\n")
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "DomainRegex", "payload": `^one\.example$`, "proxy": "DIRECT"}, {"type": "DomainRegex", "payload": `^two\.example$`, "proxy": "DIRECT"}, {"type": "Domain", "payload": "example.com.", "proxy": "DIRECT"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
	f.mu.Unlock()
	r, err := FindRules(context.Background(), []config.Target{f.target}, `DOMAIN-REGEX,^one\.example$,DIRECT`, "both", f.opts)
	if err != nil || !r.Targets[0].Source.Result.Found || len(r.Targets[0].Source.Result.Matches) != 1 || r.Targets[0].Source.Result.Matches[0].Entry.Rule.Index != 0 {
		t.Fatal(r, err)
	}
	if !strings.Contains(strings.Join(r.Targets[0].Source.Result.Limitations, " "), "literal") {
		t.Fatal("opaque match lacks limitation")
	}
	if !r.Targets[0].Runtime.Result.Found || len(r.Targets[0].Runtime.Result.Matches) != 1 || r.Targets[0].Runtime.Result.Matches[0].Entry.Rule.Index != 0 {
		t.Fatal("runtime opaque alias failed or collided", r)
	}
	r, err = FindRules(context.Background(), []config.Target{f.target}, "DOMAIN,example.com,DIRECT", "source", f.opts)
	if err != nil || r.Targets[0].Source.Result.Found || len(r.Targets[0].Source.Result.Matches) != 0 {
		t.Fatal("trailing dot was stripped", r, err)
	}
	r, err = FindRules(context.Background(), []config.Target{f.target}, "DOMAIN,example.com.,DIRECT", "source", f.opts)
	if err != nil || !r.Targets[0].Source.Result.Found {
		t.Fatal(r, err)
	}
	other := newFixture(t, false)
	other.target.ID = "other"
	quickSource(t, other, "rules:\n  - DOMAIN-REGEX,^three\\.example$,DIRECT\n  - DOMAIN-REGEX,^two\\.example$,DIRECT\n  - DOMAIN,example.com,DIRECT\n  - MATCH,DIRECT\n")
	diff, err := DiffRules(context.Background(), f.target, []config.Target{other.target}, "source", f.opts)
	if err != nil || diff.Targets[0].Source.Status != "different" || len(diff.Targets[0].Source.Result.Changes) != 4 {
		t.Fatal("opaque entries collapsed", diff, err)
	}
}

func TestRuleInspectionLookupUnknownEarlierAndWholeCoverage(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n  - RULE-SET,remote,PROXY\n  - DOMAIN,api.example.com,DIRECT\n  - DOMAIN-SUFFIX,example.com,PROXY\n  - MATCH,DIRECT\n")
	r, err := LookupRules(context.Background(), []config.Target{f.target}, "api.example.com", "source", f.opts)
	if err != nil || !r.Complete || r.Targets[0].Source.Result.Status != "unknown" || r.Targets[0].Source.Result.Winner != nil || len(r.Targets[0].Source.Result.Steps) != 4 {
		t.Fatal(r, err)
	}
	for i, want := range []string{"unknown", "match", "match", "match"} {
		if r.Targets[0].Source.Result.Steps[i].Outcome != want {
			t.Fatal(r)
		}
	}
	quickSource(t, f, "rules:\n  - DOMAIN,api.example.com,DIRECT\n  - RULE-SET,remote,PROXY\n  - DOMAIN-SUFFIX,example.com,PROXY\n  - MATCH,DIRECT\n")
	r, err = LookupRules(context.Background(), []config.Target{f.target}, "api.example.com", "source", f.opts)
	if err != nil || r.Targets[0].Source.Result.Status != "candidate" || r.Targets[0].Source.Result.Winner == nil || r.Targets[0].Source.Result.Winner.Rule.Index != 0 || len(r.Targets[0].Source.Result.Steps) != 4 {
		t.Fatal(r, err)
	}
	if !strings.Contains(strings.Join(r.Targets[0].Source.Result.Limitations, " "), "DNS") {
		t.Fatal("lookup lacks no-network limitation")
	}
	quickAssertUnchanged(t, f)
}

func TestRuleInspectionValidationAndCancellationPrecedeReads(t *testing.T) {
	a, b := newFixture(t, false), newFixture(t, false)
	a.target.ID, b.target.ID = "a", "b"
	opts, _ := inspectionOptions(t, a)
	noRead := opts
	noRead.Host = func(context.Context, config.Target, HostRequest) (HostFile, error) {
		t.Fatal("invalid input read source")
		return HostFile{}, nil
	}
	noRead.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("invalid input read runtime")
		return nil, nil, nil
	}
	for _, target := range []config.Target{{ID: ""}, {ID: "transient", Transient: true}, {ID: "override", TransportOverride: true}} {
		if _, err := FindRules(context.Background(), []config.Target{target}, "MATCH,DIRECT", "both", noRead); err == nil {
			t.Fatal("invalid target accepted")
		}
		if _, err := LookupRules(context.Background(), []config.Target{target}, "example.com", "both", noRead); err == nil {
			t.Fatal("invalid target accepted")
		}
	}
	if _, err := DiffRules(context.Background(), a.target, []config.Target{a.target}, "both", noRead); err == nil {
		t.Fatal("baseline included as destination")
	}
	if _, err := DiffRules(context.Background(), a.target, []config.Target{b.target, b.target}, "both", noRead); err == nil {
		t.Fatal("duplicate destinations accepted")
	}
	if _, err := FindRules(context.Background(), []config.Target{a.target}, "not-a-rule", "both", noRead); err == nil {
		t.Fatal("invalid query accepted")
	}
	if _, err := LookupRules(context.Background(), []config.Target{a.target}, "https://example.com", "both", noRead); err == nil {
		t.Fatal("URL lookup accepted")
	}
	if _, err := FindRules(context.Background(), []config.Target{a.target}, "MATCH,DIRECT", "wrong", noRead); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if _, err := DiffRules(context.Background(), a.target, []config.Target{b.target}, "wrong", noRead); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if _, err := LookupRules(context.Background(), []config.Target{a.target}, "example.com", "wrong", noRead); err == nil {
		t.Fatal("invalid scope accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FindRules(ctx, []config.Target{a.target}, "MATCH,DIRECT", "both", noRead); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := LookupRules(ctx, []config.Target{a.target}, "example.com", "both", noRead); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := DiffRules(ctx, a.target, []config.Target{b.target}, "both", noRead); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		cancel()
		return nil, nil, context.Canceled
	}
	if _, err := LookupRules(ctx, []config.Target{a.target}, "example.com", "both", opts); !errors.Is(err, context.Canceled) {
		t.Fatal("mid-read cancellation became partial success", err)
	}
	if _, err := os.Stat(filepath.Join(a.opts.StateDir, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("inspection wrote a receipt")
	}
}
