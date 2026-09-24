package rulework

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func TestRulesSnapshotConfigSourceFallbackIsReadOnlyAndKeepsTargetMetadata(t *testing.T) {
	f := newFixture(t, false)
	ruleOwner := f.target.RuleSource
	f.target.RuleSource = nil
	f.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: ruleOwner.ConfigID, Binary: ruleOwner.Binary, Home: ruleOwner.Home}
	f.target.ManagedCoreID = "owned"
	upstream, _ := url.Parse(f.target.Controller)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("snapshot attempted API mutation %s %s", r.Method, r.URL.Path)
			w.WriteHeader(403)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	f.target.Controller = front.URL
	opts := f.opts
	reads, opens := 0, 0
	opts.Host = func(ctx context.Context, target config.Target, req HostRequest) (HostFile, error) {
		reads++
		if req.Op != "read" {
			t.Fatalf("snapshot attempted host mutation: %s", req.Op)
		}
		if target.ConfigSource != f.target.ConfigSource || target.ManagedCoreID != f.target.ManagedCoreID || target.RuleSource == nil || target.Controller != front.URL {
			t.Fatal("fallback replaced original owner/transport metadata", target)
		}
		return ReadHostFile(ctx, target.SSHHost, req.Path)
	}
	opts.Open = func(_ context.Context, target config.Target, readOnly bool) (*core.Client, io.Closer, error) {
		opens++
		if !readOnly {
			t.Fatal("snapshot opened writable controller")
		}
		client, err := core.New(core.Options{Endpoint: target.Controller, ReadOnly: readOnly})
		return client, nil, err
	}
	opts.Validate = func(context.Context, config.Target, []byte, string) error {
		t.Fatal("snapshot validated a candidate")
		return nil
	}
	opts.ActivateOwner = func(context.Context, config.Target) error { t.Fatal("snapshot activated owner"); return nil }
	snapshot, err := ReadRulesSnapshot(context.Background(), f.target, "both", opts)
	if err != nil || snapshot.SourceBinding != "config_source" || snapshot.Source.Status != "available" || snapshot.Runtime.Status != "available" || snapshot.Version != "v1.19.29" || snapshot.Mode != "rule" || reads != 1 || opens != 1 {
		t.Fatal(snapshot, err, reads, opens)
	}
	if f.target.RuleSource != nil || f.writes != 0 {
		t.Fatal("fallback granted writes or changed runtime")
	}
	if _, err := InspectSource(context.Background(), f.target); err == nil {
		t.Fatal("read fallback became a persistent write binding")
	}
	if _, err := os.Stat(opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("snapshot created persistent state", err)
	}
	data, _ := json.Marshal(snapshot)
	if strings.Contains(string(data), "do-not-expose-this") || strings.Contains(string(data), "fingerprint") {
		t.Fatal("snapshot exposed source bytes or guards", string(data))
	}
}

func TestRulesSnapshotScopesAndIndependentAvailability(t *testing.T) {
	f := newFixture(t, false)
	opts := f.opts
	opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		t.Fatal("source scope contacted API")
		return nil, nil, nil
	}
	snapshot, err := ReadRulesSnapshot(context.Background(), f.target, "source", opts)
	if err != nil || snapshot.Source.Status != "available" || snapshot.Runtime != nil || snapshot.Source.Shape != "complete" || len(snapshot.Source.Entries) != 1 || snapshot.Source.Entries[0].Section != "rules" || snapshot.Source.Entries[0].Rule.Index != 0 {
		t.Fatal(snapshot, err)
	}
	opts = f.opts
	opts.Host = func(context.Context, config.Target, HostRequest) (HostFile, error) {
		t.Fatal("runtime scope read source")
		return HostFile{}, nil
	}
	snapshot, err = ReadRulesSnapshot(context.Background(), f.target, "runtime", opts)
	if err != nil || snapshot.Source != nil || snapshot.Runtime.Status != "available" {
		t.Fatal(snapshot, err)
	}
	opts = f.opts
	opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, &core.Error{Kind: core.KindUnreachable}
	}
	snapshot, err = ReadRulesSnapshot(context.Background(), f.target, "both", opts)
	if err != nil || snapshot.Source.Status != "available" || snapshot.Runtime.Status != "unavailable" {
		t.Fatal(snapshot, err)
	}
	f.target.Configs[0].Path = filepath.Join(t.TempDir(), "missing.yaml")
	snapshot, err = ReadRulesSnapshot(context.Background(), f.target, "both", f.opts)
	if err != nil || snapshot.Source.Status != "unavailable" || snapshot.Runtime.Status != "available" {
		t.Fatal(snapshot, err)
	}
	snapshot, err = ReadRulesSnapshot(context.Background(), f.target, "both", opts)
	if err == nil || snapshot.Source.Status != "unavailable" || snapshot.Runtime.Status != "unavailable" {
		t.Fatal(snapshot, err)
	}
	if _, err = ReadRulesSnapshot(context.Background(), f.target, "invalid", f.opts); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if scope, err := NormalizeRulesScope(""); err != nil || scope != "both" {
		t.Fatal(scope, err)
	}
}

func TestRulesSnapshotPrefersRuleBindingAndPreservesHardSourceFailure(t *testing.T) {
	f := newFixture(t, false)
	f.target.Configs = append(f.target.Configs, config.CoreConfig{ID: "other", Path: "/missing/other.yaml"})
	f.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: "other", Binary: "/invalid", Home: "/missing"}
	snapshot, err := ReadRulesSnapshot(context.Background(), f.target, "both", f.opts)
	if err != nil || snapshot.SourceBinding != "rule_source" || snapshot.Source.Status != "available" {
		t.Fatal(snapshot, err)
	}
	if err = os.WriteFile(f.target.Configs[0].Path, []byte("rules: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err = ReadRulesSnapshot(context.Background(), f.target, "both", f.opts)
	if err == nil || snapshot.Source.Status != "error" || snapshot.Runtime.Status != "available" {
		t.Fatal(snapshot, err)
	}
}

func TestRulesHealthDriftUsesReportedProjection(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n  - IP-CIDR,203.0.113.0/24,DIRECT,no-resolve\n  - DOMAIN-SUFFIX,example.com,PROXY\n  - MATCH,DIRECT\n")
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "IPCIDR", "payload": "203.0.113.0/24", "proxy": "DIRECT"}, {"type": "DomainSuffix", "payload": "example.com", "proxy": "PROXY"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
	f.mu.Unlock()
	report, err := Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err != nil || report.Targets[0].Drift == nil || !report.Targets[0].Drift.Equal || report.Targets[0].Snapshot == nil {
		t.Fatal(report, err)
	}
	if quickFindings(report.Targets[0].Findings, "source_runtime_drift") {
		t.Fatal("missing runtime no-resolve metadata became drift", report)
	}
	f.mu.Lock()
	f.rules[0]["proxy"] = "PROXY"
	f.mu.Unlock()
	report, err = Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err != nil || report.Targets[0].Drift.Equal || !quickFindings(report.Targets[0].Findings, "source_runtime_drift") {
		t.Fatal(report, err)
	}
	if f.writes != 0 {
		t.Fatal("drift check reloaded runtime")
	}
}

func TestRulesSnapshotVergeSectionsAndBaselineAreNotDrift(t *testing.T) {
	f := newFixture(t, true)
	path := filepath.Join(f.target.RuleSource.DataDir, "profiles", "owned.yaml")
	data := []byte("prepend:\n  - DOMAIN,first.example,DIRECT\nappend:\n  - DOMAIN,last.example,PROXY\ndelete:\n  - DOMAIN,deleted.example,DIRECT\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "Domain", "payload": "first.example", "proxy": "DIRECT"}, {"type": "DomainSuffix", "payload": "baseline.example", "proxy": "PROXY"}, {"type": "Domain", "payload": "last.example", "proxy": "PROXY"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
	f.mu.Unlock()
	snapshot, err := ReadRulesSnapshot(context.Background(), f.target, "both", f.opts)
	if err != nil || snapshot.Source.Shape != "verge-companion" || len(snapshot.Source.Entries) != 3 {
		t.Fatal(snapshot, err)
	}
	for i, section := range []string{"prepend", "append", "delete"} {
		if snapshot.Source.Entries[i].Section != section || snapshot.Source.Entries[i].Rule.Index != 0 {
			t.Fatal(snapshot.Source.Entries)
		}
	}
	report, err := Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err != nil || report.Targets[0].Source.Stats.Total != 2 || report.Targets[0].Drift == nil || !report.Targets[0].Drift.Equal || quickFindings(report.Targets[0].Findings, "source_runtime_drift") {
		t.Fatal(report, err)
	}
	f.mu.Lock()
	f.rules = f.rules[1:]
	f.mu.Unlock()
	report, err = Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err != nil || report.Targets[0].Drift.Equal || len(report.Targets[0].Drift.Changes) != 1 || report.Targets[0].Drift.Changes[0].Kind != "removed" {
		t.Fatal(report, err)
	}
}

func TestRulesSnapshotCancellationIsNotPartialSuccess(t *testing.T) {
	f := newFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	opts := f.opts
	opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		cancel()
		return nil, nil, context.Canceled
	}
	_, err := Healthcheck(ctx, []config.Target{f.target}, false, opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRulesSnapshotUnavailableRuntimeDoesNotRepeatMetadataRequests(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/rules" {
			t.Errorf("unavailable runtime triggered metadata request %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	opts := Options{Open: func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		client, err := core.New(core.Options{Endpoint: server.URL, ReadOnly: true})
		return client, nil, err
	}}
	snapshot, err := ReadRulesSnapshot(context.Background(), config.Target{ID: "offline", Controller: server.URL}, "runtime", opts)
	if err == nil || snapshot.Runtime.Status != "unavailable" || requests != 1 {
		t.Fatal(snapshot, err, requests)
	}
}
