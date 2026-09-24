package rulework

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/clientservice"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulecheck"
	"github.com/daviddwlee84/lazyclash/internal/sourceowner"
)

const quickSuffix = "DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT"

func TestQuickVergeRetainedRuntimeConflictAndCompanionSchema(t *testing.T) {
	f := newFixture(t, true)
	f.rules = []map[string]any{{"type": "DomainSuffix", "payload": "api.enterprise.githubcopilot.com", "proxy": "PROXY"}}
	path := filepath.Join(f.target.RuleSource.DataDir, "profiles", "owned.yaml")
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err == nil || p.Status != "blocked" || !quickFindings(p.Targets[0].Findings, "selector_conflict") {
		t.Fatal("Verge retained conflict was not blocking", p, err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(f.source) {
		t.Fatal("preview wrote Verge source")
	}
	f.rules = []map[string]any{{"type": "Match", "payload": "", "proxy": "DIRECT"}}
	if err = os.WriteFile(path, []byte("prepend: []\ndelete: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts); err == nil {
		t.Fatal("invalid companion schema accepted")
	}
}

func TestQuickAndHealthReportKnownMissingProvider(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n- RULE-SET,missing,DIRECT\n- MATCH,DIRECT\n")
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err == nil || !quickFindings(p.Targets[0].Findings, "provider_missing") {
		t.Fatal(p, err)
	}
	h, err := Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err == nil || h.Targets[0].Source == nil || !quickFindings(h.Targets[0].Source.Findings, "provider_missing") {
		t.Fatal(h, err)
	}
	quickAssertUnchanged(t, f)
}

func quickSource(t *testing.T, f *fixture, text string) {
	t.Helper()
	f.source = []byte(text)
	if err := os.WriteFile(f.target.Configs[0].Path, f.source, 0640); err != nil {
		t.Fatal(err)
	}
}
func quickFindings(findings []rulecheck.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}
func quickAssertUnchanged(t *testing.T, fixtures ...*fixture) {
	t.Helper()
	for _, f := range fixtures {
		data, err := os.ReadFile(f.target.Configs[0].Path)
		if err != nil || string(data) != string(f.source) || f.writes != 0 {
			t.Fatalf("target %s changed before preflight completed: writes=%d err=%v", f.target.ID, f.writes, err)
		}
	}
}

func TestQuickSuffixApplyVerifyRestoreAndRepeatedSkip(t *testing.T) {
	f := newFixture(t, false)
	ctx := context.Background()
	targets := []config.Target{f.target}
	p, err := PreviewRules(ctx, targets, "- "+quickSuffix, false, f.opts)
	if err != nil || p.Rule != quickSuffix || !p.HasChanges() {
		t.Fatal(p, err)
	}
	if _, err = os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("preview created receipt state", err)
	}
	r, err := ApplyRules(ctx, targets, quickSuffix, false, p.Digest, f.opts)
	if err != nil || r.Status != "completed" || len(r.Results) != 1 || r.Results[0].Receipt == nil || r.Results[0].Status != "applied_verified" {
		t.Fatal(r, err)
	}
	receipt := *r.Results[0].Receipt
	if got, err := Verify(ctx, f.target, receipt.ID, f.opts); err != nil || !got.RuntimeVerified {
		t.Fatal(got, err)
	}
	after, err := os.ReadFile(receipt.File)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	p, err = PreviewRules(ctx, targets, quickSuffix, false, f.opts)
	if err != nil || p.Status != "no_changes" || p.Targets[0].Status != "skipped_existing" || !p.Targets[0].RuntimeVerified {
		t.Fatal(p, err)
	}
	r, err = ApplyRules(ctx, targets, quickSuffix, false, p.Digest, f.opts)
	if err != nil || r.Results[0].Receipt != nil || f.writes != 1 {
		t.Fatal(r, err, f.writes)
	}
	newEntries, _ := os.ReadDir(f.opts.StateDir)
	newAfter, _ := os.ReadFile(receipt.File)
	if len(newEntries) != len(entries) || string(newAfter) != string(after) {
		t.Fatal("skip wrote source or receipt")
	}
	restored, err := Restore(ctx, f.target, receipt.ID, f.opts)
	if err != nil || restored.Status != "restored_verified" {
		t.Fatal(restored, err)
	}
	before, _ := os.ReadFile(receipt.File)
	if string(before) != string(f.source) {
		t.Fatal("restore did not retain original bytes")
	}
}

func TestQuickExistingShadowedRuleSkipsWithoutReordering(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n  - DOMAIN-SUFFIX,githubcopilot.com,PROXY\n  - "+quickSuffix+"\n  - MATCH,DIRECT\n")
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err != nil || p.Targets[0].Status != "skipped_existing" || !quickFindings(p.Targets[0].Findings, "shadowed") {
		t.Fatal(p, err)
	}
	if !quickFindings(p.Targets[0].Findings, "source_runtime_drift") {
		t.Fatal("missing source/runtime limitation", p)
	}
	r, err := ApplyRules(context.Background(), []config.Target{f.target}, quickSuffix, false, p.Digest, f.opts)
	if err != nil || r.Results[0].Receipt != nil {
		t.Fatal(r, err)
	}
	quickAssertUnchanged(t, f)
	if _, err = os.Stat(f.opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("duplicate-only operation created state")
	}
}

func TestQuickSpecificExceptionOverBroaderPolicyIsWarning(t *testing.T) {
	f := newFixture(t, false)
	quickSource(t, f, "rules:\n  - DOMAIN-SUFFIX,githubcopilot.com,PROXY\n  - MATCH,DIRECT\n")
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err != nil || p.Targets[0].Status != "ready" || !quickFindings(p.Targets[0].Findings, "overlap") {
		t.Fatal(p, err)
	}
	r, err := ApplyRules(context.Background(), []config.Target{f.target}, quickSuffix, false, p.Digest, f.opts)
	if err != nil || r.Results[0].Status != "applied_verified" {
		t.Fatal(r, err)
	}
	data, _ := os.ReadFile(f.target.Configs[0].Path)
	if strings.Index(string(data), quickSuffix) > strings.Index(string(data), "DOMAIN-SUFFIX,githubcopilot.com,PROXY") {
		t.Fatal("specific exception was not prepended")
	}
}

func TestQuickAllPreflightConflictsAndValidationFailuresWriteNothing(t *testing.T) {
	for _, failure := range []string{"conflict", "candidate-validation"} {
		t.Run(failure, func(t *testing.T) {
			a, b := newFixture(t, false), newFixture(t, false)
			a.target.ID, b.target.ID = "a", "b"
			opts := a.opts
			if failure == "conflict" {
				quickSource(t, b, "rules:\n  - DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,PROXY\n  - MATCH,DIRECT\n")
			} else {
				validate := opts.Validate
				opts.Validate = func(ctx context.Context, target config.Target, data []byte, version string) error {
					if target.ID == "b" {
						return errors.New("isolated candidate validation rejected")
					}
					return validate(ctx, target, data, version)
				}
			}
			targets := []config.Target{b.target, a.target}
			p, err := PreviewRules(context.Background(), targets, quickSuffix, true, opts)
			if err == nil || p.Status != "blocked" || p.Targets[0].TargetID != "a" || p.Targets[1].Status != "blocked" {
				t.Fatal(p, err)
			}
			if failure == "conflict" && !quickFindings(p.Targets[1].Findings, "selector_conflict") {
				t.Fatal("missing selector conflict", p)
			}
			if _, err = ApplyRules(context.Background(), targets, quickSuffix, true, p.Digest, opts); err == nil {
				t.Fatal("blocked plan applied")
			}
			quickAssertUnchanged(t, a, b)
			if _, err = os.Stat(opts.StateDir); !os.IsNotExist(err) {
				t.Fatal("failed preflight created state", err)
			}
		})
	}
}

func TestQuickAllSkipsUnavailableButSingleAndAllUnavailableFail(t *testing.T) {
	f := newFixture(t, false)
	f.target.ID = "available"
	unbound := config.Target{ID: "unbound", Controller: f.target.Controller}
	offline := f.target
	offline.ID = "offline"
	missing := f.target
	missing.ID = "missing-source"
	missing.Configs = append([]config.CoreConfig(nil), f.target.Configs...)
	missing.Configs[0].Path = filepath.Join(t.TempDir(), "absent.yaml")
	opts := f.opts
	opts.Open = func(_ context.Context, target config.Target, ro bool) (*core.Client, io.Closer, error) {
		if target.ID == "offline" {
			return nil, nil, &core.Error{Kind: core.KindUnreachable}
		}
		c, e := core.New(core.Options{Endpoint: target.Controller, ReadOnly: ro})
		return c, nil, e
	}
	targets := []config.Target{unbound, offline, missing, f.target}
	p, err := PreviewRules(context.Background(), targets, quickSuffix, true, opts)
	if err != nil || len(p.Targets) != 4 || p.Targets[0].Status != "ready" {
		t.Fatal(p, err)
	}
	for _, item := range p.Targets[1:] {
		if item.Status != "skipped_unavailable" {
			t.Fatal(item)
		}
	}
	r, err := ApplyRules(context.Background(), targets, quickSuffix, true, p.Digest, opts)
	if err != nil || r.Status != "completed_with_skips" || f.writes != 1 {
		t.Fatal(r, err)
	}
	if p, err := PreviewRules(context.Background(), []config.Target{offline}, quickSuffix, false, opts); err == nil || p.Status != "blocked" {
		t.Fatal(p, err)
	}
	if p, err := PreviewRules(context.Background(), []config.Target{offline, unbound, missing}, quickSuffix, true, opts); err == nil || p.Status != "unavailable" {
		t.Fatal(p, err)
	}
}

func TestQuickAllSkipsUnavailableDockerButBlocksMountMismatch(t *testing.T) {
	f := newFixture(t, false)
	f.target.ID = "a"
	docker := config.Target{ID: "docker", Controller: f.target.Controller, RuleSource: &config.RuleSource{Kind: "docker", Container: "offline", HostPath: "/host/config.yaml", CorePath: "/core/config.yaml", Binary: "/mihomo", Home: "/core"}}
	opts := f.opts
	opts.Docker = func(context.Context, config.Target, DockerRequest) (DockerInfo, error) {
		return DockerInfo{}, sourceowner.ErrUnavailable
	}
	p, err := PreviewRules(context.Background(), []config.Target{docker, f.target}, quickSuffix, true, opts)
	if err != nil || p.Targets[1].Status != "skipped_unavailable" {
		t.Fatal(p, err)
	}
	opts.Docker = func(context.Context, config.Target, DockerRequest) (DockerInfo, error) {
		return DockerInfo{}, errors.New("host_path does not map to core_path through a container bind mount")
	}
	p, err = PreviewRules(context.Background(), []config.Target{docker, f.target}, quickSuffix, true, opts)
	if err == nil || p.Status != "blocked" || p.Targets[1].Status != "blocked" {
		t.Fatal(p, err)
	}
	quickAssertUnchanged(t, f)
}

func TestQuickStaleDigestAndLaterUnknownStop(t *testing.T) {
	t.Run("stale", func(t *testing.T) {
		f := newFixture(t, false)
		p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
		if err != nil {
			t.Fatal(err)
		}
		quickSource(t, f, string(f.source)+"# concurrent source edit\n")
		if _, err = ApplyRules(context.Background(), []config.Target{f.target}, quickSuffix, false, p.Digest, f.opts); err == nil {
			t.Fatal("stale digest accepted")
		}
		quickAssertUnchanged(t, f)
	})
	t.Run("later-unknown", func(t *testing.T) {
		a, b, c := newFixture(t, false), newFixture(t, false), newFixture(t, false)
		a.target.ID, b.target.ID, c.target.ID = "a", "b", "c"
		b.reject = true
		targets := []config.Target{c.target, b.target, a.target}
		p, err := PreviewRules(context.Background(), targets, quickSuffix, true, a.opts)
		if err != nil {
			t.Fatal(err)
		}
		r, err := ApplyRules(context.Background(), targets, quickSuffix, true, p.Digest, a.opts)
		if err == nil || r.Status != "stopped" || len(r.Results) != 3 {
			t.Fatal(r, err)
		}
		if r.Results[0].Status != "applied_verified" || r.Results[1].Status != "runtime_result_unknown" || r.Results[1].Receipt == nil || r.Results[2].Status != "unattempted" {
			t.Fatal(r)
		}
		if a.writes != 1 || b.writes != 1 || c.writes != 0 {
			t.Fatal("reload retried or continued", a.writes, b.writes, c.writes)
		}
		quickAssertUnchanged(t, c)
	})
}

func TestQuickHealthRuntimeOnlyAndSourceLimitations(t *testing.T) {
	f := newFixture(t, false)
	f.target.RuleSource = nil
	f.mu.Lock()
	f.rules = []map[string]any{{"type": "RuleSet", "payload": "upstream", "proxy": "PROXY"}, {"type": "IPCIDR", "payload": "203.0.113.0/24", "proxy": "DIRECT"}, {"type": "Match", "payload": "", "proxy": "DIRECT"}}
	f.mu.Unlock()
	opts := f.opts
	opts.ReadOnly = true
	r, err := Healthcheck(context.Background(), []config.Target{f.target}, false, opts)
	if err != nil || len(r.Targets) != 1 || r.Targets[0].Source != nil || r.Targets[0].Runtime == nil || r.Targets[0].Runtime.Stats.Opaque != 1 || f.writes != 0 {
		t.Fatal(r, err)
	}
	limits := strings.Join(r.Targets[0].Limitations, " ")
	if !strings.Contains(limits, "No persistent rule source") || !strings.Contains(limits, "no-resolve") {
		t.Fatal(limits)
	}
	if _, err = os.Stat(opts.StateDir); !os.IsNotExist(err) {
		t.Fatal("healthcheck created persistent state")
	}
	verge := newFixture(t, true)
	r, err = Healthcheck(context.Background(), []config.Target{verge.target}, false, verge.opts)
	if err != nil || r.Targets[0].Source == nil || !strings.Contains(strings.Join(r.Targets[0].Limitations, " "), "Merge and Script") {
		t.Fatal(r, err)
	}
}

func TestQuickHealthKeepsSourceWhenRuntimeUnavailableAndReportsErrors(t *testing.T) {
	f := newFixture(t, false)
	opts := f.opts
	opts.Open = func(context.Context, config.Target, bool) (*core.Client, io.Closer, error) {
		return nil, nil, &core.Error{Kind: core.KindUnreachable}
	}
	r, err := Healthcheck(context.Background(), []config.Target{f.target}, false, opts)
	if err != nil || r.Status != "completed_with_skips" || r.Targets[0].Status != "partial" || r.Targets[0].Source == nil || r.Targets[0].Runtime != nil {
		t.Fatal(r, err)
	}
	quickSource(t, f, "rules:\n  - DOMAIN-SUFFIX,example.com,DIRECT\n  - DOMAIN-SUFFIX,example.com,PROXY\n  - MATCH,DIRECT\n")
	r, err = Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err != nil || r.Status != "completed" || r.Targets[0].Source.HasErrors() || !quickFindings(r.Targets[0].Source.Findings, "selector_conflict") {
		t.Fatal(r, err)
	}
	quickSource(t, f, "rules:\n  - DOMAIN,example.com,missing-policy\n  - MATCH,DIRECT\n")
	r, err = Healthcheck(context.Background(), []config.Target{f.target}, false, f.opts)
	if err == nil || r.Status != "errors" || !quickFindings(r.Targets[0].Source.Findings, "policy_missing") {
		t.Fatal(r, err)
	}
	quickAssertUnchanged(t, f)
}

func TestQuickDockerOwnerPipelineAndPendingSingleFileMount(t *testing.T) {
	for _, singleFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory-bind", true: "single-file-pending"}[singleFile], func(t *testing.T) {
			f := newFixture(t, false)
			host := f.target.Configs[0].Path
			corePath := filepath.Join(t.TempDir(), "container-config.yaml")
			if err := os.Symlink(host, corePath); err != nil {
				t.Fatal(err)
			}
			f.target.RuleSource = &config.RuleSource{Kind: "docker", Container: "bound-container", HostPath: host, CorePath: corePath, Binary: "/mihomo", Home: "/core"}
			visible := sha(f.source)
			identity := "bound-identity"
			f.opts.Docker = func(_ context.Context, _ config.Target, req DockerRequest) (DockerInfo, error) {
				if req.Container != "bound-container" || req.HostPath != host || req.CorePath != corePath {
					t.Fatal("incorrect Docker descriptor", req)
				}
				if !singleFile {
					data, err := os.ReadFile(host)
					if err != nil {
						return DockerInfo{}, err
					}
					visible = sha(data)
				}
				return DockerInfo{ContainerID: identity, Image: "bound-image", SourceSHA256: visible, SingleFile: singleFile}, nil
			}
			targets := []config.Target{f.target}
			p, err := PreviewRules(context.Background(), targets, quickSuffix, false, f.opts)
			if err != nil {
				t.Fatal(p, err)
			}
			r, err := ApplyRules(context.Background(), targets, quickSuffix, false, p.Digest, f.opts)
			if err != nil || r.Results[0].Receipt == nil {
				t.Fatal(r, err)
			}
			receipt := *r.Results[0].Receipt
			if receipt.OwnerIdentity != "bound-identity:bound-image" {
				t.Fatal("Docker identity missing from receipt", receipt)
			}
			if singleFile {
				if r.Results[0].Status != "persisted_pending_owner_reload" || f.writes != 0 {
					t.Fatal("stale mount reloaded", r, f.writes)
				}
				if got, err := Verify(context.Background(), f.target, receipt.ID, f.opts); err != nil || got.RuntimeVerified {
					t.Fatal(got, err)
				}
				if got, err := Restore(context.Background(), f.target, receipt.ID, f.opts); err != nil || got.Status != "restored_verified" {
					t.Fatal("pending source cannot be rolled back", got, err)
				}
				data, _ := os.ReadFile(host)
				if string(data) != string(f.source) {
					t.Fatal("pending rollback changed original bytes")
				}
			} else {
				if r.Results[0].Status != "applied_verified" || f.writes != 1 {
					t.Fatal(r, f.writes)
				}
				if got, err := Restore(context.Background(), f.target, receipt.ID, f.opts); err != nil || got.Status != "restored_verified" {
					t.Fatal(got, err)
				}
				if f.writes != 2 {
					t.Fatal("restore did not reload container path", f.writes)
				}
			}
			identity = "replacement"
			if _, err := Verify(context.Background(), f.target, receipt.ID, f.opts); err == nil {
				t.Fatal("replaced Docker identity accepted by receipt verification")
			}
		})
	}
}

func TestQuickDockerRestartWaitsForReadinessBeforeSingleReload(t *testing.T) {
	f := newFixture(t, false)
	host := f.target.Configs[0].Path
	corePath := filepath.Join(t.TempDir(), "container.yaml")
	if err := os.Symlink(host, corePath); err != nil {
		t.Fatal(err)
	}
	service := config.ClientService{Kind: "docker", DockerHost: "unix:///fixture", Container: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), MountsSHA256: strings.Repeat("c", 64)}
	f.target.RuleSource = &config.RuleSource{Kind: "docker", Container: service.Container, DockerHost: service.DockerHost, HostPath: host, CorePath: corePath, Binary: "/mihomo", Home: "/core"}
	f.target.Service = &service
	upstream, err := url.Parse(f.target.Controller)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var notReady, earlyReload atomic.Int32
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" && notReady.Load() > 0 {
			notReady.Add(-1)
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/configs" && r.Method == http.MethodPut && notReady.Load() > 0 {
			earlyReload.Add(1)
			w.WriteHeader(503)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	f.target.Controller = front.URL
	visible := sha(f.source)
	restarts := 0
	f.opts.Docker = func(context.Context, config.Target, DockerRequest) (DockerInfo, error) {
		return DockerInfo{ContainerID: service.Container, Image: service.Image, SourceSHA256: visible, SingleFile: true}, nil
	}
	f.opts.ClientServices = clientservice.Options{StateDir: filepath.Join(t.TempDir(), "service-receipts"), Host: func(_ context.Context, _ config.Target, request clientservice.Request) (clientservice.Status, error) {
		data, err := os.ReadFile(host)
		if err != nil {
			return clientservice.Status{}, err
		}
		current := sha(data)
		status := clientservice.Status{Binding: service, Running: true, State: "running", StateDigest: "stable", SourceSingleFile: true, SourceMatches: current == visible}
		if request.SourceSHA256 != "" && request.SourceSHA256 != current {
			return status, errors.New("source changed")
		}
		if request.Op == "restart" {
			restarts++
			visible = current
			notReady.Store(2)
			status.SourceMatches = true
		}
		return status, nil
	}}
	targets := []config.Target{f.target}
	p, err := PreviewRules(context.Background(), targets, quickSuffix, false, f.opts)
	if err != nil {
		t.Fatal(p, err)
	}
	r, err := ApplyRules(context.Background(), targets, quickSuffix, false, p.Digest, f.opts)
	if err != nil || r.Results[0].Status != "applied_verified" || restarts != 1 || f.writes != 1 || earlyReload.Load() != 0 {
		t.Fatal(r, err, restarts, f.writes, earlyReload.Load())
	}
	restored, err := Restore(context.Background(), f.target, r.Results[0].Receipt.ID, f.opts)
	if err != nil || restored.Status != "restored_verified" || restarts != 2 || f.writes != 2 || earlyReload.Load() != 0 {
		t.Fatal(restored, err, restarts, f.writes, earlyReload.Load())
	}
}

func TestQuickDockerServiceBindingChangeInvalidatesPreview(t *testing.T) {
	f := newFixture(t, false)
	host := f.target.Configs[0].Path
	f.target.RuleSource = &config.RuleSource{Kind: "docker", Container: "bound", DockerHost: "unix:///fixture", HostPath: host, CorePath: "/core/config.yaml", Binary: "/mihomo", Home: "/core"}
	f.opts.Docker = func(context.Context, config.Target, DockerRequest) (DockerInfo, error) {
		return DockerInfo{ContainerID: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), SourceSHA256: sha(f.source), SingleFile: true}, nil
	}
	f.opts.ClientServices.Host = func(context.Context, config.Target, clientservice.Request) (clientservice.Status, error) {
		return clientservice.Status{}, errors.New("unreviewed owner activation attempted")
	}
	p, err := PreviewRules(context.Background(), []config.Target{f.target}, quickSuffix, false, f.opts)
	if err != nil {
		t.Fatal(p, err)
	}
	f.target.Service = &config.ClientService{Kind: "docker", DockerHost: "unix:///fixture", Container: strings.Repeat("a", 64), Image: "sha256:" + strings.Repeat("b", 64), MountsSHA256: strings.Repeat("c", 64)}
	if _, err = ApplyRules(context.Background(), []config.Target{f.target}, quickSuffix, false, p.Digest, f.opts); err == nil {
		t.Fatal("changed restart owner accepted")
	}
	quickAssertUnchanged(t, f)
}
