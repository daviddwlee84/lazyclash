package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func syncFixtureCatalog(id string) ConfigSyncCatalog {
	return ConfigSyncCatalog{TargetID: id, Owner: "native", Groups: []ConfigSyncGroup{{Name: "Route"}}, Items: []ConfigSyncItem{
		{ID: "/proxies/new", Kind: "proxy", Category: "proxies", Label: "New proxy", Action: "add", MaskedDetail: "password: [masked]\n+ server: new.example"},
		{ID: "/proxies/changed", Kind: "proxy", Category: "proxies", Label: "Changed proxy", Action: "replace", MaskedDetail: "- password: [masked]\n+ password: [masked]"},
		{ID: "/rules/0", Kind: "rule", Category: "rules", Label: "DOMAIN,example.com,DIRECT", Action: "add", MaskedDetail: "+ DOMAIN,example.com,DIRECT"},
		{ID: "/proxies/destination", Kind: "proxy", Category: "proxies", Label: "Destination only", Action: "inspect", DisabledReason: "Destination-only objects are retained."},
	}}
}
func syncKey(m *configSyncModel, value string) tea.Cmd { _, cmd := m.Update(key(value)); return cmd }
func syncRun(m *configSyncModel, cmd tea.Cmd) {
	if cmd != nil {
		m.Update(cmd())
	}
}
func syncFixture(t *testing.T) *configSyncModel {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return newConfigSync(ctx, ConfigSyncOptions{SourceLabel: "Source", Targets: []ConfigSyncTarget{{ID: "a", Label: "Alpha"}, {ID: "b", Label: "Beta"}}, Load: func(_ context.Context, id string) (ConfigSyncCatalog, error) { return syncFixtureCatalog(id), nil }})
}

func TestConfigSyncSelectionReviewAndPerTargetDecisions(t *testing.T) {
	m := syncFixture(t)
	var previews []ConfigSyncDraft
	applies := 0
	m.opts.Preview = func(_ context.Context, d ConfigSyncDraft) (ConfigSyncPreview, error) {
		previews = append(previews, cloneConfigSyncDraft(d))
		return ConfigSyncPreview{Ready: true, Digest: strings.Repeat("a", 64), Summary: "2 targets", Targets: []ConfigSyncPreviewTarget{{TargetID: "a", MaskedDiff: "+ password: [masked]"}, {TargetID: "b", MaskedDiff: "- rule\n+ rule"}}}, nil
	}
	m.opts.Apply = func(_ context.Context, d ConfigSyncDraft, digest string) (ConfigSyncOutcome, error) {
		applies++
		if digest != strings.Repeat("a", 64) || len(d["a"].Selections) != 1 || len(d["b"].Selections) != 1 {
			t.Fatal("wrong reviewed candidate")
		}
		return ConfigSyncOutcome{Title: "completed", Summary: "receipt saved"}, nil
	}
	syncRun(m, m.Init())
	if m.selectedCount() != 0 {
		t.Fatal("objects preselected")
	}
	syncKey(m, " ")
	syncRun(m, syncKey(m, "l"))
	if len(m.draft["b"].Selections) != 0 {
		t.Fatal("copied another destination's choices")
	}
	syncKey(m, "j")
	syncKey(m, " ")
	syncKey(m, "g")
	syncKey(m, " ")
	syncKey(m, "enter")
	syncKey(m, "o")
	syncKey(m, "enter")
	syncKey(m, "j")
	syncKey(m, " ")
	syncKey(m, "esc")
	syncRun(m, syncKey(m, "p"))
	if m.phase != "review" || m.accept || applies != 0 {
		t.Fatal("review was not default negative")
	}
	d := previews[0]["b"]
	if !d.Selections[0].Replace || d.RulePlacement != "prepend" || !d.AllowVergeRulesOverride || len(d.AttachGroups["/proxies/changed"]) != 1 || previews[0]["a"].Selections[0].Replace {
		t.Fatalf("lost independent choices: %+v", previews[0])
	}
	syncKey(m, "enter")
	if m.phase != "select" || applies != 0 || m.selectedCount() != 2 {
		t.Fatal("Enter applied or discarded the draft")
	}
	syncRun(m, syncKey(m, "p"))
	syncKey(m, "tab")
	syncRun(m, syncKey(m, "enter"))
	if applies != 1 || m.phase != "result" {
		t.Fatal("explicit reviewed apply did not complete")
	}
}

func TestConfigSyncDependenciesErrorsAndCancellationRetainDraft(t *testing.T) {
	m := syncFixture(t)
	syncRun(m, m.Init())
	syncKey(m, " ")
	m.opts.Preview = func(_ context.Context, d ConfigSyncDraft) (ConfigSyncPreview, error) {
		if d["a"].Dependencies["/proxies/dependency"] == "" {
			return ConfigSyncPreview{Decisions: []ConfigSyncDecision{{ID: "/proxies/dependency", TargetID: "a", Label: "Dependency", MaskedDetail: "old → source"}}}, errors.New("dependency collision")
		}
		return ConfigSyncPreview{Ready: true, Digest: strings.Repeat("d", 64)}, nil
	}
	syncRun(m, syncKey(m, "p"))
	if m.phase != "decisions" || m.selectedCount() != 1 {
		t.Fatal("blocked preview lost decision or selection")
	}
	syncKey(m, "enter")
	m.preview.Decisions[0].MaskedDetail = strings.Repeat("masked field detail\n", 60)
	if text := m.View().Content; !strings.Contains(text, "Reuse the destination definition") || !strings.Contains(text, "Replace with the source definition") {
		t.Fatal("long detail hid dependency choices")
	}
	syncKey(m, "enter")
	if m.draft["a"].Dependencies["/proxies/dependency"] != "" {
		t.Fatal("default dependency choice replaced data")
	}
	syncKey(m, "enter")
	syncKey(m, "j")
	syncKey(m, "j")
	syncKey(m, "enter")
	syncRun(m, syncKey(m, "p"))
	if m.phase != "review" || m.reviewDraft["a"].Dependencies["/proxies/dependency"] != "replace" {
		t.Fatal("explicit replacement was lost")
	}
	m.opts.Apply = func(ctx context.Context, _ ConfigSyncDraft, _ string) (ConfigSyncOutcome, error) {
		<-ctx.Done()
		return ConfigSyncOutcome{Title: "unknown", Summary: "Durable receipt: unknown-write"}, ctx.Err()
	}
	syncKey(m, "tab")
	pending := syncKey(m, "enter")
	syncKey(m, "esc")
	if m.phase != "applying" {
		t.Fatal("cancellation hid a pending write")
	}
	syncRun(m, pending)
	if m.phase != "result" || !strings.Contains(m.outcome.Summary, "unknown-write") || m.resultErr == nil {
		t.Fatal("unknown result lost receipt")
	}
	syncKey(m, "e")
	if m.selectedCount() != 1 || m.draft["a"].Dependencies["/proxies/dependency"] != "replace" {
		t.Fatal("error discarded draft")
	}
	late := syncKey(m, "p")
	syncKey(m, "esc")
	syncRun(m, late)
	if m.phase != "select" || m.selectedCount() != 1 || !strings.Contains(m.message, "canceled") {
		t.Fatal("late preview reopened review after Back")
	}
}

func TestConfigSyncStaleLoadsFilterReadOnlyAndResize(t *testing.T) {
	m := syncFixture(t)
	old := m.Init()
	next := syncKey(m, "l")
	syncRun(m, next)
	syncRun(m, old)
	if _, ok := m.catalogs["a"]; ok {
		t.Fatal("canceled load updated stale target")
	}
	syncKey(m, "end")
	syncKey(m, " ")
	if m.selectedCount() != 0 {
		t.Fatal("destination-only object selected")
	}
	syncKey(m, "home")
	syncKey(m, " ")
	syncKey(m, "/")
	for _, r := range "jq/p" {
		syncKey(m, string(r))
	}
	if !m.search || m.query.Value() != "jq/p" {
		t.Fatal("typing triggered an action")
	}
	m.Update(tea.PasteMsg{Content: "\nq\np"})
	syncKey(m, "enter")
	if cmd := syncKey(m, "p"); cmd != nil {
		t.Fatal("empty filter submitted hidden choices")
	}
	syncKey(m, "/")
	syncKey(m, "esc")
	m.opts.ReadOnly = true
	m.opts.Preview = func(context.Context, ConfigSyncDraft) (ConfigSyncPreview, error) {
		return ConfigSyncPreview{Ready: true, Digest: strings.Repeat("a", 64)}, nil
	}
	m.opts.Apply = func(context.Context, ConfigSyncDraft, string) (ConfigSyncOutcome, error) {
		t.Fatal("read-only apply")
		return ConfigSyncOutcome{}, nil
	}
	syncRun(m, syncKey(m, "p"))
	syncKey(m, "tab")
	syncKey(m, "enter")
	if m.phase != "select" {
		t.Fatal("readonly review did not return to draft")
	}
	for _, phase := range []string{"select", "options", "groups", "review", "result"} {
		m.phase = phase
		for _, size := range [][2]int{{120, 32}, {80, 24}, {36, 12}, {1, 1}, {0, 0}} {
			m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			view := m.View().Content
			for _, line := range strings.Split(view, "\n") {
				if ansi.StringWidth(line) > max(1, size[0]) {
					t.Fatalf("overflow in %s at %v", phase, size)
				}
			}
		}
	}
}

func TestConfigSyncDashboardLauncherUsesOneTerminalHandoff(t *testing.T) {
	m := toolModel(t)
	m.page = configs
	m.settings.Targets = append(m.settings.Targets, config.Target{ID: "other", Controller: "http://127.0.0.1:9091"})
	sendKey(m, "S")
	if m.work == nil || m.work.phase != "config-sync-source" || m.work.result.Rows[m.work.index].ID != "target:test" {
		t.Fatal("source picker did not preserve current target")
	}
	sendKey(m, "enter")
	if m.toolPending || m.work.phase != "config-sync-destination" || len(m.work.result.Rows) != 2 {
		t.Fatal("source selection started a second terminal reader")
	}
	sendKey(m, "end")
	if cmd := sendKey(m, "enter"); cmd == nil || !m.toolPending || m.overlay != "external-tool" || m.status != "Sync configurations" {
		t.Fatal("all-target selection did not release terminal through shared handoff")
	}
}
