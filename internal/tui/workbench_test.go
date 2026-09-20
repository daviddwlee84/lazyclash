package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestWorkPreviewSelectionApplyAndReadOnly(t *testing.T) {
	m := testModel(t)
	m.settings.Targets = append(m.settings.Targets, config.Target{ID: "other", Controller: "http://127.0.0.1:9091"})
	var called []WorkRequest
	m.options.Workbench = func(_ context.Context, r WorkRequest) (WorkResult, error) {
		called = append(called, r)
		switch r.Kind {
		case "diff":
			return WorkResult{Title: "comparison", Rows: []WorkRow{{ID: "field:mode", Label: "mode", Detail: "rule → global", Selectable: true}}}, nil
		case "copy-preview":
			r.Kind = "copy-apply"
			r.Digest = "reviewed"
			return WorkResult{Title: "preview", Apply: &r}, nil
		default:
			return WorkResult{Title: "done"}, nil
		}
	}
	m.startCompare()
	sendKey(m, "enter")
	if len(called) != 0 || m.work.phase != "destination" {
		t.Fatal("source selection performed work")
	}
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(called) != 1 || called[0].Source != "test" || called[0].Destination != "other" {
		t.Fatalf("%+v", called)
	}
	click(m, findHit(t, m, "work-row", "field:mode"))
	if len(m.work.checked) != 0 || len(called) != 1 {
		t.Fatal("row click activated a mutation")
	}
	sendKey(m, " ")
	if !m.work.checked["field:mode"] {
		t.Fatal("space did not select field")
	}
	flattenCommand(t, m, sendKey(m, "p"))
	if len(called) != 2 || len(called[1].Fields) != 1 {
		t.Fatalf("%+v", called)
	}
	sendKey(m, "a")
	if m.overlay != "confirm" || len(called) != 2 {
		t.Fatal("apply skipped review")
	}
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(called) != 3 || called[2].Digest != "reviewed" || called[2].Kind != "copy-apply" {
		t.Fatalf("%+v", called)
	}
	m.options.ReadOnly = true
	if cmd := m.launchWork(WorkRequest{Kind: "copy-apply"}); cmd != nil {
		t.Fatal("readonly apply")
	}
	if cmd := m.launchWork(WorkRequest{Kind: "url"}); cmd != nil {
		t.Fatal("readonly probe")
	}
}

func TestWorkCancellationStaleResultsAndResize(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(ctx context.Context, _ WorkRequest) (WorkResult, error) {
		<-ctx.Done()
		return WorkResult{Title: "canceled"}, ctx.Err()
	}
	cmd := m.launchWork(WorkRequest{Kind: "url", Source: "test"})
	old := m.work.serial
	if again := m.launchWork(WorkRequest{Kind: "url"}); again != nil {
		t.Fatal("duplicate work")
	}
	sendKey(m, "esc")
	flattenCommand(t, m, cmd)
	if m.work.pending || !strings.Contains(m.work.result.Summary, "canceled") {
		t.Fatal("lost cancellation outcome")
	}
	sendKey(m, "esc")
	m.receiveWork(workMsg{generation: m.generation, serial: old, result: WorkResult{Title: "late"}})
	if m.overlay != "" || m.work != nil {
		t.Fatal("late result reopened surface")
	}
	m.work = &workState{phase: "result", checked: map[string]bool{}, result: WorkResult{Title: "專案 👩🏽‍💻", Rows: []WorkRow{{ID: "one", Label: "東京", Detail: strings.Repeat("detail\n", 30)}}}}
	m.overlay = "work"
	for _, size := range [][2]int{{120, 32}, {80, 24}, {36, 12}, {1, 1}, {0, 0}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		_ = m.View()
		_ = m.hitRegions()
	}
}

func TestDiscoveryDoesNotStealWorkbenchAndReceiptInvalidatesRules(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) { return WorkResult{Title: "verified"}, nil }
	m.state().snap("rules").data = map[string]any{"rules": []any{"old"}}
	cmd := m.launchWork(WorkRequest{Kind: "rule-verify", Source: m.target.ID})
	m.Update(discoveredMsg{generation: m.generation, targets: []config.Target{{ID: "new", Controller: "http://127.0.0.1:9092"}}})
	if m.overlay != "work" {
		t.Fatal("discovery stole pending work surface")
	}
	flattenCommand(t, m, cmd)
	if m.work.pending || m.work.result.Title != "verified" {
		t.Fatal("lost result")
	}
	if m.state().snap("rules").err == nil || m.state().snap("rules").data == nil {
		t.Fatal("must retain but mark old rules stale")
	}
}
