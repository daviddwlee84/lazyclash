package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestRuleInspectionDiffScopeTargetsAndReadOnly(t *testing.T) {
	m := testModel(t)
	m.page, m.options.ReadOnly = rules, true
	m.settings.Targets = append(m.settings.Targets, config.Target{ID: "other", Controller: "http://127.0.0.1:9091"}, config.Target{ID: "third", Controller: "http://127.0.0.1:9092"}, config.Target{ID: "temporary", Transient: true})
	var calls []WorkRequest
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		calls = append(calls, req)
		return WorkResult{Title: "Rule differences", Rows: []WorkRow{{ID: "other:runtime", Label: "other · runtime · different", Detail: "same rules, different order"}}}, nil
	}
	sendKey(m, "d")
	if m.work.phase != "rule-inspect-scope" || m.work.result.Rows[m.work.index].ID != "both" {
		t.Fatal("diff did not default to both scopes")
	}
	sendKey(m, "down")
	sendKey(m, "enter")
	if m.work.phase != "rule-inspect-baseline" || m.work.result.Rows[m.work.index].ID != "target:test" {
		t.Fatal("baseline did not default to current target")
	}
	sendKey(m, "enter")
	if len(m.work.result.Rows) != 3 || m.work.result.Rows[0].ID != "target:other" || len(calls) != 0 {
		t.Fatal("destination picker included baseline/transient or launched early")
	}
	sendKey(m, "end")
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(calls) != 1 || calls[0].Kind != "rule-diff" || calls[0].Scope != "runtime" || calls[0].Target.ID != "test" || !calls[0].All || len(calls[0].Targets) != 2 || calls[0].Targets[0].ID != "other" || calls[0].Targets[1].ID != "third" {
		t.Fatalf("wrong comparison request: %+v", calls)
	}
	if cmd := sendKey(m, "a"); cmd != nil || m.overlay != "work" {
		t.Fatal("read-only diff offered apply")
	}
	sendKey(m, "e")
	if m.work.result.Rows[m.work.index].ID != "runtime" {
		t.Fatal("editing forgot scope")
	}
	sendKey(m, "enter")
	sendKey(m, "down")
	sendKey(m, "enter")
	sendKey(m, "home")
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(calls) != 2 || calls[1].Target.ID != "other" || calls[1].All || len(calls[1].Targets) != 1 || calls[1].Targets[0].ID != "test" {
		t.Fatalf("wrong one-to-one comparison: %+v", calls)
	}
}

func TestRuleInspectionQueriesRetainDraftAndPartialResults(t *testing.T) {
	m := testModel(t)
	m.page, m.options.ReadOnly = rules, true
	var calls []WorkRequest
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		calls = append(calls, req)
		return WorkResult{Title: "Find results", Rows: []WorkRow{{ID: "test:source", Label: "test · source unavailable", Detail: "bind a source"}}}, errors.New("source unavailable")
	}
	sendKey(m, "f")
	for _, char := range "jkhql/?" {
		sendKey(m, string(char))
	}
	if m.overlay != "form" || m.input.Value() != "jkhql/?" {
		t.Fatal("query input triggered navigation")
	}
	m.input.SetValue("DOMAIN-SUFFIX,example.com,DIRECT")
	sendKey(m, "esc")
	sendKey(m, "f")
	if m.input.Value() != "DOMAIN-SUFFIX,example.com,DIRECT" {
		t.Fatal("query cancel lost draft")
	}
	sendKey(m, "enter")
	sendKey(m, "enter")
	sendKey(m, "end")
	sendKey(m, "enter")
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(calls) != 1 || calls[0].Scope != "source" || calls[0].Query != "DOMAIN-SUFFIX,example.com,DIRECT" || len(calls[0].Targets) != 1 || calls[0].Targets[0].ID != "test" || len(m.work.result.Rows) != 1 || !strings.Contains(m.work.result.Summary, "source unavailable") {
		t.Fatalf("lost query/source result: %+v %+v", calls, m.work)
	}
	sendKey(m, "e")
	if m.overlay != "form" || m.input.Value() != calls[0].Query {
		t.Fatal("failed query cannot be edited")
	}
	sendKey(m, "esc")
	sendKey(m, "L")
	if m.input.Value() != "" {
		t.Fatal("lookup reused exact-rule draft")
	}
	m.Update(tea.PasteMsg{Content: "q\nj\nL"})
	if len(calls) != 1 || m.overlay != "form" {
		t.Fatal("paste submitted a query")
	}
}

func TestRuleInspectionCancelDoesNotLetLateReplyReplaceNewView(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		return WorkResult{Title: req.Query}, nil
	}
	old := m.launchWork(WorkRequest{Kind: "rule-lookup", Source: "test", Scope: "both", Query: "old.example"})
	oldSerial := m.work.serial
	sendKey(m, "esc")
	if m.work != nil || m.overlay != "" {
		t.Fatal("read-only cancellation did not close immediately")
	}
	next := m.launchWork(WorkRequest{Kind: "rule-lookup", Source: "test", Scope: "both", Query: "new.example"})
	flattenCommand(t, m, next)
	flattenCommand(t, m, old)
	if m.work.serial == oldSerial || m.work.result.Title != "new.example" {
		t.Fatal("late result replaced the current query")
	}
	for _, size := range [][2]int{{120, 32}, {80, 24}, {36, 12}, {1, 1}, {0, 0}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		_ = m.View()
		_ = m.hitRegions()
	}
}
