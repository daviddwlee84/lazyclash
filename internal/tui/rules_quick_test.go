package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func TestQuickRuleDraftSelectionPreviewAndNegativeConfirmation(t *testing.T) {
	m := testModel(t)
	m.page = rules
	m.settings.Targets = append(m.settings.Targets, config.Target{ID: "other", Controller: "http://127.0.0.1:9091"}, config.Target{ID: "discovered", Transient: true})
	var calls []WorkRequest
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		calls = append(calls, req)
		if req.Kind == "quick-rule-preview" {
			req.Kind, req.Digest = "quick-rule-apply", "reviewed"
			return WorkResult{Title: "Review", Summary: req.Rule, Apply: &req}, nil
		}
		return WorkResult{Title: "Applied"}, nil
	}
	sendKey(m, "n")
	for _, char := range "jkhql/?" {
		sendKey(m, string(char))
	}
	if m.input.Value() != "jkhql/?" || m.overlay != "form" {
		t.Fatal("typing invoked an action")
	}
	m.input.SetValue("- DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT")
	sendKey(m, "esc")
	sendKey(m, "n")
	if !strings.HasPrefix(m.input.Value(), "- DOMAIN-SUFFIX") {
		t.Fatal("canceled draft was lost")
	}
	m.Update(tea.PasteMsg{Content: ""})
	sendKey(m, "enter")
	sendKey(m, "enter")
	if m.work.phase != "rule-target" || len(m.work.result.Rows) != 3 || len(calls) != 0 {
		t.Fatalf("target selection state: %+v", m.work)
	}
	sendKey(m, "end")
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(calls) != 1 || !calls[0].All || len(calls[0].Targets) != 2 || calls[0].Targets[1].ID != "other" {
		t.Fatalf("all selection included wrong targets: %+v", calls)
	}
	sendKey(m, "a")
	if m.overlay != "confirm" || !m.confirm.defaultNegative || !strings.Contains(m.footer(), "Enter / Esc / n cancel") {
		t.Fatal("apply did not request default-negative confirmation")
	}
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(calls) != 1 || m.overlay != "work" || m.work.result.Apply == nil {
		t.Fatal("Enter applied or lost the preview")
	}
	sendKey(m, "a")
	flattenCommand(t, m, sendKey(m, "y"))
	if len(calls) != 2 || calls[1].Kind != "quick-rule-apply" || calls[1].Digest != "reviewed" || len(calls[1].Targets) != 2 {
		t.Fatalf("review snapshot not forwarded: %+v", calls)
	}
	if m.state().snap("rules").err == nil {
		t.Fatal("batch apply did not invalidate active target data")
	}
}

func TestQuickRuleFailureReadOnlyAndCanceledReadsRetainDraft(t *testing.T) {
	m := testModel(t)
	m.quickRuleDraft = "DOMAIN,example.com,DIRECT"
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		return WorkResult{Title: "Blocked", Rows: []WorkRow{{ID: "test", Label: "test · blocked", Detail: "conflict"}}, Apply: &req}, errors.New("conflict")
	}
	m.startQuickRuleForm()
	sendKey(m, "enter")
	sendKey(m, "enter")
	flattenCommand(t, m, sendKey(m, "enter"))
	if len(m.work.result.Rows) != 1 || m.work.result.Apply != nil || !strings.Contains(m.work.result.Summary, "conflict") {
		t.Fatal("failed preflight discarded findings or enabled apply")
	}
	sendKey(m, "e")
	if m.overlay != "form" || m.input.Value() != m.quickRuleDraft {
		t.Fatal("failure discarded editable draft")
	}
	// Pending work remains responsive; cancellation cannot reopen a closed overlay.
	m.options.Workbench = func(ctx context.Context, req WorkRequest) (WorkResult, error) {
		<-ctx.Done()
		return WorkResult{Title: "Canceled"}, ctx.Err()
	}
	cmd := m.launchWork(WorkRequest{Kind: "quick-rule-preview", Source: "test", Rule: m.quickRuleDraft})
	serial := m.work.serial
	sendKey(m, "esc")
	flattenCommand(t, m, cmd)
	sendKey(m, "esc")
	m.receiveWork(workMsg{generation: m.generation, serial: serial, result: WorkResult{Title: "stale"}})
	if m.work != nil || m.overlay != "" {
		t.Fatal("late reply reopened closed quick rule")
	}
	m.startQuickRuleForm()
	if m.input.Value() != "DOMAIN,example.com,DIRECT" {
		t.Fatal("cancellation lost draft")
	}
	m.options.ReadOnly = true
	if cmd := m.launchWork(WorkRequest{Kind: "quick-rule-apply", Source: "test"}); cmd != nil {
		t.Fatal("read-only quick apply executed")
	}
}

func TestRuleHealthcheckCurrentScopeAndResize(t *testing.T) {
	m := testModel(t)
	m.page = rules
	m.options.ReadOnly = true
	m.settings.Targets = append(m.settings.Targets, config.Target{ID: "other", Controller: "http://127.0.0.1:9091"}, config.Target{ID: "discovered", Transient: true})
	var request WorkRequest
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		request = req
		return WorkResult{Title: "Health · warning", Rows: []WorkRow{{ID: "test", Label: "專案 é 👩🏽‍💻", Detail: strings.Repeat("opaque provider coverage\n", 30)}}}, nil
	}
	sendKey(m, "H")
	flattenCommand(t, m, sendKey(m, "enter"))
	if request.Kind != "rule-healthcheck" || request.All || len(request.Targets) != 1 || request.Targets[0].ID != "test" {
		t.Fatalf("healthcheck target: %+v", request)
	}
	sendKey(m, "esc")
	sendKey(m, "H")
	sendKey(m, "down")
	flattenCommand(t, m, sendKey(m, "enter"))
	if request.All || len(request.Targets) != 1 || request.Targets[0].ID != "other" {
		t.Fatalf("healthcheck selected saved target: %+v", request)
	}
	sendKey(m, "esc")
	sendKey(m, "H")
	sendKey(m, "end")
	flattenCommand(t, m, sendKey(m, "enter"))
	if !request.All || len(request.Targets) != 2 || request.Targets[0].ID != "test" || request.Targets[1].ID != "other" {
		t.Fatalf("healthcheck all saved targets: %+v", request)
	}
	for _, size := range [][2]int{{120, 32}, {80, 24}, {36, 12}, {1, 1}, {0, 0}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		_ = m.View()
		_ = m.hitRegions()
	}
	if m.work.result.Apply != nil {
		t.Fatal("read-only healthcheck acquired an apply action")
	}
}

func TestRuleSourceReuseInspectsBeforeSavingAndDefaultsToCancel(t *testing.T) {
	m := testModel(t)
	m.target.Configs = []config.CoreConfig{{ID: "main", Path: "/fixture/config.yaml"}}
	m.target.ConfigSource = &config.ConfigSource{Kind: "native", ConfigID: "main", Binary: "/fixture/mihomo", Home: "/fixture"}
	m.settings.Targets[0] = m.target
	inspections, saves := 0, 0
	m.options.Workbench = func(_ context.Context, req WorkRequest) (WorkResult, error) {
		inspections++
		if req.Kind != "source-inspect" || req.Target.RuleSource == nil || req.Target.RuleSource.Kind != "mihomo" {
			t.Fatalf("wrong inspection: %+v", req)
		}
		return WorkResult{}, nil
	}
	m.options.SaveTargets = func(cfg config.Config) error {
		saves++
		if inspections != 1 || cfg.Targets[0].RuleSource == nil || cfg.Targets[0].ConfigSource == nil {
			t.Fatal("binding not independently inspected")
		}
		return nil
	}
	m.startRuleSourceReuse()
	flattenCommand(t, m, sendKey(m, "enter"))
	if saves != 0 || inspections != 0 {
		t.Fatal("default confirmation performed work")
	}
	m.startRuleSourceReuse()
	flattenCommand(t, m, sendKey(m, "y"))
	if inspections != 1 || saves != 1 || m.target.RuleSource == nil {
		t.Fatal("source reuse did not inspect and save")
	}
}
