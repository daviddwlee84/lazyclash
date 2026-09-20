package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func ctrlSave(m *Model) tea.Cmd {
	_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	return cmd
}

func TestQuickSaveUsesActiveFieldWithoutConnectivityGate(t *testing.T) {
	m := testModel(t)
	m.options.ReadOnly = true // local registration edits remain allowed
	writes := 0
	m.options.SaveTargets = func(c config.Config) error {
		writes++
		if c.Targets[0].Name != "Updated name" {
			t.Errorf("active edit lost: %+v", c.Targets[0])
		}
		return nil
	}
	m.startTargetForm(true)
	m.form.index = 1
	m.beginInput("form", "")
	m.input.SetValue("Updated name") // unsynchronized text must be included
	canceled := false
	m.testPending = true
	m.testCancel = func() { canceled = true }
	cmd := ctrlSave(m)
	if cmd == nil || m.overlay != "saving" || !canceled || m.testPending {
		t.Fatal("quick save failed or kept stale connectivity test")
	}
	if duplicate := ctrlSave(m); duplicate != nil {
		t.Fatal("duplicate save while pending")
	}
	flattenCommand(t, m, cmd)
	if writes != 1 || m.overlay != "" || m.target.Name != "Updated name" {
		t.Fatalf("save result writes=%d overlay=%s", writes, m.overlay)
	}
}

func TestQuickSaveValidationAndWriteFailureKeepFieldEditable(t *testing.T) {
	m := testModel(t)
	writes := 0
	m.options.SaveTargets = func(config.Config) error { writes++; return errors.New("disk full") }
	m.startTargetForm(true)
	m.form.index = 2
	m.beginInput("form", "http://")
	if cmd := ctrlSave(m); cmd != nil || m.form.err == "" || writes != 0 {
		t.Fatal("invalid target reached persistence")
	}
	if m.form.index != 2 || m.input.Value() != "http://" || !m.input.Focused() {
		t.Fatal("invalid field lost edit state")
	}
	m.input.SetValue(m.target.Controller)
	flattenCommand(t, m, ctrlSave(m))
	if writes != 1 || m.overlay != "form" || m.form.index != 2 || !m.input.Focused() || m.input.Value() != m.target.Controller {
		t.Fatal("failed write lost draft/focus")
	}
	if !strings.Contains(m.status, "disk full") {
		t.Fatal("missing persistence error")
	}
}

func TestQuickSaveMouseUsesSameValidation(t *testing.T) {
	m := testModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	m.startTargetForm(true)
	m.form.index = 1
	m.beginInput("form", "Mouse save")
	writes := 0
	m.options.SaveTargets = func(c config.Config) error {
		writes++
		if c.Targets[0].Name != "Mouse save" {
			t.Fatal("lost current field")
		}
		return nil
	}
	flattenCommand(t, m, click(m, findHit(t, m, "button", "quick-save")))
	if writes != 1 {
		t.Fatal("mouse quick save did not persist")
	}
}

func TestQuickSaveCannotStartOtherWorkflows(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) {
		t.Fatal("Ctrl+S triggered core workflow")
		return WorkResult{}, nil
	}
	for _, kind := range []string{"work-url", "work-rule", "work-receipt", "ssh"} {
		m.startForm(kind, "workflow", "", []field{{"value", "typed"}})
		if cmd := ctrlSave(m); cmd != nil || m.overlay != "form" {
			t.Fatalf("submitted %s", kind)
		}
		if strings.Contains(m.footer(), "Ctrl+S") {
			t.Fatalf("advertised unsupported shortcut for %s", kind)
		}
	}
}

func TestQuickSaveRuleBindingRetainsOwnerInspection(t *testing.T) {
	m := testModel(t)
	m.target.Configs = []config.CoreConfig{{ID: "main", Path: "/fixture/config.yaml"}}
	m.target.RuleSource = &config.RuleSource{Kind: "mihomo", ConfigID: "main", Binary: "/fixture/mihomo", Home: "/fixture"}
	m.settings.Targets[0] = m.target
	m.options.SaveTargets = func(config.Config) error { t.Fatal("saved unverified owner"); return nil }
	inspections := 0
	m.options.Workbench = func(_ context.Context, r WorkRequest) (WorkResult, error) {
		inspections++
		if r.Kind != "source-inspect" {
			t.Fatal(r.Kind)
		}
		return WorkResult{}, errors.New("owner unavailable")
	}
	m.startRuleSourceForm()
	flattenCommand(t, m, ctrlSave(m))
	if inspections != 1 || m.overlay != "form" || !m.input.Focused() {
		t.Fatal("owner validation bypassed or draft lost")
	}
}
