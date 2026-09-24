package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
)

func (m *Model) startConfigSync() tea.Cmd {
	if !m.canRunTool() {
		return nil
	}
	rows := m.savedRuleInspectionTargets("")
	m.work = &workState{request: WorkRequest{Kind: "config-sync-launch"}, phase: "config-sync-source", checked: map[string]bool{}, result: WorkResult{Title: "Sync configurations · choose source", Summary: "Select complete objects or ordered rules in the shared interactive selector. Every destination starts with no objects selected.", Rows: rows}}
	for i, row := range rows {
		if row.ID == "target:"+m.target.ID {
			m.work.index = i
		}
	}
	m.overlay = "work"
	return nil
}
func (m *Model) chooseConfigSyncTarget(id string) tea.Cmd {
	w := m.work
	if w.phase == "config-sync-source" {
		w.request.Source = strings.TrimPrefix(id, "target:")
		w.phase, w.index = "config-sync-destination", 0
		w.result.Title = "Sync configurations · choose destination"
		w.result.Summary = "Source: " + w.request.Source + "\nSelections and dependency choices are independent for each destination."
		w.result.Rows = m.savedRuleInspectionTargets(w.request.Source)
		if len(w.result.Rows) > 0 {
			w.result.Rows = append(w.result.Rows, WorkRow{ID: "*", Label: fmt.Sprintf("All other saved targets (%d)", len(w.result.Rows)), Detail: "Inspect and select objects separately for every target; no target is preselected for changes."})
		}
		return nil
	}
	args := []string{"configs", "sync", w.request.Source}
	if id == "*" {
		args = append(args, "--all")
	} else {
		args = append(args, strings.TrimPrefix(id, "target:"))
	}
	args = append(args, "--interactive")
	m.work, m.overlay = nil, ""
	return m.runTool("Sync configurations", false, args...)
}
