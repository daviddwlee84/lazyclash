package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

func ruleInspectionKind(kind string) bool {
	return kind == "rule-diff" || kind == "rule-find" || kind == "rule-lookup"
}

func ruleInspectionTitle(kind string) string {
	switch kind {
	case "rule-diff":
		return "Compare rules"
	case "rule-find":
		return "Find exact rule"
	default:
		return "Look up host / IP"
	}
}

func (m *Model) ruleInspectionRequest(kind string) WorkRequest {
	req := m.ruleInspectDrafts[kind]
	req.Kind = kind
	if req.Scope == "" {
		req.Scope = "both"
	}
	if req.Source == "" && !req.All {
		req.Source = m.target.ID
	}
	return req
}

func (m *Model) rememberRuleInspection(req WorkRequest) {
	if m.ruleInspectDrafts == nil {
		m.ruleInspectDrafts = map[string]WorkRequest{}
	}
	// Retain user choices, not credentials or a stale target inventory.
	req.Target, req.DestinationTarget, req.Targets = config.Target{}, config.Target{}, nil
	m.ruleInspectDrafts[req.Kind] = req
}

func (m *Model) startRuleInspection(kind string) tea.Cmd {
	req := m.ruleInspectionRequest(kind)
	if kind == "rule-diff" {
		return m.startRuleInspectionScope(req)
	}
	label := "Exact rule (raw text or one YAML item)"
	if kind == "rule-lookup" {
		label = "Hostname or literal destination IP (no DNS lookup)"
	}
	return m.startForm("work-"+kind, ruleInspectionTitle(kind), "", []field{{label, req.Query}})
}

func (m *Model) retainRuleInspectionDraft() {
	if m.form == nil || m.form.kind != "work-rule-find" && m.form.kind != "work-rule-lookup" {
		return
	}
	if m.form.index < len(m.form.fields) {
		m.form.fields[m.form.index].value = m.input.Value()
	}
	req := m.ruleInspectionRequest(strings.TrimPrefix(m.form.kind, "work-"))
	req.Query = m.form.fields[0].value
	m.rememberRuleInspection(req)
}

func (m *Model) showRuleInspectionPicker(req WorkRequest, phase, title string, rows []WorkRow, selected string) tea.Cmd {
	m.rememberRuleInspection(req)
	summary := "Read-only inspection · scope: " + req.Scope
	if req.Query != "" {
		summary += "\nQuery: " + req.Query
	}
	if phase == "rule-inspect-destination" {
		summary += "\nBaseline: " + req.Source
	}
	if len(rows) == 0 {
		summary += "\nNo saved target is available for this selection."
	}
	w := &workState{request: req, phase: phase, checked: map[string]bool{}, result: WorkResult{Title: title, Summary: summary, Rows: rows}}
	for i, row := range rows {
		if row.ID == selected {
			w.index = i
			break
		}
	}
	m.work, m.overlay, m.form = w, "work", nil
	m.input.Blur()
	return nil
}

func (m *Model) startRuleInspectionScope(req WorkRequest) tea.Cmd {
	rows := []WorkRow{
		{ID: "both", Label: "Both runtime and persistent source", Detail: "Show independently observed runtime and source results. Missing source ownership does not hide available runtime evidence."},
		{ID: "runtime", Label: "Runtime rules only", Detail: "Inspect the controller's ordered rule snapshot. Some source modifiers are not exposed by this API."},
		{ID: "source", Label: "Persistent source only", Detail: "Inspect the explicitly bound rule owner. Verge companion sections retain their separate context; they are not the composed runtime."},
	}
	return m.showRuleInspectionPicker(req, "rule-inspect-scope", ruleInspectionTitle(req.Kind)+" · choose scope", rows, req.Scope)
}

func (m *Model) savedRuleInspectionTargets(exclude string) []WorkRow {
	var rows []WorkRow
	for _, target := range m.settings.Targets {
		if target.Transient || target.ID == exclude {
			continue
		}
		label := target.Label()
		if target.ID == m.target.ID {
			label += " [current]"
		}
		rows = append(rows, WorkRow{ID: "target:" + target.ID, Label: label, Detail: target.Controller + " via " + defaultString(target.SSHHost, "local")})
	}
	return rows
}

func (m *Model) startRuleInspectionTargets(req WorkRequest, baseline bool) tea.Cmd {
	phase, title, selected, excluded := "rule-inspect-target", " · choose targets", req.Source, ""
	if baseline {
		phase, title = "rule-inspect-baseline", " · choose baseline"
	} else if req.Kind == "rule-diff" {
		phase, title, selected, excluded = "rule-inspect-destination", " · compare baseline with", req.Destination, req.Source
	}
	rows := m.savedRuleInspectionTargets(excluded)
	selected = "target:" + selected
	if !baseline && len(rows) > 0 {
		label := fmt.Sprintf("All saved targets (%d)", len(rows))
		if req.Kind == "rule-diff" {
			label = fmt.Sprintf("All other saved targets (%d)", len(rows))
		}
		rows = append(rows, WorkRow{ID: "*", Label: label, Detail: "Read each saved target independently. Unavailable snapshots are reported without changing any target."})
		if req.All {
			selected = "*"
		}
	}
	return m.showRuleInspectionPicker(req, phase, ruleInspectionTitle(req.Kind)+title, rows, selected)
}

func (m *Model) chooseRuleInspection(id string) tea.Cmd {
	w := m.work
	req := w.request
	switch w.phase {
	case "rule-inspect-scope":
		req.Scope = id
		return m.startRuleInspectionTargets(req, req.Kind == "rule-diff")
	case "rule-inspect-baseline":
		req.Source = strings.TrimPrefix(id, "target:")
		return m.startRuleInspectionTargets(req, false)
	case "rule-inspect-target", "rule-inspect-destination":
		req.All = id == "*"
		id = strings.TrimPrefix(id, "target:")
		if req.Kind == "rule-diff" {
			req.Destination = id
		} else {
			req.Source = id
		}
		if req.All {
			if req.Kind == "rule-diff" {
				req.Destination = ""
			} else {
				req.Source = ""
			}
		}
		return m.launchWork(req)
	}
	return nil
}

func (m *Model) prepareRuleInspection(req WorkRequest) WorkRequest {
	m.rememberRuleInspection(req)
	req.Targets = nil
	if req.All {
		for _, target := range m.settings.Targets {
			if !target.Transient && (req.Kind != "rule-diff" || target.ID != req.Source) {
				req.Targets = append(req.Targets, target)
			}
		}
	} else if req.Kind == "rule-diff" {
		req.Targets = []config.Target{req.DestinationTarget}
	} else {
		req.Targets = []config.Target{req.Target}
	}
	return req
}
