package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type button struct {
	id, label string
	enabled   bool
}

func buttonLine(buttons []button, width, y int) (string, []hitRegion) {
	var parts []string
	var hits []hitRegion
	x := 0
	for _, b := range buttons {
		label := "[" + b.label + "]"
		if !b.enabled {
			label = "(" + b.label + ")"
		}
		w := ansi.StringWidth(label)
		if x+w > width {
			continue
		}
		parts = append(parts, label)
		if b.enabled {
			hits = append(hits, hitRegion{rect: rect{x, y, w, 1}, kind: "button", id: b.id})
		}
		x += w + 1
	}
	return fit(strings.Join(parts, " "), width), hits
}
func (m *Model) overlayView(width, height int) string {
	lines, _ := m.overlayLayout(width, height)
	return strings.Join(lines, "\n")
}
func (m *Model) overlayLayout(width, height int) ([]string, []hitRegion) {
	if m.overlay == "work" {
		return m.workLayout(width, height)
	}
	if m.overlay == "form" {
		lines, hits, _ := m.formLayout(width, height)
		return lines, hits
	}
	var lines []string
	var hits []hitRegion
	var buttons []button
	switch m.overlay {
	case "search":
		return nil, nil
	case "targets":
		lines = []string{m.accent("Targets · select a row, then Connect / Test / Edit")}
		var rows []row
		for _, t := range m.settings.Targets {
			label := t.Label() + " · " + t.Controller
			if t.SSHHost != "" {
				label += " via " + t.SSHHost
			}
			if t.ID == m.settings.DefaultTarget {
				label += " [default]"
			}
			if t.ID == m.target.ID {
				label += " [current]"
			}
			if t.Transient {
				label += " [temporary]"
			}
			rows = append(rows, row{id: t.ID, label: label})
		}
		pos := position{index: m.targetIndex}
		h := max(0, height-4)
		lines = append(lines, m.listLines(rows, &pos, width, h, true)...)
		start := visibleStart(&pos, rows, h)
		for i := start; i < len(rows) && i < start+h; i++ {
			hits = append(hits, hitRegion{rect: rect{0, 1 + i - start, width, 1}, kind: "target-row", id: rows[i].id, index: i})
		}
		lines = append(lines, fit(core.Sanitize(m.testResult), width))
		has := len(rows) > 0
		buttons = []button{{"connect", "Connect", has}, {"test", "T Test", has && m.options.TestTarget != nil && !m.testPending}, {"add", "n Add", true}, {"edit", "e Edit", has}, {"cancel", "Close", true}}
	case "palette":
		lines = []string{m.accent("Actions"), m.input.View()}
		var rows []row
		for _, a := range m.paletteActions() {
			rows = append(rows, row{id: a.id, label: a.label + " [" + strings.Join(a.keys, "/") + "]"})
		}
		pos := position{index: m.paletteIndex}
		h := max(0, height-3)
		lines = append(lines, m.listLines(rows, &pos, width, h, true)...)
		start := visibleStart(&pos, rows, h)
		for i := start; i < len(rows) && i < start+h; i++ {
			hits = append(hits, hitRegion{rect: rect{0, 2 + i - start, width, 1}, kind: "palette-row", id: rows[i].id, index: i})
		}
		buttons = []button{{"run", "Run", len(rows) > 0}, {"cancel", "Cancel", true}}
	case "confirm":
		text := ""
		if m.confirm != nil {
			text = m.confirm.title + "\n\n" + m.confirm.body
		}
		lines = m.detailLines(text, width, max(0, height-1), 0)
		buttons = []button{{"confirm", "Confirm", m.confirm != nil}, {"cancel", "Cancel", true}}
	case "help":
		lines = fitLines(m.legacyOverlayView(width, max(1, height-1)), width, max(0, height-1))
		buttons = []button{{"cancel", "Close", true}}
	default:
		lines = fitLines(m.legacyOverlayView(width, height), width, height)
	}
	if len(buttons) > 0 {
		lines = fitLines(strings.Join(lines, "\n"), width, max(0, height-1))
		text, regions := buttonLine(buttons, width, height-1)
		lines = append(lines, text)
		hits = append(hits, regions...)
	}
	return fitLines(strings.Join(lines, "\n"), width, height), hits
}
func (m *Model) formLayout(width, height int) ([]string, []hitRegion, int) {
	f := m.form
	if f == nil {
		return nil, nil, -1
	}
	lines := []string{m.accent(f.title)}
	var hits []hitRegion
	review := f.index >= len(f.fields)
	caption := "Review the values before continuing"
	if f.kind == "target" {
		caption = "Review · Save retains the draft even when connectivity is offline"
	}
	if f.kind == "work-url" {
		caption = "Review · active diagnosis sends bounded HEAD / DNS / URLTests"
	}
	if f.kind == "work-rule" {
		caption = "Review · next step previews the exact persistent domain rule"
	}
	if !review {
		caption = fmt.Sprintf("Field %d/%d · Tab next / Shift+Tab back", f.index+1, len(f.fields))
	}
	lines = append(lines, fit(caption, width))
	count := max(0, height-6)
	start := max(0, min(max(0, f.index-count+1), max(0, len(f.fields)-count)))
	for i := start; i < len(f.fields) && i < start+count; i++ {
		field := f.fields[i]
		mark := "  "
		if i == f.index {
			mark = "> "
		}
		hits = append(hits, hitRegion{rect: rect{0, len(lines), width, 1}, kind: "field", id: fmt.Sprint(i), index: i})
		lines = append(lines, fit(mark+field.label+": "+defaultString(core.Sanitize(field.value), "(empty)"), width))
	}
	inputY := -1
	if !review {
		inputY = len(lines)
		lines = append(lines, fit(m.input.View(), width))
	} else {
		lines = append(lines, fit("Review the values; Shift+Tab returns to editing.", width))
	}
	result := m.testResult
	if f.err != "" {
		result = "Invalid: " + f.err
	}
	lines = append(lines, fit(core.Sanitize(result), width))
	label := "Review"
	if review {
		label = "Save"
		switch f.kind {
		case "ssh":
			label = "Discover"
		case "work-url":
			label = "Diagnose"
		case "work-rule":
			label = "Preview"
		case "work-receipt":
			label = "Continue"
		}
	}
	buttons := []button{{"save", label, true}, {"cancel", "Cancel", true}}
	if f.kind == "target" {
		buttons = append(buttons, button{"draft-test", "Ctrl+T Test", m.options.TestTarget != nil && !m.testPending})
	}
	lines = fitLines(strings.Join(lines, "\n"), width, max(0, height-1))
	text, regions := buttonLine(buttons, width, height-1)
	lines = append(lines, text)
	hits = append(hits, regions...)
	for i := range hits {
		if hits[i].y >= height {
			hits[i].h = 0
		}
	}
	if inputY >= height-1 {
		inputY = -1
	}
	return fitLines(strings.Join(lines, "\n"), width, height), hits, inputY
}
func (m *Model) overlayButton(id string) tea.Cmd {
	if strings.HasPrefix(id, "work-") {
		return m.workButton(id)
	}
	switch id {
	case "cancel":
		if m.overlay == "confirm" && m.confirm != nil && m.confirm.back != "" {
			m.overlay = m.confirm.back
			m.confirm = nil
			return nil
		}
		m.invalidateTargetTest()
		m.overlay = ""
		m.form = nil
		m.confirm = nil
		m.input.Blur()
		return nil
	case "connect":
		if m.overlay == "targets" && len(m.settings.Targets) > 0 {
			return m.connect(m.settings.Targets[min(m.targetIndex, len(m.settings.Targets)-1)])
		}
	case "test":
		if m.overlay == "targets" {
			return m.testPickedTarget()
		}
	case "add":
		if m.overlay == "targets" {
			return m.startTargetForm(false)
		}
	case "edit":
		if m.overlay == "targets" && len(m.settings.Targets) > 0 {
			return m.startTargetEdit(m.settings.Targets[min(m.targetIndex, len(m.settings.Targets)-1)])
		}
	case "run":
		if m.overlay == "palette" {
			actions := m.paletteActions()
			if len(actions) > 0 {
				a := actions[min(m.paletteIndex, len(actions)-1)]
				m.overlay = ""
				m.input.Blur()
				return m.dispatchAction(a.id)
			}
		}
	case "confirm":
		if m.overlay == "confirm" && m.confirm != nil {
			c := m.confirm
			m.confirm = nil
			m.overlay = ""
			return c.run()
		}
	case "draft-test":
		if m.overlay == "form" {
			return m.testDraft()
		}
	case "save":
		if m.overlay == "form" && m.form != nil {
			f := m.form
			if f.index < len(f.fields) {
				f.fields[f.index].value = m.input.Value()
				f.index = len(f.fields)
				m.input.Blur()
				return nil
			}
			return m.submitForm()
		}
	}
	return nil
}
