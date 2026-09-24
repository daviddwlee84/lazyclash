package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// WorkRequest is a user-selected operation, never a shell command.
type WorkRequest struct {
	Target, DestinationTarget                            config.Target
	Kind, Source, Destination, URL, Via, Digest, Receipt string
	Fields, Groups                                       []string
	ObserveOnly                                          bool
	Rule                                                 string
	All                                                  bool
	Targets                                              []config.Target
	Scope, Query                                         string
}
type WorkRow struct {
	ID, Label, Detail string
	Selectable        bool
}
type WorkResult struct {
	Title, Summary           string
	Rows                     []WorkRow
	Apply, Verify, Recommend *WorkRequest
}
type workState struct {
	request              WorkRequest
	result               WorkResult
	phase                string
	index, offset, focus int
	checked              map[string]bool
	pending              bool
	serverHelp           bool
	serial               uint64
	cancel               context.CancelFunc
}
type workMsg struct {
	generation, serial uint64
	result             WorkResult
	err                error
}

func (m *Model) startCompare() tea.Cmd {
	m.work = &workState{phase: "source", checked: map[string]bool{}}
	m.work.result.Title = "Compare targets · choose source"
	for _, t := range m.settings.Targets {
		if !t.Transient {
			m.work.result.Rows = append(m.work.result.Rows, WorkRow{ID: t.ID, Label: t.Label(), Detail: t.Controller + " via " + defaultString(t.SSHHost, "local")})
		}
	}
	m.overlay = "work"
	return nil
}
func (m *Model) launchWork(req WorkRequest) tea.Cmd {
	if m.options.Workbench == nil {
		return nil
	}
	for _, t := range m.settings.Targets {
		if t.ID == req.Source {
			req.Target = t
		}
		if t.ID == req.Destination {
			req.DestinationTarget = t
		}
	}
	if req.Source == m.target.ID {
		req.Target = m.target
	}
	if req.Kind == "quick-rule-preview" || req.Kind == "rule-healthcheck" {
		if req.All {
			req.Targets = nil
			for _, t := range m.settings.Targets {
				if !t.Transient {
					req.Targets = append(req.Targets, t)
				}
			}
		} else {
			req.Targets = []config.Target{req.Target}
		}
	}
	if ruleInspectionKind(req.Kind) {
		req = m.prepareRuleInspection(req)
	}
	if m.work != nil && m.work.pending {
		return nil
	}
	if m.options.ReadOnly && (strings.HasSuffix(req.Kind, "apply") || req.Kind == "rule-restore" || req.Kind == "url" && !req.ObserveOnly) {
		m.status = "Read-only: this operation is unavailable"
		return nil
	}
	m.workSerial++
	ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
	m.work = &workState{request: req, phase: "result", checked: map[string]bool{}, pending: true, serial: m.workSerial, cancel: cancel, result: WorkResult{Title: "Working · " + req.Kind, Summary: "Esc requests cancellation. An interrupted write can have an unknown result."}}
	if ruleInspectionKind(req.Kind) {
		m.work.result.Summary = "Reading rule snapshots… Esc cancels this inspection."
	}
	m.overlay = "work"
	m.input.Blur()
	m.form = nil
	generation, serial, run := m.generation, m.workSerial, m.options.Workbench
	return func() tea.Msg {
		defer cancel()
		result, err := run(ctx, req)
		return workMsg{generation, serial, result, err}
	}
}
func (m *Model) receiveWork(msg workMsg) tea.Cmd {
	if m.work == nil || msg.generation != m.generation || msg.serial != m.work.serial {
		return nil
	}
	w := m.work
	if m.serverWork() {
		return m.receiveServerWork(msg)
	}
	w.pending = false
	w.cancel = nil
	w.result = msg.result
	if msg.err != nil {
		w.result.Summary += "\nFailed: " + safeError(msg.err)
		w.result.Apply = nil
	}
	if w.result.Title == "" {
		w.result.Title = w.request.Kind
	}
	m.status = "Finished · " + w.result.Title
	affected := ""
	if w.request.Kind == "quick-rule-apply" {
		refreshCurrent := false
		for _, target := range w.request.Targets {
			m.invalidateRuleWorkTarget(target.ID)
			refreshCurrent = refreshCurrent || target.ID == m.target.ID
		}
		if refreshCurrent {
			return m.refresh(true)
		}
		return nil
	}
	switch w.request.Kind {
	case "copy-apply":
		affected = w.request.Destination
	case "rule-apply", "rule-restore", "rule-verify":
		affected = w.request.Source
	}
	if affected != "" {
		if s := m.states[affected]; s != nil {
			for _, key := range []string{"config", "proxies", "rules", "proxyProviders", "ruleProviders"} {
				snap := s.snap(key)
				snap.err = errors.New("external operation finished; awaiting refresh")
				snap.serial++
				snap.loading = false
			}
		}
		if affected == m.target.ID {
			return m.refresh(true)
		}
	}
	return nil
}
func (m *Model) closeWork() tea.Cmd {
	if m.work != nil && m.work.pending {
		m.work.cancel()
		if m.serverWork() || ruleInspectionKind(m.work.request.Kind) {
			m.workSerial++
			m.work = nil
			m.overlay = ""
			return nil
		}
		m.work.result.Summary = "Cancellation requested; waiting for the operation result. Writes may already have applied."
		return nil
	}
	m.workSerial++
	m.work = nil
	m.overlay = ""
	return nil
}
func (m *Model) chooseWorkTarget() tea.Cmd {
	w := m.work
	if w == nil || len(w.result.Rows) == 0 {
		return nil
	}
	id := w.result.Rows[min(w.index, len(w.result.Rows)-1)].ID
	if ruleInspectionKind(w.request.Kind) {
		return m.chooseRuleInspection(id)
	}
	if w.phase == "rule-target" {
		m.quickRuleScope = id
		req := w.request
		req.All = id == "all"
		req.Source = strings.TrimPrefix(id, "target:")
		if req.All {
			req.Source = ""
		}
		return m.launchWork(req)
	}
	if w.phase == "source" {
		w.request.Source = id
		w.phase = "destination"
		w.index = 0
		w.result.Title = "Compare targets · choose destination"
		w.result.Summary = "Source: " + id
		w.result.Rows = nil
		for _, t := range m.settings.Targets {
			if t.ID != id && !t.Transient {
				w.result.Rows = append(w.result.Rows, WorkRow{ID: t.ID, Label: t.Label(), Detail: t.Controller + " via " + defaultString(t.SSHHost, "local")})
			}
		}
		return nil
	}
	req := w.request
	req.Kind = "diff"
	req.Destination = id
	return m.launchWork(req)
}
func (m *Model) workButton(id string) tea.Cmd {
	w := m.work
	if w == nil {
		return nil
	}
	if id == "work-close" {
		return m.closeWork()
	}
	if strings.HasPrefix(id, "server-") {
		return m.serverButton(id)
	}
	if w.pending {
		return nil
	}
	switch id {
	case "work-choose":
		return m.chooseWorkTarget()
	case "work-edit":
		req := w.request
		if ruleInspectionKind(req.Kind) {
			m.rememberRuleInspection(req)
			m.work = nil
			return m.startRuleInspection(req.Kind)
		}
		if strings.HasPrefix(req.Kind, "quick-rule-") {
			m.quickRuleDraft = req.Rule
			m.work = nil
			return m.startQuickRuleForm()
		}
		if req.Kind == "url" {
			m.work = nil
			return m.startForm("work-url", "Diagnose a URL", "", []field{{"URL", req.URL}, {"Alternative policy (optional)", req.Via}, {"Observe only (true/false)", fmt.Sprint(req.ObserveOnly)}})
		}
		if req.Kind == "rule-preview" {
			m.work = nil
			return m.startForm("work-rule", "Preview exact domain rule", "", []field{{"Hostname", req.URL}, {"Existing policy", req.Via}})
		}
	case "work-toggle":
		if len(w.result.Rows) > 0 {
			r := w.result.Rows[w.index]
			if r.Selectable {
				w.checked[r.ID] = !w.checked[r.ID]
			}
		}
	case "work-preview":
		req := w.request
		req.Kind = "copy-preview"
		req.Fields = nil
		req.Groups = nil
		for _, r := range w.result.Rows {
			if w.checked[r.ID] {
				kind, name, _ := strings.Cut(r.ID, ":")
				if kind == "field" {
					req.Fields = append(req.Fields, name)
				} else if kind == "group" {
					req.Groups = append(req.Groups, name)
				}
			}
		}
		if len(req.Fields)+len(req.Groups) == 0 {
			m.status = "Select at least one field or manual Selector"
			return nil
		}
		return m.launchWork(req)
	case "work-apply":
		if w.result.Apply != nil && !m.options.ReadOnly {
			req := *w.result.Apply
			if req.Kind == "quick-rule-apply" {
				m.ask("Apply reviewed rule", w.result.Summary, func() tea.Cmd { return m.launchWork(req) })
				m.confirm.defaultNegative = true
				return nil
			}
			return m.ask("Apply reviewed change", w.result.Summary, func() tea.Cmd { return m.launchWork(req) })
		}
	case "work-verify":
		if w.result.Verify != nil {
			return m.launchWork(*w.result.Verify)
		}
	case "work-recommend":
		if w.result.Recommend != nil {
			return m.launchWork(*w.result.Recommend)
		}
	}
	return nil
}
func (m *Model) workKey(msg tea.KeyPressMsg) tea.Cmd {
	w := m.work
	if w == nil {
		m.overlay = ""
		return nil
	}
	if m.serverWork() {
		if handled, command := m.serverKey(msg); handled {
			return command
		}
	}
	switch msg.String() {
	case "esc", "q":
		return m.closeWork()
	case "tab", "shift+tab":
		w.focus = 1 - w.focus
	case "up", "k":
		m.moveWork(-1)
	case "down", "j":
		m.moveWork(1)
	case "pgup":
		w.offset = max(0, w.offset-10)
	case "pgdown":
		w.offset += 10
	case "home", "g":
		w.index = 0
		w.offset = 0
	case "end", "G":
		w.index = max(0, len(w.result.Rows)-1)
	case "space", " ":
		return m.workButton("work-toggle")
	case "enter":
		if w.phase != "result" {
			return m.workButton("work-choose")
		}
		return m.workButton("work-toggle")
	case "e":
		return m.workButton("work-edit")
	case "p":
		return m.workButton("work-preview")
	case "a":
		return m.workButton("work-apply")
	case "v":
		return m.workButton("work-verify")
	case "r":
		return m.workButton("work-recommend")
	}
	return nil
}
func (m *Model) moveWork(delta int) {
	if m.work == nil {
		return
	}
	w := m.work
	if w.focus == 1 {
		w.offset = max(0, w.offset+delta)
	} else {
		w.index = max(0, min(max(0, len(w.result.Rows)-1), w.index+delta))
		w.offset = 0
	}
}
func (m *Model) workLayout(width, height int) ([]string, []hitRegion) {
	w := m.work
	if w == nil {
		return nil, nil
	}
	lines := []string{m.accent(w.result.Title)}
	var hits []hitRegion
	if height < 3 {
		return fitLines(strings.Join(lines, "\n"), width, height), nil
	}
	detail := w.result.Summary
	if len(w.result.Rows) > 0 {
		detail = w.result.Rows[min(w.index, len(w.result.Rows)-1)].Detail + "\n\n" + detail
	}
	if m.serverWork() && w.serverHelp {
		detail = serverHelpText
	}
	listHeight := min(max(0, (height-4)/2), len(w.result.Rows))
	start := max(0, w.index-listHeight+1)
	if width < 65 && w.focus == 1 {
		listHeight = 0
	}
	for i := start; i < len(w.result.Rows) && i < start+listHeight; i++ {
		r := w.result.Rows[i]
		mark := "  "
		if i == w.index {
			mark = "> "
		}
		if r.Selectable {
			if w.checked[r.ID] {
				mark += "[x] "
			} else {
				mark += "[ ] "
			}
		}
		lines = append(lines, fit(core.Sanitize(mark+r.Label), width))
		hits = append(hits, hitRegion{rect: rect{0, len(lines) - 1, width, 1}, kind: "work-row", id: r.ID, index: i})
	}
	hint := "Tab list/detail · ↑↓/jk · PgUp/PgDn detail"
	if w.focus == 1 {
		hint += " · DETAIL"
	} else {
		hint += " · LIST"
	}
	lines = append(lines, fit(hint, width))
	detailHeight := max(0, height-len(lines)-1)
	// Clamp scrolling against actual wrapped content, including narrow resizes.
	wrapped := strings.Split(ansi.Wrap(core.Sanitize(detail), max(1, width), ""), "\n")
	maxOffset := max(0, len(wrapped)-detailHeight)
	offset := min(w.offset, maxOffset)
	lines = append(lines, m.detailLines(detail, width, detailHeight, offset)...)
	buttons := []button{}
	if m.serverWork() {
		buttons = append(buttons, m.serverButtons()...)
	}
	if w.phase != "result" {
		buttons = append(buttons, button{"work-choose", "Enter Choose", len(w.result.Rows) > 0})
	}
	if w.request.Kind == "url" || w.request.Kind == "rule-preview" || strings.HasPrefix(w.request.Kind, "quick-rule-") || ruleInspectionKind(w.request.Kind) {
		buttons = append(buttons, button{"work-edit", "e Edit", !w.pending})
	}
	if w.request.Kind == "diff" {
		buttons = append(buttons, button{"work-toggle", "Space Select", !w.pending}, button{"work-preview", "p Preview", !w.pending})
	}
	if w.result.Apply != nil {
		buttons = append(buttons, button{"work-apply", "a Apply", !w.pending && !m.options.ReadOnly})
	}
	if w.result.Verify != nil {
		buttons = append(buttons, button{"work-verify", "v Verify", !w.pending})
	}
	if w.result.Recommend != nil {
		buttons = append(buttons, button{"work-recommend", "r Rule preview", !w.pending})
	}
	buttons = append(buttons, button{"work-close", map[bool]string{true: "Esc Cancel", false: "Esc Close"}[w.pending], true})
	lines = fitLines(strings.Join(lines, "\n"), width, height-1)
	text, regions := buttonLine(buttons, width, height-1)
	lines = append(lines, text)
	hits = append(hits, regions...)
	return lines, hits
}

func (m *Model) startURLForm() tea.Cmd {
	return m.startForm("work-url", "Diagnose a URL", "", []field{{"URL", ""}, {"Alternative policy (optional)", ""}, {"Observe only (true/false)", fmt.Sprint(m.options.ReadOnly)}})
}
func (m *Model) startRuleForm() tea.Cmd {
	return m.startForm("work-rule", "Preview exact domain rule", "", []field{{"Hostname", ""}, {"Existing policy", ""}})
}

func (m *Model) workMouseContext() string {
	if m.work == nil {
		return ""
	}
	return fmt.Sprintf("%s/%d/%d/%t/%v", m.work.phase, m.work.index, m.work.focus, m.work.pending, m.work.checked)
}
func (m *Model) startRuleSourceForm() tea.Cmd {
	s := config.RuleSource{Kind: "mihomo"}
	if m.target.RuleSource != nil {
		s = *m.target.RuleSource
	}
	return m.startForm("work-source", "Bind persistent rule owner (explicit write source)", "", []field{{"Owner (mihomo/verge)", s.Kind}, {"Mihomo registered config ID", s.ConfigID}, {"Mihomo binary: absolute host path", s.Binary}, {"Mihomo home: absolute host path", s.Home}, {"Verge data directory: absolute host path", s.DataDir}, {"Verge active profile UID", s.ProfileUID}, {"Declared Verge compatibility version (2.5.2)", s.Version}})
}
func (m *Model) submitRuleSourceForm(value func(int) string) tea.Cmd {
	c := cloneSettings(m.settings)
	found := false
	var target config.Target
	for i := range c.Targets {
		if c.Targets[i].ID == m.target.ID && !c.Targets[i].Transient {
			c.Targets[i].RuleSource = &config.RuleSource{Kind: value(0), ConfigID: value(1), Binary: value(2), Home: value(3), DataDir: value(4), ProfileUID: value(5), Version: value(6)}
			found = true
			target = c.Targets[i]
		}
	}
	if !found {
		m.form.err = "Save this target before binding a rule source"
		return nil
	}
	if err := config.Validate(c); err != nil {
		m.form.err = safeError(err)
		return nil
	}
	if m.options.Workbench == nil || m.options.SaveTargets == nil {
		m.form.err = "Source validation or saving is unavailable"
		return nil
	}
	m.overlay = "saving"
	m.status = "Checking persistent owner before saving binding…"
	run, save, ctx := m.options.Workbench, m.options.SaveTargets, m.ctx
	return func() tea.Msg {
		inspectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_, err := run(inspectCtx, WorkRequest{Kind: "source-inspect", Source: target.ID, Target: target})
		if err == nil {
			err = save(c)
		}
		return savedMsg{settings: c, selected: target.ID, err: err}
	}
}
