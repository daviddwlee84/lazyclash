package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
)

// RuleReviewOptions connects both the dashboard and standalone review command
// to the same domain operations. No write is triggered by opening the view.
type RuleReviewOptions struct {
	Snapshot      ruleobserve.Snapshot
	ReadOnly      bool
	BlockedReason string
	Policies      func(context.Context) ([]string, error)
	Preview       func(context.Context, []string) (rulework.QuickPlan, error)
	Apply         func(context.Context, []string, string) (rulework.QuickResult, error)
	Save          func(context.Context, ruleobserve.Snapshot) (string, error)
}

type reviewDraft struct {
	host, policy             string
	suffix, checked, ignored bool
}
type ruleReviewMsg struct {
	owner    *ruleReview
	serial   uint64
	kind     string
	policies []string
	plan     rulework.QuickPlan
	result   rulework.QuickResult
	saved    string
	err      error
}
type ruleReview struct {
	ctx                                        context.Context
	opts                                       RuleReviewOptions
	drafts                                     map[string]reviewDraft
	policies                                   []string
	input                                      textinput.Model
	inputMode, filter, notice, phase, body     string
	index, offset, focus, scope, width, height int
	serial                                     uint64
	cancel                                     context.CancelFunc
	policySerial                               uint64
	policyCancel                               context.CancelFunc
	policyLoading, previewValid                bool
	pendingKind                                string
	pending, closed, embedded, help            bool
	plan                                       rulework.QuickPlan
	rules                                      []string
	result                                     rulework.QuickResult
}

func newRuleReview(ctx context.Context, opts RuleReviewOptions, embedded bool) *ruleReview {
	in := textinput.New()
	in.CharLimit = 1024
	m := &ruleReview{ctx: ctx, opts: opts, embedded: embedded, drafts: map[string]reviewDraft{}, input: in, width: 100, height: 28, phase: "list"}
	for _, g := range opts.Snapshot.Groups {
		m.drafts[g.Key] = reviewDraft{host: g.Host}
	}
	return m
}

func RunRuleReview(ctx context.Context, opts RuleReviewOptions, in io.Reader, out io.Writer) (rulework.QuickResult, error) {
	m := newRuleReview(ctx, opts, false)
	defer m.close()
	_, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return m.result, ctx.Err()
	}
	return m.result, err
}
func (m *ruleReview) close() {
	m.closed = true
	m.serial++
	if m.cancel != nil {
		m.cancel()
	}
	if m.policyCancel != nil {
		m.policyCancel()
	}
}
func (m *ruleReview) Init() tea.Cmd {
	if m.closed || m.policyLoading || m.opts.Policies == nil {
		return nil
	}
	m.policyLoading = true
	m.policySerial++
	ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
	m.policyCancel = cancel
	msg := ruleReviewMsg{owner: m, serial: m.policySerial, kind: "policies"}
	load := m.opts.Policies
	return func() tea.Msg {
		defer cancel()
		msg.policies, msg.err = load(ctx)
		return msg
	}
}
func (m *ruleReview) operation(kind string, run func(context.Context, *ruleReviewMsg)) tea.Cmd {
	if m.pending {
		return nil
	}
	m.serial++
	m.pending = true
	m.pendingKind = kind
	ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
	m.cancel = cancel
	msg := ruleReviewMsg{owner: m, serial: m.serial, kind: kind}
	return func() tea.Msg { defer cancel(); run(ctx, &msg); return msg }
}
func (m *ruleReview) rows() []ruleobserve.Group {
	var rows []ruleobserve.Group
	for _, g := range m.opts.Snapshot.Groups {
		d := m.drafts[g.Key]
		if d.ignored || !strings.Contains(strings.ToLower(g.Host+" "+g.Key), strings.ToLower(m.filter)) {
			continue
		}
		fallback := false
		for _, v := range g.Variants {
			if strings.EqualFold(v.Rule, "Match") {
				fallback = true
			}
		}
		if m.scope == 0 && g.ErrorCount+g.OtherCount == 0 || m.scope == 1 && !fallback {
			continue
		}
		rows = append(rows, g)
	}
	// Prefer observed fallback errors, retaining domain order within each tier.
	sort.SliceStable(rows, func(i, j int) bool {
		priority := func(g ruleobserve.Group) int {
			for _, v := range g.Variants {
				if v.Kind == ruleobserve.KindDialError && strings.EqualFold(v.Rule, "Match") {
					return 0
				}
			}
			if g.ErrorCount > 0 {
				return 1
			}
			return 2
		}
		a, b := priority(rows[i]), priority(rows[j])
		if a != b {
			return a < b
		}
		return rows[i].Host < rows[j].Host
	})
	return rows
}
func (m *ruleReview) selected() (ruleobserve.Group, bool) {
	rows := m.rows()
	if len(rows) == 0 {
		return ruleobserve.Group{}, false
	}
	m.index = min(max(m.index, 0), len(rows)-1)
	return rows[m.index], true
}
func (m *ruleReview) draftKeys() []string {
	var keys []string
	for _, g := range m.opts.Snapshot.Groups {
		d := m.drafts[g.Key]
		if d.checked && !d.ignored {
			keys = append(keys, g.Key)
		}
	}
	if len(keys) == 0 {
		if g, ok := m.selected(); ok {
			keys = append(keys, g.Key)
		}
	}
	return keys
}
func (m *ruleReview) prepare() tea.Cmd {
	if m.pending || m.opts.Preview == nil {
		return nil
	}
	if m.opts.BlockedReason != "" {
		m.notice = m.opts.BlockedReason
		return nil
	}
	var rules []string
	seen := map[string]bool{}
	for _, g := range m.opts.Snapshot.Groups {
		d := m.drafts[g.Key]
		if !d.checked || d.ignored {
			continue
		}
		if !slices.Contains(m.policies, d.policy) {
			m.notice = "Assign an existing policy with p before previewing."
			return nil
		}
		rule, err := ruleobserve.Candidate(d.host, d.policy, d.suffix)
		if err != nil {
			m.notice = core.Sanitize(err.Error())
			return nil
		}
		if !seen[rule] {
			rules = append(rules, rule)
			seen[rule] = true
		}
	}
	if len(rules) == 0 {
		m.notice = "Select candidates with Space and assign a policy with p."
		return nil
	}
	m.rules = rules
	m.previewValid = false
	m.notice = "Validating the complete batch…"
	return m.operation("preview", func(ctx context.Context, msg *ruleReviewMsg) { msg.plan, msg.err = m.opts.Preview(ctx, rules) })
}
func (m *ruleReview) apply() tea.Cmd {
	if !m.canApply() {
		return nil
	}
	rules, digest := append([]string(nil), m.rules...), m.plan.Digest
	m.notice = "Applying the reviewed batch…"
	return m.operation("apply", func(ctx context.Context, msg *ruleReviewMsg) { msg.result, msg.err = m.opts.Apply(ctx, rules, digest) })
}

func (m *ruleReview) canApply() bool {
	return m.phase == "preview" && m.previewValid && !m.pending && !m.opts.ReadOnly && m.opts.BlockedReason == "" && m.opts.Apply != nil && m.plan.Status == "ready" && m.plan.HasChanges() && m.plan.Digest != "" && len(m.rules) > 0
}
func reviewPlanText(p rulework.QuickPlan) string {
	lines := []string{"Batch: " + p.Status, "Digest: " + p.Digest}
	for _, t := range p.Targets {
		lines = append(lines, "", t.TargetID+" · "+t.Status, t.Message)
		if t.Owner != nil {
			lines = append(lines, "Owner: "+t.Owner.Kind+" · "+t.Owner.File)
		}
		for _, f := range t.Findings {
			lines = append(lines, f.Severity+": "+f.Message)
		}
		if h := rulework.FormatQuickExistingHealth(t.ExistingHealth); h != "" {
			lines = append(lines, h)
		}
		lines = append(lines, t.Diff)
	}
	return strings.Join(lines, "\n")
}
func reviewResultText(r rulework.QuickResult) string {
	lines := []string{"Batch: " + r.Status}
	for _, t := range r.Results {
		lines = append(lines, "", t.TargetID+" · "+t.Status, t.Message)
		if t.Receipt != nil {
			lines = append(lines, "Receipt: "+t.Receipt.ID, t.Receipt.Message)
		}
	}
	return strings.Join(lines, "\n")
}
func (m *ruleReview) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.closed {
		return m, nil
	}
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.input.SetWidth(max(1, m.width-10))
		return m, nil
	case ruleReviewMsg:
		if msg.owner != m {
			return m, nil
		}
		if msg.kind == "policies" {
			if msg.serial != m.policySerial || !m.policyLoading {
				return m, nil
			}
			m.policyLoading, m.policyCancel = false, nil
			if msg.err != nil {
				m.notice = "Policies unavailable: " + core.Sanitize(msg.err.Error()) + " · r retries"
				return m, nil
			}
			m.policies = nil
			for _, policy := range msg.policies {
				if _, err := ruleobserve.Candidate("example.invalid", policy, false); err == nil {
					m.policies = append(m.policies, policy)
				}
			}
			sort.Strings(m.policies)
			m.policies = slices.Compact(m.policies)
			return m, nil
		}
		if msg.serial != m.serial || !m.pending || msg.kind != m.pendingKind {
			return m, nil
		}
		m.pending = false
		m.pendingKind = ""
		m.cancel = nil
		switch msg.kind {
		case "preview":
			m.plan = msg.plan
			m.previewValid = msg.err == nil
			m.phase = "preview"
			m.offset = 0
			m.body = reviewPlanText(msg.plan)
		case "apply":
			m.result = msg.result
			m.phase = "result"
			m.offset = 0
			m.body = reviewResultText(msg.result)
		case "save":
			m.notice = "Saved observation: " + msg.saved
		}
		if msg.err != nil {
			m.notice = core.Sanitize(msg.err.Error())
		} else if msg.kind != "save" {
			m.notice = ""
		}
		return m, nil
	case tea.PasteMsg:
		if m.inputMode != "" {
			return m, m.updateInput(msg)
		}
		return m, nil
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" && !m.pending {
			m.close()
			if !m.embedded {
				return m, tea.Quit
			}
			return m, nil
		}
		if m.inputMode != "" {
			switch key {
			case "esc":
				if m.inputMode == "filter" {
					m.filter = ""
					m.index = 0
					m.offset = 0
				}
				m.inputMode = ""
				m.input.Blur()
				return m, nil
			case "enter":
				value := strings.TrimSpace(m.input.Value())
				if m.inputMode == "filter" {
					m.filter = value
				} else if m.inputMode == "policy" {
					if !slices.Contains(m.policies, value) {
						m.notice = "Choose an existing policy: " + strings.Join(m.policies, ", ")
						return m, nil
					}
					for _, k := range m.draftKeys() {
						d := m.drafts[k]
						d.policy = value
						m.drafts[k] = d
					}
				} else if g, ok := m.selected(); ok {
					d := m.drafts[g.Key]
					if _, err := ruleobserve.Candidate(value, "DIRECT", d.suffix); err != nil {
						m.notice = core.Sanitize(err.Error())
						return m, nil
					}
					d.host = value
					m.drafts[g.Key] = d
				}
				m.inputMode = ""
				m.input.Blur()
				m.notice = ""
				return m, nil
			}
			return m, m.updateInput(msg)
		}
		if m.help {
			if key == "?" || key == "esc" || key == "q" {
				m.help = false
			} else if key == "j" || key == "down" {
				m.offset++
			} else if key == "k" || key == "up" {
				m.offset = max(0, m.offset-1)
			}
			return m, nil
		}
		if key == "?" {
			m.help = true
			m.offset = 0
			return m, nil
		}
		if m.pending {
			if (key == "esc" || key == "ctrl+c") && m.cancel != nil {
				m.cancel()
				if m.pendingKind == "preview" {
					m.serial++
					m.pending, m.previewValid = false, false
					m.pendingKind, m.phase, m.cancel = "", "list", nil
					m.notice = "Preview canceled; selections retained."
				} else {
					m.notice = "Cancellation requested; waiting for the operation result."
				}
			}
			return m, nil
		}
		if m.phase != "list" {
			switch key {
			case "esc", "enter", "q":
				m.phase = "list"
				m.previewValid = false
				m.offset = 0
			case "y":
				if m.phase == "preview" {
					return m, m.apply()
				}
			case "j", "down":
				m.offset++
			case "k", "up":
				m.offset = max(0, m.offset-1)
			case "pgdown":
				m.offset += max(1, m.height-6)
			case "pgup":
				m.offset = max(0, m.offset-max(1, m.height-6))
			}
			return m, nil
		}
		switch key {
		case "q", "esc", "ctrl+c":
			m.close()
			if !m.embedded {
				return m, tea.Quit
			}
			return m, nil
		case "down", "j":
			if m.focus == 1 {
				m.offset++
			} else {
				m.index = min(m.index+1, max(0, len(m.rows())-1))
			}
		case "up", "k":
			if m.focus == 1 {
				m.offset = max(0, m.offset-1)
			} else {
				m.index = max(0, m.index-1)
			}
		case "home", "g":
			m.index = 0
			m.offset = 0
		case "end", "G":
			m.index = max(0, len(m.rows())-1)
		case "tab", "shift+tab", "left", "right", "h", "l", "enter":
			m.focus = 1 - m.focus
			m.offset = 0
		case "space":
			if g, ok := m.selected(); ok && g.Host != "" {
				d := m.drafts[g.Key]
				d.checked = !d.checked
				m.drafts[g.Key] = d
			} else {
				m.notice = "Unparsed warnings have no verified destination to turn into a rule."
			}
		case "i":
			for _, k := range m.draftKeys() {
				d := m.drafts[k]
				d.ignored = true
				d.checked = false
				m.drafts[k] = d
			}
			m.index = 0
		case "u":
			for k, d := range m.drafts {
				d.ignored = false
				m.drafts[k] = d
			}
		case "v":
			m.scope = (m.scope + 1) % 3
			m.index = 0
			m.offset = 0
		case "/":
			m.inputMode = "filter"
			m.input.SetValue(m.filter)
			return m, m.input.Focus()
		case "p":
			if g, ok := m.selected(); !ok || g.Host == "" {
				m.notice = "Select an observed hostname or IP first."
				return m, nil
			}
			m.inputMode = "policy"
			m.input.SetValue("")
			m.notice = "Available policies: " + strings.Join(m.policies, ", ")
			return m, m.input.Focus()
		case "e":
			if g, ok := m.selected(); ok && g.Host != "" {
				m.inputMode = "host"
				m.input.SetValue(m.drafts[g.Key].host)
				return m, m.input.Focus()
			}
		case "s":
			for _, k := range m.draftKeys() {
				d := m.drafts[k]
				if _, err := ruleobserve.Candidate(d.host, "DIRECT", !d.suffix); err != nil {
					m.notice = core.Sanitize(err.Error())
					return m, nil
				}
			}
			for _, k := range m.draftKeys() {
				d := m.drafts[k]
				d.suffix = !d.suffix
				m.drafts[k] = d
			}
			m.notice = "Suffix scope includes subdomains; review the proposed rule before applying."
		case "a":
			return m, m.prepare()
		case "r":
			return m, m.Init()
		case "w":
			if m.opts.Save != nil {
				snapshot := m.opts.Snapshot
				return m, m.operation("save", func(ctx context.Context, msg *ruleReviewMsg) { msg.saved, msg.err = m.opts.Save(ctx, snapshot) })
			}
		}
	}
	if m.inputMode != "" {
		return m, m.updateInput(message)
	}
	return m, nil
}

func (m *ruleReview) updateInput(message tea.Msg) tea.Cmd {
	before := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(message)
	if m.inputMode == "filter" && m.input.Value() != before {
		m.filter = m.input.Value()
		m.index, m.offset = 0, 0
	}
	return cmd
}
func (m *ruleReview) detail(g ruleobserve.Group) string {
	d := m.drafts[g.Key]
	b, _ := json.MarshalIndent(g, "", "  ")
	rule := "Assign a policy with p."
	if d.policy != "" {
		if v, err := ruleobserve.Candidate(d.host, d.policy, d.suffix); err == nil {
			rule = v
		} else {
			rule = err.Error()
		}
	}
	if g.Host == "" {
		rule = "No verified destination; inspection only."
	}
	return "Candidate: " + rule + "\n\nObserved evidence (counts are log records):\n" + string(b)
}
func (m *ruleReview) View() tea.View {
	w, h := max(1, m.width), max(1, m.height)
	s := m.opts.Snapshot
	lines := []string{fit("Review observed connection logs · "+core.Sanitize(s.TargetID), w), fit(fmt.Sprintf("%s · %s → %s · logs %d · gaps %d · dropped %d · unparsed %d", s.Mode, s.StartedAt.Format("15:04:05"), s.UpdatedAt.Format("15:04:05"), s.Observed, s.Gaps, s.Dropped, s.Unparsed), w)}
	bodyHeight := max(0, h-5)
	foot := "↑↓/jk select · Space mark · p policy · a preview · ? help · Esc back"
	if m.help {
		body := "Observed connection review\n\nv cycles anomalies / observed MATCH connections / all. A successful dial does not establish application health. No logs means no evidence, not complete rule coverage.\n\nSpace selects a domain; p assigns an existing policy to marked rows (or the current row). s explicitly toggles DOMAIN-SUFFIX; e edits the hostname. IP-only candidates use /32 or /128,no-resolve. No policy is guessed from a failure.\n\n/ searches as you type; Enter accepts and Esc clears the filter. Tab or h/l switches list/details; j/k scrolls the focused pane. i ignores selected rows, u restores ignored rows. w saves this observation snapshot; r reloads available policies.\n\na validates the complete ordered batch and shows its source diff. y applies only from a ready preview; Enter/Esc returns without applying. Esc cancels preview and keeps selections. During apply, Esc requests cancellation and waits for its actual result.\n\nOrdinary observation covers only the time this target is connected in lazyclash. Gaps, truncation and unsupported log formats remain visible."
		lines = append(lines, configSyncText(body, w, bodyHeight, m.offset)...)
		foot = "↑↓/jk scroll · ? / Esc close help"
	} else if m.phase != "list" {
		lines = append(lines, configSyncText(m.body, w, bodyHeight, m.offset)...)
		foot = "↑↓/jk scroll · Enter / Esc back"
		if m.canApply() {
			foot = "y Apply reviewed batch · Enter / Esc back · ↑↓ scroll"
		}
	} else {
		rows := m.rows()
		var body []string
		leftW := w
		if w >= 88 {
			leftW = w * 45 / 100
		}
		start := max(0, m.index-max(0, (bodyHeight-2)/2))
		for i := start; i < len(rows) && len(body) < bodyHeight; i++ {
			g := rows[i]
			d := m.drafts[g.Key]
			mark := "[ ]"
			if d.checked {
				mark = "[x]"
			}
			cursor := "  "
			if i == m.index {
				cursor = "> "
			}
			host := g.Host
			if host == "" {
				host = "Other / unparsed warnings"
			}
			body = append(body, fit(fmt.Sprintf("%s%s %s · anomalies %d", cursor, mark, core.Sanitize(host), g.ErrorCount+g.OtherCount), leftW))
		}
		if len(rows) == 0 {
			body = append(body, fit("No matching observations. v changes view; / filters.", leftW))
		}
		detail := "Select a row to inspect its evidence."
		if g, ok := m.selected(); ok {
			detail = m.detail(g)
		}
		if w < 88 && m.focus == 1 {
			body = configSyncText(detail, w, bodyHeight, m.offset)
		} else {
			body = fitLines(strings.Join(body, "\n"), leftW, bodyHeight)
			if w >= 88 {
				right := configSyncText(detail, w-leftW-3, bodyHeight, m.offset)
				for i := range body {
					body[i] += " │ " + right[i]
				}
			}
		}
		lines = append(lines, body...)
	}
	notice := m.notice
	if m.opts.BlockedReason != "" {
		notice = m.opts.BlockedReason
	} else if m.opts.ReadOnly {
		notice = "Read-only · " + notice
	}
	if m.pending {
		notice = "Working · " + notice
	} else if m.policyLoading {
		notice = "Loading policies · " + notice
	}
	lines = append(lines, fit(core.Sanitize(notice), w))
	if m.inputMode != "" {
		lines = append(lines, fit(m.inputMode+": "+m.input.View(), w))
		foot = "Enter accept · Esc cancel · type to edit"
		if m.inputMode == "filter" {
			foot = "Enter accept filter · Esc clear · type to filter"
		}
	} else {
		lines = append(lines, fit("View: "+[]string{"anomalies", "observed MATCH connections", "all"}[m.scope]+" · Focus: "+[]string{"list", "details"}[m.focus]+" · v change · Tab focus · w save", w))
	}
	lines = append(lines, fit(foot, w))
	if len(lines) > h {
		lines = lines[:h]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	return v
}

var _ tea.Model = (*ruleReview)(nil)
