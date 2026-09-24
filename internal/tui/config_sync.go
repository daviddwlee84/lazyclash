package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
)

// ConfigSync values contain display-only, masked data. Raw configurations and
// credentials stay inside the service adapter supplied by the caller.
type ConfigSyncTarget struct{ ID, Label string }
type ConfigSyncItem struct {
	ID, Category, Label, Action, MaskedDetail, DisabledReason string
	Kind                                                      string
}
type ConfigSyncGroup struct{ Name string }
type ConfigSyncCatalog struct {
	TargetID, Owner, Summary string
	Items                    []ConfigSyncItem
	Groups                   []ConfigSyncGroup
}
type ConfigSyncSelection struct {
	ID      string
	Replace bool
}
type ConfigSyncTargetDraft struct {
	Selections              []ConfigSyncSelection
	Dependencies            map[string]string
	AttachGroups            map[string][]string
	RulePlacement           string
	AllowVergeRulesOverride bool
}
type ConfigSyncDraft map[string]ConfigSyncTargetDraft
type ConfigSyncDecision struct {
	ID, TargetID, Label, MaskedDetail string
}
type ConfigSyncPreviewTarget struct{ TargetID, Summary, MaskedDiff string }
type ConfigSyncPreview struct {
	Digest, Summary string
	Targets         []ConfigSyncPreviewTarget
	Decisions       []ConfigSyncDecision
	Ready           bool
}
type ConfigSyncOutcome struct {
	Title, Summary string
	Result         any
}
type ConfigSyncOptions struct {
	SourceLabel string
	Targets     []ConfigSyncTarget
	Initial     ConfigSyncDraft
	ReadOnly    bool
	Load        func(context.Context, string) (ConfigSyncCatalog, error)
	Preview     func(context.Context, ConfigSyncDraft) (ConfigSyncPreview, error)
	Apply       func(context.Context, ConfigSyncDraft, string) (ConfigSyncOutcome, error)
}

// RunConfigSync owns a single terminal reader. Dashboard callers must use the
// existing tea.Exec handoff before invoking this standalone selector.
func RunConfigSync(ctx context.Context, opts ConfigSyncOptions, in io.Reader, out io.Writer) (ConfigSyncOutcome, error) {
	if len(opts.Targets) == 0 || opts.Load == nil || opts.Preview == nil || opts.Apply == nil {
		return ConfigSyncOutcome{}, errors.New("configuration sync selector requires targets and service callbacks")
	}
	m := newConfigSync(ctx, opts)
	defer m.cancelOperation()
	result, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return ConfigSyncOutcome{}, ctx.Err()
	}
	if err != nil {
		return ConfigSyncOutcome{}, err
	}
	final := result.(*configSyncModel)
	if !final.finished {
		return final.outcome, wizard.ErrCanceled
	}
	return final.outcome, final.resultErr
}

type configSyncMsg struct {
	id      uint64
	kind    string
	target  string
	catalog ConfigSyncCatalog
	preview ConfigSyncPreview
	outcome ConfigSyncOutcome
	err     error
}
type configSyncModel struct {
	ctx                      context.Context
	opts                     ConfigSyncOptions
	draft                    ConfigSyncDraft
	catalogs                 map[string]ConfigSyncCatalog
	phase, pending, message  string
	target, index, offset    int
	focus, option, decision  int
	choice, reviewTarget     int
	width, height            int
	query                    textinput.Model
	search, accept, finished bool
	help                     bool
	helpOffset               int
	preview                  ConfigSyncPreview
	reviewDraft              ConfigSyncDraft
	outcome                  ConfigSyncOutcome
	resultErr                error
	attachProxy              string
	groupIndex               int
	serial                   uint64
	cancel                   context.CancelFunc
}

func newConfigSync(ctx context.Context, opts ConfigSyncOptions) *configSyncModel {
	query := textinput.New()
	query.Prompt = "Filter: "
	query.CharLimit = 256
	m := &configSyncModel{ctx: ctx, opts: opts, draft: cloneConfigSyncDraft(opts.Initial), catalogs: map[string]ConfigSyncCatalog{}, phase: "select", width: 100, height: 28, query: query}
	for _, target := range opts.Targets {
		d := m.draft[target.ID]
		if d.RulePlacement == "" {
			d.RulePlacement = "anchored"
		}
		if d.Dependencies == nil {
			d.Dependencies = map[string]string{}
		}
		if d.AttachGroups == nil {
			d.AttachGroups = map[string][]string{}
		}
		m.draft[target.ID] = d
	}
	return m
}

func cloneConfigSyncDraft(src ConfigSyncDraft) ConfigSyncDraft {
	out := ConfigSyncDraft{}
	for id, draft := range src {
		draft.Selections = append([]ConfigSyncSelection(nil), draft.Selections...)
		choices := map[string]string{}
		for key, value := range draft.Dependencies {
			choices[key] = value
		}
		draft.Dependencies = choices
		attachments := map[string][]string{}
		for key, names := range draft.AttachGroups {
			attachments[key] = append([]string(nil), names...)
		}
		draft.AttachGroups = attachments
		out[id] = draft
	}
	return out
}

func (m *configSyncModel) targetID() string { return m.opts.Targets[m.target].ID }
func (m *configSyncModel) Init() tea.Cmd    { return m.load() }
func (m *configSyncModel) cancelOperation() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}
func (m *configSyncModel) operation(kind string) (context.Context, uint64) {
	m.cancelOperation()
	m.serial++
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel, m.pending = cancel, kind
	return ctx, m.serial
}
func (m *configSyncModel) load() tea.Cmd {
	ctx, id := m.operation("load")
	target, load := m.targetID(), m.opts.Load
	m.message = "Reading source and destination configuration…"
	return func() tea.Msg {
		catalog, err := load(ctx, target)
		return configSyncMsg{id: id, kind: "load", target: target, catalog: catalog, err: err}
	}
}
func (m *configSyncModel) selectedCount() int {
	count := 0
	for _, draft := range m.draft {
		count += len(draft.Selections)
	}
	return count
}
func (m *configSyncModel) prepare() tea.Cmd {
	if m.phase == "select" && m.query.Value() != "" && len(m.rows()) == 0 {
		m.message = "No matching objects. Clear the filter before previewing retained selections."
		return nil
	}
	if m.selectedCount() == 0 {
		m.message = "Select at least one whole object or rule with Space."
		return nil
	}
	ctx, id := m.operation("preview")
	draft, preview := cloneConfigSyncDraft(m.draft), m.opts.Preview
	m.phase, m.message = "previewing", "Checking selected objects, dependencies, resources and rule order…"
	return func() tea.Msg {
		plan, err := preview(ctx, draft)
		return configSyncMsg{id: id, kind: "preview", preview: plan, err: err}
	}
}
func (m *configSyncModel) apply() tea.Cmd {
	if !m.preview.Ready || m.opts.ReadOnly || m.preview.Digest == "" || m.pending != "" {
		return nil
	}
	ctx, id := m.operation("apply")
	draft, digest, apply := cloneConfigSyncDraft(m.reviewDraft), m.preview.Digest, m.opts.Apply
	m.phase, m.message = "applying", "Applying the reviewed plan. Esc requests cancellation; completed writes remain applied."
	return func() tea.Msg {
		outcome, err := apply(ctx, draft, digest)
		return configSyncMsg{id: id, kind: "apply", outcome: outcome, err: err}
	}
}
func (m *configSyncModel) receive(msg configSyncMsg) {
	if msg.id != m.serial || msg.kind != m.pending {
		return
	}
	m.cancelOperation()
	m.pending, m.message = "", ""
	if msg.err != nil {
		m.message = "Failed: " + safeError(msg.err)
	}
	switch msg.kind {
	case "load":
		if msg.target != m.targetID() {
			return
		}
		if msg.err == nil || len(msg.catalog.Items) > 0 {
			m.catalogs[msg.target] = msg.catalog
		}
		m.index = min(m.index, max(0, len(m.rows())-1))
	case "preview":
		m.preview, m.reviewDraft = msg.preview, cloneConfigSyncDraft(m.draft)
		m.phase, m.offset, m.accept, m.reviewTarget, m.focus = "review", 0, false, 0, 0
		if msg.err != nil {
			m.preview.Ready = false
		}
		if len(msg.preview.Decisions) > 0 {
			m.phase, m.decision = "decisions", 0
		}
	case "apply":
		m.outcome, m.resultErr = msg.outcome, msg.err
		m.phase, m.offset = "result", 0
	}
}

func (m *configSyncModel) rows() []ConfigSyncItem {
	items := m.catalogs[m.targetID()].Items
	query := strings.ToLower(m.query.Value())
	var rows []ConfigSyncItem
	for _, item := range items {
		if query == "" || strings.Contains(strings.ToLower(item.Category+" "+item.Label), query) {
			rows = append(rows, item)
		}
	}
	return rows
}
func (m *configSyncModel) toggle() {
	rows := m.rows()
	if len(rows) == 0 {
		return
	}
	item := rows[min(m.index, len(rows)-1)]
	d := m.draft[m.targetID()]
	for i, selected := range d.Selections {
		if selected.ID == item.ID {
			d.Selections = append(d.Selections[:i:i], d.Selections[i+1:]...)
			delete(d.AttachGroups, item.ID)
			m.draft[m.targetID()], m.message = d, ""
			return
		}
	}
	if item.DisabledReason != "" {
		m.message = item.DisabledReason
		return
	}
	d.Selections = append(d.Selections, ConfigSyncSelection{ID: item.ID, Replace: item.Action == "replace"})
	m.draft[m.targetID()], m.message = d, "Selected "+item.Action+": "+item.Label
}
func (m *configSyncModel) moveTarget(delta int) tea.Cmd {
	m.target = (m.target + len(m.opts.Targets) + delta) % len(m.opts.Targets)
	m.index, m.offset, m.focus = 0, 0, 0
	m.query.SetValue("")
	return m.load()
}
func (m *configSyncModel) back() tea.Cmd {
	if m.phase == "applying" {
		m.cancelOperation()
		m.message = "Cancellation requested. Waiting for the result; writes may already have applied."
		return nil
	}
	wasPending := m.pending
	m.cancelOperation()
	m.serial++
	m.pending = ""
	switch m.phase {
	case "select":
		return tea.Quit
	case "choice":
		m.phase = "decisions"
	case "result":
		m.finished = true
		return tea.Quit
	default:
		m.phase, m.offset, m.focus = "select", 0, 0
		if wasPending == "preview" {
			m.message = "Preview canceled; selections retained."
		}
	}
	return nil
}

func (m *configSyncModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.query.SetWidth(max(1, m.width-10))
	case configSyncMsg:
		m.receive(msg)
	case tea.PasteMsg:
		if m.search {
			var cmd tea.Cmd
			m.query, cmd = m.query.Update(msg)
			m.index = 0
			return m, cmd
		}
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" {
			if m.phase == "applying" {
				return m, m.back()
			}
			m.cancelOperation()
			return m, tea.Quit
		}
		if m.search {
			switch key {
			case "esc":
				m.search = false
				m.query.Blur()
				m.query.SetValue("")
				m.index = 0
				return m, nil
			case "enter":
				m.search = false
				m.query.Blur()
				return m, nil
			}
			var cmd tea.Cmd
			before := m.query.Value()
			m.query, cmd = m.query.Update(msg)
			if before != m.query.Value() {
				m.index = 0
			}
			return m, cmd
		}
		if m.help {
			switch key {
			case "esc", "q", "?":
				m.help = false
			case "up", "k":
				m.helpOffset = max(0, m.helpOffset-1)
			case "down", "j":
				m.helpOffset++
			}
			return m, nil
		}
		if key == "?" && m.pending == "" {
			m.help = true
			m.helpOffset = 0
			return m, nil
		}
		if key == "esc" || key == "q" {
			return m, m.back()
		}
		switch m.phase {
		case "select":
			switch key {
			case "up", "k":
				if m.focus == 0 {
					m.index = max(0, m.index-1)
					m.offset = 0
				} else {
					m.offset = max(0, m.offset-1)
				}
			case "down", "j":
				if m.focus == 0 {
					m.index = min(max(0, len(m.rows())-1), m.index+1)
					m.offset = 0
				} else {
					m.offset++
				}
			case "tab", "shift+tab":
				m.focus = 1 - m.focus
			case "home":
				m.index, m.offset = 0, 0
			case "g":
				rows := m.rows()
				if len(rows) > 0 {
					item := rows[min(m.index, len(rows)-1)]
					if item.Kind != "proxy" || !m.selected(item.ID) {
						m.message = "Select a proxy with Space before attaching destination groups."
					} else {
						m.attachProxy, m.groupIndex, m.phase = item.ID, 0, "groups"
					}
				}
			case "end", "G":
				m.index = max(0, len(m.rows())-1)
			case "pgup":
				m.offset = max(0, m.offset-10)
			case "pgdown":
				m.offset += 10
			case "left", "h":
				return m, m.moveTarget(-1)
			case "right", "l":
				return m, m.moveTarget(1)
			case "space", " ":
				m.toggle()
			case "/":
				m.search = true
				m.focus = 0
				return m, m.query.Focus()
			case "r":
				return m, m.load()
			case "c":
				d := m.draft[m.targetID()]
				d.Selections = nil
				d.Dependencies = map[string]string{}
				d.AttachGroups = map[string][]string{}
				m.draft[m.targetID()] = d
			case "o":
				m.phase, m.option = "options", 0
			case "p", "enter":
				return m, m.prepare()
			}
		case "options":
			switch key {
			case "up", "down", "j", "k", "tab", "shift+tab":
				m.option = 1 - m.option
			case "space", " ", "enter", "left", "right", "h", "l":
				d := m.draft[m.targetID()]
				if m.option == 0 {
					if d.RulePlacement == "prepend" {
						d.RulePlacement = "anchored"
					} else {
						d.RulePlacement = "prepend"
					}
				} else {
					d.AllowVergeRulesOverride = !d.AllowVergeRulesOverride
				}
				m.draft[m.targetID()] = d
			}
		case "groups":
			groups := m.catalogs[m.targetID()].Groups
			switch key {
			case "up", "k":
				m.groupIndex = max(0, m.groupIndex-1)
			case "down", "j":
				m.groupIndex = min(max(0, len(groups)-1), m.groupIndex+1)
			case "enter":
				m.phase = "select"
			case "space", " ":
				if len(groups) > 0 {
					d := m.draft[m.targetID()]
					names := d.AttachGroups[m.attachProxy]
					name := groups[m.groupIndex].Name
					found := false
					for i, v := range names {
						if v == name {
							names = append(names[:i:i], names[i+1:]...)
							found = true
							break
						}
					}
					if !found {
						names = append(names, name)
					}
					if d.AttachGroups == nil {
						d.AttachGroups = map[string][]string{}
					}
					d.AttachGroups[m.attachProxy] = names
					m.draft[m.targetID()] = d
				}
			}
		case "decisions":
			switch key {
			case "up", "k":
				if m.focus == 1 {
					m.offset = max(0, m.offset-1)
				} else {
					m.decision = max(0, m.decision-1)
					m.offset = 0
				}
			case "down", "j":
				if m.focus == 1 {
					m.offset++
				} else {
					m.decision = min(len(m.preview.Decisions)-1, m.decision+1)
					m.offset = 0
				}
			case "tab", "shift+tab":
				m.focus = 1 - m.focus
			case "pgup":
				m.offset = max(0, m.offset-10)
			case "pgdown":
				m.offset += 10
			case "enter", "space", " ":
				m.phase, m.choice, m.offset = "choice", 0, 0
			case "p":
				return m, m.prepare()
			case "e":
				m.phase = "select"
			}
		case "choice":
			switch key {
			case "up", "k":
				m.choice = max(0, m.choice-1)
			case "down", "j":
				m.choice = min(2, m.choice+1)
			case "pgup":
				m.offset = max(0, m.offset-10)
			case "pgdown":
				m.offset += 10
			case "enter":
				decision := m.preview.Decisions[m.decision]
				d := m.draft[decision.TargetID]
				if d.Dependencies == nil {
					d.Dependencies = map[string]string{}
				}
				d.Dependencies[decision.ID] = []string{"", "reuse", "replace"}[m.choice]
				m.draft[decision.TargetID], m.phase = d, "decisions"
			}
		case "review":
			switch key {
			case "up", "k":
				m.offset = max(0, m.offset-1)
			case "down", "j":
				m.offset++
			case "pgup":
				m.offset = max(0, m.offset-10)
			case "pgdown":
				m.offset += 10
			case "left", "h":
				m.reviewTarget = max(0, m.reviewTarget-1)
				m.offset = 0
			case "right", "l":
				m.reviewTarget = min(max(0, len(m.preview.Targets)-1), m.reviewTarget+1)
				m.offset = 0
			case "tab", "shift+tab":
				if m.preview.Ready && !m.opts.ReadOnly {
					m.accept = !m.accept
				}
			case "enter":
				if m.accept {
					return m, m.apply()
				}
				return m, m.back()
			case "e":
				return m, m.back()
			case "p":
				return m, m.prepare()
			}
		case "result":
			switch key {
			case "up", "k":
				m.offset = max(0, m.offset-1)
			case "down", "j":
				m.offset++
			case "e":
				m.phase, m.offset, m.accept = "select", 0, false
			case "enter":
				m.finished = true
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m *configSyncModel) selectionSummary() string {
	var parts []string
	for _, target := range m.opts.Targets {
		parts = append(parts, fmt.Sprintf("%s: %d", target.Label, len(m.draft[target.ID].Selections)))
	}
	return strings.Join(parts, " · ")
}
