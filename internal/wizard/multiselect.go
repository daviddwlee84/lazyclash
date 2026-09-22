package wizard

import (
	"context"
	"fmt"
	"io"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

type MultiSpec struct {
	Title, Description string
	Choices            []Choice
	Selected           []string
	AllowEmpty, Back   bool
}

func MultiChoose(ctx context.Context, spec MultiSpec, in io.Reader, out io.Writer) ([]string, error) {
	m := newMultiPicker(spec)
	result, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	m = result.(*multiPicker)
	if m.back {
		return m.values(), ErrBack
	}
	if !m.submitted {
		return m.values(), ErrCanceled
	}
	return m.values(), nil
}

type multiPicker struct {
	spec                    MultiSpec
	checked                 map[string]bool
	query                   textinput.Model
	search, submitted, back bool
	index, width, height    int
	err                     string
}

func newMultiPicker(spec MultiSpec) *multiPicker {
	m := &multiPicker{spec: spec, checked: map[string]bool{}, width: 80, height: 24}
	m.query = textinput.New()
	m.query.Prompt = "Find: "
	for _, value := range spec.Selected {
		m.checked[value] = true
	}
	return m
}
func (m *multiPicker) Init() tea.Cmd { return nil }
func (m *multiPicker) rows() []Choice {
	var rows []Choice
	for _, c := range m.spec.Choices {
		if strings.Contains(strings.ToLower(c.Label+" "+c.Value), strings.ToLower(m.query.Value())) {
			rows = append(rows, c)
		}
	}
	return rows
}
func (m *multiPicker) values() []string {
	var result []string
	for _, c := range m.spec.Choices {
		if m.checked[c.Value] {
			result = append(result, c.Value)
		}
	}
	return result
}
func (m *multiPicker) submit() tea.Cmd {
	if len(m.rows()) == 0 && m.query.Value() != "" {
		m.err = "No matches; clear the filter before continuing"
		return nil
	}
	if !m.spec.AllowEmpty && len(m.values()) == 0 {
		m.err = "Select at least one item with Space"
		return nil
	}
	m.submitted = true
	return tea.Quit
}
func (m *multiPicker) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.query.SetWidth(max(1, m.width-8))
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
			case "up", "down":
				delta := 1
				if key == "up" {
					delta = -1
				}
				m.index = max(0, min(m.index+delta, len(m.rows())-1))
				return m, nil
			}
			old := m.query.Value()
			var cmd tea.Cmd
			m.query, cmd = m.query.Update(msg)
			if old != m.query.Value() {
				m.index = 0
			}
			return m, cmd
		}
		switch key {
		case "esc":
			m.back = m.spec.Back
			return m, tea.Quit
		case "enter", "ctrl+s":
			return m, m.submit()
		case "/":
			m.search = true
			return m, m.query.Focus()
		case "up", "k":
			m.index = max(0, m.index-1)
		case "down", "j":
			m.index = min(max(0, len(m.rows())-1), m.index+1)
		case "home":
			m.index = 0
		case "end", "G":
			m.index = max(0, len(m.rows())-1)
		case "space":
			rows := m.rows()
			if len(rows) > 0 {
				value := rows[min(m.index, len(rows)-1)].Value
				m.checked[value] = !m.checked[value]
				m.err = ""
			}
		}
	}
	return m, nil
}
func (m *multiPicker) View() tea.View {
	rows := m.rows()
	count := max(1, m.height-7)
	start := max(0, min(m.index-count/2, len(rows)-count))
	lines := []string{clean(m.spec.Title), clean(m.spec.Description), fmt.Sprintf("%d selected · %d matching", len(m.values()), len(rows))}
	if m.search {
		lines = append(lines, m.query.View())
	} else {
		lines = append(lines, "Filter: "+clean(m.query.Value()))
	}
	for i := start; i < min(len(rows), start+count); i++ {
		mark := "[ ]"
		if m.checked[rows[i].Value] {
			mark = "[x]"
		}
		cursor := "  "
		if i == m.index {
			cursor = "> "
		}
		lines = append(lines, cursor+mark+" "+clean(rows[i].Label))
	}
	if len(rows) == 0 {
		lines = append(lines, "No matching choices")
	}
	lines = append(lines, clean(m.err))
	back := "cancel"
	if m.spec.Back {
		back = "back"
	}
	lines = append(lines, "↑↓/j/k move · Space toggle · / search · Enter next · Esc "+back+" · Ctrl+C cancel")
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], m.width, "")
	}
	if len(lines) > m.height {
		lines = lines[:m.height]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	return v
}
