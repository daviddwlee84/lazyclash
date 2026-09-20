// Package wizard provides terminal forms shared by CLI commands and dashboard
// handoffs. Forms collect drafts; callers own domain validation and execution.
package wizard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

type Kind uint8

const (
	Text Kind = iota
	Secret
	Multiline
	Select
	Toggle
)

type Choice struct{ Value, Label string }
type Field struct {
	Key, Label, Value, Help string
	Kind                    Kind
	Options                 []Choice
	Required                bool
}
type Spec struct {
	Title, Description, SubmitLabel string
	Fields                          []Field
}

var ErrCanceled = errors.New("wizard canceled")

func Edit(ctx context.Context, spec Spec, in io.Reader, out io.Writer) (map[string]string, error) {
	if len(spec.Fields) == 0 {
		return nil, errors.New("wizard has no fields")
	}
	m := newForm(spec)
	seen := map[string]bool{}
	for _, f := range m.spec.Fields {
		if f.Key == "" || seen[f.Key] {
			return nil, errors.New("wizard fields require distinct keys")
		}
		seen[f.Key] = true
		if f.Kind == Select && len(f.Options) == 0 {
			return nil, errors.New("wizard selection has no choices")
		}
	}
	result, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	form := result.(*form)
	if !form.submitted {
		return nil, ErrCanceled
	}
	return form.values(), nil
}

func Choose(ctx context.Context, title string, choices []Choice, in io.Reader, out io.Writer) (string, error) {
	values, err := Edit(ctx, Spec{Title: title, SubmitLabel: "Select", Fields: []Field{{Key: "choice", Label: "Selection", Kind: Select, Options: choices, Required: true}}}, in, out)
	return values["choice"], err
}

func Confirm(ctx context.Context, title, body string, in io.Reader, out io.Writer) (bool, error) {
	m := &review{title: title, body: body, width: 80, height: 24}
	result, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		return false, err
	}
	return result.(*review).accepted, nil
}

// Pause keeps a terminal handoff's printed result visible before the dashboard
// reacquires the terminal. It doesn't enter the alternate screen or parse input
// outside Bubble Tea's cancellable terminal reader.
func Pause(ctx context.Context, message string, in io.Reader, out io.Writer) error {
	_, err := tea.NewProgram(pause{message: message}, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type pause struct{ message string }

func (p pause) Init() tea.Cmd { return nil }
func (p pause) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "enter", "esc", "ctrl+c":
			return p, tea.Quit
		}
	}
	return p, nil
}
func (p pause) View() tea.View { return tea.NewView(clean(p.message) + " · Enter / Esc to return") }

type hit struct{ x, y, width, index int }
type form struct {
	spec          Spec
	inputs        []textinput.Model
	areas         []textarea.Model
	index         int
	width, height int
	err           string
	submitted     bool
	searching     bool
	search        textinput.Model
	pressed       int
}

func newForm(spec Spec) *form {
	// Own the draft, including slices, so cancellation cannot mutate a caller.
	spec.Fields = append([]Field(nil), spec.Fields...)
	m := &form{spec: spec, width: 80, height: 24, pressed: -2}
	m.search = textinput.New()
	m.search.Prompt = "Find: "
	for i := range m.spec.Fields {
		f := &m.spec.Fields[i]
		f.Options = append([]Choice(nil), f.Options...)
		if f.Kind == Toggle && len(f.Options) == 0 {
			f.Options = []Choice{{"false", "Off"}, {"true", "On"}}
		}
		if len(f.Options) > 0 && f.Value == "" {
			f.Value = f.Options[0].Value
		}
		input := textinput.New()
		input.Prompt = "> "
		input.CharLimit = 65536
		input.SetValue(f.Value)
		if f.Kind == Secret {
			input.EchoMode = textinput.EchoPassword
			input.EchoCharacter = '•'
		}
		area := textarea.New()
		area.SetValue(f.Value)
		area.CharLimit = 1 << 20
		area.SetHeight(6)
		m.inputs = append(m.inputs, input)
		m.areas = append(m.areas, area)
	}
	return m
}

func (m *form) Init() tea.Cmd { return m.focus(0) }
func (m *form) sync() {
	if m.index >= len(m.spec.Fields) {
		return
	}
	f := &m.spec.Fields[m.index]
	if f.Kind == Multiline {
		f.Value = m.areas[m.index].Value()
	} else if f.Kind == Text || f.Kind == Secret {
		f.Value = m.inputs[m.index].Value()
	}
}
func (m *form) values() map[string]string {
	m.sync()
	values := map[string]string{}
	for _, field := range m.spec.Fields {
		values[field.Key] = field.Value
	}
	return values
}
func (m *form) focus(index int) tea.Cmd {
	m.sync()
	for i := range m.inputs {
		m.inputs[i].Blur()
		m.areas[i].Blur()
	}
	m.search.Blur()
	m.searching = false
	m.search.SetValue("")
	m.index = max(0, min(index, len(m.spec.Fields)))
	if m.index == len(m.spec.Fields) {
		return nil
	}
	m.inputs[m.index].SetWidth(max(1, m.width-6))
	m.areas[m.index].SetWidth(max(1, m.width-4))
	m.areas[m.index].SetHeight(max(1, min(7, m.height-10)))
	if m.spec.Fields[m.index].Kind == Multiline {
		return m.areas[m.index].Focus()
	}
	if m.spec.Fields[m.index].Kind == Text || m.spec.Fields[m.index].Kind == Secret {
		return m.inputs[m.index].Focus()
	}
	return nil
}
func (m *form) submit() tea.Cmd {
	m.sync()
	if m.searching && len(m.choices()) == 0 {
		m.err = "No matching choices; clear the search before selecting"
		return nil
	}
	for i, field := range m.spec.Fields {
		if field.Required && strings.TrimSpace(field.Value) == "" {
			m.err = clean(field.Label) + " is required"
			return m.focus(i)
		}
		if field.Kind == Select || field.Kind == Toggle {
			valid := false
			for _, c := range field.Options {
				valid = valid || c.Value == field.Value
			}
			if !valid {
				m.err = "Choose a value for " + clean(field.Label)
				return m.focus(i)
			}
		}
	}
	m.submitted = true
	return tea.Quit
}
func (m *form) choices() []Choice {
	if m.index >= len(m.spec.Fields) {
		return nil
	}
	var choices []Choice
	query := strings.ToLower(m.search.Value())
	for _, choice := range m.spec.Fields[m.index].Options {
		if strings.Contains(strings.ToLower(choice.Label+" "+choice.Value), query) {
			choices = append(choices, choice)
		}
	}
	return choices
}
func (m *form) moveChoice(delta int) {
	choices := m.choices()
	if len(choices) == 0 {
		return
	}
	f := &m.spec.Fields[m.index]
	index := 0
	for i, choice := range choices {
		if choice.Value == f.Value {
			index = i
		}
	}
	f.Value = choices[max(0, min(index+delta, len(choices)-1))].Value
}

func (m *form) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.pressed = -2
		for i := range m.inputs {
			m.inputs[i].SetWidth(max(1, m.width-6))
			m.areas[i].SetWidth(max(1, m.width-4))
			m.areas[i].SetHeight(max(1, min(7, m.height-10)))
		}
		return m, nil
	case tea.MouseClickMsg:
		if msg.Mouse().Button == tea.MouseLeft {
			m.pressed = m.hit(msg.Mouse().X, msg.Mouse().Y)
		}
		return m, nil
	case tea.MouseReleaseMsg:
		i := m.hit(msg.Mouse().X, msg.Mouse().Y)
		pressed := m.pressed
		m.pressed = -2
		if i != pressed || i == -2 || msg.Mouse().Button != tea.MouseLeft {
			return m, nil
		}
		if i == -1 {
			return m, m.submit()
		}
		if i == -3 {
			return m, tea.Quit
		}
		if i >= 100000 {
			choices := m.choices()
			if index := i - 100000; index < len(choices) {
				m.spec.Fields[m.index].Value = choices[index].Value
			}
			return m, nil
		}
		return m, m.focus(i)
	case tea.KeyPressMsg:
		m.pressed = -2
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.searching {
				m.searching = false
				m.search.Blur()
				m.search.SetValue("")
				return m, nil
			}
			return m, tea.Quit
		case "ctrl+s":
			return m, m.submit()
		case "tab":
			return m, m.focus((m.index + 1) % (len(m.spec.Fields) + 1))
		case "shift+tab":
			return m, m.focus((m.index + len(m.spec.Fields)) % (len(m.spec.Fields) + 1))
		}
		if m.index == len(m.spec.Fields) {
			if msg.String() == "enter" {
				return m, m.submit()
			}
			return m, nil
		}
		f := &m.spec.Fields[m.index]
		if f.Kind == Select || f.Kind == Toggle {
			switch msg.String() {
			case "up", "down":
				if msg.String() == "up" {
					m.moveChoice(-1)
				} else {
					m.moveChoice(1)
				}
				return m, nil
			case "enter":
				if m.searching {
					if len(m.choices()) == 0 {
						m.err = "No matching choices"
						return m, nil
					}
					m.searching = false
					m.search.Blur()
					m.search.SetValue("")
					return m, nil
				}
				if len(m.spec.Fields) == 1 {
					return m, m.submit()
				}
				return m, m.focus(m.index + 1)
			}
			if !m.searching {
				switch msg.String() {
				case "k", "left", "h":
					m.moveChoice(-1)
				case "j", "right", "l", "space":
					m.moveChoice(1)
				case "/":
					m.searching = true
					return m, m.search.Focus()
				}
				return m, nil
			}
		} else if msg.String() == "enter" && f.Kind != Multiline {
			return m, m.focus(m.index + 1)
		}
	}
	var cmd tea.Cmd
	if m.searching {
		m.search, cmd = m.search.Update(msg)
		choices := m.choices()
		if len(choices) > 0 {
			found := false
			for _, c := range choices {
				found = found || c.Value == m.spec.Fields[m.index].Value
			}
			if !found {
				m.spec.Fields[m.index].Value = choices[0].Value
			}
		}
	} else if m.index < len(m.spec.Fields) {
		if m.spec.Fields[m.index].Kind == Multiline {
			m.areas[m.index], cmd = m.areas[m.index].Update(msg)
		} else if m.spec.Fields[m.index].Kind == Text || m.spec.Fields[m.index].Kind == Secret {
			m.inputs[m.index], cmd = m.inputs[m.index].Update(msg)
		}
	}
	return m, cmd
}

func (m *form) layout() ([]string, []hit) {
	lines := []string{clean(m.spec.Title), clean(m.spec.Description), ""}
	var hits []hit
	count := max(1, min(len(m.spec.Fields), m.height/3))
	start := max(0, min(m.index-count/2, len(m.spec.Fields)-count))
	for i := start; i < start+count; i++ {
		f := m.spec.Fields[i]
		value := f.Value
		if i == m.index && (f.Kind == Text || f.Kind == Secret) {
			value = m.inputs[i].Value()
		}
		if f.Kind == Secret && value != "" {
			value = "••••••••"
		}
		if f.Kind == Multiline {
			value = "(multiline draft)"
		}
		for _, c := range f.Options {
			if c.Value == value {
				value = c.Label
			}
		}
		prefix := "  "
		if i == m.index {
			prefix = "> "
		}
		hits = append(hits, hit{0, len(lines), m.width, i})
		lines = append(lines, prefix+clean(f.Label)+": "+clean(value))
	}
	lines = append(lines, "")
	if m.index < len(m.spec.Fields) {
		f := m.spec.Fields[m.index]
		lines = append(lines, clean(f.Help))
		switch f.Kind {
		case Text, Secret:
			lines = append(lines, m.inputs[m.index].View())
		case Multiline:
			lines = append(lines, strings.Split(m.areas[m.index].View(), "\n")...)
		case Select, Toggle:
			if m.searching {
				lines = append(lines, m.search.View())
			}
			choices := m.choices()
			selected := 0
			for i, c := range choices {
				if c.Value == f.Value {
					selected = i
				}
			}
			choiceCount := max(1, min(5, m.height-len(lines)-4))
			first := max(0, min(selected-choiceCount/2, len(choices)-choiceCount))
			for i := first; i < min(len(choices), first+choiceCount); i++ {
				prefix := "  "
				if choices[i].Value == f.Value {
					prefix = "> "
				}
				hits = append(hits, hit{0, len(lines), m.width, 100000 + i})
				lines = append(lines, prefix+clean(choices[i].Label))
			}
			if len(choices) == 0 {
				lines = append(lines, "No matching choices")
			}
		}
	}
	if len(lines) > max(0, m.height-3) {
		lines = lines[:max(0, m.height-3)]
	}
	for len(lines) < max(0, m.height-3) {
		lines = append(lines, "")
	}
	lines = append(lines, clean(m.err))
	label := m.spec.SubmitLabel
	if label == "" {
		label = "Review"
	}
	button := "[Ctrl+S " + clean(label) + "]"
	hits = append(hits, hit{0, len(lines), ansi.StringWidth(button), -1}, hit{ansi.StringWidth(button) + 2, len(lines), 12, -3})
	lines = append(lines, button+"  [Esc Cancel]")
	lines = append(lines, fmt.Sprintf("Field %d/%d · Tab/Shift+Tab · Select: arrows/j/k, / search", min(m.index+1, len(m.spec.Fields)), len(m.spec.Fields)))
	return lines, hits
}
func (m *form) hit(x, y int) int {
	if x < 0 || y < 0 || x >= m.width || y >= m.height {
		return -2
	}
	_, hits := m.layout()
	for i := len(hits) - 1; i >= 0; i-- {
		h := hits[i]
		if y == h.y && x >= h.x && x < h.x+h.width {
			return h.index
		}
	}
	return -2
}
func (m *form) View() tea.View {
	lines, _ := m.layout()
	return terminalView(lines, m.width, m.height)
}

type review struct {
	title, body           string
	width, height, offset int
	acceptFocus, accepted bool
	pressed               int
}

func (m *review) Init() tea.Cmd { m.pressed = -1; return nil }
func (m *review) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.pressed = -1
	case tea.KeyPressMsg:
		m.pressed = -1
		switch msg.String() {
		case "esc", "ctrl+c":
			return m, tea.Quit
		case "tab", "shift+tab", "left", "right", "h", "l":
			m.acceptFocus = !m.acceptFocus
		case "up", "k":
			m.offset = max(0, m.offset-1)
		case "down", "j":
			m.offset++
		case "pgdown":
			m.offset += max(1, m.height-5)
		case "pgup":
			m.offset = max(0, m.offset-max(1, m.height-5))
		case "enter":
			m.accepted = m.acceptFocus
			return m, tea.Quit
		}
	case tea.MouseClickMsg:
		m.pressed = -1
		if msg.Mouse().Button == tea.MouseLeft {
			m.pressed = m.buttonAt(msg.Mouse().X, msg.Mouse().Y)
		}
	case tea.MouseReleaseMsg:
		pressed := m.pressed
		m.pressed = -1
		if next := m.buttonAt(msg.Mouse().X, msg.Mouse().Y); pressed >= 0 && next == pressed && msg.Mouse().Button == tea.MouseLeft {
			m.accepted = next == 1
			return m, tea.Quit
		}
	}
	return m, nil
}
func (m *review) buttonAt(x, y int) int {
	if m.height < 4 || x < 0 || x >= m.width || y != m.height-2 {
		return -1
	}
	if x < 10 {
		return 0
	}
	if x >= 12 && x < 21 && m.width >= 21 {
		return 1
	}
	return -1
}
func (m *review) View() tea.View {
	body := strings.Split(cleanMultiline(m.body), "\n")
	height := max(1, m.height-5)
	start := max(0, min(m.offset, len(body)-height))
	lines := []string{clean(m.title), ""}
	for i := start; i < min(len(body), start+height); i++ {
		lines = append(lines, body[i])
	}
	for len(lines) < max(0, m.height-2) {
		lines = append(lines, "")
	}
	buttons := "[ Cancel ]  [ Apply ]"
	if m.acceptFocus {
		buttons = "  Cancel    [ Apply ]"
	} else {
		buttons = "[ Cancel ]    Apply"
	}
	lines = append(lines, buttons, "Tab/Left/Right choose · Enter confirm · Up/Down scroll · Esc cancel")
	return terminalView(lines, m.width, m.height)
}
func terminalView(lines []string, width, height int) tea.View {
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], max(1, width), "")
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}
func clean(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
}
func cleanMultiline(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, value)
}
