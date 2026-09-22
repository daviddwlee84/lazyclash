package tui

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/topology"
)

type TopologyOptions struct {
	Load                func(context.Context, bool) (topology.Graph, error)
	Authenticate        func(context.Context, error) (*exec.Cmd, error)
	Live, CanLive       bool
	Focus, View, Format string
}

// RunTopology is used by the CLI and by a dashboard terminal handoff, so only
// one Bubble Tea program owns terminal input at a time.
func RunTopology(ctx context.Context, opts TopologyOptions, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m := newTopologyBrowser(ctx, opts)
	defer func() {
		if m.cancel != nil {
			m.cancel()
		}
	}()
	_, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type topologyLoaded struct {
	serial uint64
	graph  topology.Graph
	err    error
}
type topologyDrawn struct {
	serial uint64
	body   string
	err    error
}
type topologyAuth struct{ err error }
type topologyNotice struct{ text string }

type topologyBrowser struct {
	ctx                                          context.Context
	opts                                         TopologyOptions
	graph                                        topology.Graph
	query                                        textinput.Model
	search, help, pending                        bool
	index, listOffset, pane, x, y, width, height int
	focus, body, notice                          string
	loadErr                                      error
	serial, drawSerial                           uint64
	cancel                                       context.CancelFunc
}

func newTopologyBrowser(ctx context.Context, opts TopologyOptions) *topologyBrowser {
	q := textinput.New()
	q.Prompt = "Find: "
	return &topologyBrowser{ctx: ctx, opts: opts, query: q, width: 100, height: 28, focus: opts.Focus}
}

func (m *topologyBrowser) Init() tea.Cmd { return m.reload() }
func (m *topologyBrowser) reload() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
	m.cancel = cancel
	m.serial++
	m.pending = true
	m.notice = "Reading topology; navigation remains available"
	serial, live, load := m.serial, m.opts.Live, m.opts.Load
	return func() tea.Msg {
		defer cancel()
		g, err := load(ctx, live)
		return topologyLoaded{serial, g, err}
	}
}

func (m *topologyBrowser) rows() []topology.Node {
	var rows []topology.Node
	q := strings.ToLower(m.query.Value())
	for _, n := range m.graph.Nodes {
		if strings.Contains(strings.ToLower(n.Name+" "+n.Kind+" "+n.Type), q) {
			rows = append(rows, n)
		}
	}
	return rows
}
func (m *topologyBrowser) selected() string {
	rows := m.rows()
	if len(rows) == 0 {
		return ""
	}
	return rows[max(0, min(m.index, len(rows)-1))].ID
}
func (m *topologyBrowser) draw() tea.Cmd {
	m.drawSerial++
	serial := m.drawSerial
	g, err := m.graph.Focus(m.focus)
	if err != nil {
		m.notice = err.Error()
		return nil
	}
	view, format, width := m.opts.View, m.opts.Format, max(20, m.width-34)
	return func() tea.Msg {
		if view == "relations" {
			return topologyDrawn{serial, g.Relations(), nil}
		}
		if format == "mermaid" {
			return topologyDrawn{serial, topology.Mermaid(g), nil}
		}
		body, err := topology.ASCII(g, width)
		if err != nil {
			body = g.Relations()
		}
		return topologyDrawn{serial, body, err}
	}
}
func (m *topologyBrowser) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.query.SetWidth(max(1, m.width-8))
		return m, nil
	case topologyLoaded:
		if msg.serial != m.serial {
			return m, nil
		}
		m.pending = false
		m.loadErr = msg.err
		if msg.err != nil {
			m.notice = safeError(msg.err) + " · prior snapshot retained"
			if connection.IsAuthRequired(msg.err) {
				m.notice += " · A Authenticate"
			}
			return m, nil
		}
		selected := m.selected()
		m.graph = msg.graph
		m.index = 0
		for i, n := range m.rows() {
			if n.ID == selected {
				m.index = i
			}
		}
		m.notice = "Snapshot ready"
		return m, m.draw()
	case topologyDrawn:
		if msg.serial != m.drawSerial {
			return m, nil
		}
		m.body = msg.body
		if msg.err != nil {
			m.notice = msg.err.Error() + " · showing relations"
		}
		return m, nil
	case topologyAuth:
		if msg.err != nil {
			m.notice = safeError(msg.err)
			return m, nil
		}
		return m, m.reload()
	case topologyNotice:
		m.notice = msg.text
		return m, nil
	case tea.PasteMsg:
		if m.search {
			var cmd tea.Cmd
			m.query, cmd = m.query.Update(msg)
			m.index, m.listOffset = 0, 0
			return m, cmd
		}
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.search {
			switch key {
			case "enter":
				m.search = false
				m.query.Blur()
				return m, nil
			case "esc":
				m.search = false
				m.query.Blur()
				m.query.SetValue("")
				m.index = 0
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
				m.index, m.listOffset = 0, 0
			}
			return m, cmd
		}
		if m.help {
			if key == "esc" || key == "?" {
				m.help = false
			}
			return m, nil
		}
		switch key {
		case "q", "esc":
			return m, tea.Quit
		case "?":
			m.help = true
		case "/":
			m.search = true
			return m, m.query.Focus()
		case "tab", "shift+tab":
			m.pane = 1 - m.pane
		case "up", "k", "down", "j", "pgup", "pgdown":
			delta := 1
			if key == "up" || key == "k" || key == "pgup" {
				delta = -1
			}
			if key == "pgup" || key == "pgdown" {
				delta *= max(1, m.height-8)
			}
			if m.pane == 0 {
				m.index = max(0, min(m.index+delta, len(m.rows())-1))
			} else {
				m.y = max(0, min(m.y+delta, len(strings.Split(m.content(), "\n"))-1))
			}
		case "left", "h":
			if m.pane == 1 {
				m.x = max(0, m.x-8)
			}
		case "right", "l":
			if m.pane == 1 {
				m.x += 8
			}
		case "home":
			if m.pane == 0 {
				m.index = 0
			} else {
				m.x, m.y = 0, 0
			}
		case "end", "G":
			if m.pane == 0 {
				m.index = max(0, len(m.rows())-1)
			}
		case "enter":
			if id := m.selected(); id != "" {
				m.focus = id
				m.x, m.y = 0, 0
				return m, m.draw()
			}
		case "a":
			m.focus = ""
			m.x, m.y = 0, 0
			return m, m.draw()
		case "v":
			if m.opts.View == "relations" {
				m.opts.View = "graph"
			} else {
				m.opts.View = "relations"
			}
			m.x, m.y = 0, 0
			return m, m.draw()
		case "m":
			m.opts.View = "graph"
			if m.opts.Format == "mermaid" {
				m.opts.Format = "ascii"
			} else {
				m.opts.Format = "mermaid"
			}
			m.x, m.y = 0, 0
			return m, m.draw()
		case "s":
			if m.opts.CanLive {
				m.opts.Live = !m.opts.Live
				return m, m.reload()
			}
		case "r":
			return m, m.reload()
		case "A":
			if m.opts.Authenticate != nil && connection.IsAuthRequired(m.loadErr) {
				cmd, err := m.opts.Authenticate(m.ctx, m.loadErr)
				if err != nil {
					m.notice = safeError(err)
					return m, nil
				}
				return m, tea.ExecProcess(cmd, func(err error) tea.Msg { return topologyAuth{err} })
			}
		case "y":
			g, err := m.graph.Focus(m.focus)
			if err != nil {
				m.notice = err.Error()
				return m, nil
			}
			source := topology.Mermaid(g)
			return m, func() tea.Msg {
				if err := clipboard.WriteAll(source); err != nil {
					return topologyNotice{"Clipboard unavailable"}
				}
				return topologyNotice{"Mermaid copied"}
			}
		}
	}
	return m, nil
}

func (m *topologyBrowser) content() string {
	return m.graph.Summary() + "\n\n" + m.graph.Detail(m.selected()) + "\n" + m.body
}
func topologyLine(s string, width int) string {
	s = strings.ReplaceAll(core.Sanitize(s), "\t", " ")
	s = ansi.Truncate(s, max(1, width), "")
	return s + strings.Repeat(" ", max(0, width-ansi.StringWidth(s)))
}
func (m *topologyBrowser) View() tea.View {
	mode := "static"
	if m.opts.Live {
		mode = "config + live"
	}
	header := "Routing topology · " + mode
	if m.pending {
		header += " · loading"
	}
	if m.help {
		help := header + "\n↑↓ / j/k select or scroll · Tab switch pane\nEnter focus subtree · a all · / search\nv graph/relations · m Mermaid source · y copy Mermaid\nr refresh · A authenticate when requested\n←→ / h/l pan details · Home reset scroll\nEsc/? close help · Ctrl+C return\nCurrent selection is not proof of observed traffic."
		if m.opts.CanLive {
			help += "\ns static/live"
		}
		return topologyView(help, m.width, m.height)
	}
	rows := m.rows()
	height := max(1, m.height-5)
	leftWidth := min(32, max(12, m.width/3))
	narrow := m.width < 60
	if narrow {
		leftWidth = m.width
	}
	listOffset := m.listOffset
	if m.index < listOffset {
		listOffset = m.index
	}
	if m.index >= listOffset+height {
		listOffset = m.index - height + 1
	}
	lines := strings.Split(m.content(), "\n")
	var out strings.Builder
	out.WriteString(topologyLine(header, m.width) + "\n")
	if m.search {
		out.WriteString(topologyLine(m.query.View(), m.width) + "\n")
	} else {
		focus := "all"
		for _, n := range m.graph.Nodes {
			if n.ID == m.focus || n.Name == m.focus {
				focus = n.Name
				break
			}
		}
		out.WriteString(topologyLine(fmt.Sprintf("Nodes: %d · focus: %s · pane: %d", len(rows), focus, m.pane+1), m.width) + "\n")
	}
	for i := 0; i < height; i++ {
		left := ""
		if pos := listOffset + i; pos < len(rows) {
			prefix := "  "
			if pos == m.index {
				prefix = "> "
			}
			left = prefix + strings.ReplaceAll(rows[pos].Name, "\n", " ")
		}
		right := ""
		rightWidth := max(1, m.width-leftWidth-3)
		if narrow {
			rightWidth = m.width
		}
		if pos := m.y + i; pos < len(lines) {
			right = ansi.Cut(lines[pos], m.x, m.x+rightWidth)
		}
		if narrow {
			if m.pane == 0 {
				out.WriteString(topologyLine(left, m.width))
			} else {
				out.WriteString(topologyLine(right, m.width))
			}
		} else {
			out.WriteString(topologyLine(left, leftWidth) + " | " + topologyLine(right, rightWidth))
		}
		out.WriteByte('\n')
	}
	out.WriteString(topologyLine(m.notice, m.width) + "\n")
	footer := "Tab pane · / search · Enter focus · v list/graph · r refresh · ? help · Esc back"
	if m.opts.CanLive {
		footer = "Tab pane · / search · Enter focus · v list/graph · s live · r refresh · ? help · Esc back"
	}
	out.WriteString(topologyLine(footer, m.width))
	return topologyView(out.String(), m.width, m.height)
}

func topologyView(content string, width, height int) tea.View {
	lines := strings.Split(content, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], max(1, width), "")
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	return v
}
