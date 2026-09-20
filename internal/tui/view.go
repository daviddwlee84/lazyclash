package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func (m *Model) View() tea.View {
	width, height := max(m.width, 1), max(m.height, 1)
	contentHeight := max(1, height-5)
	content := m.body(width, contentHeight)
	if m.overlay != "" && m.overlay != "search" {
		content = m.overlayView(width, contentHeight)
	}
	lines := []string{m.header(width), m.tabs(width)}
	lines = append(lines, fitLines(content, width, contentHeight)...)
	status := m.status
	if m.pending != "" {
		status = "PENDING: " + m.pending
	}
	if m.gPrefix {
		status = "g … (press g for first row)"
	}
	if query := m.state().view(m.page).query; query != "" {
		status = "Filter: " + core.Sanitize(query) + " · Esc clears · " + status
	}
	lines = append(lines, fit(core.Sanitize(status), width))
	if m.overlay == "search" {
		lines = append(lines, fit("Search: "+m.input.View(), width))
	} else {
		toolbar, _ := m.toolbar(width)
		lines = append(lines, toolbar)
	}
	lines = append(lines, fit(m.footer(), width))
	if len(lines) > height {
		lines = lines[:height]
	}
	output := strings.Join(lines, "\n")
	if os.Getenv("NO_COLOR") != "" {
		output = ansi.Strip(output)
	}
	view := tea.NewView(output)
	view.AltScreen = true
	if m.mouseEnabled {
		view.MouseMode = tea.MouseModeCellMotion
	}
	view.WindowTitle = "lazyclash"
	if cursor := m.input.Cursor(); cursor != nil {
		y, x := -1, 0
		switch m.overlay {
		case "search":
			y = 2 + contentHeight + 1
			x = 8
		case "palette":
			y = 3
		case "form":
			_, _, inputY := m.formLayout(width, contentHeight)
			if inputY >= 0 {
				y = inputY + 2
			}

		}
		if y >= 0 && y < height {
			cursor.Position.X = min(width-1, max(0, cursor.Position.X+x))
			cursor.Position.Y = y
			if os.Getenv("NO_COLOR") != "" {
				cursor.Color = nil
			}
			view.Cursor = cursor
		}
	}
	return view
}
func (m *Model) header(width int) string {
	label := defaultString(m.target.Label(), "no target")
	status := "offline"
	if m.opening {
		status = "connecting"
	} else if m.client != nil {
		status = "connected"
	}
	if m.options.ReadOnly {
		status += " read-only"
	}
	cfg := m.configData()
	if m.state().snap("config").err != nil || m.state().snap("version").err != nil {
		status += " stale"
	}
	mode := defaultString(str(cfg, "mode"), "?")
	tun := boolLabel(object(cfg["tun"]), "enable")
	s := m.state()
	traffic := "↑ ? ↓ ?"
	if s.traffic != nil {
		traffic = "↑ " + bytesLabel(s.traffic["up"]) + "/s ↓ " + bytesLabel(s.traffic["down"]) + "/s"
	}
	if s.streamErrors["traffic"] != "" {
		traffic += " stale"
	}
	return fit(m.accent("lazyclash")+"  "+core.Sanitize(label)+" ["+status+"]  "+mode+" TUN:"+tun+"  "+traffic, width)
}
func boolLabel(obj core.Object, key string) string {
	v, ok := obj[key].(bool)
	if !ok {
		return "?"
	}
	if v {
		return "on"
	}
	return "off"
}
func (m *Model) tabs(width int) string { text, _ := m.tabLayout(width); return text }
func (m *Model) body(width, height int) string {
	if m.page == overview {
		return m.overviewView(width, height)
	}
	v := m.state().view(m.page)
	fresh := m.freshness(m.page)
	if m.page == connections {
		if object(m.state().snap("connections").data)["lazyclashTruncated"] == true {
			fresh += " · first 2000 shown"
		}
		if v.exactFilter.Kind != "" {
			fresh += " · exact " + v.exactFilter.Kind + " filter · Esc clears"
		}
	}
	if m.page == logs {
		fresh = "Logs: " + defaultString(m.state().logLevel, "all levels") + " · "
		if m.state().follow {
			fresh += "following"
		} else {
			fresh += "paused"
		}
		fresh += fmt.Sprintf(" · last %d retained", logLimit)
		if e := m.state().streamErrors["logs"]; e != "" {
			fresh += " · stale: " + e
		}
	}
	if m.page == configs {
		fresh = "Registered complete YAMLs · core host paths · Enter applies runtime state"
		if m.target.Transient {
			fresh = "Temporary target: : Edit current target and save before registering YAML"
		}
	}
	var columns [][]string
	var widths []int
	panes := m.panes(width, height)
	for _, p := range panes {
		title := fresh
		if m.page == proxies {
			title = []string{"Groups", "Members (* current)", "Details"}[p.pane]
			if width < 100 {
				title += " · Tab changes pane"
			}
		} else if p.detail {
			title = "Details"
			if width < 100 {
				title += " · Shift+Tab returns"
			}
		}
		var rows []string
		if p.detail {
			rows = m.detailLines(m.details(m.page), p.w, p.h-1, v.detailOffset)
		} else {
			rows = m.listLines(m.rowsFor(m.page, p.pane), &v.positions[p.pane], p.w, p.h-1, v.focus == p.pane)
		}
		columns = append(columns, append([]string{fit(m.focusTitle(title, v.focus == p.pane), p.w)}, rows...))
		widths = append(widths, p.w)
	}
	h := height
	if m.page == proxies {
		h = max(0, height-1)
	}
	out := joinColumns(columns, widths, h)
	if m.page == proxies {
		out = fit(fresh, width) + "\n" + out
	}
	return out
}
func (m *Model) freshness(p page) string {
	keys := []string{"config"}
	switch p {
	case proxies:
		keys = []string{"proxies"}
	case connections:
		keys = []string{"connections"}
	case rules:
		keys = []string{"rules"}
	case providers:
		keys = []string{"proxyProviders", "ruleProviders"}
	}
	var statuses []string
	for _, key := range keys {
		s := m.state().snap(key)
		label := ""
		if len(keys) > 1 {
			label = key + ": "
		}
		switch {
		case s.err != nil && s.data != nil:
			statuses = append(statuses, label+"STALE · "+safeError(s.err))
		case s.err != nil:
			statuses = append(statuses, label+"Unavailable · "+safeError(s.err))
		case s.loading && s.data == nil:
			statuses = append(statuses, label+"Loading…")
		case s.loading:
			statuses = append(statuses, label+"Refreshing · "+s.at.Format("15:04:05"))
		case s.data != nil:
			statuses = append(statuses, label+"Updated "+s.at.Format("15:04:05"))
		default:
			statuses = append(statuses, label+"Not loaded")
		}
	}
	return strings.Join(statuses, " · ")
}
func (m *Model) listLines(rows []row, pos *position, width, height int, focused bool) []string {
	height = max(0, height)
	if height == 0 {
		return nil
	}
	if len(rows) == 0 {
		return fitLines("No matching items. / filter · r refresh · : actions", width, height)
	}
	selected := resolvePosition(pos, rows)
	start := visibleStart(pos, rows, height)
	lines := make([]string, 0, height)
	for i := start; i < len(rows) && len(lines) < height; i++ {
		mark := "  "
		if i == selected {
			if focused {
				mark = "> "
			} else {
				mark = "· "
			}
		}
		line := fit(mark+core.Sanitize(rows[i].label), width)
		if i == selected && focused {
			line = m.accent(line)
		}
		lines = append(lines, line)
	}
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", max(0, width)))
	}
	return lines
}
func (m *Model) detailLines(text string, width, height, offset int) []string {
	lines := strings.Split(ansi.Wrap(core.Sanitize(text), max(1, width), ""), "\n")
	offset = max(0, min(offset, max(0, len(lines)-max(1, height))))
	return fitLines(strings.Join(lines[offset:], "\n"), width, max(0, height))
}
func (m *Model) focusTitle(title string, active bool) string {
	if active {
		return m.accent("> " + title)
	}
	return "  " + title
}
func (m *Model) accent(text string) string {
	if os.Getenv("NO_COLOR") != "" {
		return text
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render(text)
}
func fit(text string, width int) string {
	width = max(0, width)
	text = strings.NewReplacer("\r", "", "\n", " ↵ ", "\t", " ").Replace(text)
	text = ansi.Truncate(text, width, "…")
	return text + strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
}
func fitLines(text string, width, height int) []string {
	if height <= 0 {
		return nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = fit(lines[i], width)
	}
	for len(lines) < height {
		lines = append(lines, strings.Repeat(" ", max(0, width)))
	}
	return lines
}
func joinColumns(columns [][]string, widths []int, height int) string {
	lines := make([]string, height)
	for r := 0; r < height; r++ {
		cells := make([]string, len(columns))
		for c := range columns {
			value := ""
			if r < len(columns[c]) {
				value = columns[c][r]
			}
			cells[c] = fit(value, widths[c])
		}
		lines[r] = strings.Join(cells, " │ ")
	}
	return strings.Join(lines, "\n")
}
func bytesLabel(value any) string {
	if value == nil {
		return "?"
	}
	var n float64
	switch v := value.(type) {
	case float64:
		n = v
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case json.Number:
		n, _ = v.Float64()
	default:
		var err error
		n, err = strconv.ParseFloat(fmt.Sprint(v), 64)
		if err != nil {
			return "?"
		}
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}
func (m *Model) contextHint() string {
	labels := map[string]string{
		"select": "choose", "delay": "node delay", "delay-group": "group delay",
		"close-connection": "close selected", "close-all": "close all", "log-follow": "follow/pause", "log-clear": "clear", "log-level": "level",
		"provider-update": "update", "provider-health": "healthcheck", "config-apply": "apply", "config-add": "register", "config-edit": "edit", "config-remove": "remove",
	}
	if m.page == overview {
		labels = map[string]string{"mode": "mode", "tun": "TUN (core state)", "lan": "Allow LAN"}
	}
	var hints []string
	if m.page == proxies && m.state().view(proxies).focus == 0 {
		hints = append(hints, "Enter members")
	}
	for _, a := range m.actions() {
		label, ok := labels[a.id]
		if ok && a.enabled && len(a.keys) > 0 {
			hints = append(hints, strings.Join(a.keys, "/")+" "+label)
		}
	}
	if m.page == rules {
		hints = append(hints, "Rules preserve core order", "Tab details")
	}
	if m.page == proxies {
		hints = append(hints, "* current")
	}
	if m.options.ReadOnly {
		hints = append(hints, "read-only")
	}
	if len(hints) == 0 {
		return "r refresh · : actions"
	}
	return strings.Join(hints, " · ")
}

func (m *Model) footer() string {
	switch m.overlay {
	case "search":
		return "Type to filter · ↑↓ select · Enter accept · Esc clear"
	case "palette":
		return "Type to find action · ↑↓ select · Enter run · Esc cancel"
	case "form":
		return "Tab / Enter next · Shift+Tab back · Ctrl+T test · Esc cancel"
	case "targets":
		return "↑↓/jk select · Enter connect · T test · n add · e edit · Esc close"
	case "confirm":
		return "Enter / y confirm · Esc / n cancel"
	case "help":
		return "↑↓/jk scroll · Esc / ? close"
	case "saving":
		return "Saving settings…"
	}
	if m.width < 60 {
		return "↑↓ · : menu · ? help · q quit"
	}
	return "↑↓/jk move · Tab pane · 1–7 pages · t targets · : actions · M mouse · ? help · q quit"
}
func (m *Model) legacyOverlayView(width, height int) string {
	var text string
	switch m.overlay {
	case "palette":
		actions := m.paletteActions()
		var rows []row
		for _, a := range actions {
			keys := strings.Join(a.keys, "/")
			if keys != "" {
				keys = " [" + keys + "]"
			}
			rows = append(rows, row{id: a.id, label: a.label + keys})
		}
		p := position{index: m.paletteIndex}
		return strings.Join(append([]string{m.accent("Actions"), m.input.View()}, m.listLines(rows, &p, width, max(0, height-2), true)...), "\n")
	case "targets":
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
		p := position{index: m.targetIndex}
		return strings.Join(append([]string{m.accent("Targets · ordered")}, m.listLines(rows, &p, width, height-1, true)...), "\n")
	case "confirm":
		if m.confirm != nil {
			text = m.confirm.title + "\n\n" + m.confirm.body + "\n\nConfirm with Enter / y. Cancel with Esc / n."
		}
	case "help":
		lines := []string{pageNames[m.page] + " · keyboard help", "↑↓ or j/k move · PgUp/PgDn page · gg/Home first · G/End last", "Tab/Shift+Tab or h/l focus pane · [ ] or 1–7 switch page", "/ live filter: typing owns keys; Enter accepts without acting", "t targets · : action menu · Esc back/clear · q/Ctrl+C quit", "", "Available actions:"}
		for _, a := range m.actions() {
			keys := strings.Join(a.keys, "/")
			if keys == "" {
				keys = ":"
			}
			suffix := ""
			if !a.enabled {
				suffix = " [unavailable]"
			}
			lines = append(lines, keys+"  "+a.label+suffix)
		}
		lines = append(lines, "", "? means unknown. STALE retains the last successful result.", "TUN is reported by the core; system routing is not verified.", "Connections and logs may contain sensitive hostnames.", "Logs retain only the latest 1000 entries in memory.", "YAML apply changes runtime state; Verge may overwrite it.", "Delay tests call individual nodes with concurrency 4.")
		return strings.Join(m.detailLines(strings.Join(lines, "\n"), width, height, m.helpOffset), "\n")
	case "form":
		return m.formView(width, height)
	case "saving":
		text = "Saving settings…"
	}
	return strings.Join(m.detailLines(text, width, height, 0), "\n")
}
func (m *Model) formView(width, height int) string {
	lines, _, _ := m.formLayout(width, height)
	return strings.Join(lines, "\n")
}
