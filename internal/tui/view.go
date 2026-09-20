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
	lines = append(lines, fit(core.Sanitize(status), width))
	if m.overlay == "search" {
		lines = append(lines, fit("Search: "+m.input.View(), width))
	} else {
		v := m.state().view(m.page)
		filter := ""
		if v.query != "" {
			filter = "Filter: " + core.Sanitize(v.query) + "  "
		}
		lines = append(lines, fit(filter+m.contextHint(), width))
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
			if m.form != nil && m.form.index < len(m.form.fields) {
				n := len(m.form.fields)
				lineCount := n + 4
				if m.form.err != "" {
					lineCount += 2
				}
				y = n + 5
				if lineCount > contentHeight {
					y = 6
				}
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
func (m *Model) tabs(width int) string {
	var parts []string
	for i, name := range pageNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if page(i) == m.page {
			label = m.accent("[" + label + "]")
		}
		parts = append(parts, label)
	}
	full := strings.Join(parts, "  ")
	if ansi.StringWidth(full) > width {
		return fit(fmt.Sprintf("[%d %s]  [ / ] change page · 1–7", m.page+1, pageNames[m.page]), width)
	}
	return fit(full, width)
}
func (m *Model) body(width, height int) string {
	if m.page == overview {
		return m.overviewView(width, height)
	}
	if m.page == proxies {
		return m.proxiesView(width, height)
	}
	s := m.state()
	v := s.view(m.page)
	fresh := m.freshness(m.page)
	if m.page == connections && object(s.snap("connections").data)["lazyclashTruncated"] == true {
		fresh += " · first 2000 connections shown"
	}
	if m.page == logs {
		fresh = "Logs: " + defaultString(s.logLevel, "all levels") + " · "
		if s.follow {
			fresh += "following"
		} else {
			fresh += "paused"
		}
		fresh += fmt.Sprintf(" · last %d retained", logLimit)
		if e := s.streamErrors["logs"]; e != "" {
			fresh += " · stale: " + e
		}
	}
	if m.page == configs {
		fresh = "Registered complete YAMLs · core host paths · Enter applies runtime state"
		if m.target.Transient {
			fresh = "Temporary target: : Edit current target and save before registering YAML"
		}
	}
	if width < 100 {
		if v.focus == 1 && m.page != logs {
			return strings.Join(append([]string{fit(m.accent("Details · Shift+Tab returns"), width)}, m.detailLines(m.details(m.page), width, height-1, v.detailOffset)...), "\n")
		}
		return strings.Join(append([]string{fit(fresh, width)}, m.listLines(m.rowsFor(m.page, 0), &v.positions[0], width, height-1, true)...), "\n")
	}
	left := width * 55 / 100
	right := max(1, width-left-3)
	list := append([]string{fit(fresh, left)}, m.listLines(m.rowsFor(m.page, 0), &v.positions[0], left, height-1, v.focus == 0)...)
	detail := append([]string{fit(m.focusTitle("Details", v.focus == 1), right)}, m.detailLines(m.details(m.page), right, height-1, v.detailOffset)...)
	if m.page == logs {
		return strings.Join(append([]string{fit(fresh, width)}, m.listLines(m.rowsFor(logs, 0), &v.positions[0], width, height-1, true)...), "\n")
	}
	return joinColumns([][]string{list, detail}, []int{left, right}, height)
}
func (m *Model) proxiesView(width, height int) string {
	v := m.state().view(proxies)
	fresh := m.freshness(proxies)
	height = max(1, height-1)
	if width < 100 {
		title := "Groups"
		pane := v.focus
		var lines []string
		if pane == 2 {
			title = "Details"
			lines = m.detailLines(m.details(proxies), width, height-1, v.detailOffset)
		} else {
			if pane == 1 {
				title = "Members"
				if g, ok := m.group(); ok {
					title += " · " + g.Name
				}
			}
			lines = m.listLines(m.rowsFor(proxies, pane), &v.positions[pane], width, height-1, true)
		}
		return strings.Join(append([]string{fit(fresh, width), fit(m.accent(title)+" · Tab changes pane", width)}, lines...), "\n")
	}
	widths := []int{width * 27 / 100, width * 36 / 100, 0}
	widths[2] = max(1, width-widths[0]-widths[1]-6)
	groups := append([]string{fit(m.focusTitle("Groups", v.focus == 0), widths[0])}, m.listLines(m.rowsFor(proxies, 0), &v.positions[0], widths[0], height-1, v.focus == 0)...)
	members := append([]string{fit(m.focusTitle("Members (* current)", v.focus == 1), widths[1])}, m.listLines(m.rowsFor(proxies, 1), &v.positions[1], widths[1], height-1, v.focus == 1)...)
	detail := append([]string{fit(m.focusTitle("Details", v.focus == 2), widths[2])}, m.detailLines(m.details(proxies), widths[2], height-1, v.detailOffset)...)
	return fit(fresh, width) + "\n" + joinColumns([][]string{groups, members, detail}, widths, height)
}
func (m *Model) overviewView(width, height int) string {
	s := m.state()
	version := object(s.snap("version").data)
	cfg := m.configData()
	lines := []string{
		"Controller: " + m.target.Controller,
		"SSH: " + defaultString(m.target.SSHHost, "local / direct"),
		"Core version: " + defaultString(str(version, "version"), "unknown"),
		"Mode: " + defaultString(str(cfg, "mode"), "unknown") + "   TUN (core report): " + boolLabel(object(cfg["tun"]), "enable") + "   Allow LAN: " + boolLabel(cfg, "allow-lan"),
		"Upload: " + bytesLabel(s.traffic["up"]) + "/s   Download: " + bytesLabel(s.traffic["down"]) + "/s",
		"Memory: " + bytesLabel(s.memory["inuse"]),
		"", m.freshness(overview),
		"", "m mode · u TUN · a Allow LAN · t choose target",
		"TUN state is the core's response; system routing is not verified.",
	}
	for _, key := range []string{"traffic", "memory", "logs"} {
		if e := s.streamErrors[key]; e != "" {
			lines = append(lines, key+" stream stale: "+e)
		}
	}
	if s.lastOperation != "" {
		lines = append(lines, "Last operation: "+s.lastOperation)
	}
	if s.lastApplied != "" {
		lines = append(lines, "Last applied by lazyclash: "+s.lastApplied)
	}
	text := core.Sanitize(strings.Join(lines, "\n"))
	return strings.Join(m.detailLines(text, width, height, m.state().view(overview).detailOffset), "\n")
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
	start := max(0, min(pos.offset, len(rows)-height))
	if selected < start {
		start = selected
	}
	if selected >= start+height {
		start = selected - height + 1
	}
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
		return "Tab / Enter next · Shift+Tab back · Esc cancel"
	case "targets":
		return "↑↓/jk select · Enter connect · n add · e edit · Esc close"
	case "confirm":
		return "Enter / y confirm · Esc / n cancel"
	case "help":
		return "↑↓/jk scroll · Esc / ? close"
	case "saving":
		return "Saving settings…"
	}
	return "↑↓/jk move · Tab/h/l pane · [ ] page · / filter · t targets · : actions · ? help · q quit"
}
func (m *Model) overlayView(width, height int) string {
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
	f := m.form
	if f == nil {
		return ""
	}
	lines := []string{m.accent(f.title)}
	if f.index == len(f.fields) {
		lines = append(lines, "Review · Enter saves · Shift+Tab edits")
	}
	for i, field := range f.fields {
		mark := "  "
		if i == f.index {
			mark = "> "
		}
		value := defaultString(field.value, "(empty)")
		lines = append(lines, fit(mark+field.label+": "+core.Sanitize(value), width))
	}
	if f.index < len(f.fields) {
		lines = append(lines, "", fit(f.fields[f.index].label, width), m.input.View())
	}
	if f.err != "" {
		lines = append(lines, "", "Invalid: "+f.err)
	}
	if len(lines) > height && f.index < len(f.fields) {
		lines = []string{m.accent(f.title), fmt.Sprintf("Field %d/%d · Tab next / Shift+Tab back", f.index+1, len(f.fields)), f.fields[f.index].label, "", m.input.View(), "", f.err}
	}
	return strings.Join(fitLines(strings.Join(lines, "\n"), width, height), "\n")
}
