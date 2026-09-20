package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

type rect struct{ x, y, w, h int }

func (r rect) contains(x, y int) bool { return x >= r.x && y >= r.y && x < r.x+r.w && y < r.y+r.h }

type hitRegion struct {
	rect
	kind, id    string
	pane, index int
}
type mousePress struct {
	hit     hitRegion
	context string
}
type paneRegion struct {
	rect
	pane   int
	detail bool
}

// panes is shared by rendering and hit testing. Coordinates are body-relative.
func (m *Model) panes(width, height int) []paneRegion {
	v := m.state().view(m.page)
	if m.page == overview {
		return nil
	}
	if m.page == proxies {
		if width < 100 {
			return []paneRegion{{rect{0, 1, width, max(0, height-1)}, v.focus, v.focus == 2}}
		}
		widths := []int{width * 27 / 100, width * 36 / 100, 0}
		widths[2] = max(1, width-widths[0]-widths[1]-6)
		return []paneRegion{{rect{0, 1, widths[0], max(0, height-1)}, 0, false}, {rect{widths[0] + 3, 1, widths[1], max(0, height-1)}, 1, false}, {rect{widths[0] + widths[1] + 6, 1, widths[2], max(0, height-1)}, 2, true}}
	}
	if m.page == logs {
		return []paneRegion{{rect{0, 0, width, height}, 0, false}}
	}
	if width < 100 {
		return []paneRegion{{rect{0, 0, width, height}, v.focus, v.focus == 1}}
	}
	left := width * 55 / 100
	return []paneRegion{{rect{0, 0, left, height}, 0, false}, {rect{left + 3, 0, max(1, width-left-3), height}, 1, true}}
}
func visibleStart(pos *position, rows []row, height int) int {
	if height <= 0 || len(rows) == 0 {
		return 0
	}
	selected := resolvePosition(pos, rows)
	start := max(0, min(pos.offset, len(rows)-height))
	if selected < start {
		start = selected
	}
	if selected >= start+height {
		start = selected - height + 1
	}
	return max(0, start)
}
func (m *Model) tabLayout(width int) (string, []hitRegion) {
	labels := make([]string, len(pageNames))
	total := 0
	for i, name := range pageNames {
		labels[i] = fmt.Sprintf("%d %s", i+1, name)
		if page(i) == m.page {
			labels[i] = "[" + labels[i] + "]"
		}
		total += ansi.StringWidth(labels[i]) + 2
	}
	if total-2 > width {
		for i := range labels {
			labels[i] = fmt.Sprint(i + 1)
			if page(i) == m.page {
				labels[i] = fmt.Sprintf("[%d %s]", i+1, pageNames[i])
			}
		}
	}
	var parts []string
	var hits []hitRegion
	x := 0
	for i, label := range labels {
		w := ansi.StringWidth(label)
		if x+w > width {
			break
		}
		hits = append(hits, hitRegion{rect: rect{x, 1, w, 1}, kind: "tab", id: fmt.Sprint(i), index: i})
		if page(i) == m.page {
			label = m.accent(label)
		}
		parts = append(parts, label)
		x += w + 2
	}
	return fit(strings.Join(parts, "  "), width), hits
}
func (m *Model) toolbar(width int) (string, []hitRegion) {
	wanted := []string{"refresh", "targets"}
	switch m.page {
	case overview:
		wanted = []string{"overview-inspect", "probe-ip", "probe-latency", "mode", "tun", "history-window", "graph-style"}
	case proxies:
		wanted = []string{"select", "delay", "delay-group"}
	case connections:
		wanted = []string{"close-connection", "close-all"}
	case logs:
		wanted = []string{"log-follow", "log-level", "log-clear"}
	case providers:
		wanted = []string{"provider-update", "provider-health"}
	case configs:
		wanted = []string{"config-apply", "config-add", "config-edit", "config-remove"}
	}
	short := map[string]string{"overview-inspect": "Inspect", "refresh": "Refresh", "targets": "Targets", "select": "Choose", "delay": "Delay", "delay-group": "Group delay", "close-connection": "Close", "close-all": "Close all", "log-follow": "Follow", "log-level": "Level", "log-clear": "Clear", "provider-update": "Update", "provider-health": "Healthcheck", "config-apply": "Apply", "config-add": "Register", "config-edit": "Edit", "config-remove": "Remove", "probe-ip": "IP.SB", "probe-latency": "Websites", "mode": "Mode", "tun": "TUN", "history-window": "Window", "graph-style": "Style"}
	actions := m.actions()
	var parts []string
	var hits []hitRegion
	x := 0
	for _, id := range wanted {
		for _, a := range actions {
			if a.id != id {
				continue
			}
			key := ""
			if len(a.keys) > 0 {
				key = a.keys[0] + " "
			}
			label := "[" + key + short[id] + "]"
			if !a.enabled {
				label = "(" + key + short[id] + ")"
			}
			w := ansi.StringWidth(label)
			if x+w > width {
				continue
			}
			parts = append(parts, label)
			if a.enabled {
				hits = append(hits, hitRegion{rect: rect{x, m.height - 2, w, 1}, kind: "action", id: id})
			}
			x += w + 1
		}
	}
	return fit(strings.Join(parts, " "), width), hits
}
func (m *Model) hitRegions() []hitRegion {
	width, height := max(1, m.width), max(1, m.height-5)
	if m.overlay != "" {
		_, hits := m.overlayLayout(width, height)
		for i := range hits {
			hits[i].y += 2
		}
		return hits
	}
	_, hits := m.tabLayout(width)
	_, buttons := m.toolbar(width)
	hits = append(hits, buttons...)
	if len(m.settings.Targets) > 0 {
		hits = append(hits, hitRegion{rect: rect{0, 0, width, 1}, kind: "action", id: "targets"})
	}
	footer := m.footer()
	for label, id := range map[string]string{"t targets": "targets", ": actions": "palette", ": menu": "palette", "M mouse": "mouse", "? help": "help", "q quit": "quit"} {
		if pos := strings.Index(footer, label); pos >= 0 {
			x := ansi.StringWidth(footer[:pos])
			w := ansi.StringWidth(label)
			if x+w <= width {
				hits = append(hits, hitRegion{rect: rect{x, m.height - 1, w, 1}, kind: "action", id: id})
			}
		}
	}
	if m.page == overview {
		lines, regions := m.overviewLayout(width)
		offset := max(0, min(m.state().view(overview).detailOffset, max(0, len(lines)-height)))
		for _, r := range regions {
			r.y -= offset
			if r.y >= 0 && r.y < height {
				r.y += 2
				hits = append(hits, r)
			}
		}
		return hits
	}
	v := m.state().view(m.page)
	for _, p := range m.panes(width, height) {
		r := p.rect
		r.y += 2
		hits = append(hits, hitRegion{rect: r, kind: "pane", pane: p.pane})
		if p.detail {
			continue
		}
		rows := m.rowsFor(m.page, p.pane)
		start := visibleStart(&v.positions[p.pane], rows, p.h-1)
		for i := start; i < len(rows) && i < start+p.h-1; i++ {
			hits = append(hits, hitRegion{rect: rect{p.x, p.y + 3 + i - start, p.w, 1}, kind: "row", id: rows[i].id, pane: p.pane, index: i})
		}
	}
	return hits
}
func hitAt(hits []hitRegion, x, y int) (hitRegion, bool) {
	for i := len(hits) - 1; i >= 0; i-- {
		if hits[i].contains(x, y) {
			return hits[i], true
		}
	}
	return hitRegion{}, false
}
func (m *Model) mouseContext() string {
	v := m.state().view(m.page)
	form := ""
	if m.form != nil {
		form = fmt.Sprintf("%p/%d", m.form, m.form.index)
	}
	picked := ""
	if m.targetIndex >= 0 && m.targetIndex < len(m.settings.Targets) {
		picked = m.settings.Targets[m.targetIndex].ID
	}
	paletteID := ""
	if m.overlay == "palette" {
		actions := m.paletteActions()
		if len(actions) > 0 {
			paletteID = actions[min(m.paletteIndex, len(actions)-1)].id
		}
	}
	return fmt.Sprint(m.workSerial, "|", m.workMouseContext()) + fmt.Sprintf("%d|%d|%s|%d|%s|%s|%s|%s|%d|%s|%t|%s|%d|%s|%s", m.generation, m.page, m.overlay, v.focus, v.positions[0].selected, v.positions[1].selected, picked, form, m.testSerial, m.pending, m.options.ReadOnly, m.overviewSelection, m.paletteIndex, paletteID, m.input.Value())
}
func (m *Model) mouseClick(msg tea.MouseClickMsg) tea.Cmd {
	m.pressed = nil
	if !m.mouseEnabled || msg.Button != tea.MouseLeft || msg.X < 0 || msg.Y < 0 || msg.X >= m.width || msg.Y >= m.height {
		return nil
	}
	hit, ok := hitAt(m.hitRegions(), msg.X, msg.Y)
	if !ok {
		return nil
	}
	switch hit.kind {
	case "pane":
		m.state().view(m.page).focus = hit.pane
	case "row":
		v := m.state().view(m.page)
		v.focus = hit.pane
		v.positions[hit.pane].selected = hit.id
		v.positions[hit.pane].index = hit.index
		if m.page == logs {
			m.state().follow = false
		}
		m.reconcile()
	case "overview":
		m.overviewSelection = hit.id
	case "target-row":
		m.targetIndex = hit.index
		m.invalidateTargetTest()
	case "work-row":
		if m.work != nil {
			m.work.index = hit.index
			m.work.offset = 0
			m.work.focus = 0
		}
	case "palette-row":
		m.paletteIndex = hit.index
	case "field":
		if m.form == nil {
			return nil
		}
		if m.form.index < len(m.form.fields) {
			m.form.fields[m.form.index].value = m.input.Value()
		}
		m.form.index = hit.index
		return m.beginInput("form", m.form.fields[hit.index].value)
	default:
		m.pressed = &mousePress{hit, m.mouseContext()}
	}
	return nil
}
func (m *Model) mouseRelease(msg tea.MouseReleaseMsg) tea.Cmd {
	press := m.pressed
	m.pressed = nil
	if !m.mouseEnabled || msg.Button != tea.MouseLeft || press == nil || press.context != m.mouseContext() {
		return nil
	}
	hit, ok := hitAt(m.hitRegions(), msg.X, msg.Y)
	if !ok || hit.kind != press.hit.kind || hit.id != press.hit.id {
		return nil
	}
	switch hit.kind {
	case "tab":
		return m.changePage(hit.index)
	case "action":
		return m.dispatchAction(hit.id)
	case "button":
		return m.overlayButton(hit.id)
	}
	return nil
}
func (m *Model) dispatchAction(id string) tea.Cmd {
	for _, a := range m.actions() {
		if a.id == id && a.enabled {
			return m.runAction(id)
		}
	}
	return nil
}
func (m *Model) mouseWheel(msg tea.MouseWheelMsg) tea.Cmd {
	m.pressed = nil
	if !m.mouseEnabled {
		return nil
	}
	delta := 3
	if msg.Button == tea.MouseWheelUp {
		delta = -3
	} else if msg.Button != tea.MouseWheelDown {
		return nil
	}
	switch m.overlay {
	case "work":
		m.moveWork(delta)
		return nil
	case "help":
		m.helpOffset = max(0, m.helpOffset+delta)
		return nil
	case "targets":
		m.targetIndex = max(0, min(max(0, len(m.settings.Targets)-1), m.targetIndex+delta))
		m.invalidateTargetTest()
		return nil
	case "palette":
		m.paletteIndex = max(0, min(max(0, len(m.paletteActions())-1), m.paletteIndex+delta))
		return nil
	case "":
	default:
		return nil
	}
	if m.page != overview {
		if hit, ok := hitAt(m.hitRegions(), msg.X, msg.Y); ok && (hit.kind == "pane" || hit.kind == "row") {
			m.state().view(m.page).focus = hit.pane
		}
	}
	m.move(delta, false)
	return nil
}
