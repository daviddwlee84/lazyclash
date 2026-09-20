package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

type row struct {
	id, label, detail, kind string
	data                    core.Object
}

func (m *Model) proxyData() map[string]core.Proxy {
	v, _ := m.state().snap("proxies").data.(map[string]core.Proxy)
	return v
}
func (m *Model) configData() core.Object { return object(m.state().snap("config").data) }
func (m *Model) group() (core.Proxy, bool) {
	v := m.state().view(proxies)
	rows := m.rowsFor(proxies, 0)
	pos := resolvePosition(&v.positions[0], rows)
	if pos < 0 {
		return core.Proxy{}, false
	}
	p, ok := m.proxyData()[rows[pos].id]
	return p, ok
}
func (m *Model) rowsFor(p page, pane int) []row {
	s := m.state()
	v := s.view(p)
	var rows []row
	switch p {
	case proxies:
		all := m.proxyData()
		if pane == 0 {
			for _, name := range sortedKeys(all) {
				p := all[name]
				if len(p.All) == 0 && !isGroup(p.Type) {
					continue
				}
				rows = append(rows, row{id: name, label: name + "  → " + p.Now, detail: p.Type})
			}
		} else {
			group, ok := m.group()
			if !ok {
				return nil
			}
			for _, name := range group.All {
				p := all[name]
				mark := "  "
				if name == group.Now {
					mark = "* "
				}
				delay := "?"
				if len(p.History) > 0 {
					h := p.History[len(p.History)-1]
					if h.Delay > 0 {
						delay = fmt.Sprintf("%d ms", h.Delay)
					} else {
						delay = "timeout"
					}
				}
				rows = append(rows, row{id: name, label: mark + name + "  " + delay, detail: p.Type})
			}
		}
	case connections:
		obj := object(s.snap("connections").data)
		for _, item := range array(obj["connections"]) {
			c := object(item)
			if !v.exactFilter.Match(c) {
				continue
			}
			id, _ := c["id"].(string)
			metadata := object(c["metadata"])
			host := str(metadata, "host")
			if host == "" {
				host = str(metadata, "destinationIP")
			}
			port := str(metadata, "destinationPort")
			if port != "" {
				host += ":" + port
			}
			rows = append(rows, row{id: id, label: host + "  " + str(c, "rule"), detail: str(metadata, "sourceIP"), data: c})
		}
		sort.SliceStable(rows, func(i, j int) bool { return str(rows[i].data, "start") < str(rows[j].data, "start") })
	case logs:
		for _, entry := range s.logs {
			if s.logLevel != "" && s.logLevel != entry.level {
				continue
			}
			rows = append(rows, row{id: strconv.Itoa(entry.id), label: entry.at.Format("15:04:05") + " " + entry.level + " " + entry.message, detail: entry.message})
		}
	case rules:
		obj := object(s.snap("rules").data)
		for i, item := range array(obj["rules"]) {
			r := object(item)
			rows = append(rows, row{id: strconv.Itoa(i), label: fmt.Sprintf("%d  %s  %s → %s", i+1, str(r, "type"), str(r, "payload"), str(r, "proxy")), data: r})
		}
	case providers:
		for _, kind := range []string{"proxies", "rules"} {
			key := "proxyProviders"
			if kind == "rules" {
				key = "ruleProviders"
			}
			obj := object(s.snap(key).data)
			collection := object(obj["providers"])
			if collection == nil {
				collection = obj
			}
			for _, name := range sortedKeys(collection) {
				provider := object(collection[name])
				if provider == nil {
					continue
				}
				rows = append(rows, row{id: kind + ":" + name, label: kind + "  " + name, kind: kind, detail: name, data: provider})
			}
		}
	case configs:
		for _, c := range m.target.Configs {
			name := c.Name
			if name == "" {
				name = c.ID
			}
			rows = append(rows, row{id: c.ID, label: name, detail: c.Path})
		}
	}
	// In Proxies, search belongs to the focused list so searching a member does
	// not inadvertently remove its parent group.
	if v.query != "" && (p != proxies || v.focus == pane) {
		filtered := rows[:0]
		for _, r := range rows {
			if contains(r.label+" "+r.detail, v.query) {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	return rows
}
func isGroup(kind string) bool {
	switch strings.ToLower(kind) {
	case "selector", "urltest", "fallback", "loadbalance", "load-balance", "url-test", "relay":
		return true
	}
	return false
}
func selectable(p core.Proxy) bool {
	switch strings.ToLower(p.Type) {
	case "selector", "urltest", "url-test", "fallback":
		return true
	}
	return false
}
func array(v any) []any { a, _ := v.([]any); return a }
func resolvePosition(pos *position, rows []row) int {
	if len(rows) == 0 {
		return -1
	}
	if pos.selected != "" {
		for i, r := range rows {
			if r.id == pos.selected {
				return i
			}
		}
	}
	return min(max(pos.index, 0), len(rows)-1)
}
func (m *Model) currentRows() []row {
	v := m.state().view(m.page)
	pane := v.focus
	if m.page != proxies || pane == 2 {
		pane = 0
	}
	return m.rowsFor(m.page, pane)
}
func (m *Model) currentPosition() *position {
	v := m.state().view(m.page)
	pane := v.focus
	if m.page != proxies || pane == 2 {
		pane = 0
	}
	return &v.positions[pane]
}
func (m *Model) selectedRow() (row, bool) {
	rows := m.currentRows()
	i := resolvePosition(m.currentPosition(), rows)
	if i < 0 {
		return row{}, false
	}
	return rows[i], true
}
func (m *Model) reconcile() {
	v := m.state().view(m.page)
	for pane := 0; pane < 2; pane++ {
		if m.page != proxies && pane > 0 {
			break
		}
		rows := m.rowsFor(m.page, pane)
		pos := &v.positions[pane]
		index := resolvePosition(pos, rows)
		if index < 0 {
			pos.selected = ""
			pos.index = 0
			pos.offset = 0
		} else {
			pos.index = index
			pos.selected = rows[index].id
			pos.offset = min(pos.offset, index)
		}
	}
}
func (m *Model) move(n int, absolute bool) {
	v := m.state().view(m.page)
	if m.page == overview || (m.page == proxies && v.focus == 2) || (m.page != proxies && m.page != logs && v.focus == 1) {
		if absolute {
			v.detailOffset = max(0, n)
		} else {
			v.detailOffset = max(0, v.detailOffset+n)
		}
		if m.page == overview {
			lines, _ := m.overviewLayout(max(1, m.width))
			v.detailOffset = min(v.detailOffset, max(0, len(lines)-max(1, m.height-5)))
		}
		return
	}
	rows := m.currentRows()
	if len(rows) == 0 {
		return
	}
	pos := m.currentPosition()
	i := resolvePosition(pos, rows)
	if absolute {
		i = n
	} else {
		i += n
	}
	i = min(max(i, 0), len(rows)-1)
	pos.index, pos.selected = i, rows[i].id
	if m.page == logs {
		m.state().follow = false
	}
}
func (m *Model) details(p page) string {
	s := m.state()
	if p == proxies {
		group, ok := m.group()
		if !ok {
			return "Select a proxy group."
		}
		v := s.view(proxies)
		if v.focus == 0 {
			return "Group: " + group.Name + "\nType: " + group.Type + "\nCurrent: " + group.Now + "\n\nEnter or Tab to choose a member.\n* marks the current member."
		}
		rows := m.rowsFor(proxies, 1)
		i := resolvePosition(&v.positions[1], rows)
		if i < 0 {
			return "No matching members."
		}
		p, ok := m.proxyData()[rows[i].id]
		if !ok {
			return "Member: " + rows[i].id + "\nDetails unavailable"
		}
		alive := "unknown"
		if p.Alive != nil {
			alive = strconv.FormatBool(*p.Alive)
		}
		out := "Node: " + p.Name + "\nType: " + p.Type + "\nAlive: " + alive + "\nUDP: " + strconv.FormatBool(p.UDP) + "\n\nGroup: " + group.Name + "\nCurrent: " + group.Now
		if len(p.History) > 0 {
			h := p.History[len(p.History)-1]
			out += fmt.Sprintf("\nLast delay: %d ms\nMeasured: %s", h.Delay, h.Time)
		} else {
			out += "\nDelay: not measured"
		}
		if !selectable(group) {
			out += "\n\nThis group has no manual selection."
		}
		return out
	}
	r, ok := m.selectedRow()
	if !ok {
		return "No item selected."
	}
	if p == configs {
		return "Core host path:\n" + r.detail + "\n\nApply loads the complete YAML, including listener ports. It changes runtime state only. It does not update the core startup source or Verge's selected profile. Verge may overwrite this state later.\n\nLast applied by lazyclash:\n" + defaultString(s.lastApplied, "none this session")
	}
	if p == logs {
		return r.detail
	}
	data, err := json.MarshalIndent(core.Redact(r.data), "", "  ")
	if err != nil {
		return safeError(err)
	}
	return core.Sanitize(string(data))
}
func defaultString(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
