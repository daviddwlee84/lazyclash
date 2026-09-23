package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/dashboard"
	"time"
)

type action struct {
	id, label string
	keys      []string
	enabled   bool
}
type confirmation struct {
	title, body string
	back        string
	run         func() tea.Cmd
}

func (m *Model) actions() []action {
	connected := m.client != nil && !m.opening
	write := connected && !m.options.ReadOnly && !m.client.IsReadOnly() && m.pending == ""
	selected, hasRow := m.selectedRow()
	group, hasGroup := m.group()
	cfg := m.configData()
	genericWrite := write && m.target.ManagedRPi == nil
	modeWrite := genericWrite && m.knownRoutingMode() && m.state().snap("config").err == nil
	a := []action{
		{"tool-setup", "Setup Mihomo client", nil, m.canRunTool() && !m.options.ReadOnly && m.target.ManagedRPi == nil},
		{"tool-core", "Manage installed cores", nil, m.canRunTool()},
		{"tool-client-service", "Existing target service: status / start / stop / autostart", nil, m.canRunTool() && m.target.ID != "" && !m.target.Transient && !m.target.TransportOverride && m.target.ManagedCoreID == "" && m.target.ManagedRPi == nil},
		{"tool-servers", "Servers / VPS / Tailnet: deploy, manage and share", nil, m.options.Workbench != nil && !m.toolPending},
		{"tool-analytics", "Historical analytics: sources, domains, traffic and activity", nil, m.canRunTool()},
		{"tool-analytics-setup", "Configure historical analytics collection", nil, m.canRunTool() && !m.options.ReadOnly},
		{"tool-network", "Diagnose VPN / TUN / DNS conflicts", nil, m.canRunTool()},
		{"tool-topology", "Routing topology: configuration / current selections", nil, m.canRunTool() && m.target.ID != "" && !m.target.Transient && !m.target.TransportOverride},
		{"tool-checks", "Saved connectivity checks: review / add / edit / run", []string{"C"}, m.canRunTool() && m.target.ID != "" && !m.target.Transient && !m.target.TransportOverride},
		{"tool-source", "Bind node / group configuration source", nil, m.canRunTool() && m.target.ID != "" && !m.target.Transient && !m.target.TransportOverride},
		{"work-inventory", "受管 RPi：查看區網裝置 inventory", nil, m.options.Workbench != nil && m.target.ManagedRPi != nil},
		{"work-compare", "Compare targets / copy selected settings", nil, m.options.Workbench != nil && len(m.settings.Targets) > 1},
		{"work-url", "Diagnose URL and inspect routing topology", nil, m.options.Workbench != nil && m.target.ID != ""},
		{"work-rule", "Preview / add domain rule", nil, m.options.Workbench != nil && m.target.ID != ""},
		{"work-source", "Bind persistent rule source", nil, m.options.Workbench != nil && m.target.ID != ""},
		{"work-receipt", "Verify / restore rule receipt", nil, m.options.Workbench != nil && m.target.ID != ""},
		{"palette", "Open action menu", []string{":"}, true}, {"help", "Show help", []string{"?"}, true}, {"quit", "Quit", []string{"q"}, true},
		{"mouse", "Toggle mouse capture", []string{"M"}, true},
		{"target-test", "Test current target connectivity", nil, m.target.ID != "" && m.options.TestTarget != nil && !m.testPending},
		{"refresh", "Refresh", []string{"r"}, connected}, {"targets", "Choose target", []string{"t"}, len(m.settings.Targets) > 0},
		{"reconnect", "Reconnect current target", nil, m.target.ID != ""},
		{"target-add", "Add target", nil, true}, {"target-edit", "Edit current target", nil, m.target.ID != ""}, {"target-remove", "Remove current target", nil, m.target.ID != ""},
		{"target-default", "Make current target default", nil, m.target.ID != ""}, {"target-up", "Move current target earlier", nil, m.target.ID != ""}, {"target-down", "Move current target later", nil, m.target.ID != ""},
		{"discover", "Discover local controllers", nil, m.options.Discover != nil}, {"discover-ssh", "Discover SSH host", nil, m.options.DiscoverHost != nil},
		{"authenticate", "Authenticate SSH and reconnect", []string{"A"}, m.canAuthenticate()},
		{"mode", "Cycle mode (rule / global / direct)", []string{"m"}, modeWrite},
		{"mode-rule", "Set routing mode: Rule", nil, modeWrite && m.routingMode() != "rule"},
		{"mode-global", "Set routing mode: Global", nil, modeWrite && m.routingMode() != "global"},
		{"mode-direct", "Set routing mode: Direct", nil, modeWrite && m.routingMode() != "direct"},
		{"tun", "Toggle TUN", []string{"u"}, genericWrite && knownBool(object(cfg["tun"]), "enable")},
		{"lan", "Toggle Allow LAN", []string{"a"}, genericWrite && knownBool(cfg, "allow-lan")},
	}
	switch m.page {
	case overview:
		a = append(a, action{"overview-inspect", "Inspect selected metric / group", []string{"enter"}, m.overviewSelection != ""}, action{"history-window", "Cycle history: 1m / 5m / 15m", []string{"w"}, true}, action{"graph-style", "Cycle chart style", []string{"v"}, true}, action{"probe-ip", "Test IP.SB egress", []string{"i"}, !m.options.ReadOnly && m.options.ProbeIP != nil && m.target.ProbeProxy != "" && m.state().probePending == ""}, action{"probe-latency", "Test website latency", []string{"L"}, !m.options.ReadOnly && m.options.ProbeLatency != nil && m.target.ProbeProxy != "" && m.state().probePending == ""})
	case proxies:
		manage := m.canRunTool() && m.target.ID != "" && !m.target.Transient && !m.target.TransportOverride
		node := hasRow && m.state().view(proxies).focus == 1
		a = append(a, action{"tool-proxy-add", "Add proxy", []string{"n"}, manage && !m.options.ReadOnly}, action{"tool-proxy-import", "Import proxy links / YAML", nil, manage && !m.options.ReadOnly}, action{"tool-proxy-edit", "Edit selected proxy", []string{"e"}, manage && node && !m.options.ReadOnly}, action{"tool-proxy-export", "Share selected proxy (URL / JSON / QR)", []string{"y"}, manage && node}, action{"tool-proxy-copy", "Copy selected proxy to another target", nil, manage && node && !m.options.ReadOnly}, action{"tool-proxy-duplicate", "Duplicate selected proxy", nil, manage && node && !m.options.ReadOnly}, action{"tool-group-add", "Add proxy group", nil, manage && !m.options.ReadOnly}, action{"tool-group-edit", "Edit current group", nil, manage && hasGroup && !m.options.ReadOnly})
		a = append(a, action{"select", "Select proxy member", []string{"enter"}, write && hasGroup && selectable(group) && m.state().view(proxies).focus == 1 && hasRow}, action{"delay", "Test selected node delay", []string{"d"}, write && hasRow && m.state().view(proxies).focus == 1}, action{"delay-group", "Test this group's nodes (4 at a time)", []string{"D"}, write && hasGroup})
	case connections:
		a = append(a, action{"close-connection", "Close selected connection", []string{"x"}, write && hasRow && selected.id != ""}, action{"close-all", "Close all connections", []string{"X"}, write})
	case logs:
		a = append(a, action{"log-follow", "Toggle log follow", []string{"space"}, true}, action{"log-clear", "Clear displayed logs", []string{"c"}, true}, action{"log-level", "Cycle log level filter", []string{"v"}, true})
	case providers:
		r, _ := m.selectedRow()
		a = append(a, action{"provider-update", "Update selected provider", []string{"U"}, genericWrite && hasRow}, action{"provider-health", "Healthcheck selected proxy provider", []string{"H"}, genericWrite && hasRow && r.kind == "proxies"})
	case configs:
		a = append(a, action{"config-apply", "Apply complete YAML", []string{"enter"}, genericWrite && hasRow}, action{"config-add", "Register complete YAML path", []string{"n"}, m.target.ID != "" && !m.target.Transient}, action{"config-edit", "Edit registered YAML", []string{"e"}, hasRow && !m.target.Transient}, action{"config-remove", "Remove registered YAML", []string{"x"}, hasRow && !m.target.Transient})
	}
	return a
}
func knownBool(o core.Object, key string) bool { _, ok := o[key].(bool); return ok }
func (m *Model) key(msg tea.KeyPressMsg) tea.Cmd {
	key := msg.String()
	v := m.state().view(m.page)
	if key != "g" {
		m.gPrefix = false
	}
	switch key {
	case "q":
		return tea.Quit
	case "?":
		m.overlay = "help"
		m.helpOffset = 0
		return nil
	case "/":
		return m.beginInput("search", v.query)
	case ":":
		m.paletteIndex = 0
		return m.beginInput("palette", "")
	case "esc":
		v.query = ""
		v.exactFilter = dashboard.Filter{}
		m.gPrefix = false
		return nil
	case "up", "k":
		m.move(-1, false)
		return nil
	case "down", "j":
		m.move(1, false)
		return nil
	case "pgup":
		m.move(-max(m.height-9, 1), false)
		return nil
	case "pgdown":
		m.move(max(m.height-9, 1), false)
		return nil
	case "home":
		m.move(0, true)
		return nil
	case "end", "G":
		if m.page == overview {
			lines, _ := m.overviewLayout(max(1, m.width))
			m.move(len(lines), true)
			return nil
		}
		m.move(len(m.currentRows())-1, true)
		return nil
	case "g":
		if m.gPrefix {
			m.move(0, true)
			m.gPrefix = false
		} else {
			m.gPrefix = true
		}
		return nil
	case "tab", "right", "l":
		m.focus(1)
		return nil
	case "shift+tab", "left", "h":
		m.focus(-1)
		return nil
	case "[":
		return m.changePage((int(m.page) + len(pageNames) - 1) % len(pageNames))
	case "]":
		return m.changePage((int(m.page) + 1) % len(pageNames))
	case "1", "2", "3", "4", "5", "6", "7":
		return m.changePage(int(key[0] - '1'))
	case "enter":
		if m.page == overview && m.overviewSelection != "" {
			return m.activateOverview(m.overviewSelection)
		}
		if m.page == proxies && v.focus == 0 {
			v.focus = 1
			m.reconcile()
			return nil
		}
		if m.page != configs && m.page != proxies {
			v.focus = 1
			return nil
		}
	}
	for _, a := range m.actions() {
		for _, k := range a.keys {
			if k == key {
				if !a.enabled {
					m.status = a.label + ": unavailable (read-only, pending, or no matching data)"
					return nil
				}
				return m.runAction(a.id)
			}
		}
	}
	return nil
}
func (m *Model) focus(direction int) {
	v := m.state().view(m.page)
	n := 2
	if m.page == proxies {
		n = 3
	}
	if m.page == overview {
		_, hits := m.overviewLayout(max(1, m.width))
		if len(hits) > 0 {
			index := -1
			for i, h := range hits {
				if h.id == m.overviewSelection {
					index = i
				}
			}
			if index < 0 && direction < 0 {
				index = 0
			}
			index = (index + direction + len(hits)) % len(hits)
			m.overviewSelection = hits[index].id
			v.detailOffset = max(0, hits[index].y-max(1, m.height-5)/2)
		}
		return
	}
	if m.page == logs {
		n = 1
	}
	v.focus = (v.focus + direction + n) % n
	m.reconcile()
}
func (m *Model) changePage(index int) tea.Cmd {
	m.pressed = nil
	m.page = page(index)
	m.gPrefix = false
	m.reconcile()
	return m.refresh(true)
}
func (m *Model) beginInput(overlay, value string) tea.Cmd {
	m.overlay = overlay
	m.input.SetValue(value)
	m.input.CursorEnd()
	return m.input.Focus()
}
func (m *Model) inputUpdate(msg tea.Msg) tea.Cmd {
	before := m.input.Value()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	if m.overlay == "search" && before != m.input.Value() {
		v := m.state().view(m.page)
		v.query = m.input.Value()
		p := m.currentPosition()
		*p = position{}
		m.reconcile()
	}
	if m.overlay == "palette" && before != m.input.Value() {
		m.paletteIndex = 0
	}
	if m.overlay == "form" && m.form != nil && m.form.index < len(m.form.fields) {
		if before != m.input.Value() {
			m.form.err = ""
			m.invalidateTargetTest()
		}
		m.form.fields[m.form.index].value = m.input.Value()
	}
	return cmd
}
func (m *Model) paletteActions() []action {
	var out []action
	for _, a := range m.actions() {
		if a.enabled && contains(a.label, m.input.Value()) {
			out = append(out, a)
		}
	}
	return out
}
func (m *Model) overlayKey(msg tea.KeyPressMsg) tea.Cmd {
	key := msg.String()
	switch m.overlay {
	case "ssh-auth":
		return m.authenticationKey(msg)
	case "work":
		return m.workKey(msg)
	case "search":
		switch key {
		case "esc":
			m.state().view(m.page).query = ""
			m.overlay = ""
			m.input.Blur()
			return nil
		case "enter":
			m.overlay = ""
			m.input.Blur()
			return nil
		case "up":
			m.move(-1, false)
			return nil
		case "down":
			m.move(1, false)
			return nil
		}
		return m.inputUpdate(msg)
	case "palette":
		switch key {
		case "esc":
			m.overlay = ""
			m.input.Blur()
			return nil
		case "up":
			m.paletteIndex = max(0, m.paletteIndex-1)
			return nil
		case "down":
			m.paletteIndex = min(max(0, len(m.paletteActions())-1), m.paletteIndex+1)
			return nil
		case "enter":
			actions := m.paletteActions()
			if len(actions) == 0 {
				return nil
			}
			a := actions[min(m.paletteIndex, len(actions)-1)]
			m.overlay = ""
			m.input.Blur()
			return m.runAction(a.id)
		}
		return m.inputUpdate(msg)
	case "confirm":
		if key == "esc" || key == "n" {
			m.overlay = ""
			if m.confirm != nil {
				m.overlay = m.confirm.back
			}
			m.confirm = nil
			return nil
		}
		if key == "enter" || key == "y" {
			c := m.confirm
			m.confirm = nil
			m.overlay = ""
			if c != nil {
				return c.run()
			}
		}
		return nil
	case "help":
		switch key {
		case "esc", "?", "q":
			m.overlay = ""
		case "j", "down":
			m.helpOffset++
		case "k", "up":
			m.helpOffset = max(0, m.helpOffset-1)
		}
		return nil
	case "targets":
		if key == "j" || key == "down" || key == "k" || key == "up" || key == "esc" || key == "q" {
			m.invalidateTargetTest()
		}
		switch key {
		case "s":
			if !m.options.ReadOnly {
				return m.toolAction("tool-setup")
			}
		case "c":
			return m.toolAction("tool-core")
		case "T":
			return m.testPickedTarget()

		case "esc", "q":
			m.overlay = ""
		case "j", "down":
			m.targetIndex = min(max(0, len(m.settings.Targets)-1), m.targetIndex+1)
		case "k", "up":
			m.targetIndex = max(0, m.targetIndex-1)
		case "enter":
			if len(m.settings.Targets) > 0 {
				return m.connect(m.settings.Targets[m.targetIndex])
			}
		case "n":
			return m.startTargetForm(false)
		case "e":
			if len(m.settings.Targets) > 0 {
				m.targetIndex = min(m.targetIndex, len(m.settings.Targets)-1)
				return m.startTargetEdit(m.settings.Targets[m.targetIndex])
			}
		}
		return nil
	case "form":
		return m.formKey(msg)
	}
	return nil
}
func (m *Model) mutate(label string, fn func(context.Context, *core.Client) error, applied string) tea.Cmd {
	if m.client == nil || m.pending != "" || m.options.ReadOnly || m.client.IsReadOnly() {
		return nil
	}
	m.pending = label
	m.status = label + " pending…"
	m.state().lastOperation = m.status
	generation, client, ctx := m.generation, m.client, m.ctx
	return func() tea.Msg { err := fn(ctx, client); return writeMsg{generation, label, applied, err} }
}
func (m *Model) ask(title, body string, run func() tea.Cmd) tea.Cmd {
	back := ""
	if m.overlay == "work" || m.overlay == "form" {
		back = m.overlay
	}
	m.confirm = &confirmation{title: title, body: body, run: run, back: back}
	m.overlay = "confirm"
	return nil
}
func (m *Model) runAction(id string) tea.Cmd {
	if strings.HasPrefix(id, "tool-") {
		return m.toolAction(id)
	}
	switch id {
	case "work-inventory":
		return m.launchWork(WorkRequest{Kind: "rpi-inventory", Source: m.target.ID})
	case "work-compare":
		return m.startCompare()
	case "work-url":
		return m.startURLForm()
	case "work-rule":
		return m.startRuleForm()
	case "work-source":
		return m.startRuleSourceForm()
	case "work-receipt":
		return m.startForm("work-receipt", "Verify or restore saved rule receipt", "", []field{{"Receipt ID", ""}, {"Action (verify/restore)", "verify"}})
	case "palette":
		m.paletteIndex = 0
		return m.beginInput("palette", "")
	case "help":
		m.overlay = "help"
		m.helpOffset = 0
		return nil
	case "quit":
		return tea.Quit
	case "overview-inspect":
		return m.activateOverview(m.overviewSelection)
	case "mouse":
		m.mouseEnabled = !m.mouseEnabled
		m.pressed = nil
		m.status = fmt.Sprintf("Mouse capture %t · M toggles terminal text selection", m.mouseEnabled)
		return nil
	case "target-test":
		return m.testTarget(m.target, false)
	case "history-window":
		switch m.historyWindow {
		case time.Minute:
			m.historyWindow = 5 * time.Minute
		case 5 * time.Minute:
			m.historyWindow = 15 * time.Minute
		default:
			m.historyWindow = time.Minute
		}
		return nil
	case "graph-style":
		switch m.graphStyle {
		case "braille":
			m.graphStyle = "block"
		case "block":
			m.graphStyle = "ascii"
		default:
			m.graphStyle = "braille"
		}
		return nil
	case "probe-ip":
		return m.startProbe("ip")
	case "probe-latency":
		return m.startProbe("latency")
	case "refresh":
		return m.refresh(true)
	case "targets":
		m.overlay = "targets"
		for i, t := range m.settings.Targets {
			if t.ID == m.target.ID {
				m.targetIndex = i
			}
		}
		return nil
	case "reconnect":
		return m.connect(m.target)
	case "target-add":
		return m.startTargetForm(false)
	case "target-edit":
		return m.startTargetForm(true)
	case "target-remove":
		return m.ask("Remove target", "Remove "+m.target.Label()+" from lazyclash? The running core is unaffected.", func() tea.Cmd {
			c := cloneSettings(m.settings)
			for i, t := range c.Targets {
				if t.ID == m.target.ID {
					c.Targets = append(c.Targets[:i], c.Targets[i+1:]...)
					break
				}
			}
			if c.DefaultTarget == m.target.ID {
				c.DefaultTarget = ""
			}
			return m.save(c, "")
		})
	case "target-default":
		c := cloneSettings(m.settings)
		c.DefaultTarget = m.target.ID
		return m.save(c, m.target.ID)
	case "target-up", "target-down":
		c := cloneSettings(m.settings)
		for i, t := range c.Targets {
			if t.ID == m.target.ID {
				j := i - 1
				if id == "target-down" {
					j = i + 1
				}
				if j >= 0 && j < len(c.Targets) {
					c.Targets[i], c.Targets[j] = c.Targets[j], c.Targets[i]
				}
				break
			}
		}
		return m.save(c, m.target.ID)
	case "discover":
		m.status = "Discovering local controllers…"
		return m.discover("")
	case "discover-ssh":
		return m.startForm("ssh", "Discover SSH host", "", []field{{label: "SSH host alias", value: ""}})
	case "authenticate":
		return m.showAuthentication()
	case "mode":
		current := str(m.configData(), "mode")
		next := "rule"
		switch strings.ToLower(current) {
		case "rule":
			next = "global"
		case "global":
			next = "direct"
		}
		return m.patch("Set mode to "+next, core.Object{"mode": next})
	case "mode-rule", "mode-global", "mode-direct":
		mode := strings.TrimPrefix(id, "mode-")
		return m.patch("Set mode to "+mode, core.Object{"mode": mode})
	case "tun":
		enabled, _ := object(m.configData()["tun"])["enable"].(bool)
		return m.patch(fmt.Sprintf("Set TUN %t (core state)", !enabled), core.Object{"tun": core.Object{"enable": !enabled}})
	case "lan":
		enabled, _ := m.configData()["allow-lan"].(bool)
		return m.patch(fmt.Sprintf("Set Allow LAN %t", !enabled), core.Object{"allow-lan": !enabled})
	case "select":
		group, ok := m.group()
		r, has := m.selectedRow()
		if !ok || !has || !selectable(group) {
			return nil
		}
		return m.mutate("Select "+r.id+" in "+group.Name, func(ctx context.Context, c *core.Client) error { return c.Select(ctx, group.Name, r.id) }, "")
	case "delay":
		r, ok := m.selectedRow()
		if !ok {
			return nil
		}
		return m.mutate("Measure delay for "+r.id, func(ctx context.Context, c *core.Client) error { _, err := c.Delay(ctx, r.id); return err }, "")
	case "delay-group":
		g, ok := m.group()
		if !ok {
			return nil
		}
		names := append([]string(nil), g.All...)
		return m.mutate("Measure "+g.Name+" nodes", func(ctx context.Context, c *core.Client) error { return delayAll(ctx, c, names) }, "")
	case "close-connection":
		r, ok := m.selectedRow()
		if !ok || r.id == "" {
			return nil
		}
		return m.mutate("Close connection "+r.id, func(ctx context.Context, c *core.Client) error { return c.CloseConnections(ctx, r.id) }, "")
	case "close-all":
		return m.ask("Close all connections", "Target: "+m.target.Label()+"\nDisconnect every current connection? Applications may reconnect.", func() tea.Cmd {
			return m.mutate("Close all connections", func(ctx context.Context, c *core.Client) error { return c.CloseConnections(ctx, "") }, "")
		})
	case "log-follow":
		s := m.state()
		s.follow = !s.follow
		if s.follow {
			m.move(len(m.currentRows())-1, true)
			s.follow = true
		}
		return nil
	case "log-clear":
		m.state().logs = nil
		m.state().view(logs).positions[0] = position{}
		return nil
	case "log-level":
		levels := []string{"", "debug", "info", "warning", "error", "silent"}
		s := m.state()
		for i, l := range levels {
			if s.logLevel == l {
				s.logLevel = levels[(i+1)%len(levels)]
				break
			}
		}
		m.reconcile()
		return nil
	case "provider-update", "provider-health":
		r, ok := m.selectedRow()
		if !ok {
			return nil
		}
		kind, name := r.kind, r.detail
		return m.mutate(id+" "+name, func(ctx context.Context, c *core.Client) error {
			if id == "provider-health" {
				return c.HealthcheckProvider(ctx, name)
			}
			return c.UpdateProvider(ctx, kind, name)
		}, "")
	case "config-add":
		return m.startConfigForm(false)
	case "config-edit":
		return m.startConfigForm(true)
	case "config-remove":
		r, ok := m.selectedRow()
		if !ok {
			return nil
		}
		return m.ask("Remove YAML registration", "Remove "+r.label+" from "+m.target.Label()+"? The YAML file is unaffected.", func() tea.Cmd {
			c := cloneSettings(m.settings)
			for i := range c.Targets {
				if c.Targets[i].ID != m.target.ID {
					continue
				}
				for j, cc := range c.Targets[i].Configs {
					if cc.ID == r.id {
						c.Targets[i].Configs = append(c.Targets[i].Configs[:j], c.Targets[i].Configs[j+1:]...)
						break
					}
				}
			}
			return m.save(c, m.target.ID)
		})
	case "config-apply":
		r, ok := m.selectedRow()
		if !ok {
			return nil
		}
		return m.ask("Apply complete YAML", "Target: "+m.target.Label()+"\nCore host path: "+r.detail+"\n\nLoads runtime settings and listener ports. Does not change the startup config or Verge profile. Verge may overwrite it later. Connection loss leaves the result uncertain.", func() tea.Cmd {
			return m.mutate("Apply "+r.label, func(ctx context.Context, c *core.Client) error { _, err := c.ApplyConfig(ctx, r.detail); return err }, r.detail)
		})
	}
	return nil
}
func (m *Model) patch(label string, patch core.Object) tea.Cmd {
	return m.mutate(label, func(ctx context.Context, c *core.Client) error { _, err := c.SetConfig(ctx, patch); return err }, "")
}
