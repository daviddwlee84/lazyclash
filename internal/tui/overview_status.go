package tui

import (
	"net"
	"net/url"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

var routingModes = []struct{ value, label, description string }{
	{"rule", "Rule", "Rule: follow routing rules."},
	{"global", "Global", "Global: use the GLOBAL group."},
	{"direct", "Direct", "Direct: connect without a proxy."},
}

func (m *Model) routingMode() string {
	return strings.ToLower(str(m.configData(), "mode"))
}

func (m *Model) knownRoutingMode() bool {
	for _, mode := range routingModes {
		if m.routingMode() == mode.value {
			return true
		}
	}
	return false
}

// Scope is the selected controller endpoint, not an assertion about every
// process or the operating system's system-proxy settings on this machine.
func (m *Model) controllerScope() string {
	if m.target.SSHHost != "" {
		return "SSH CONTROLLER"
	}
	if m.target.Controller == "" {
		return "NO CONTROLLER"
	}
	u, err := url.Parse(m.target.Controller)
	if err == nil && (u.Scheme == "unix" || strings.EqualFold(u.Hostname(), "localhost") || net.ParseIP(u.Hostname()).IsLoopback()) {
		return "LOCAL CONTROLLER"
	}
	return "REMOTE CONTROLLER"
}

func (m *Model) controllerStatus() string {
	switch {
	case m.opening:
		return "CONNECTING"
	case m.currentAuth():
		return "SSH AUTH REQUIRED"
	case m.client == nil:
		return "OFFLINE"
	case m.state().snap("config").err != nil:
		return "STALE"
	case m.state().snap("config").data == nil:
		return "LOADING"
	default:
		return "CONNECTED"
	}
}

// The controls and their hit regions share the exact panel layout, including
// wrapping in narrow terminals. Selecting a named mode never cycles through an
// intermediate mode, and only enabled controls receive clickable regions.
func (m *Model) overviewStatusLayout(width int) ([]string, []hitRegion) {
	border := 1
	if width < 4 {
		border = 0
	}
	inner := max(1, width-2*border)
	state := m.controllerStatus()
	title := m.controllerScope() + " · " + state
	if m.options.ReadOnly || m.client != nil && m.client.IsReadOnly() {
		title += " · READ-ONLY"
	}
	target := "Target: " + core.Sanitize(defaultString(m.target.Label(), "none"))
	if m.target.SSHHost != "" {
		target += " · " + core.Sanitize(m.target.SSHHost)
	}
	body := []string{target}
	var hits []hitRegion
	enabled := map[string]bool{}
	for _, action := range m.actions() {
		enabled[action.id] = action.enabled
	}
	mode := m.routingMode()
	row := "Mode: "
	x := ansi.StringWidth(row)
	for _, option := range routingModes {
		label := "[" + option.label + "]"
		if mode == option.value {
			label = "[* " + option.label + "]"
		} else if !enabled["mode-"+option.value] {
			label = "(" + option.label + ")"
		}
		w := ansi.StringWidth(label)
		if x+w > inner && x > 0 {
			body = append(body, row)
			row, x = "", 0
		}
		if enabled["mode-"+option.value] && w <= inner {
			hits = append(hits, hitRegion{rect: rect{border + x, 1 + len(body), w, 1}, kind: "action", id: "mode-" + option.value})
		}
		if mode == option.value {
			label = m.accent(label)
		}
		row += label + " "
		x += w + 1
	}
	if x+len("m cycle") <= inner {
		row += "m cycle"
	}
	body = append(body, row)
	description := "Waiting for routing state."
	for _, option := range routingModes {
		if mode == option.value {
			description = option.description
			if state != "CONNECTED" {
				description = "Last mode: " + option.label + " · " + state
			}
		}
	}
	if m.pending != "" {
		description = "Pending: " + core.Sanitize(m.pending)
	}
	body = append(body, description)
	cfg := m.configData()
	status := "TUN (core): " + boolLabel(object(cfg["tun"]), "enable") + " · LAN: " + boolLabel(cfg, "allow-lan")
	port := str(cfg, "mixed-port")
	if port == "0" {
		port = "off"
	}
	port = "Mixed port: " + defaultString(port, "?")
	if ansi.StringWidth(status+" · "+port) <= inner {
		body = append(body, status+" · "+port)
	} else {
		body = append(body, status, port)
	}
	return panel(m.accent(title), body, width), hits
}
