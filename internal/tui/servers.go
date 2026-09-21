package tui

import (
	"context"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

const serverHelpText = "Servers / VPS\n↑↓ or j/k select · Tab switches list/details · Enter inspects selected remote status\nr reloads local inventory and refreshes selected row · a opens shared CLI actions\nn deploys to an existing SSH host or creates a cloud VPS · t registers a Tailnet device or sets up an exit · p deploys a Tailnet proxy\nTailnet actions select/release exits or manage owned proxies without stopping Tailscale.\nProxy-service start/stop/remove and VPS power/delete are separate actions. Stopped VMs can still be billed.\nExports contain credentials. Client import previews the selected persistent configuration source.\nEsc returns from help, then closes the view; pending reads are canceled and late results are discarded."

func (m *Model) serverWork() bool {
	return m.work != nil && strings.HasPrefix(m.work.request.Kind, "servers-")
}

func (m *Model) startServers() tea.Cmd {
	if m.options.Workbench == nil || m.toolPending {
		return nil
	}
	if m.work != nil && m.work.cancel != nil {
		m.work.cancel()
	}
	m.work = &workState{request: WorkRequest{Kind: "servers-list"}, phase: "result", checked: map[string]bool{}, result: WorkResult{Title: "Servers / VPS", Summary: "Loading saved inventory…"}}
	m.overlay = "work"
	m.input.Blur()
	return m.refreshServerWork(false)
}

func (m *Model) selectedServerRow() (WorkRow, bool) {
	if !m.serverWork() || m.work.index < 0 || m.work.index >= len(m.work.result.Rows) {
		return WorkRow{}, false
	}
	return m.work.result.Rows[m.work.index], true
}

// The inventory read is separate from remote observation: its result can render
// before SSH or a cloud CLI responds, and navigation stays usable during I/O.
func (m *Model) refreshServerWork(remote bool) tea.Cmd {
	if !m.serverWork() || m.work.pending || m.options.Workbench == nil {
		return nil
	}
	req := WorkRequest{Kind: "servers-list"}
	if remote {
		row, ok := m.selectedServerRow()
		if !ok {
			return nil
		}
		req.Kind, req.Receipt = "servers-status", row.ID
	}
	m.workSerial++
	ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
	m.work.request = req
	m.work.pending = true
	m.work.serial = m.workSerial
	m.work.cancel = cancel
	if remote {
		m.status = "Refreshing selected server / VPS…"
	} else {
		m.status = "Loading saved servers / VPS…"
	}
	generation, serial, run := m.generation, m.workSerial, m.options.Workbench
	return func() tea.Msg {
		defer cancel()
		result, err := run(ctx, req)
		return workMsg{generation: generation, serial: serial, result: result, err: err}
	}
}

func (m *Model) receiveServerWork(msg workMsg) tea.Cmd {
	w := m.work
	selected, _ := m.selectedServerRow()
	w.pending = false
	w.cancel = nil
	if msg.err == nil || len(msg.result.Rows) > 0 {
		w.result = msg.result
		w.index = min(w.index, max(0, len(w.result.Rows)-1))
		for i, row := range w.result.Rows {
			if row.ID == selected.ID {
				w.index = i
				break
			}
		}
	}
	if msg.err != nil {
		w.result.Summary += "\nRefresh failed; saved inventory retained: " + safeError(msg.err)
		m.status = "Server refresh failed"
		return nil
	}
	m.status = "Servers / VPS inventory ready"
	if w.request.Kind == "servers-list" && len(w.result.Rows) > 0 {
		return m.refreshServerWork(true)
	}
	return nil
}

func (m *Model) serverButtons() []button {
	_, has := m.selectedServerRow()
	idle := !m.toolPending
	return []button{{"server-deploy", "n Deploy", idle && !m.options.ReadOnly}, {"server-tailnet", "t Tailnet", idle && !m.options.ReadOnly}, {"server-tailnet-proxy", "p Proxy", idle && !m.options.ReadOnly}, {"server-actions", "a Actions", idle && has}, {"server-refresh", "r Refresh", idle}, {"server-help", "? Help", true}}
}

func (m *Model) serverButton(id string) tea.Cmd {
	if !m.serverWork() {
		return nil
	}
	if id == "server-help" {
		m.work.serverHelp = !m.work.serverHelp
		return nil
	}
	if m.toolPending {
		return nil
	}
	if m.work.pending {
		if m.work.cancel != nil {
			m.work.cancel()
		}
		m.workSerial++
		m.work.serial = m.workSerial
		m.work.pending = false
		m.work.cancel = nil
	}
	switch id {
	case "server-deploy":
		if !m.options.ReadOnly {
			return m.runTool("Deploy proxy server", false, "servers", "deploy", "--interactive")
		}
	case "server-tailnet":
		if !m.options.ReadOnly {
			return m.runTool("Set up Tailnet device", false, "tailnet", "setup", "--interactive")
		}
	case "server-tailnet-proxy":
		if !m.options.ReadOnly {
			return m.runTool("Deploy Tailnet proxy", false, "tailnet", "proxy", "deploy", "--interactive")
		}
	case "server-refresh":
		return m.refreshServerWork(false)
	case "server-status":
		return m.refreshServerWork(true)
	case "server-actions":
		row, ok := m.selectedServerRow()
		if !ok {
			return nil
		}
		kind, serverID, _ := strings.Cut(row.ID, ":")
		if kind == "server" {
			return m.runTool("Manage proxy server", false, "servers", "manage", serverID, "--interactive")
		}
		if kind == "tailnet" {
			return m.runTool("Manage Tailnet exit", false, "tailnet", "exit", "manage", serverID, "--interactive")
		}
		if kind == "tailnet-proxy" {
			return m.runTool("Manage Tailnet proxy", false, "tailnet", "proxy", "manage", serverID, "--interactive")
		}
		if kind == "host" {
			return m.runTool("Manage VPS", false, "vps", "manage", serverID, "--interactive")
		}
	}
	return nil
}

func (m *Model) serverKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	key := msg.String()
	if (key == "esc" || key == "q") && m.work.serverHelp {
		m.work.serverHelp = false
		return true, nil
	}
	if key != "g" {
		m.gPrefix = false
	}
	switch key {
	case "g":
		if m.gPrefix {
			m.work.index = 0
			m.work.offset = 0
			m.gPrefix = false
		} else {
			m.gPrefix = true
		}
		return true, nil
	case "h", "left":
		m.work.focus = 0
		return true, nil
	case "l", "right":
		m.work.focus = 1
		return true, nil
	}
	for _, binding := range []struct{ key, id string }{{"n", "server-deploy"}, {"t", "server-tailnet"}, {"p", "server-tailnet-proxy"}, {"a", "server-actions"}, {"r", "server-refresh"}, {"enter", "server-status"}, {"?", "server-help"}} {
		if msg.String() == binding.key {
			return true, m.serverButton(binding.id)
		}
	}
	return false, nil
}
