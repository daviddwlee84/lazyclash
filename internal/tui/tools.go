package tui

import (
	"context"
	"errors"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/wizard"
)

// terminalTask uses Bubble Tea's supported terminal release/reacquire protocol.
// The same command/wizard runs from both entry points; no second terminal reader
// competes with the dashboard.
type terminalTask struct {
	ctx         context.Context
	args        []string
	run         func(context.Context, []string, io.Reader, io.Writer, io.Writer) error
	pause       func(context.Context, string, io.Reader, io.Writer) error
	in          io.Reader
	out, errOut io.Writer
	viewOnly    bool
}

func (t *terminalTask) SetStdin(in io.Reader)   { t.in = in }
func (t *terminalTask) SetStdout(out io.Writer) { t.out = out }
func (t *terminalTask) SetStderr(out io.Writer) { t.errOut = out }
func (t *terminalTask) Run() error {
	err := t.run(t.ctx, t.args, t.in, t.out, t.errOut)
	if errors.Is(err, wizard.ErrCanceled) || errors.Is(err, context.Canceled) {
		return err
	}
	if t.viewOnly && err == nil {
		return nil
	}
	label := "Operation finished"
	if err != nil {
		label = "Operation did not complete"
		fmt.Fprintln(t.errOut, safeError(err))
	}
	pause := t.pause
	if pause == nil {
		pause = wizard.Pause
	}
	if pauseErr := pause(t.ctx, label, t.in, t.errOut); pauseErr != nil && err == nil {
		return pauseErr
	}
	return err
}

type toolMsg struct {
	generation, serial uint64
	label              string
	err                error
}
type toolSettingsMsg struct {
	toolMsg
	settings config.Config
	loadErr  error
}

func (m *Model) canRunTool() bool {
	return m.options.RunCommand != nil && !m.toolPending && (!m.opening || m.serverWork()) && m.pending == "" && !m.authPending() && (m.work == nil || !m.work.pending)
}
func (m *Model) runTool(label string, targeted bool, args ...string) tea.Cmd {
	if !m.canRunTool() {
		return nil
	}
	if m.overlay != "" && m.overlay != "palette" && m.overlay != "targets" && !(m.overlay == "work" && m.serverWork()) {
		return nil
	}
	m.toolReturnServers = m.overlay == "work" && m.serverWork()
	if targeted {
		if m.target.ID == "" || m.target.Transient || m.target.TransportOverride {
			m.status = "Save this target before managing its persistent configuration"
			return nil
		}
		args = toolTargetArgs(m.target, args)
	}
	m.invalidateTargetTest()
	m.input.Blur()
	m.pressed = nil
	m.toolSerial++
	m.toolPending = true
	m.overlay = "external-tool"
	m.status = label
	request := toolMsg{generation: m.generation, serial: m.toolSerial, label: label}
	task := &terminalTask{ctx: m.ctx, args: append([]string(nil), args...), run: m.options.RunCommand, viewOnly: label == "Routing topology" || label == "Historical analytics"}
	return tea.Exec(task, func(err error) tea.Msg { request.err = err; return request })
}

func toolTargetArgs(target config.Target, args []string) []string {
	prefix := []string{"--target", target.ID}
	for _, reference := range []struct{ name, value string }{{"--secret-env", target.SecretEnv}, {"--secret-file", target.SecretFile}, {"--ca-cert", target.CAFile}} {
		if reference.value != "" {
			prefix = append(prefix, reference.name, reference.value)
		}
	}
	return append(prefix, args...)
}
func (m *Model) receiveTool(msg toolMsg) tea.Cmd {
	if msg.serial != m.toolSerial || !m.toolPending {
		return nil
	}
	if msg.generation != m.generation {
		m.toolPending = false
		if m.overlay == "external-tool" {
			m.overlay = ""
		}
		m.pressed = nil
		return nil
	}
	m.toolPending = false
	m.overlay = ""
	m.pressed = nil
	if msg.label == "Import proxies" || msg.label == "Add proxy" {
		// The shared wizard may write several targets. Invalidate cached data
		// even after a partial result, then refresh the visible target normally.
		for _, state := range m.states {
			for _, key := range []string{"config", "proxies", "rules", "proxyProviders", "ruleProviders"} {
				snap := state.snap(key)
				snap.err = errors.New("import finished; awaiting refresh")
				snap.loading = false
				snap.serial++
			}
		}
	}
	if errors.Is(msg.err, wizard.ErrCanceled) {
		m.status = msg.label + " canceled"
	} else if msg.err != nil {
		m.status = msg.label + ": " + safeError(msg.err)
	} else {
		m.status = msg.label + " completed"
	}
	if m.toolReturnServers {
		m.toolReturnServers = false
		m.overlay = "work"
		return tea.Batch(m.refreshServerWork(false), m.refresh(true))
	}
	if m.options.ReloadTargets == nil {
		return m.refresh(true)
	}
	reload := m.options.ReloadTargets
	return func() tea.Msg {
		settings, err := reload()
		return toolSettingsMsg{toolMsg: msg, settings: settings, loadErr: err}
	}
}
func (m *Model) receiveToolSettings(msg toolSettingsMsg) tea.Cmd {
	if msg.generation != m.generation || msg.serial != m.toolSerial {
		return nil
	}
	if msg.loadErr != nil {
		m.status = "Reload settings: " + safeError(msg.loadErr)
		return nil
	}
	previous := map[string]bool{}
	for _, t := range m.settings.Targets {
		previous[t.ID] = true
	}
	old := m.target
	m.settings = cloneSettings(msg.settings)
	var added *config.Target
	for _, t := range m.settings.Targets {
		if !previous[t.ID] {
			copy := t
			if added != nil {
				added = nil
				break
			}
			added = &copy
		}
	}
	if added != nil && msg.err == nil && msg.label == "Setup Mihomo" {
		return m.connect(*added)
	}
	for _, t := range m.settings.Targets {
		if t.ID == old.ID {
			m.target = t
			if !sameConnection(old, t) {
				return m.connect(t)
			}
			return m.refresh(true)
		}
	}
	if old.Transient {
		m.target = old
		return m.refresh(true)
	}
	if len(m.settings.Targets) > 0 {
		return m.connect(m.settings.Targets[0])
	}
	if m.cancel != nil {
		m.cancel()
	}
	command := cleanup(m.client, m.closer)
	m.client, m.closer = nil, nil
	m.target = config.Target{}
	m.generation++
	m.opening = false
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.status = "No targets. Press : to set up or discover a core."
	return command
}
func (m *Model) toolAction(id string) tea.Cmd {
	if m.options.ReadOnly {
		switch id {
		case "tool-setup", "tool-proxy-add", "tool-proxy-import", "tool-proxy-edit", "tool-proxy-copy", "tool-proxy-duplicate", "tool-group-add", "tool-group-edit":
			return nil
		}
	}
	r, has := m.selectedRow()
	switch id {
	case "tool-analytics":
		return m.runTool("Historical analytics", false, "analytics", "report", "--interactive")
	case "tool-analytics-setup":
		if m.options.ReadOnly {
			return nil
		}
		return m.runTool("Configure analytics", false, "analytics", "setup", "--interactive")
	case "tool-servers":
		return m.startServers()
	case "tool-setup":
		if m.target.ManagedRPi != nil {
			m.status = "受管 RPi 安裝及服務生命週期由 RPi-ImmortalWrt 管理"
			return nil
		}
		return m.runTool("Setup Mihomo", false, "setup", "--interactive")
	case "tool-client-service":
		if m.options.ReadOnly {
			return m.runTool("Existing service status", true, "targets", "service", "status")
		}
		return m.runTool("Existing target service", true, "targets", "service", "--interactive")
	case "tool-core":
		target := m.target
		if m.overlay == "targets" && m.targetIndex >= 0 && m.targetIndex < len(m.settings.Targets) {
			target = m.settings.Targets[m.targetIndex]
		}
		if target.ManagedCoreID != "" && !m.options.ReadOnly {
			return m.runTool("Configure managed core", false, "cores", "configure", target.ManagedCoreID, "--interactive")
		}
		return m.runTool("Managed cores", false, "cores", "list")
	case "tool-checks":
		return m.runTool("Saved connectivity checks", true, "diagnostics", "checks", "--interactive")
	case "tool-network":
		if m.target.ID != "" && !m.target.Transient && !m.target.TransportOverride {
			return m.runTool("Network diagnosis", true, "diagnostics", "network")
		}
		return m.runTool("Network diagnosis", false, "diagnostics", "network")
	case "tool-source":
		return m.runTool("Bind configuration source", true, "configs", "source", "set", "--interactive")
	case "tool-topology":
		return m.runTool("Routing topology", true, "topology", "--interactive")
	case "tool-proxy-add":
		return m.runTool("Add proxy", true, "proxies", "add", "--interactive")
	case "tool-proxy-import":
		return m.runTool("Import proxies", true, "proxies", "import", "--interactive")
	case "tool-proxy-edit", "tool-proxy-copy", "tool-proxy-duplicate", "tool-proxy-export":
		if !has {
			return nil
		}
		verb := map[string]string{"tool-proxy-edit": "edit", "tool-proxy-copy": "copy", "tool-proxy-duplicate": "duplicate", "tool-proxy-export": "export"}[id]
		return m.runTool("Proxy "+verb, true, "proxies", verb, r.id, "--interactive")
	case "tool-group-add":
		return m.runTool("Add group", true, "groups", "add", "--interactive")
	case "tool-group-edit":
		group, ok := m.group()
		if !ok {
			return nil
		}
		return m.runTool("Edit group", true, "groups", "edit", group.Name, "--interactive")
	}
	return nil
}
