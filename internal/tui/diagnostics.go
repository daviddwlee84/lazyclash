package tui

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
)

type targetTestMsg struct {
	generation, serial uint64
	targetID           string
	draft              bool
	result             string
	err                error
}
type probeMsg struct {
	generation             uint64
	targetID, kind, result string
	err                    error
}

func (m *Model) invalidateTargetTest() {
	if m.testCancel != nil {
		m.testCancel()
		m.testCancel = nil
	}
	m.testSerial++
	m.testPending = false
	m.testResult = ""
}
func (m *Model) testDraft() tea.Cmd {
	if m.form == nil || m.form.kind != "target" {
		return nil
	}
	if m.form.index < len(m.form.fields) {
		m.form.fields[m.form.index].value = m.input.Value()
	}
	t := m.draftTarget()
	if err := config.ValidateTarget(t); err != nil {
		m.form.err = safeError(err)
		return nil
	}
	m.form.err = ""
	return m.testTarget(t, true)
}
func (m *Model) testPickedTarget() tea.Cmd {
	if len(m.settings.Targets) == 0 {
		return nil
	}
	return m.testTarget(m.settings.Targets[min(m.targetIndex, len(m.settings.Targets)-1)], false)
}
func (m *Model) testTarget(target config.Target, draft bool) tea.Cmd {
	if m.options.TestTarget == nil || m.testPending {
		return nil
	}
	m.testSerial++
	m.testPending = true
	m.testResult = "Testing controller connectivity…"
	m.status = m.testResult
	generation, serial, run := m.generation, m.testSerial, m.options.TestTarget
	ctx, cancel := context.WithTimeout(m.ctx, 20*time.Second)
	m.testCancel = cancel
	return func() tea.Msg {
		defer cancel()
		result, err := run(ctx, target)
		return targetTestMsg{generation, serial, target.ID, draft, result, err}
	}
}
func (m *Model) receiveTargetTest(msg targetTestMsg) tea.Cmd {
	if msg.generation != m.generation || msg.serial != m.testSerial {
		return nil
	}
	if msg.draft && (m.overlay != "form" || m.form == nil || m.form.kind != "target") {
		return nil
	}
	m.testPending = false
	if m.testCancel != nil {
		m.testCancel()
		m.testCancel = nil
	}
	m.testResult = msg.result
	if msg.err != nil {
		m.testResult += "\nTest failed: " + safeError(msg.err)
	}
	m.status = "Connectivity · " + msg.targetID + " · " + m.testResult
	return nil
}
func (m *Model) startProbe(kind string) tea.Cmd {
	if m.options.ReadOnly || m.target.ProbeProxy == "" || m.state().probePending != "" {
		return nil
	}
	run := m.options.ProbeIP
	if kind == "latency" {
		run = m.options.ProbeLatency
	}
	if run == nil {
		return nil
	}
	m.state().probePending = kind
	m.status = "Testing " + kind + " through configured data proxy…"
	generation, target, ctx := m.generation, m.target, m.ctx
	return func() tea.Msg {
		result, err := run(ctx, target)
		return probeMsg{generation, target.ID, kind, result, err}
	}
}
func (m *Model) receiveProbe(msg probeMsg) tea.Cmd {
	if msg.generation != m.generation || msg.targetID != m.target.ID {
		return nil
	}
	m.state().probePending = ""
	result := msg.result
	if msg.err != nil {
		result += "\nFailed: " + safeError(msg.err)
	}
	if msg.kind == "ip" {
		m.state().probeIP = result
	} else {
		m.state().probeLatency = result
	}
	m.status = "Probe finished · " + msg.kind
	return nil
}
