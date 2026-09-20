package tui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type authState struct {
	generation, serial         uint64
	targetID, host, controller string
	pending                    bool
	message                    string
	phase                      string
	cancel                     context.CancelFunc
}

type authPreparedMsg struct {
	authMsg
	command *exec.Cmd
}

type authMsg struct {
	generation, serial         uint64
	targetID, host, controller string
	err                        error
}

func (m *Model) authKey() string {
	return m.target.ID + "\x00" + m.target.SSHHost + "\x00" + m.target.Controller
}

func (m *Model) currentAuth() bool {
	a := m.auth
	return a != nil && !m.closed && a.generation == m.generation && a.targetID == m.target.ID && a.host == m.target.SSHHost && a.controller == m.target.Controller
}

func (m *Model) authPending() bool { return m.currentAuth() && m.auth.pending }

func (m *Model) canAuthenticate() bool {
	return !m.closed && m.target.SSHHost != "" && m.options.Authenticate != nil && !m.opening && !m.authPending() && m.pending == "" && (m.work == nil || !m.work.pending)
}

func (m *Model) newAuthState() {
	m.authSerial++
	m.auth = &authState{generation: m.generation, serial: m.authSerial, targetID: m.target.ID, host: m.target.SSHHost, controller: m.target.Controller}
}

// A typed SSH failure offers a terminal handoff; an HTTP API authentication
// error never opens this dialog. Each target transport is offered once per TUI
// session. Later failures retain a visible explicit retry, without prompt loops.
func (m *Model) requireAuthentication(err error) {
	var required *connection.AuthRequiredError
	if !connection.IsAuthRequired(err) || !errors.As(err, &required) || required.Host != m.target.SSHHost || m.target.SSHHost == "" || m.options.Authenticate == nil {
		return
	}
	m.newAuthState()
	m.auth.message = "OpenSSH needs authentication or host-key approval."
	m.status = "SSH authentication required · A authenticate · t choose target"
	if m.authOffered == nil {
		m.authOffered = map[string]bool{}
	}
	alreadyOffered := m.authOffered[m.authKey()]
	m.authOffered[m.authKey()] = true
	// Keep a user's form, work result or other modal in control. A remains
	// available after closing it; no delayed dialog steals their next input.
	if !alreadyOffered && m.overlay == "" && m.pending == "" && (m.work == nil || !m.work.pending) {
		m.overlay = "ssh-auth"
		m.input.Blur()
		m.pressed = nil
	}
}

func (m *Model) showAuthentication() tea.Cmd {
	if !m.canAuthenticate() {
		return nil
	}
	if m.overlay != "" && m.overlay != "ssh-auth" {
		return nil
	}
	if !m.currentAuth() {
		m.newAuthState()
	}
	if m.authOffered == nil {
		m.authOffered = map[string]bool{}
	}
	m.authOffered[m.authKey()] = true
	m.overlay = "ssh-auth"
	m.input.Blur()
	m.pressed = nil
	return nil
}

func (m *Model) authenticateCurrent() tea.Cmd {
	if m.overlay != "ssh-auth" || !m.currentAuth() || !m.canAuthenticate() {
		return nil
	}
	a := m.auth
	m.authSerial++
	a.serial = m.authSerial
	ctx, cancel := context.WithCancel(m.ctx)
	a.cancel = cancel
	a.pending = true
	a.phase = "preparing"
	a.message = "Preparing OpenSSH authentication. Esc cancels before the terminal handoff."
	m.status = "Preparing SSH authentication · " + core.Sanitize(a.host)
	m.pressed = nil
	request := authMsg{generation: a.generation, serial: a.serial, targetID: a.targetID, host: a.host, controller: a.controller}
	prepare := m.options.Authenticate
	return func() tea.Msg {
		command, err := prepare(ctx, request.host)
		request.err = err
		return authPreparedMsg{authMsg: request, command: command}
	}
}

func (m *Model) matchesAuth(msg authMsg) bool {
	return m.currentAuth() && m.auth.pending && msg.generation == m.auth.generation && msg.serial == m.auth.serial && msg.targetID == m.auth.targetID && msg.host == m.auth.host && msg.controller == m.auth.controller
}

func (m *Model) receiveAuthenticationPrepared(msg authPreparedMsg) tea.Cmd {
	if !m.matchesAuth(msg.authMsg) || m.auth.phase != "preparing" {
		return nil
	}
	if m.overlay != "ssh-auth" || m.opening || m.pending != "" || (m.work != nil && m.work.pending) {
		m.auth.cancel()
		m.auth.pending = false
		m.auth.phase = ""
		m.status = "SSH authentication deferred · A authenticate when ready"
		return nil
	}
	if msg.err != nil || msg.command == nil {
		m.auth.cancel()
		m.auth.pending = false
		m.auth.phase = ""
		m.auth.message = "Could not start OpenSSH authentication."
		if msg.err != nil {
			m.auth.message += " " + safeError(msg.err)
		}
		m.status = "SSH authentication did not start · retry explicitly or Cancel"
		return nil
	}
	m.auth.phase = "prompt"
	m.auth.message = "OpenSSH owns the terminal until authentication finishes."
	m.status = "Authenticating SSH · " + core.Sanitize(m.auth.host)
	request := msg.authMsg
	return tea.ExecProcess(msg.command, func(err error) tea.Msg {
		request.err = err
		return request
	})
}

func (m *Model) receiveAuthentication(msg authMsg) tea.Cmd {
	if !m.matchesAuth(msg) || m.auth.phase != "prompt" {
		return nil
	}
	if m.auth.cancel != nil {
		m.auth.cancel()
	}
	m.auth.pending = false
	m.auth.phase = ""
	m.pressed = nil
	if msg.err != nil {
		m.auth.message = "SSH authentication failed or was canceled. " + safeError(msg.err) + "\nEnter retries only when you choose; Esc returns to the dashboard."
		m.status = "SSH authentication failed or canceled · retry explicitly or Cancel"
		return nil
	}
	m.auth = nil
	return m.connect(m.target)
}

func (m *Model) cancelAuthentication() tea.Cmd {
	if m.overlay != "ssh-auth" || (m.authPending() && m.auth.phase == "prompt") {
		return nil
	}
	if m.currentAuth() && m.auth.pending {
		if m.auth.cancel != nil {
			m.auth.cancel()
		}
		m.auth.pending = false
		m.auth.phase = ""
		m.authSerial++
		m.auth.serial = m.authSerial
	}
	m.overlay = ""
	m.pressed = nil
	m.status = "SSH authentication deferred · A authenticate · t choose target"
	return nil
}

func (m *Model) authenticationKey(msg tea.KeyPressMsg) tea.Cmd {
	switch msg.String() {
	case "enter", "A":
		return m.authenticateCurrent()
	case "esc", "q":
		return m.cancelAuthentication()
	}
	return nil
}

func (m *Model) authenticationText() string {
	if !m.currentAuth() {
		return "SSH authentication\nThis request is no longer current. Close and select the intended target."
	}
	return core.Sanitize(fmt.Sprintf("SSH authentication required\n\nTarget: %s\nSSH host: %s\n\n%s\n\nChoose Authenticate to use OpenSSH in your terminal.\nOpenSSH handles passwords, keys and host-key approval; lazyclash does not collect or save a password.", m.target.Label(), m.auth.host, strings.TrimSpace(m.auth.message)))
}
