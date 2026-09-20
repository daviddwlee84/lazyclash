package tui

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func authModel(t *testing.T) (*Model, *int) {
	t.Helper()
	m := testModel(t)
	m.target.SSHHost = "fixture-password-host"
	m.settings.Targets[0] = m.target
	calls := 0
	m.options.Authenticate = func(_ context.Context, host string) (*exec.Cmd, error) {
		if host != m.target.SSHHost {
			t.Fatalf("authentication used another host: %s", host)
		}
		calls++
		return exec.Command("false"), nil
	}
	return m, &calls
}

func authOutcome(m *Model, err error) authMsg {
	a := m.auth
	return authMsg{generation: a.generation, serial: a.serial, targetID: a.targetID, host: a.host, controller: a.controller, err: err}
}

func requireAuth(m *Model) {
	m.Update(openedMsg{generation: m.generation, err: &connection.AuthRequiredError{Host: m.target.SSHHost}})
}

func prepareAuthentication(t *testing.T, m *Model, command tea.Cmd) tea.Cmd {
	t.Helper()
	if command == nil {
		t.Fatal("authentication preparation was not scheduled")
	}
	message, ok := command().(authPreparedMsg)
	if !ok {
		t.Fatal("authentication preparation returned another message")
	}
	_, next := m.Update(message)
	return next
}

func TestSSHAuthRequiresTypedCurrentConnectionFailure(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		stale bool
		want  bool
	}{
		{"typed", &connection.AuthRequiredError{Host: "fixture-password-host"}, false, true},
		{"wrapped", fmt.Errorf("source read: %w", &connection.AuthRequiredError{Host: "fixture-password-host"}), false, true},
		{"plain text", errors.New("Permission denied (password)"), false, false},
		{"API auth", &core.Error{Kind: core.KindAuth, Operation: "read version"}, false, false},
		{"wrong host", &connection.AuthRequiredError{Host: "other-host"}, false, false},
		{"stale", &connection.AuthRequiredError{Host: "fixture-password-host"}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, calls := authModel(t)
			m.generation = 3
			generation := m.generation
			if test.stale {
				generation--
			}
			m.Update(openedMsg{generation: generation, err: test.err})
			if (m.overlay == "ssh-auth") != test.want || *calls != 0 {
				t.Fatalf("overlay=%q auth calls=%d", m.overlay, *calls)
			}
		})
	}
}

func TestSSHAuthCancelLeavesVisibleRetryWithoutRepeatDialogs(t *testing.T) {
	m, calls := authModel(t)
	requireAuth(m)
	if !strings.Contains(m.View().Content, "Enter Authenticate") || !strings.Contains(m.View().Content, "fixture-password-host") {
		t.Fatal("authentication target/action is not visible")
	}
	click(m, findHit(t, m, "button", "ssh-auth-cancel"))
	if m.overlay != "" || *calls != 0 || !strings.Contains(m.footer(), "A authenticate") {
		t.Fatalf("cancel stole terminal or removed retry: %q %d %s", m.overlay, *calls, m.footer())
	}
	// A reconnect failing on the same transport must not reopen the modal.
	m.connect(m.target)
	requireAuth(m)
	if m.overlay != "" {
		t.Fatal("reconnect repeated the auth dialog")
	}
	sendKey(m, "A")
	if m.overlay != "ssh-auth" || *calls != 0 {
		t.Fatal("explicit retry did not show the choice")
	}
}

func TestSSHAuthDoesNotInterruptFormsOrWork(t *testing.T) {
	for _, overlay := range []string{"form", "work", "confirm", "palette", "targets"} {
		t.Run(overlay, func(t *testing.T) {
			m, calls := authModel(t)
			m.overlay = overlay
			requireAuth(m)
			if m.overlay != overlay || *calls != 0 || !m.currentAuth() {
				t.Fatal("authentication interrupted the active surface")
			}
			if command := m.showAuthentication(); command != nil || m.overlay != overlay {
				t.Fatal("explicit dispatch stole an owned surface")
			}
			m.overlay = ""
			if !strings.Contains(m.footer(), "A authenticate") {
				t.Fatal("deferred request has no visible retry")
			}
		})
	}
}

func TestSSHAuthOwnershipPendingFailureAndReadOnly(t *testing.T) {
	m, calls := authModel(t)
	m.options.ReadOnly = true
	requireAuth(m)
	command := sendKey(m, "enter")
	if command == nil || *calls != 0 || !m.authPending() {
		t.Fatal("read-only mode blocked explicit authentication")
	}
	if next := sendKey(m, "enter"); next != nil || *calls != 0 {
		t.Fatal("duplicate authentication preparation started")
	}
	if command = prepareAuthentication(t, m, command); command == nil || *calls != 1 {
		t.Fatal("prepared authentication did not hand off the terminal")
	}
	first := authOutcome(m, errors.New("exit status 255"))
	if next := sendKey(m, "enter"); next != nil || *calls != 1 {
		t.Fatal("duplicate authentication started")
	}
	m.receiveAuthentication(first)
	if m.authPending() || m.overlay != "ssh-auth" || m.opening || !strings.Contains(m.auth.message, "canceled") {
		t.Fatal("failed authentication retried automatically")
	}
	if command = click(m, findHit(t, m, "button", "ssh-authenticate")); command == nil || *calls != 1 {
		t.Fatal("explicit button retry failed")
	}
	if command = prepareAuthentication(t, m, command); command == nil || *calls != 2 {
		t.Fatal("prepared retry did not hand off the terminal")
	}
	second := authOutcome(m, nil)
	m.receiveAuthentication(first)
	if !m.authPending() {
		t.Fatal("old result canceled the new attempt")
	}
	wrong := second
	wrong.host = "other-host"
	m.receiveAuthentication(wrong)
	if !m.authPending() {
		t.Fatal("another host result was accepted")
	}
	priorGeneration := m.generation
	if command = m.receiveAuthentication(second); command == nil || !m.opening || m.generation == priorGeneration || m.auth != nil {
		t.Fatal("confirmed authentication did not reconnect")
	}
	m.receiveAuthentication(second)
	if m.generation != priorGeneration+1 {
		t.Fatal("duplicate success reconnected again")
	}
}

func TestSSHAuthTargetSwitchDropsLateResultsAndMousePress(t *testing.T) {
	m, calls := authModel(t)
	requireAuth(m)
	button := findHit(t, m, "button", "ssh-authenticate")
	m.mouseClick(tea.MouseClickMsg{X: button.x, Y: button.y, Button: tea.MouseLeft})
	m.connect(config.Target{ID: "other", Controller: "http://127.0.0.1:9091", SSHHost: "other-host"})
	m.mouseRelease(tea.MouseReleaseMsg{X: button.x, Y: button.y, Button: tea.MouseLeft})
	if *calls != 0 || m.auth != nil {
		t.Fatal("stale authentication button acted on a new target")
	}
	m.receiveAuthentication(authMsg{generation: m.generation - 1, targetID: "test", host: "fixture-password-host"})
	if m.target.ID != "other" || m.auth != nil {
		t.Fatal("late authentication restored old target")
	}
}

func TestSSHAuthFactoryFailureAndResize(t *testing.T) {
	m, _ := authModel(t)
	m.options.Authenticate = func(context.Context, string) (*exec.Cmd, error) { return nil, errors.New("unavailable") }
	requireAuth(m)
	if command := prepareAuthentication(t, m, sendKey(m, "enter")); command != nil || m.authPending() || !strings.Contains(m.auth.message, "Could not start") {
		t.Fatal("failed factory left pending request")
	}
	for _, size := range [][2]int{{120, 32}, {36, 12}, {1, 1}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		_ = m.View()
		_ = m.hitRegions()
	}
}

func TestSSHAuthPreparationIsAsyncAndCancelable(t *testing.T) {
	m, _ := authModel(t)
	started := make(chan struct{})
	m.options.Authenticate = func(ctx context.Context, _ string) (*exec.Cmd, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	requireAuth(m)
	prepared := make(chan tea.Cmd, 1)
	go func() { prepared <- sendKey(m, "enter") }()
	var command tea.Cmd
	select {
	case command = <-prepared:
	case <-time.After(time.Second):
		m.cancel()
		<-prepared
		t.Fatal("keypress blocked on SSH policy preparation")
	}
	select {
	case <-started:
		t.Fatal("command factory ran inside Update")
	default:
	}
	result := make(chan tea.Msg, 1)
	go func() { result <- command() }()
	<-started
	// Preparation is cancellable from the same overlay while its effect waits.
	sendKey(m, "esc")
	if m.overlay != "" || m.authPending() {
		t.Fatal("Esc did not release the preparing dialog")
	}
	select {
	case message := <-result:
		if _, next := m.Update(message); next != nil || m.overlay != "" || m.authPending() {
			t.Fatal("canceled preparation stole the terminal on completion")
		}
	case <-time.After(time.Second):
		t.Fatal("authentication preparation context was not canceled")
	}
	if !strings.Contains(m.footer(), "A authenticate") {
		t.Fatal("canceled preparation removed explicit retry")
	}
}

func TestSSHAuthPreparedResultCannotStealChangedSurface(t *testing.T) {
	for _, change := range []string{"cancel", "form", "work", "mutation", "target", "controller", "host", "closed"} {
		t.Run(change, func(t *testing.T) {
			m, _ := authModel(t)
			requireAuth(m)
			command := sendKey(m, "enter")
			message := command().(authPreparedMsg)
			switch change {
			case "cancel":
				m.cancelAuthentication()
			case "form":
				m.overlay = "form"
			case "work":
				m.work = &workState{pending: true}
			case "mutation":
				m.pending = "control action"
			case "target":
				m.connect(config.Target{ID: "other", Controller: "http://127.0.0.1:9091", SSHHost: "other-host"})
			case "controller":
				m.target.Controller = "http://127.0.0.1:9092"
			case "host":
				m.target.SSHHost = "other-host"
			case "closed":
				m.Close()
			}
			if _, next := m.Update(message); next != nil {
				t.Fatal("late prepared command took terminal ownership")
			}
			if change == "form" && (m.overlay != "form" || m.authPending()) {
				t.Fatal("late prepared result interrupted the current form")
			}
		})
	}
}
