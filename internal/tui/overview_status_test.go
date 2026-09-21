package tui

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func TestOverviewNamedModeButtonsWriteSelectedModeOnce(t *testing.T) {
	fixture := testcore.NewHandler()
	server := httptest.NewServer(fixture)
	defer server.Close()
	m := testModel(t)
	m.page = overview
	m.target.Controller = server.URL
	m.client, _ = core.New(core.Options{Endpoint: server.URL})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	// Rule -> Direct must not cycle through Global or issue two PATCHes.
	h := findHit(t, m, "action", "mode-direct")
	flattenCommand(t, m, click(m, h))
	patches := 0
	for _, request := range fixture.Requests() {
		if request.Method == http.MethodPatch {
			patches++
			if request.Path != "/configs" || request.Body["mode"] != "direct" {
				t.Fatalf("wrong mode/endpoint: %+v", request)
			}
		}
	}
	if patches != 1 {
		t.Fatalf("expected one explicit mode write, got %d", patches)
	}
}

func TestOverviewStatusScopeAndVisibleControls(t *testing.T) {
	for _, test := range []struct{ controller, ssh, want string }{
		{"http://127.0.0.1:9097", "", "LOCAL CONTROLLER"},
		{"http://[::1]:9090", "", "LOCAL CONTROLLER"},
		{"unix:///tmp/test.sock", "", "LOCAL CONTROLLER"},
		{"http://127.0.0.1:9090", "remote-alias", "SSH CONTROLLER"},
		{"https://example.test:9090", "", "REMOTE CONTROLLER"},
	} {
		m := testModel(t)
		m.page = overview
		m.target.Controller, m.target.SSHHost = test.controller, test.ssh
		m.client, _ = core.New(core.Options{Endpoint: "http://127.0.0.1:9090"})
		m.state().snap("config").data = core.Object{"mode": "direct", "tun": core.Object{"enable": true}, "allow-lan": false, "mixed-port": 7897}
		for _, width := range []int{36, 80, 120} {
			m.Update(tea.WindowSizeMsg{Width: width, Height: 32})
			view := ansi.Strip(m.View().Content)
			for _, want := range []string{test.want, "[* Direct]", "[Rule]", "[Global]", "m Mode: direct", "TUN (core): on", "Mixed port: 7897"} {
				if !strings.Contains(view, want) {
					t.Fatalf("%d columns missing %q:\n%s", width, want, view)
				}
			}
			for _, action := range []string{"mode-rule", "mode-global"} {
				h := findHit(t, m, "action", action)
				line := strings.Split(view, "\n")[h.y]
				label := "Rule"
				if action == "mode-global" {
					label = "Global"
				}
				if !strings.Contains(ansi.Cut(line, h.x, h.x+h.w), label) {
					t.Fatalf("click region is not on its visible label: %+v %q", h, line)
				}
			}
		}
	}
}

func TestOverviewModeControlsDisabledForUncertainState(t *testing.T) {
	for _, state := range []string{"read-only", "pending", "stale", "offline", "unknown"} {
		t.Run(state, func(t *testing.T) {
			m := testModel(t)
			m.page = overview
			m.client, _ = core.New(core.Options{Endpoint: m.target.Controller})
			m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
			switch state {
			case "read-only":
				m.options.ReadOnly = true
			case "pending":
				m.pending = "Set mode to global"
			case "stale":
				m.state().snap("config").err = errors.New("connection lost")
			case "offline":
				m.client = nil
			case "unknown":
				m.state().snap("config").data = nil
			}
			if cmd := sendKey(m, "m"); cmd != nil {
				t.Fatal("cycle was enabled with uncertain/read-only state")
			}
			for _, h := range m.hitRegions() {
				if strings.HasPrefix(h.id, "mode-") {
					t.Fatalf("disabled mode has clickable region: %+v", h)
				}
			}
			if state == "stale" || state == "offline" {
				if !strings.Contains(ansi.Strip(m.View().Content), "Last mode: Rule") {
					t.Fatal("cached mode was presented as live state")
				}
			}
		})
	}
}
