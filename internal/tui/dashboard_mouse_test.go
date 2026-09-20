package tui

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

func findHit(t *testing.T, m *Model, kind, id string) hitRegion {
	t.Helper()
	for _, h := range m.hitRegions() {
		if h.kind == kind && h.id == id {
			return h
		}
	}
	t.Fatalf("missing %s/%s regions=%+v", kind, id, m.hitRegions())
	return hitRegion{}
}
func press(m *Model, h hitRegion) tea.Cmd {
	_, cmd := m.Update(tea.MouseClickMsg{Button: tea.MouseLeft, X: h.x, Y: h.y})
	return cmd
}
func release(m *Model, h hitRegion) tea.Cmd {
	_, cmd := m.Update(tea.MouseReleaseMsg{Button: tea.MouseLeft, X: h.x, Y: h.y})
	return cmd
}
func click(m *Model, h hitRegion) tea.Cmd { press(m, h); return release(m, h) }

func TestOverviewDefaultsAndPreferenceOverrides(t *testing.T) {
	m := New(Options{})
	defer m.Close()
	if m.page != overview || !m.mouseEnabled || m.graphStyle != "braille" || m.historyWindow != 5*time.Minute {
		t.Fatalf("defaults %+v", m)
	}
	no := false
	m2 := New(Options{Config: config.Config{TUI: config.TUIPreferences{StartPage: "logs", Mouse: &no, GraphStyle: "ascii", HistoryWindow: "1m"}}})
	defer m2.Close()
	if m2.page != logs || m2.mouseEnabled || m2.graphStyle != "ascii" || m2.historyWindow != time.Minute {
		t.Fatal("preferences ignored")
	}
	yes := true
	m3 := New(Options{Config: m2.settings, StartPage: "proxies", Mouse: &yes, HistoryWindow: 15 * time.Minute})
	defer m3.Close()
	if m3.page != proxies || !m3.mouseEnabled || m3.historyWindow != 15*time.Minute {
		t.Fatal("explicit override ignored")
	}
}
func TestMouseSelectionIsNotActivationAndReleaseRevalidates(t *testing.T) {
	m := testModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	client, _ := core.New(core.Options{Endpoint: m.target.Controller})
	m.client = client
	beta := findHit(t, m, "row", "Beta")
	click(m, beta)
	if m.pending != "" || m.state().view(proxies).focus != 1 || m.currentPosition().selected != "Beta" {
		t.Fatal("row activated instead of selecting")
	}
	button := findHit(t, m, "action", "select")
	press(m, button)
	m.move(-1, false)
	if cmd := release(m, button); cmd != nil || m.pending != "" {
		t.Fatal("changed selection activated old press")
	}
	press(m, button)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	if cmd := release(m, button); cmd != nil {
		t.Fatal("resize failed to cancel press")
	}
	press(m, button)
	m.options.ReadOnly = true
	if cmd := release(m, button); cmd != nil {
		t.Fatal("read-only release activated")
	}
	m.options.ReadOnly = false
	if cmd := click(m, button); cmd == nil || m.pending == "" {
		t.Fatal("explicit same-target button failed")
	}
}
func TestMouseModalCapturePaletteAndDisable(t *testing.T) {
	m := testModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	tab := findHit(t, m, "tab", "0")
	click(m, tab)
	if m.page != overview {
		t.Fatal("tab did not navigate")
	}
	sendKey(m, "?")
	click(m, tab)
	if m.page != overview || m.overlay != "help" {
		t.Fatal("help click leaked through")
	}
	close := findHit(t, m, "button", "cancel")
	click(m, close)
	if m.overlay != "" {
		t.Fatal("close failed")
	}
	sendKey(m, "M")
	if m.mouseEnabled || m.View().MouseMode != tea.MouseModeNone {
		t.Fatal("mouse not disabled")
	}
	other := findHit(t, m, "tab", "1")
	click(m, other)
	if m.page != overview {
		t.Fatal("disabled mouse navigated")
	}
	sendKey(m, "/")
	sendKey(m, "M")
	if m.input.Value() != "M" || m.mouseEnabled {
		t.Fatal("typing M toggled capture")
	}
	sendKey(m, "esc")
	sendKey(m, "M")
	sendKey(m, ":")
	for _, r := range "Toggle mouse" {
		sendKey(m, string(r))
	}
	run := findHit(t, m, "button", "run")
	click(m, run)
	if m.mouseEnabled || m.overlay != "" {
		t.Fatal("palette mouse toggle failed")
	}
}
func TestMouseWheelAndScrolledRowsShareGeometry(t *testing.T) {
	m := testModel(t)
	m.page = connections
	var items []any
	for i := 0; i < 100; i++ {
		items = append(items, core.Object{"id": fmt.Sprint(i), "metadata": core.Object{"host": fmt.Sprintf("host-%d", i)}})
	}
	m.state().snap("connections").data = core.Object{"connections": items}
	m.reconcile()
	for _, width := range []int{36, 80, 120} {
		m.Update(tea.WindowSizeMsg{Width: width, Height: 24})
		m.state().view(connections).focus = 0
		m.move(80, true)
		rows := m.rowsFor(connections, 0)
		pos := m.currentPosition()
		start := visibleStart(pos, rows, 18)
		h := findHit(t, m, "row", rows[start].id)
		click(m, h)
		if m.currentPosition().selected != rows[start].id {
			t.Fatal("hit selection disagrees with visible row")
		}
	}
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 24})
	m.Update(tea.MouseWheelMsg{Button: tea.MouseWheelDown, X: 100, Y: 10})
	if m.state().view(connections).focus != 1 || m.state().view(connections).detailOffset != 3 {
		t.Fatal("wheel did not focus/scroll detail")
	}
}
func TestTargetDraftTestNeverSavesOrSelectsAndEditsInvalidate(t *testing.T) {
	m := testModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	called := 0
	m.options.TestTarget = func(ctx context.Context, target config.Target) (string, error) {
		called++
		if target.ID != "draft" {
			t.Errorf("tested %q", target.ID)
		}
		return "reachable", nil
	}
	original := m.target
	m.startTargetEdit(config.Target{ID: "draft", Controller: "http://example.test:9090"})
	cmd := m.testDraft()
	if cmd == nil {
		t.Fatal("test unavailable")
	}
	msg := cmd()
	if called != 1 || m.target.ID != original.ID || len(m.settings.Targets) != 1 {
		t.Fatal("draft test changed saved target")
	}
	sendKey(m, "x")
	m.Update(msg)
	if m.testResult != "" || m.testPending {
		t.Fatal("late draft result survived edit")
	}
	// Clicking another field only focuses it; no save or test occurs.
	h := findHit(t, m, "field", "2")
	click(m, h)
	if m.form.index != 2 || m.target.ID != original.ID {
		t.Fatal("field click changed target")
	}
	m.form.fields[0].value = "draft"
	m.input.SetValue("http://example.test:9090")
	flattenCommand(t, m, m.testDraft())
	if !strings.Contains(m.testResult, "reachable") {
		t.Fatal("draft result missing")
	}
	click(m, findHit(t, m, "button", "cancel"))
	if m.overlay != "" || m.target.ID != original.ID {
		t.Fatal("draft cancel changed active target")
	}
}
func TestProbeWorksWithoutControllerAndReadOnlyBlocks(t *testing.T) {
	m := testModel(t)
	m.page = overview
	m.target.ProbeProxy = "http://127.0.0.1:7890"
	calls := 0
	m.options.ProbeIP = func(context.Context, config.Target) (string, error) { calls++; return "IP.SB egress: 203.0.113.8", nil }
	m.options.ReadOnly = true
	if cmd := m.startProbe("ip"); cmd != nil {
		t.Fatal("read-only probe started")
	}
	m.options.ReadOnly = false
	flattenCommand(t, m, m.startProbe("ip"))
	if calls != 1 || !strings.Contains(m.state().probeIP, "203.0.113.8") {
		t.Fatal("offline API prevented explicit data probe")
	}
}
func TestOverviewFullAggregationExactDrillAndPureView(t *testing.T) {
	m := testModel(t)
	m.page = overview
	var items []any
	for i := 0; i < 2100; i++ {
		network := "tcp"
		if i == 2099 {
			network = "udp"
		}
		items = append(items, core.Object{"id": fmt.Sprint(i), "metadata": core.Object{"network": network, "host": "udp-is-only-a-host.test"}, "chains": []any{"Node", "Group"}, "rule": "Match"})
	}
	m.Update(readMsg{generation: m.generation, key: "connections", data: core.Object{"connections": items, "uploadTotal": float64(123), "downloadTotal": float64(456)}})
	if got := m.state().metrics.Snapshot(time.Now()).Connections.Count; got != 2100 {
		t.Fatalf("aggregate used trimmed list %d", got)
	}
	if got := len(array(object(m.state().snap("connections").data)["connections"])); got != 2000 {
		t.Fatalf("browse cap %d", got)
	}
	m.overviewSelection = "protocol:udp"
	sendKey(m, "enter")
	if m.page != connections || len(m.rowsFor(connections, 0)) != 0 {
		t.Fatal("exact network filter matched host substring or lost cap")
	}
	sendKey(m, "esc")
	if len(m.rowsFor(connections, 0)) != 2000 {
		t.Fatal("Esc did not clear exact filter")
	}
	m.page = overview
	before := m.state().metrics
	for _, size := range [][2]int{{120, 32}, {80, 24}, {36, 12}, {1, 1}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		view := ansi.Strip(m.View().Content)
		for _, line := range strings.Split(view, "\n") {
			if ansi.StringWidth(line) != size[0] {
				t.Fatalf("width %d: %q", size[0], line)
			}
		}
	}
	if !reflect.DeepEqual(before, m.state().metrics) {
		t.Fatal("View mutated telemetry")
	}
	m.overviewSelection = "group:Group"
	sendKey(m, "enter")
	if m.page != proxies || m.state().view(proxies).positions[0].selected != "Group" {
		t.Fatal("group drill failed")
	}
}

func TestPaletteMouseReleaseUsesSemanticActionAndProbeRouteChangeInvalidates(t *testing.T) {
	m := testModel(t)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	sendKey(m, ":")
	m.paletteIndex = 4
	run := findHit(t, m, "button", "run")
	press(m, run)
	// Enabling Refresh inserts an action before the selected Targets row.
	client, _ := core.New(core.Options{Endpoint: m.target.Controller})
	m.client = client
	if cmd := release(m, run); cmd != nil || m.overlay != "palette" {
		t.Fatal("palette release executed a different action")
	}
	m.overlay = ""
	m.target.ProbeProxy = "http://127.0.0.1:7890"
	m.state().probeIP = "old route"
	m.state().probePending = "ip"
	oldGeneration := m.generation
	target := m.target
	target.ProbeProxy = "http://127.0.0.1:7891"
	m.connect(target)
	m.Update(probeMsg{generation: oldGeneration, targetID: target.ID, kind: "ip", result: "late old route"})
	if m.state().probeIP != "" || m.state().probePending != "" {
		t.Fatal("old route probe survived target edit")
	}
	if sameConnection(target, config.Target{Controller: target.Controller, ProbeProxy: "http://127.0.0.1:7890"}) {
		t.Fatal("probe route did not affect connection revision")
	}
}
func TestOverviewEndAndNarrowSummary(t *testing.T) {
	m := testModel(t)
	m.page = overview
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	now := time.Now()
	m.state().metrics.AddTraffic(now, core.Object{"up": float64(123), "down": float64(321)})
	m.state().metrics.AddConnections(now, core.Object{"connections": []any{core.Object{"metadata": core.Object{"network": "tcp"}}}})
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "Network types") || !strings.Contains(view, "TCP") || strings.Contains(view, "5m0s") {
		t.Fatalf("narrow summary missing: %s", view)
	}
	sendKey(m, "G")
	if m.state().view(overview).detailOffset == 0 {
		t.Fatal("G scrolled to top")
	}
	before := m.state().view(overview).detailOffset
	m.move(100, false)
	if m.state().view(overview).detailOffset != before {
		t.Fatal("overscroll escaped bottom")
	}
	sendKey(m, "home")
	if m.state().view(overview).detailOffset != 0 {
		t.Fatal("Home failed")
	}
}
