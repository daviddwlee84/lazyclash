package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func serverInventory() WorkResult {
	return WorkResult{Title: "Servers / VPS", Summary: "Saved inventory", Rows: []WorkRow{{ID: "server:one", Label: "one · vless-reality", Detail: "Saved one"}, {ID: "server:two", Label: "two · hysteria2", Detail: "Saved two"}, {ID: "host:vm", Label: "vm · VPS", Detail: "Saved host"}}}
}

func TestServersInventoryRendersBeforeRemoteRefreshAndPreservesSelection(t *testing.T) {
	m := testModel(t)
	calls := []WorkRequest{}
	m.options.Workbench = func(_ context.Context, r WorkRequest) (WorkResult, error) {
		calls = append(calls, r)
		return serverInventory(), nil
	}
	initial := m.startServers()
	if initial == nil || m.overlay != "work" || !m.work.pending {
		t.Fatal("inventory did not start")
	}
	message := initial().(workMsg)
	_, refresh := m.Update(message)
	if refresh == nil || !m.work.pending || len(m.work.result.Rows) != 3 || len(calls) != 1 || calls[0].Kind != "servers-list" {
		t.Fatal("remote refresh blocked initial inventory", calls, m.work)
	}
	if !strings.Contains(m.View().Content, "one") {
		t.Fatal("saved inventory not rendered while remote pending")
	}
	sendKey(m, "j")
	if m.work.index != 1 {
		t.Fatal("navigation blocked by remote refresh")
	}
	response := refresh().(workMsg)
	response.result.Rows = []WorkRow{response.result.Rows[1], response.result.Rows[2], response.result.Rows[0]}
	m.Update(response)
	row, ok := m.selectedServerRow()
	if !ok || row.ID != "server:two" || m.work.index != 0 || m.work.pending {
		t.Fatal("refresh did not preserve selected identity", m.work)
	}
	if len(calls) != 2 || calls[1].Receipt != "server:one" {
		t.Fatal("selected refresh request wrong", calls)
	}
}

func TestServersCancelDiscardsLateReadAndFailuresKeepRows(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) { return serverInventory(), nil }
	initial := m.startServers()
	message := initial().(workMsg)
	_, refresh := m.Update(message)
	response := refresh().(workMsg)
	response.result = WorkResult{}
	response.err = errors.New("SSH offline")
	m.Update(response)
	if len(m.work.result.Rows) != 3 || !strings.Contains(m.work.result.Summary, "SSH offline") {
		t.Fatal("failed read erased inventory")
	}
	refresh = m.refreshServerWork(true)
	serial := m.work.serial
	sendKey(m, "esc")
	if m.work != nil || m.overlay != "" {
		t.Fatal("readonly cancellation blocked return")
	}
	m.receiveWork(workMsg{generation: m.generation, serial: serial, result: serverInventory()})
	if m.work != nil || m.overlay != "" {
		t.Fatal("late result reopened servers view")
	}
	_ = refresh
}

func TestServersActionsSeparateServiceAndVPSAndRestoreInventory(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) { return WorkResult{Title: "Servers / VPS"}, nil }
	m.options.RunCommand = func(context.Context, []string, io.Reader, io.Writer, io.Writer) error { return nil }
	m.startServers()
	m.work.pending = false
	m.work.result = serverInventory()
	cmd := click(m, findHit(t, m, "button", "server-actions"))
	if cmd == nil || m.overlay != "external-tool" || !m.toolReturnServers || !m.toolPending {
		t.Fatal("server actions did not release terminal")
	}
	request := toolMsg{generation: m.generation, serial: m.toolSerial, label: "Manage proxy server"}
	refresh := m.receiveTool(request)
	if refresh == nil || m.overlay != "work" || !m.work.pending || m.toolReturnServers {
		t.Fatal("tool return did not retain inventory")
	}
	m.work.pending = false
	m.work.index = 2
	cmd = m.serverButton("server-actions")
	if cmd == nil || m.status != "Manage VPS" {
		t.Fatal("VPS row did not select VM actions")
	}
}

func TestServersEmptyReadOnlyAndResize(t *testing.T) {
	m := testModel(t)
	m.options.ReadOnly = true
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) {
		return WorkResult{Title: "Servers / VPS", Summary: "No servers"}, nil
	}
	initial := m.startServers()
	m.Update(initial())
	if m.work.pending || m.serverButton("server-actions") != nil || m.serverButton("server-deploy") != nil {
		t.Fatal("empty/readonly action remained enabled")
	}
	for _, size := range [][2]int{{80, 24}, {30, 8}, {1, 1}, {0, 0}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		_ = m.View()
		_ = m.hitRegions()
	}
	for _, a := range m.actions() {
		if a.id == "tool-servers" && !a.enabled {
			t.Fatal("server inventory should be available without connected client")
		}
	}
}

func TestTailnetRowsUseSharedCLIAndReadOnlySetupDisabled(t *testing.T) {
	m := testModel(t)
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) { return WorkResult{}, nil }
	m.options.RunCommand = func(context.Context, []string, io.Reader, io.Writer, io.Writer) error { return nil }
	m.startServers()
	m.work.pending = false
	m.work.result = WorkResult{Rows: []WorkRow{{ID: "tailnet:pi", Label: "pi"}, {ID: "tailnet-proxy:gateway", Label: "gateway"}}}
	if command := m.serverButton("server-actions"); command == nil || m.status != "Manage Tailnet exit" {
		t.Fatal("exit action missing")
	}
	m.receiveTool(toolMsg{generation: m.generation, serial: m.toolSerial, label: "Manage Tailnet exit"})
	m.work.pending = false
	m.work.index = 1
	if command := m.serverButton("server-actions"); command == nil || m.status != "Manage Tailnet proxy" {
		t.Fatal("proxy action missing")
	}
	m.receiveTool(toolMsg{generation: m.generation, serial: m.toolSerial, label: "Manage Tailnet proxy"})
	m.work.pending = false
	m.options.ReadOnly = true
	if m.serverButton("server-tailnet") != nil || m.serverButton("server-tailnet-proxy") != nil {
		t.Fatal("readonly setup enabled")
	}
	m.options.ReadOnly = false
	if command := m.serverButton("server-tailnet"); command == nil || m.status != "Set up Tailnet device" {
		t.Fatal("Tailnet setup not discoverable")
	}
}
