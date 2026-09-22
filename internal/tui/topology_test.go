package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/topology"
)

func TestTopologyBrowserIgnoresLateReadsAndKeepsTypingOwnership(t *testing.T) {
	g, _ := topology.Parse([]byte("proxy-groups:\n- {name: 'qjkh/ 東京', type: select, proxies: [DIRECT]}\n"), topology.Source{})
	m := newTopologyBrowser(context.Background(), TopologyOptions{Load: func(context.Context, bool) (topology.Graph, error) { return g, nil }, CanLive: true})
	first := m.reload()
	second := m.reload()
	m.Update(first())
	if len(m.graph.Nodes) != 0 || !m.pending {
		t.Fatal("stale read applied")
	}
	_, draw := m.Update(second())
	if len(m.graph.Nodes) == 0 || m.pending || draw == nil {
		t.Fatal("fresh snapshot not accepted")
	}
	m.Update(draw())
	m.Update(tea.KeyPressMsg{Code: '/'})
	m.Update(tea.PasteMsg{Content: "qjkh/"})
	if !m.search || len(m.rows()) != 1 || m.opts.Live {
		t.Fatal("search keystrokes triggered actions")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_, draw = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.focus == "" || draw == nil {
		t.Fatal("focus missing")
	}
	newDraw := m.draw()
	m.Update(draw())
	m.body = "current"
	m.Update(topologyDrawn{serial: m.drawSerial - 1, body: "old"})
	if m.body != "current" {
		t.Fatal("old layout applied")
	}
	m.Update(newDraw())
	if m.cancel != nil {
		m.cancel()
	}
}

func TestTopologyBrowserResizeAndReadOnlyEntry(t *testing.T) {
	m := newTopologyBrowser(context.Background(), TopologyOptions{})
	m.graph, _ = topology.Parse([]byte("proxy-groups:\n- {name: '專案 👩🏽‍💻 é', type: select, proxies: [DIRECT]}\n"), topology.Source{})
	m.body = "long diagram\nnext line"
	for _, size := range []tea.WindowSizeMsg{{Width: 1, Height: 1}, {Width: 30, Height: 10}, {Width: 80, Height: 24}, {Width: 140, Height: 40}} {
		m.Update(size)
		for _, pane := range []int{0, 1} {
			m.pane = pane
			lines := strings.Split(m.View().Content, "\n")
			if len(lines) > size.Height {
				t.Fatal("height overflow")
			}
			for _, line := range lines {
				if ansi.StringWidth(line) > size.Width {
					t.Fatalf("width overflow: %q", line)
				}
			}
		}
		m.help = true
		for _, line := range strings.Split(m.View().Content, "\n") {
			if ansi.StringWidth(line) > size.Width {
				t.Fatal("help overflow")
			}
		}
		m.help = false
	}
	dashboard := toolModel(t)
	dashboard.options.ReadOnly = true
	if cmd := dashboard.toolAction("tool-topology"); cmd == nil {
		t.Fatal("read-only topology unavailable")
	}
}

func TestTopologyPendingReadDoesNotOwnTypingAndFailureRetainsSnapshot(t *testing.T) {
	started := make(chan struct{})
	m := newTopologyBrowser(context.Background(), TopologyOptions{Load: func(ctx context.Context, _ bool) (topology.Graph, error) {
		close(started)
		<-ctx.Done()
		return topology.Graph{}, ctx.Err()
	}})
	m.graph, _ = topology.Parse([]byte("proxy-groups: [{name: saved, type: select, proxies: [DIRECT]}]"), topology.Source{})
	cmd := m.reload()
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	<-started
	m.Update(tea.KeyPressMsg{Code: '/'})
	m.Update(tea.PasteMsg{Content: "saved"})
	if !m.pending || m.query.Value() != "saved" || len(m.rows()) != 1 {
		t.Fatal("pending read blocked typing")
	}
	m.cancel()
	m.Update(<-done)
	if m.pending || len(m.graph.Nodes) != 2 || !errors.Is(m.loadErr, context.Canceled) {
		t.Fatal("failed read replaced useful snapshot")
	}
}
