package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/testcore"
)

func testModel(t *testing.T) *Model {
	t.Helper()
	m := New(Options{Config: config.Config{Targets: []config.Target{{ID: "test", Controller: "http://127.0.0.1:9090"}}}})
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.events = make(chan streamMsg, 64)
	m.status = "test"
	t.Cleanup(func() { _ = m.Close() })
	m.state().snap("proxies").data = map[string]core.Proxy{
		"Group": {Name: "Group", Type: "Selector", All: []string{"Alpha", "Beta", "專案 é 👩🏽‍💻"}, Now: "Alpha"},
		"Alpha": {Name: "Alpha", Type: "Direct"}, "Beta": {Name: "Beta", Type: "Shadowsocks"}, "專案 é 👩🏽‍💻": {Name: "專案 é 👩🏽‍💻", Type: "Trojan"},
	}
	m.state().snap("config").data = core.Object{"mode": "rule", "tun": core.Object{"enable": false}, "allow-lan": false}
	return m
}
func key(s string) tea.KeyPressMsg {
	codes := map[string]rune{"enter": tea.KeyEnter, "esc": tea.KeyEscape, "tab": tea.KeyTab, "up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight, "home": tea.KeyHome, "end": tea.KeyEnd}
	if c, ok := codes[s]; ok {
		return tea.KeyPressMsg{Code: c}
	}
	return tea.KeyPressMsg{Code: []rune(s)[0], Text: s}
}
func sendKey(m *Model, s string) tea.Cmd { _, cmd := m.Update(key(s)); return cmd }
func flattenCommand(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, child := range batch {
			flattenCommand(t, m, child)
		}
		return
	}
	_, _ = m.Update(msg)
}

func TestTextInputOwnsShortcutsAndPaste(t *testing.T) {
	m := testModel(t)
	sendKey(m, "/")
	for _, c := range "jkhql/?" {
		sendKey(m, string(c))
	}
	if got := m.input.Value(); got != "jkhql/?" {
		t.Fatalf("input = %q", got)
	}
	if m.overlay != "search" || m.page != proxies {
		t.Fatal("text invoked navigation")
	}
	m.Update(tea.PasteMsg{Content: "q\nenter\nj"})
	if m.overlay != "search" {
		t.Fatal("paste invoked action")
	}
	sendKey(m, "enter")
	if m.overlay != "" {
		t.Fatal("Enter did not leave filter")
	}
	if m.pending != "" {
		t.Fatal("Enter acted on filtered result")
	}
	sendKey(m, "/")
	sendKey(m, "esc")
	if m.state().view(proxies).query != "" {
		t.Fatal("Esc did not clear filter")
	}
}
func TestFilterCursorMovementPreservesSelection(t *testing.T) {
	m := testModel(t)
	m.state().view(proxies).focus = 1
	sendKey(m, "/")
	sendKey(m, "a")
	sendKey(m, "down")
	selected := m.currentPosition().selected
	sendKey(m, "left")
	if m.currentPosition().selected != selected {
		t.Fatal("cursor movement reset selection")
	}
	if m.state().view(proxies).focus != 1 {
		t.Fatal("text cursor changed pane")
	}
	sendKey(m, "b")
	if m.currentPosition().index != 0 {
		t.Fatal("query edit did not reset selection")
	}
}
func TestArrowAndVimNavigationAndPaneFocus(t *testing.T) {
	m := testModel(t)
	sendKey(m, "enter")
	if m.state().view(proxies).focus != 1 {
		t.Fatal("Enter did not focus members")
	}
	sendKey(m, "j")
	r, _ := m.selectedRow()
	if r.id != "Beta" {
		t.Fatalf("j selected %q", r.id)
	}
	sendKey(m, "up")
	r, _ = m.selectedRow()
	if r.id != "Alpha" {
		t.Fatal("arrow differed from Vim")
	}
	sendKey(m, "G")
	r, _ = m.selectedRow()
	if r.id != "專案 é 👩🏽‍💻" {
		t.Fatal("G did not select last")
	}
	sendKey(m, "g")
	sendKey(m, "g")
	r, _ = m.selectedRow()
	if r.id != "Alpha" {
		t.Fatal("gg did not select first")
	}
	sendKey(m, "tab")
	if m.state().view(proxies).focus != 2 {
		t.Fatal("Tab did not focus detail")
	}
	sendKey(m, "j")
	if m.state().view(proxies).detailOffset != 1 {
		t.Fatal("detail did not scroll")
	}
	sendKey(m, "h")
	if m.state().view(proxies).focus != 1 {
		t.Fatal("h did not return to members")
	}
}
func TestReadGenerationSerialAndStaleData(t *testing.T) {
	m := testModel(t)
	m.generation = 8
	s := m.state().snap("proxies")
	s.serial = 4
	old := m.proxyData()
	m.Update(readMsg{generation: 7, serial: 4, key: "proxies", data: map[string]core.Proxy{}})
	if len(m.proxyData()) != len(old) {
		t.Fatal("old target response committed")
	}
	m.Update(readMsg{generation: 8, serial: 3, key: "proxies", err: errors.New("late failure")})
	if s.err != nil {
		t.Fatal("old refresh failure committed")
	}
	m.Update(readMsg{generation: 8, serial: 4, key: "proxies", err: errors.New("offline")})
	if len(m.proxyData()) != len(old) || s.err == nil {
		t.Fatal("failed refresh removed good data")
	}
	if !strings.Contains(m.freshness(proxies), "STALE") {
		t.Fatal("stale data unlabeled")
	}
	m.Update(readMsg{generation: 8, serial: 4, key: "proxies", data: map[string]core.Proxy{}})
	if len(m.proxyData()) != 0 || s.err != nil {
		t.Fatal("successful empty result retained rows")
	}
}
func TestRefreshKeepsIdentityAndTargetViewState(t *testing.T) {
	m := testModel(t)
	m.state().view(proxies).focus = 1
	m.move(1, false)
	s := m.state().snap("proxies")
	s.serial = 1
	m.Update(readMsg{generation: m.generation, serial: 1, key: "proxies", data: map[string]core.Proxy{"Group": {Name: "Group", Type: "Selector", All: []string{"Beta", "Alpha"}, Now: "Beta"}, "Beta": {Name: "Beta"}, "Alpha": {Name: "Alpha"}}})
	r, _ := m.selectedRow()
	if r.id != "Beta" || m.currentPosition().index != 0 {
		t.Fatal("refresh followed row index")
	}
	m.state().view(proxies).query = "Beta"
	original := m.target
	m.connect(config.Target{ID: "other", Controller: "http://localhost:9091"})
	m.connect(original)
	if m.state().view(proxies).query != "Beta" {
		t.Fatal("target switch lost view state")
	}
	if m.client != nil || m.pending != "" {
		t.Fatal("target switch retained old controls")
	}
}
func TestBoundedLogAndConnectionSnapshots(t *testing.T) {
	m := testModel(t)
	for i := 0; i < logLimit+50; i++ {
		m.Update(streamMsg{generation: m.generation, resource: "logs", data: core.Object{"type": "info", "payload": fmt.Sprint(i)}})
	}
	if len(m.state().logs) != logLimit || m.state().logs[0].message != "50" {
		t.Fatal("logs are not a bounded recent buffer")
	}
	oldCount := len(m.state().logs)
	m.Update(streamMsg{generation: m.generation + 1, resource: "logs", data: core.Object{"payload": "late"}})
	if len(m.state().logs) != oldCount {
		t.Fatal("old target stream accepted")
	}
	items := make([]any, connectionLimit+100)
	for i := range items {
		items[i] = core.Object{"id": fmt.Sprint(i)}
	}
	m.Update(readMsg{generation: m.generation, key: "connections", data: core.Object{"connections": items}})
	obj := object(m.state().snap("connections").data)
	if len(array(obj["connections"])) != connectionLimit || obj["lazyclashTruncated"] != true {
		t.Fatal("connection snapshot not bounded/labeled")
	}
}
func TestResponsiveUnicodeNoColorAndUntrustedLabels(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	m := testModel(t)
	m.target.Name = "bad\x1b]52;c;secret\a\nname"
	m.state().view(proxies).focus = 1
	for _, size := range [][2]int{{1, 1}, {20, 8}, {80, 24}, {140, 40}, {0, 0}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		output := m.View().Content
		if strings.Contains(output, "\x1b") {
			t.Fatal("NO_COLOR/untrusted escape remains")
		}
		lines := strings.Split(output, "\n")
		if len(lines) > max(1, size[1]) {
			t.Fatalf("height overflow at %v", size)
		}
		for _, line := range lines {
			if ansi.StringWidth(line) > max(1, size[0]) {
				t.Fatalf("width overflow at %v: %q", size, line)
			}
		}
	}
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if !strings.Contains(m.View().Content, "專案 é 👩🏽‍💻") {
		t.Fatal("Unicode labels missing")
	}
}
func TestUnknownStateAndStaleHeader(t *testing.T) {
	m := testModel(t)
	m.state().snap("config").data = nil
	header := m.header(200)
	if !strings.Contains(header, "TUN:?") || strings.Contains(header, "TUN:off") {
		t.Fatalf("unknown rendered false: %s", header)
	}
	m.state().snap("config").data = core.Object{"mode": "rule", "tun": core.Object{"enable": true}}
	m.state().snap("config").err = errors.New("offline")
	if !strings.Contains(m.header(200), "stale") {
		t.Fatal("header did not mark cached settings stale")
	}
}
func TestFormsReviewAndTemporaryTargetRules(t *testing.T) {
	m := testModel(t)
	m.startTargetForm(false)
	m.Update(tea.PasteMsg{Content: "q\nj"})
	if m.overlay != "form" {
		t.Fatal("paste submitted form")
	}
	for m.form.index < len(m.form.fields) {
		sendKey(m, "tab")
	}
	m.Update(tea.PasteMsg{Content: "paste on review"}) // must not index beyond the last field
	if m.overlay != "form" {
		t.Fatal("review paste invoked save")
	}
	sendKey(m, "enter")
	if m.form.err == "" {
		t.Fatal("invalid form was accepted")
	}
	m.overlay = ""
	m.target.Transient = true
	m.page = configs
	for _, a := range m.actions() {
		if a.id == "config-add" && a.enabled {
			t.Fatal("YAML registered against transient target")
		}
	}
}
func TestTargetSaveMarksIntentionalPersistence(t *testing.T) {
	m := testModel(t)
	m.target.Transient = true
	m.settings.Targets[0] = m.target
	saved := false
	m.options.SaveTargets = func(c config.Config) error {
		saved = true
		if c.Targets[0].Transient {
			t.Error("explicit target save stayed transient")
		}
		return nil
	}
	m.startTargetForm(true)
	for m.form.index < len(m.form.fields) {
		sendKey(m, "tab")
	}
	cmd := sendKey(m, "enter")
	flattenCommand(t, m, cmd)
	if !saved || m.overlay != "" {
		t.Fatal("form did not complete save")
	}
}

func TestSelectionUsesSharedAPIAndSuppressesDuplicateWrites(t *testing.T) {
	var mu sync.Mutex
	selected := "Alpha"
	var puts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			var body core.Object
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			selected = fmt.Sprint(body["name"])
			mu.Unlock()
			puts.Add(1)
			w.WriteHeader(204)
			return
		}
		mu.Lock()
		current := selected
		mu.Unlock()
		json.NewEncoder(w).Encode(core.Object{"proxies": core.Object{"Group": core.Object{"type": "Selector", "all": []string{"Alpha", "Beta"}, "now": current}}})
	}))
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := testModel(t)
	m.client = client
	m.state().view(proxies).focus = 1
	m.move(1, false)
	cmd := sendKey(m, "enter")
	if cmd == nil || m.pending == "" {
		t.Fatal("selection not immediately pending")
	}
	if duplicate := sendKey(m, "enter"); duplicate != nil {
		t.Fatal("duplicate write scheduled")
	}
	msg := cmd()
	m.Update(msg)
	if puts.Load() != 1 || m.pending != "" || !strings.Contains(m.status, "succeeded") {
		t.Fatalf("bad result puts=%d status=%q", puts.Load(), m.status)
	}
}
func TestReadOnlyAndDestructiveConfirmation(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := testModel(t)
	m.client = client
	m.page = connections
	if cmd := sendKey(m, "X"); cmd != nil || m.overlay != "confirm" || deletes.Load() != 0 {
		t.Fatal("destructive operation skipped confirmation")
	}
	sendKey(m, "esc")
	if deletes.Load() != 0 {
		t.Fatal("cancel performed delete")
	}
	sendKey(m, "X")
	cmd := sendKey(m, "enter")
	if cmd == nil {
		t.Fatal("confirmed delete not scheduled")
	}
	m.Update(cmd())
	if deletes.Load() != 1 {
		t.Fatal("confirmed delete not sent")
	}
	m.options.ReadOnly = true
	if cmd := sendKey(m, "X"); cmd != nil || m.overlay != "" {
		t.Fatal("read-only offered destructive action")
	}
	m.page = proxies
	m.state().view(proxies).focus = 1
	if cmd := sendKey(m, "d"); cmd != nil {
		t.Fatal("read-only performed active probe")
	}
}
func TestStartupDoesNotCallOpenerUntilCommandRuns(t *testing.T) {
	var opened atomic.Bool
	m := New(Options{Config: config.Config{Targets: []config.Target{{ID: "slow", Controller: "http://localhost:1"}}}, Open: func(context.Context, config.Target) (*core.Client, io.Closer, error) {
		opened.Store(true)
		return nil, nil, errors.New("deliberately unavailable")
	}})
	cmd := m.Init()
	if cmd == nil || opened.Load() {
		t.Fatal("startup performed blocking open")
	}
	if !strings.Contains(m.View().Content, "connecting") {
		t.Fatal("initial frame lacks connection state")
	}
	sendKey(m, "?")
	if m.overlay != "help" {
		t.Fatal("opening blocked input")
	}
	m.Close()
}
func TestDelayAllUsesBoundedIndividualRequests(t *testing.T) {
	var active, maxActive, count atomic.Int32
	release := make(chan struct{})
	reached := make(chan struct{}, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		count.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/proxies/") || !strings.HasSuffix(r.URL.Path, "/delay") {
			t.Errorf("wrong endpoint %s", r.URL.Path)
		}
		select {
		case reached <- struct{}{}:
		default:
		}
		<-release
		io.WriteString(w, `{"delay":12}`)
	}))
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- delayAll(context.Background(), client, []string{"a", "b", "c", "d", "e", "f"}) }()
	for i := 0; i < 4; i++ {
		select {
		case <-reached:
		case <-time.After(2 * time.Second):
			t.Fatal("four requests did not start")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maxActive.Load() > 4 || count.Load() != 6 {
		t.Fatalf("concurrency=%d count=%d", maxActive.Load(), count.Load())
	}
}

func TestMissingConnectionIDCannotCloseAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(204)
	}))
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := testModel(t)
	m.client = client
	m.page = connections
	m.state().snap("connections").data = core.Object{"connections": []any{core.Object{"metadata": core.Object{"host": "example.org"}}}}
	if cmd := sendKey(m, "x"); cmd != nil {
		flattenCommand(t, m, cmd)
		t.Fatal("missing ID was actionable")
	}
	if cmd := m.runAction("close-connection"); cmd != nil {
		flattenCommand(t, m, cmd)
		t.Fatal("empty ID became close-all")
	}
}
func TestRuntimeDetailsRedactCredentialsWithoutChangingState(t *testing.T) {
	m := testModel(t)
	m.page = providers
	original := core.Object{"password": "hidden", "authentication": []any{"user:password"}, "name": "service"}
	m.state().snap("proxyProviders").data = core.Object{"providers": core.Object{"service": original}}
	detail := m.details(providers)
	if strings.Contains(detail, "hidden") || strings.Contains(detail, "user:password") {
		t.Fatal("runtime detail leaked credentials")
	}
	if original["password"] != "hidden" {
		t.Fatal("redaction changed internal state")
	}
}
func TestInputHasVisibleCursorWithoutColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	m := testModel(t)
	sendKey(m, "/")
	sendKey(m, "q")
	v := m.View()
	if v.Cursor == nil || v.Cursor.Position.Y != m.height-2 {
		t.Fatal("search cursor is missing or misplaced")
	}
	if v.Cursor.Color != nil {
		t.Fatal("NO_COLOR cursor is colored")
	}
}
func TestLogControlsAndMessageBound(t *testing.T) {
	m := testModel(t)
	m.page = logs
	sendKey(m, " ")
	if m.state().follow {
		t.Fatal("Space did not pause follow")
	}
	sendKey(m, " ")
	if !m.state().follow {
		t.Fatal("Space did not resume follow")
	}
	m.Update(streamMsg{generation: m.generation, resource: "logs", data: core.Object{"type": "info", "payload": strings.Repeat("界", 5000)}})
	if len([]rune(m.state().logs[0].message)) > 4200 || !strings.Contains(m.state().logs[0].message, "truncated") {
		t.Fatal("oversized log entry was not bounded")
	}
}

func TestDiscoveryCanceledOnQuitAndTargetSwitch(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, switchTarget := range []bool{false, true} {
			t.Run(fmt.Sprintf("remote=%t/switch=%t", remote, switchTarget), func(t *testing.T) {
				started := make(chan struct{})
				canceled := make(chan struct{})
				discover := func(ctx context.Context) ([]config.Target, error) {
					close(started)
					<-ctx.Done()
					close(canceled)
					return nil, ctx.Err()
				}
				m := New(Options{Discover: discover, DiscoverHost: func(ctx context.Context, _ string) ([]config.Target, error) { return discover(ctx) }})
				host := ""
				if remote {
					host = "fake-ssh-alias"
				}
				cmd := m.discover(host)
				done := make(chan tea.Msg, 1)
				go func() { done <- cmd() }()
				<-started
				if switchTarget {
					m.connect(config.Target{ID: "replacement", Controller: "http://localhost:9091"})
				} else {
					m.Close()
				}
				select {
				case <-canceled:
				case <-time.After(time.Second):
					t.Fatal("discovery context survived close/switch")
				}
				<-done
				m.Close()
			})
		}
	}
}

func TestWideFixtureViewKeepsVS16NamesAndAdjacentPanes(t *testing.T) {
	server := testcore.NewServer()
	defer server.Close()
	client, err := core.New(core.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	m := testModel(t)
	m.client = client
	proxies, err := client.Proxies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m.state().snap("proxies").data = proxies
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	output := ansi.Strip(m.View().Content)
	findLine := func(name string) string {
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, name) {
				return line
			}
		}
		t.Fatalf("missing name %q:\n%s", name, output)
		return ""
	}
	automatic := findLine(testcore.Automatic)
	if strings.Count(automatic, "│") != 2 || !strings.Contains(automatic, testcore.Taipei) || !strings.Contains(automatic, "Group: "+testcore.Automatic) {
		t.Fatalf("automatic row lost pane content: %q", automatic)
	}
	balance := findLine("⚖️ Balance")
	if strings.Count(balance, "│") != 2 || !strings.Contains(balance, testcore.Tokyo) || !strings.Contains(balance, "Type: URLTest") {
		t.Fatalf("balance row lost pane content: %q", balance)
	}
	for _, line := range strings.Split(output, "\n") {
		if ansi.StringWidth(line) != 120 {
			t.Fatalf("line has wrong terminal width %d: %q", ansi.StringWidth(line), line)
		}
	}
}
func TestWideViewWithANSIAndZeroWidthGraphemeNames(t *testing.T) {
	names := []string{"♻️ Auto", "⚖️ Balance", "é 專案", "👩🏽‍💻 Development", "zero\u200bwidth", "\x1b[31m♻️ Auto\x1b[0m", "\x1b]52;c;hidden\a⚖️ Balance"}
	for _, name := range names {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			m := testModel(t)
			m.state().snap("proxies").data = map[string]core.Proxy{name: {Name: name, Type: "Selector", All: []string{"member é 👩🏽‍💻"}, Now: "member é 👩🏽‍💻"}, "member é 👩🏽‍💻": {Name: "member é 👩🏽‍💻", Type: "Direct"}}
			m.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
			output := ansi.Strip(m.View().Content)
			lines := strings.Split(output, "\n")
			line := lines[4]
			if !strings.Contains(line, core.Sanitize(name)) || !strings.Contains(line, "member é 👩🏽‍💻") || strings.Count(line, "│") != 2 {
				t.Fatalf("name/pane lost: %q", line)
			}
			if strings.Contains(output, "hidden") || strings.Contains(output, "\x1b") {
				t.Fatal("untrusted terminal control content rendered")
			}
			if group, _ := m.group(); group.Name != name {
				t.Fatal("rendering changed API identity")
			}
			for _, line := range lines {
				if ansi.StringWidth(line) != 120 {
					t.Fatalf("line width=%d: %q", ansi.StringWidth(line), line)
				}
			}
		})
	}
}
func TestTargetSwitchRetainsUncertainMutationOutcome(t *testing.T) {
	m := testModel(t)
	original := m.target
	m.pending = "Apply complete YAML"
	oldGeneration := m.generation
	m.connect(config.Target{ID: "other", Controller: "http://localhost:9091"})
	note := m.states[original.ID].lastOperation
	if !strings.Contains(note, "interrupted") || !strings.Contains(note, "outcome may be unknown") {
		t.Fatalf("lost interrupted receipt: %q", note)
	}
	m.Update(writeMsg{generation: oldGeneration, label: "Apply complete YAML"})
	if m.state().lastOperation != "" || m.states[original.ID].lastOperation != note {
		t.Fatal("late receipt mutated other target or erased uncertainty")
	}
	m.connect(original)
	client, err := core.New(core.Options{Endpoint: "http://localhost:9090"})
	if err != nil {
		t.Fatal(err)
	}
	m.Update(openedMsg{generation: m.generation, client: client})
	if !strings.Contains(m.status, "outcome may be unknown") {
		t.Fatalf("revisit hid interrupted receipt: %q", m.status)
	}
	m.page = overview
	if !strings.Contains(m.overviewView(120, 30), "Last operation: Apply complete YAML interrupted") {
		t.Fatal("overview omitted operation receipt")
	}
}
