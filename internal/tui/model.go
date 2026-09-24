// Package tui presents the same controller operations as the CLI in a terminal dashboard.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/dashboard"
)

type Options struct {
	RunCommand     func(context.Context, []string, io.Reader, io.Writer, io.Writer) error
	ReloadTargets  func() (config.Config, error)
	Workbench      func(context.Context, WorkRequest) (WorkResult, error)
	Config         config.Config
	InitialTarget  string
	ReadOnly       bool
	StartPage      string
	Mouse          *bool
	GraphStyle     string
	HistoryWindow  time.Duration
	TestTarget     func(context.Context, config.Target) (string, error)
	NodeProvenance map[string]map[string]string
	ProbeIP        func(context.Context, config.Target) (string, error)
	ProbeLatency   func(context.Context, config.Target) (string, error)
	Open           func(context.Context, config.Target) (*core.Client, io.Closer, error)
	Discover       func(context.Context) ([]config.Target, error)
	DiscoverHost   func(context.Context, string) ([]config.Target, error)
	SaveTargets    func(config.Config) error
	Authenticate   func(context.Context, string) (*exec.Cmd, error)
}

type page int

const (
	overview page = iota
	proxies
	connections
	logs
	rules
	providers
	configs
)

var pageNames = []string{"Overview", "Proxies", "Connections", "Logs", "Rules", "Providers", "Configs"}

const logLimit = 1000
const connectionLimit = 2000

type position struct {
	selected      string
	index, offset int
}
type viewState struct {
	query        string
	focus        int
	positions    [3]position
	detailOffset int
	exactFilter  dashboard.Filter
}
type snapshot struct {
	data    any
	err     error
	at      time.Time
	loading bool
	serial  uint64
}
type logEntry struct {
	id             int
	at             time.Time
	level, message string
}
type targetState struct {
	views                 map[page]*viewState
	data                  map[string]*snapshot
	logs                  []logEntry
	logSeq                int
	logLevel              string
	follow                bool
	traffic, memory       core.Object
	streamErrors          map[string]string
	lastApplied           string
	lastOperation         string
	metrics               dashboard.State
	probeIP, probeLatency string
	probePending          string
}

func newTargetState() *targetState {
	s := &targetState{views: map[page]*viewState{}, data: map[string]*snapshot{}, follow: true, streamErrors: map[string]string{}}
	for p := overview; p <= configs; p++ {
		s.views[p] = &viewState{}
	}
	for _, key := range []string{"config", "version", "proxies", "connections", "rules", "proxyProviders", "ruleProviders"} {
		s.data[key] = &snapshot{}
	}
	return s
}
func (s *targetState) view(p page) *viewState {
	if s.views[p] == nil {
		s.views[p] = &viewState{}
	}
	return s.views[p]
}
func (s *targetState) snap(key string) *snapshot {
	if s.data[key] == nil {
		s.data[key] = &snapshot{}
	}
	return s.data[key]
}

type Model struct {
	toolPending       bool
	toolReturnServers bool
	toolSerial        uint64
	auth              *authState
	authSerial        uint64
	authOffered       map[string]bool
	work              *workState
	workSerial        uint64
	quickRuleDraft    string
	quickRuleScope    string
	ruleInspectDrafts map[string]WorkRequest
	options           Options
	settings          config.Config
	target            config.Target
	states            map[string]*targetState
	page              page
	width, height     int
	generation        uint64
	ctx               context.Context
	cancel            context.CancelFunc
	client            *core.Client
	closer            io.Closer
	events            chan streamMsg
	opening           bool
	status            string
	pending           string
	overlay           string
	input             textinput.Model
	paletteIndex      int
	targetIndex       int
	form              *formState
	confirm           *confirmation
	helpOffset        int
	gPrefix           bool
	discovered        bool
	closed            bool
	mouseEnabled      bool
	graphStyle        string
	historyWindow     time.Duration
	pressed           *mousePress
	testSerial        uint64
	testResult        string
	testPending       bool
	testCancel        context.CancelFunc
	overviewSelection string
}

type tickMsg time.Time
type openedMsg struct {
	generation uint64
	client     *core.Client
	closer     io.Closer
	err        error
}
type discoveredMsg struct {
	generation uint64
	targets    []config.Target
	err        error
}
type readMsg struct {
	generation, serial uint64
	key                string
	data               any
	err                error
}
type writeMsg struct {
	generation     uint64
	label, applied string
	err            error
}
type streamMsg struct {
	generation uint64
	resource   string
	data       core.Object
	err        error
}
type savedMsg struct {
	settings config.Config
	selected string
	err      error
}

func New(options Options) *Model {
	in := textinput.New()
	in.SetVirtualCursor(false)
	in.CharLimit = 2048
	m := &Model{options: options, settings: cloneSettings(options.Config), states: map[string]*targetState{}, page: overview, width: 80, height: 24, input: in, status: "Connecting…"}
	prefs := options.Config.TUI.WithDefaults()
	m.mouseEnabled = prefs.Mouse == nil || *prefs.Mouse
	if options.Mouse != nil {
		m.mouseEnabled = *options.Mouse
	}
	m.graphStyle = prefs.GraphStyle
	if options.GraphStyle != "" {
		m.graphStyle = options.GraphStyle
	}
	m.historyWindow, _ = time.ParseDuration(prefs.HistoryWindow)
	if options.HistoryWindow > 0 {
		m.historyWindow = options.HistoryWindow
	}
	if m.historyWindow != time.Minute && m.historyWindow != 5*time.Minute && m.historyWindow != 15*time.Minute {
		m.historyWindow = 5 * time.Minute
	}
	startPage := prefs.StartPage
	if options.StartPage != "" {
		startPage = options.StartPage
	}
	for i, name := range pageNames {
		if strings.EqualFold(name, startPage) {
			m.page = page(i)
		}
	}
	id := options.InitialTarget
	if id == "" {
		id = m.settings.DefaultTarget
	}
	for _, t := range m.settings.Targets {
		if t.ID == id {
			m.target = t
			break
		}
	}
	if m.target.ID == "" && id == "" && len(m.settings.Targets) > 0 {
		m.target = m.settings.Targets[0]
	}
	if m.target.ID == "" && id != "" {
		m.status = "Unknown target: " + core.Sanitize(id)
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.state()
	return m
}

func cloneSettings(c config.Config) config.Config {
	c.Targets = append([]config.Target(nil), c.Targets...)
	for i := range c.Targets {
		c.Targets[i].Configs = append([]config.CoreConfig(nil), c.Targets[i].Configs...)
		c.Targets[i].Checks = append([]config.DiagnosticCheck(nil), c.Targets[i].Checks...)
		for j := range c.Targets[i].Checks {
			c.Targets[i].Checks[j].ExpectedStatuses = append([]int(nil), c.Targets[i].Checks[j].ExpectedStatuses...)
		}
		if c.Targets[i].RuleSource != nil {
			source := *c.Targets[i].RuleSource
			c.Targets[i].RuleSource = &source
		}
		if c.Targets[i].Service != nil {
			service := *c.Targets[i].Service
			c.Targets[i].Service = &service
		}
		if c.Targets[i].ConfigSource != nil {
			source := *c.Targets[i].ConfigSource
			c.Targets[i].ConfigSource = &source
		}
	}
	return c
}
func (m *Model) state() *targetState {
	if m.states[m.target.ID] == nil {
		m.states[m.target.ID] = newTargetState()
	}
	return m.states[m.target.ID]
}
func (m *Model) Init() tea.Cmd {
	if m.target.ID != "" {
		return tea.Batch(m.connect(m.target), tick())
	}
	if m.options.InitialTarget != "" {
		return tick()
	}
	m.status = "Discovering local controllers…"
	m.opening = true
	return tea.Batch(m.discover(""), tick())
}
func tick() tea.Cmd { return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }

// Close cancels streams and closes only resources owned by this dashboard.
// Call after Program.Run returns, including on errors or signals.
func (m *Model) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	m.invalidateTargetTest()
	if m.cancel != nil {
		m.cancel()
	}
	var errs []error
	if m.client != nil {
		errs = append(errs, m.client.Close())
	}
	if m.closer != nil {
		errs = append(errs, m.closer.Close())
	}
	return errors.Join(errs...)
}
func cleanup(c *core.Client, closer io.Closer) tea.Cmd {
	return func() tea.Msg {
		if c != nil {
			_ = c.Close()
		}
		if closer != nil {
			_ = closer.Close()
		}
		return nil
	}
}
func (m *Model) connect(target config.Target) tea.Cmd {
	m.authSerial++
	m.auth = nil
	if m.work != nil {
		if m.work.cancel != nil {
			m.work.cancel()
		}
		m.work = nil
		m.workSerial++
	}
	if m.pending != "" {
		m.state().lastOperation = m.pending + " interrupted; outcome may be unknown. Refresh before retrying."
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.state().metrics.Gap(time.Now())
	m.state().probePending = ""
	if m.target.ID == target.ID && !sameProbeRoute(m.target, target) {
		m.state().probeIP = ""
		m.state().probeLatency = ""
	}
	m.pressed = nil
	m.invalidateTargetTest()
	oldClient, oldCloser := m.client, m.closer
	m.client, m.closer = nil, nil
	m.target = target
	m.generation++
	m.pending = ""
	m.opening = true
	m.overlay = ""
	m.confirm = nil
	m.gPrefix = false
	m.status = "Connecting to " + core.Sanitize(target.Label()) + "…"
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.events = make(chan streamMsg, 64)
	for _, s := range m.state().data {
		s.loading = false
		if s.data != nil {
			s.err = errors.New("reconnecting; awaiting refreshed data")
		}
	}
	for _, resource := range []string{"traffic", "memory", "logs"} {
		m.state().streamErrors[resource] = "awaiting new stream"
	}
	ctx, generation, open := m.ctx, m.generation, m.options.Open
	return tea.Batch(cleanup(oldClient, oldCloser), func() tea.Msg {
		if open == nil {
			return openedMsg{generation: generation, err: errors.New("controller opener unavailable")}
		}
		client, closer, err := open(ctx, target)
		if ctx.Err() != nil {
			if client != nil {
				_ = client.Close()
			}
			if closer != nil {
				_ = closer.Close()
			}
			return nil
		}
		return openedMsg{generation, client, closer, err}
	})
}
func (m *Model) discover(host string) tea.Cmd {
	generation, local, remote := m.generation, m.options.Discover, m.options.DiscoverHost
	parentContext := m.ctx
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parentContext, 20*time.Second)
		defer cancel()
		var targets []config.Target
		var err error
		if host == "" && local != nil {
			targets, err = local(ctx)
		} else if host != "" && remote != nil {
			targets, err = remote(ctx, host)
		} else {
			err = errors.New("discovery is unavailable; add a target manually")
		}
		return discoveredMsg{generation, targets, err}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.pressed = nil
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.input.SetWidth(max(1, m.width-8))
		return m, nil
	case tea.MouseClickMsg:
		return m, m.mouseClick(msg)
	case tea.MouseReleaseMsg:
		return m, m.mouseRelease(msg)
	case tea.MouseWheelMsg:
		return m, m.mouseWheel(msg)
	case workMsg:
		return m, m.receiveWork(msg)
	case toolMsg:
		return m, m.receiveTool(msg)
	case toolSettingsMsg:
		return m, m.receiveToolSettings(msg)
	case targetTestMsg:
		return m, m.receiveTargetTest(msg)
	case probeMsg:
		return m, m.receiveProbe(msg)
	case tea.KeyPressMsg:
		m.pressed = nil
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.overlay != "" {
			return m, m.overlayKey(msg)
		}
		return m, m.key(msg)
	case tea.PasteMsg:
		if m.overlay == "search" || m.overlay == "palette" || m.overlay == "form" {
			return m, m.inputUpdate(msg)
		}
		return m, nil
	case openedMsg:
		if msg.generation != m.generation {
			return m, cleanup(msg.client, msg.closer)
		}
		m.opening = false
		if msg.err != nil {
			m.status = "Connection failed: " + safeError(msg.err)
			m.requireAuthentication(msg.err)
			return m, cleanup(msg.client, msg.closer)
		}
		m.auth = nil
		m.client, m.closer = msg.client, msg.closer
		m.status = "Connected"
		if m.state().lastOperation != "" {
			m.status += " · " + m.state().lastOperation
		}
		return m, tea.Batch(m.refresh(true), m.startStreams())
	case discoveredMsg:
		if msg.generation != m.generation {
			return m, nil
		}
		m.opening = false
		if msg.err != nil {
			m.status = "Discovery failed: " + safeError(msg.err)
			return m, nil
		}
		if len(msg.targets) == 0 {
			m.status = "No controller found. Press : then Add target, or Discover SSH host."
			return m, nil
		}
		added := 0
		for _, target := range msg.targets {
			found := false
			for _, existing := range m.settings.Targets {
				if existing.Controller == target.Controller && existing.SSHHost == target.SSHHost {
					found = true
					break
				}
			}
			if found {
				continue
			}
			base := target.ID
			if base == "" {
				base = "discovered"
			}
			target.ID = base
			target.Transient = true
			for n := 2; m.hasTarget(target.ID); n++ {
				target.ID = fmt.Sprintf("%s-%d", base, n)
			}
			m.settings.Targets = append(m.settings.Targets, target)
			added++
		}
		m.discovered = true
		m.status = fmt.Sprintf("Found %d controllers (%d new). Edit/save a target to persist discovery.", len(msg.targets), added)
		if m.overlay != "" {
			return m, nil
		}
		if m.target.ID == "" && len(m.settings.Targets) == 1 {
			return m, m.connect(m.settings.Targets[0])
		}
		m.overlay = "targets"
		m.targetIndex = 0
		return m, nil
	case readMsg:
		if msg.generation != m.generation {
			return m, nil
		}
		s := m.state().snap(msg.key)
		if s.serial != msg.serial {
			return m, nil
		}
		s.loading = false
		if msg.err != nil {
			s.err = msg.err
			if msg.key == "connections" {
				m.state().metrics.SourceGap(time.Now(), "connections")
			}
			return m, nil
		}
		if msg.key == "connections" {
			if data := object(msg.data); data != nil {
				m.state().metrics.AddConnections(time.Now(), data)
				items := array(data["connections"])
				if len(items) > connectionLimit {
					trimmed := core.Object{}
					for key, value := range data {
						trimmed[key] = value
					}
					trimmed["connections"] = append([]any(nil), items[:connectionLimit]...)
					trimmed["lazyclashTruncated"] = true
					msg.data = trimmed
				}
			}
		}
		s.data, s.err, s.at = msg.data, nil, time.Now()
		m.reconcile()
		return m, nil
	case writeMsg:
		if msg.generation != m.generation {
			return m, nil
		}
		m.pending = ""
		if msg.err != nil {
			m.status = msg.label + ": " + safeError(msg.err) + "; outcome may need verification"
		} else {
			m.status = msg.label + " succeeded; refreshing"
			if msg.applied != "" {
				m.state().lastApplied = msg.applied + " at " + time.Now().Format("15:04:05")
			}
		}
		m.state().lastOperation = m.status
		return m, m.refresh(true)
	case streamMsg:
		if msg.generation != m.generation {
			return m, nil
		}
		if msg.err != nil {
			m.state().streamErrors[msg.resource] = safeError(msg.err)
			m.state().metrics.SourceGap(time.Now(), msg.resource)
		} else {
			delete(m.state().streamErrors, msg.resource)
			switch msg.resource {
			case "traffic":
				m.state().traffic = msg.data
				m.state().metrics.AddTraffic(time.Now(), msg.data)
			case "memory":
				m.state().memory = msg.data
				m.state().metrics.AddMemory(time.Now(), msg.data)
			case "logs":
				s := m.state()
				s.logSeq++
				s.logs = append(s.logs, logEntry{id: s.logSeq, at: time.Now(), level: str(msg.data, "type"), message: boundedLog(str(msg.data, "payload"))})
				if len(s.logs) > logLimit {
					s.logs = append([]logEntry(nil), s.logs[len(s.logs)-logLimit:]...)
				}
				if s.follow {
					v := s.view(logs)
					v.positions[0].index = len(m.rowsFor(logs, 0)) - 1
					v.positions[0].selected = ""
				}
			}
		}
		return m, waitEvent(m.ctx, m.events)
	case authMsg:
		return m, m.receiveAuthentication(msg)
	case authPreparedMsg:
		return m, m.receiveAuthenticationPrepared(msg)
	case savedMsg:
		if msg.err != nil {
			m.status = "Save failed: " + safeError(msg.err)
			if m.form != nil {
				m.overlay = "form"
				if m.form.index < len(m.form.fields) {
					return m, m.input.Focus()
				}
			} else {
				m.overlay = ""
			}
			return m, nil
		}
		oldTarget := m.target
		m.settings = msg.settings
		m.status = "Settings saved"
		m.overlay = ""
		m.form = nil
		m.discovered = false
		selected := msg.selected
		if selected == "" {
			selected = oldTarget.ID
		}
		for _, t := range m.settings.Targets {
			if t.ID == selected {
				if oldTarget.ID != t.ID || !sameConnection(oldTarget, t) {
					return m, m.connect(t)
				}
				m.target = t
				return m, nil
			}
		}
		if len(m.settings.Targets) > 0 {
			return m, m.connect(m.settings.Targets[0])
		}
		if m.cancel != nil {
			m.cancel()
		}
		cmd := cleanup(m.client, m.closer)
		m.client = nil
		m.closer = nil
		m.target = config.Target{}
		m.generation++
		m.ctx, m.cancel = context.WithCancel(context.Background())
		m.status = "No targets. Press : to add or discover."
		return m, cmd
	case tickMsg:
		for _, s := range m.states {
			s.metrics.Prune(time.Time(msg))
		}
		return m, tea.Batch(tick(), m.refresh(false))
	}
	if m.overlay == "search" || m.overlay == "palette" || m.overlay == "form" {
		return m, m.inputUpdate(msg)
	}
	return m, nil
}
func sameConnection(a, b config.Target) bool {
	return a.Controller == b.Controller && a.SSHHost == b.SSHHost && a.SecretEnv == b.SecretEnv && a.SecretFile == b.SecretFile && a.Secret == b.Secret && a.CAFile == b.CAFile && a.SourceConfig == b.SourceConfig && sameProbeRoute(a, b)
}
func (m *Model) hasTarget(id string) bool {
	for _, t := range m.settings.Targets {
		if t.ID == id {
			return true
		}
	}
	return false
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	return core.Sanitize(err.Error())
}

func (m *Model) refresh(full bool) tea.Cmd {
	if m.client == nil {
		return nil
	}
	keys := []string{"config", "connections"}
	if full || m.state().snap("version").data == nil {
		keys = append(keys, "version")
	}
	switch m.page {
	case proxies, overview:
		keys = append(keys, "proxies")
	case rules:
		if full || m.state().snap("rules").data == nil || m.state().snap("rules").err != nil {
			keys = append(keys, "rules")
		}
	case providers:
		keys = append(keys, "proxyProviders", "ruleProviders")
	}
	cmds := make([]tea.Cmd, 0, len(keys))
	for _, key := range keys {
		s := m.state().snap(key)
		if s.loading && !full {
			continue
		}
		s.loading = true
		s.serial++
		cmds = append(cmds, m.fetch(key, s.serial))
	}
	return tea.Batch(cmds...)
}
func (m *Model) fetch(key string, serial uint64) tea.Cmd {
	client, ctx, generation := m.client, m.ctx, m.generation
	return func() tea.Msg {
		var data any
		var err error
		switch key {
		case "config":
			data, err = client.Config(ctx)
		case "version":
			data, err = client.Version(ctx)
		case "proxies":
			data, err = client.Proxies(ctx)
		case "connections":
			data, err = client.Connections(ctx)
		case "rules":
			data, err = client.Rules(ctx)
		case "proxyProviders":
			data, err = client.Providers(ctx, "proxies")
		case "ruleProviders":
			data, err = client.Providers(ctx, "rules")
		}
		return readMsg{generation, serial, key, data, err}
	}
}
func waitEvent(ctx context.Context, ch <-chan streamMsg) tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-ch:
			return msg
		case <-ctx.Done():
			return nil
		}
	}
}
func (m *Model) startStreams() tea.Cmd {
	client, ctx, generation, ch := m.client, m.ctx, m.generation, m.events
	start := func() tea.Msg {
		for _, resource := range []string{"traffic", "memory", "logs"} {
			go func(resource string) {
				backoff := time.Second
				send := func(msg streamMsg) bool {
					select {
					case ch <- msg:
						return true
					case <-ctx.Done():
						return false
					}
				}
				for ctx.Err() == nil {
					query := url.Values{}
					if resource == "logs" {
						query.Set("level", "debug")
					}
					err := client.Stream(ctx, resource, query, func(data core.Object) {
						if ctx.Err() == nil {
							send(streamMsg{generation: generation, resource: resource, data: data})
						}
					})
					if ctx.Err() != nil {
						return
					}
					if err == nil {
						err = io.EOF
					}
					if !send(streamMsg{generation: generation, resource: resource, err: err}) {
						return
					}
					timer := time.NewTimer(backoff)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						return
					}
					backoff = min(backoff*2, 30*time.Second)
				}
			}(resource)
		}
		return nil
	}
	return tea.Batch(start, waitEvent(ctx, ch))
}

// delayAll tests individual nodes, never the group endpoint, which can alter automatic selections.
func delayAll(ctx context.Context, client *core.Client, names []string) error {
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			_, err := client.Delay(ctx, name)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
			}
		}(name)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(errs...)
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func str(m core.Object, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return core.Sanitize(fmt.Sprint(v))
	}
	return ""
}
func object(v any) core.Object {
	switch v := v.(type) {
	case core.Object:
		return v
	case map[string]any:
		return core.Object(v)
	}
	return nil
}
func contains(s, q string) bool {
	return strings.Contains(strings.ToLower(core.Sanitize(s)), strings.ToLower(q))
}

func boundedLog(message string) string {
	const maxRunes = 4096
	runes := []rune(message)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes]) + " … [entry truncated]"
	}
	return message
}

func sameProbeRoute(a, b config.Target) bool {
	return a.ProbeProxy == b.ProbeProxy && a.ProbeUsername == b.ProbeUsername && a.ProbePasswordEnv == b.ProbePasswordEnv && a.ProbePasswordFile == b.ProbePasswordFile && a.ProbeCAFile == b.ProbeCAFile
}
