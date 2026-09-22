package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/analytics"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/rulework"
)

// AnalyticsOptions deliberately exposes report reads and an explicit manual
// diagnosis only. This browser has no rule-writing or collector-control API.
type AnalyticsOptions struct {
	Query    analytics.Query
	Load     func(context.Context, analytics.Query) (analytics.Report, error)
	TargetID string
	ReadOnly bool
	Diagnose func(context.Context, string, string, string) (string, error)
}

func RunAnalytics(ctx context.Context, opts AnalyticsOptions, in io.Reader, out io.Writer) error {
	if opts.Load == nil {
		return errors.New("analytics browser requires a report reader")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m := newAnalyticsBrowser(ctx, opts)
	defer m.close()
	_, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out)).Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type analyticsLoaded struct {
	serial uint64
	query  analytics.Query
	report analytics.Report
	err    error
}

type analyticsDiagnosed struct {
	serial uint64
	body   string
	err    error
}

type analyticsCrumb struct {
	query  analytics.Query
	filter string
	index  int
	period string
}

type analyticsBrowser struct {
	ctx                                       context.Context
	opts                                      AnalyticsOptions
	query, reportQuery                        analytics.Query
	report                                    analytics.Report
	hasReport, pending, stale, help           bool
	closed                                    bool
	width, height                             int
	index, listOffset, pane, scroll           int
	input                                     textinput.Model
	inputMode, filter, notice                 string
	period                                    string
	history                                   []analyticsCrumb
	serial, diagSerial                        uint64
	cancel, diagCancel                        context.CancelFunc
	diagPending                               bool
	diagDomain, diagTarget, diagVia, diagBody string
}

func newAnalyticsBrowser(ctx context.Context, opts AnalyticsOptions) *analyticsBrowser {
	query := opts.Query
	if query.GroupBy == "" {
		query.GroupBy = "source"
	}
	if query.Timezone == "" {
		query.Timezone = analytics.DefaultTimezone
	}
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.To.IsZero() {
		query.To = time.Now()
	}
	period := "custom"
	for _, candidate := range []string{"day", "week", "month"} {
		if from, err := analyticsPeriodStart(query.To, candidate, query.Timezone); err == nil && query.From.Equal(from) {
			period = candidate
			break
		}
	}
	if query.From.IsZero() {
		query.From, _ = analyticsPeriodStart(query.To, "day", query.Timezone)
		period = "day"
	}
	in := textinput.New()
	in.CharLimit = 2048
	m := &analyticsBrowser{ctx: ctx, opts: opts, query: query, period: period, input: in, width: 100, height: 28}
	return m
}

func (m *analyticsBrowser) Init() tea.Cmd { return m.reload() }

func (m *analyticsBrowser) close() {
	m.closed = true
	m.serial++
	if m.cancel != nil {
		m.cancel()
	}
	m.cancelDiagnosis()
}

func (m *analyticsBrowser) cancelDiagnosis() {
	m.diagSerial++
	if m.diagCancel != nil {
		m.diagCancel()
	}
	m.diagCancel = nil
	m.diagPending = false
}

func (m *analyticsBrowser) reload() tea.Cmd {
	if m.closed || m.opts.Load == nil {
		m.notice = "No analytics report reader is available"
		return nil
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.cancelDiagnosis()
	m.diagBody = ""
	m.serial++
	m.pending = true
	m.notice = "Reading stored history; previous rows remain visible"
	ctx, cancel := context.WithTimeout(m.ctx, 60*time.Second)
	m.cancel = cancel
	serial, query, load := m.serial, m.query, m.opts.Load
	return func() tea.Msg {
		defer cancel()
		report, err := load(ctx, query)
		return analyticsLoaded{serial: serial, query: query, report: report, err: err}
	}
}

func (m *analyticsBrowser) rows() []analytics.ReportRow {
	rows := make([]analytics.ReportRow, 0, len(m.report.Rows))
	needle := strings.ToLower(m.filter)
	for _, row := range m.report.Rows {
		text := row.SourceID + " " + row.Kind + " " + row.Scope + " " + row.Key
		if strings.Contains(strings.ToLower(text), needle) {
			rows = append(rows, row)
		}
	}
	return rows
}

func (m *analyticsBrowser) selected() (analytics.ReportRow, bool) {
	rows := m.rows()
	if m.index < 0 || m.index >= len(rows) {
		return analytics.ReportRow{}, false
	}
	return rows[m.index], true
}

func (m *analyticsBrowser) snapshotMatches() bool {
	return m.hasReport && m.reportQuery == m.query && !m.pending && !m.stale
}

func (m *analyticsBrowser) drill() tea.Cmd {
	if !m.snapshotMatches() {
		m.notice = "Wait for a current report before drilling into retained rows"
		return nil
	}
	row, ok := m.selected()
	if !ok || row.SourceID == "" {
		m.notice = "Select a row with a known observation source"
		return nil
	}
	next := m.query
	next.SourceID = row.SourceID
	if m.query.GroupBy != "source" && (row.Key == "" || strings.HasPrefix(row.Key, "(")) {
		m.pane = 1
		m.notice = "Unattributed values have no exact value to filter; inspect coverage and source details"
		return nil
	}
	switch m.query.GroupBy {
	case "source":
		next.GroupBy = "domain"
	case "domain":
		next.Domain, next.GroupBy = row.Key, "process"
	case "process":
		next.Process, next.GroupBy = row.Key, "route"
	case "route":
		next.Route, next.GroupBy = row.Key, "ip"
	case "ip":
		next.IP, next.GroupBy = row.Key, "domain"
	case "principal":
		next.Principal, next.GroupBy = row.Key, "domain"
	default:
		return nil
	}
	m.history = append(m.history, analyticsCrumb{m.query, m.filter, m.index, m.period})
	m.query = next
	m.index, m.listOffset, m.scroll, m.pane = 0, 0, 0, 0
	m.filter = ""
	return m.reload()
}

func analyticsPeriodStart(end time.Time, period, zone string) (time.Time, error) {
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return time.Time{}, err
	}
	// End is exclusive: midnight belongs to the preceding calendar window.
	n := end.Add(-time.Nanosecond).In(loc)
	start := time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, loc)
	switch period {
	case "day":
	case "week":
		start = start.AddDate(0, 0, -(int(n.Weekday())+6)%7)
	case "month":
		start = time.Date(n.Year(), n.Month(), 1, 0, 0, 0, 0, loc)
	default:
		return time.Time{}, errors.New("unknown analytics calendar window")
	}
	return start, nil
}

func (m *analyticsBrowser) cycleWindow() tea.Cmd {
	next := map[string]string{"day": "week", "week": "month", "month": "day"}[m.period]
	if next == "" {
		next = "day"
	}
	// Keep the report's end anchored, so inspecting historical windows does not
	// unexpectedly jump to today. The CLI starts current windows at its own now.
	start, err := analyticsPeriodStart(m.query.To, next, m.query.Timezone)
	if err != nil || !m.query.To.After(start) {
		m.notice = "This report boundary cannot form that calendar window"
		return nil
	}
	m.query.From, m.period = start, next
	m.index, m.listOffset, m.scroll = 0, 0, 0
	return m.reload()
}

func (m *analyticsBrowser) cycleGroup() tea.Cmd {
	groups := []string{"source", "domain", "process", "route", "ip"}
	next := 0
	for i, group := range groups {
		if group == m.query.GroupBy {
			next = (i + 1) % len(groups)
		}
	}
	m.query.GroupBy = groups[next]
	m.index, m.listOffset, m.scroll = 0, 0, 0
	return m.reload()
}

func (m *analyticsBrowser) promptDiagnosis() tea.Cmd {
	if m.opts.ReadOnly {
		m.notice = "Read-only: manual network diagnosis is disabled"
		return nil
	}
	if m.opts.Diagnose == nil {
		m.notice = "Manual diagnosis is unavailable in this view"
		return nil
	}
	if !m.snapshotMatches() {
		m.notice = "Refresh the report before diagnosing a selected domain"
		return nil
	}
	row, ok := m.selected()
	if !ok || row.SourceID == "" || row.Scope == "" {
		m.notice = "Diagnosis requires a row with a known source and observation scope"
		return nil
	}
	domain := m.query.Domain
	if m.query.GroupBy == "domain" {
		domain = row.Key
	}
	normalized, err := rulework.NormalizeDomain(domain)
	if err != nil {
		m.notice = "Select an attributed DNS domain; IPs and unknown domains cannot be diagnosed here"
		return nil
	}
	m.cancelDiagnosis()
	m.diagDomain = normalized
	m.inputMode = "target"
	m.layoutInput()
	m.input.SetValue(m.opts.TargetID)
	m.notice = "Choose a registered client target for this manual network probe; source IDs are not assumed to be targets"
	return m.input.Focus()
}

var analyticsTargetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (m *analyticsBrowser) promptDiagnosisPolicy() tea.Cmd {
	target := strings.TrimSpace(m.input.Value())
	if !analyticsTargetPattern.MatchString(target) {
		m.notice = "Enter a registered client target ID (letters, numbers, dot, dash or underscore)"
		return nil
	}
	m.diagTarget = target
	m.inputMode = "policy"
	m.layoutInput()
	m.input.SetValue("")
	m.notice = "Optionally compare DIRECT, PROXY, or an existing group; blank Enter uses the current route"
	return m.input.Focus()
}

func (m *analyticsBrowser) runDiagnosis() tea.Cmd {
	if m.opts.ReadOnly || m.opts.Diagnose == nil || m.diagDomain == "" {
		return nil
	}
	via := strings.TrimSpace(m.input.Value())
	if len(via) > 256 || analyticsText(via) != via || !analyticsTargetPattern.MatchString(m.diagTarget) {
		m.notice = "Use a valid registered target and an existing policy name without control characters"
		return nil
	}
	m.inputMode = ""
	m.input.Blur()
	m.cancelDiagnosis()
	ctx, cancel := context.WithTimeout(m.ctx, 90*time.Second)
	m.diagCancel = cancel
	m.diagPending = true
	m.diagVia = via
	m.diagBody = ""
	m.pane, m.scroll = 1, 0
	m.notice = "Running explicit network diagnosis; Esc cancels"
	serial, target, domain, run := m.diagSerial, m.diagTarget, m.diagDomain, m.opts.Diagnose
	return func() tea.Msg {
		defer cancel()
		body, err := run(ctx, target, domain, via)
		return analyticsDiagnosed{serial, body, err}
	}
}

func (m *analyticsBrowser) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if m.closed {
		return m, nil
	}
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = max(1, msg.Width), max(1, msg.Height)
		m.layoutInput()
		return m, nil
	case analyticsLoaded:
		if msg.serial != m.serial {
			return m, nil
		}
		m.pending = false
		m.cancel = nil
		m.stale = msg.err != nil
		if msg.err != nil {
			m.notice = "Refresh failed; prior snapshot retained: " + safeError(msg.err)
			return m, nil
		}
		selected, had := m.selected()
		m.report, m.reportQuery, m.hasReport = msg.report, msg.query, true
		m.index = min(m.index, max(0, len(m.rows())-1))
		if had {
			for i, row := range m.rows() {
				if row.SourceID == selected.SourceID && row.Key == selected.Key {
					m.index = i
					break
				}
			}
		}
		m.notice = "Stored observations ready; scopes remain separate"
		return m, nil
	case analyticsDiagnosed:
		if msg.serial != m.diagSerial {
			return m, nil
		}
		m.diagPending, m.diagCancel = false, nil
		m.diagBody = core.Sanitize(msg.body)
		if msg.err != nil {
			m.diagBody = "Diagnosis failed: " + safeError(msg.err)
		}
		m.notice = "Diagnosis finished; no rules were changed"
		return m, nil
	case tea.PasteMsg:
		if m.inputMode != "" {
			msg.Content = analyticsText(msg.Content)
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			if m.inputMode == "search" {
				m.filter = m.input.Value()
				m.index, m.listOffset, m.scroll = 0, 0, 0
			}
			return m, cmd
		}
	case tea.KeyPressMsg:
		key := msg.String()
		if key == "ctrl+c" {
			m.close()
			return m, tea.Quit
		}
		if m.inputMode != "" {
			switch key {
			case "esc":
				if m.inputMode == "search" {
					m.filter = ""
					m.index, m.listOffset = 0, 0
				}
				m.inputMode = ""
				m.input.Blur()
				return m, nil
			case "enter":
				if m.inputMode == "target" {
					return m, m.promptDiagnosisPolicy()
				}
				if m.inputMode == "policy" {
					return m, m.runDiagnosis()
				}
				m.inputMode = ""
				m.input.Blur()
				return m, nil
			}
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			if m.inputMode == "search" {
				m.filter = m.input.Value()
				m.index, m.listOffset, m.scroll = 0, 0, 0
			}
			return m, cmd
		}
		if m.help {
			if key == "esc" || key == "?" || key == "q" {
				m.help = false
			}
			return m, nil
		}
		switch key {
		case "q":
			m.close()
			return m, tea.Quit
		case "esc":
			if m.diagPending || m.diagBody != "" {
				m.cancelDiagnosis()
				m.diagBody = ""
				m.notice = "Returned to stored observations"
				return m, nil
			}
			if m.filter != "" {
				m.filter = ""
				m.index, m.listOffset = 0, 0
				return m, nil
			}
			if len(m.history) > 0 {
				last := m.history[len(m.history)-1]
				m.history = m.history[:len(m.history)-1]
				m.query, m.filter, m.index, m.period = last.query, last.filter, last.index, last.period
				m.listOffset, m.scroll, m.pane = 0, 0, 0
				return m, m.reload()
			}
			m.close()
			return m, tea.Quit
		case "?":
			m.help = true
		case "/":
			m.inputMode = "search"
			m.layoutInput()
			m.input.SetValue(m.filter)
			return m, m.input.Focus()
		case "tab", "shift+tab":
			m.pane = 1 - m.pane
		case "j", "down", "k", "up", "pgdown", "pgup":
			delta := 1
			if key == "k" || key == "up" || key == "pgup" {
				delta = -1
			}
			if key == "pgup" || key == "pgdown" {
				delta *= max(1, m.height-7)
			}
			if m.pane == 0 {
				m.index = max(0, min(m.index+delta, len(m.rows())-1))
				m.scroll = 0
			} else {
				m.scroll = max(0, min(m.scroll+delta, len(strings.Split(m.details(), "\n"))-1))
			}
		case "home":
			m.index, m.listOffset, m.scroll = 0, 0, 0
		case "end", "G":
			m.index = max(0, len(m.rows())-1)
		case "enter":
			return m, m.drill()
		case "g":
			return m, m.cycleGroup()
		case "w":
			return m, m.cycleWindow()
		case "r":
			return m, m.reload()
		case "d":
			return m, m.promptDiagnosis()
		}
	}
	if m.inputMode != "" {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(message)
		return m, cmd
	}
	return m, nil
}

func (m *analyticsBrowser) layoutInput() {
	prompt := map[string]string{"target": "Target ID: ", "policy": "Policy (optional): ", "search": "Filter: "}[m.inputMode]
	if m.width < 28 {
		prompt = map[string]string{"target": "ID: ", "policy": "Via: ", "search": "/ "}[m.inputMode]
	}
	if m.width < 8 {
		prompt = ""
	}
	m.input.Prompt = prompt
	m.input.SetWidth(max(1, m.width-ansi.StringWidth(prompt)-1))
}

func analyticsText(value string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(core.Sanitize(value))
}

func analyticsValue(value, missing string) string {
	if value == "" {
		return missing
	}
	return analyticsText(value)
}

func analyticsBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	n := float64(value)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB"} {
		n /= 1024
		if n < 1024 || unit == "TiB" {
			return fmt.Sprintf("%.2f %s", n, unit)
		}
	}
	return "unknown"
}

func analyticsMetricLabels(row analytics.ReportRow) (up, down, connections, active string) {
	up, down, connections = analyticsBytes(row.UploadBytes), analyticsBytes(row.DownloadBytes), fmt.Sprint(row.Connections)
	switch row.Kind {
	case "mihomo":
	case "access", "xray-access", "v2ray-access":
		up, down = "unavailable", "unavailable"
	case "interface", "host-interface", "vnstat", "stats", "xray-stats", "v2ray-stats":
		connections = "unavailable"
	default:
		up, down, connections = "unknown", "unknown", "unknown"
	}
	active = "unavailable"
	if row.ActiveMinutesAvailable {
		active = fmt.Sprintf("%d min", row.ActiveMinutes)
	}
	return
}

func analyticsCoverage(c analytics.Coverage) string {
	fraction := "unknown"
	if c.ExpectedSeconds > 0 {
		fraction = fmt.Sprintf("%.1f%%", max(0, min(100, 100*c.ObservedSeconds/c.ExpectedSeconds)))
	}
	partial := ""
	if c.Partial {
		partial = " · PARTIAL"
	}
	return fmt.Sprintf("%s: %s observed%s · state %s · gaps %d · resets %d · dropped %d",
		analyticsValue(c.SourceID, "unknown source"), fraction, partial, analyticsValue(c.Status.State, "unknown"), c.Status.GapCount, c.Status.ResetCount, c.Status.DroppedEvents)
}

func analyticsTime(at time.Time, zone string) string {
	if at.IsZero() {
		return "unknown"
	}
	if loc, err := time.LoadLocation(zone); err == nil {
		at = at.In(loc)
	}
	return at.Format("2006-01-02 15:04:05 -07:00")
}

// FormatAnalyticsReport does not sum observation sources or manufacture zeroes
// for unsupported dimensions. It is also the noninteractive report formatter.
func FormatAnalyticsReport(report analytics.Report) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Historical analytics · %s → %s (end exclusive)\nTimezone: %s · resolution: %s · group: %s\n",
		analyticsTime(report.From, report.Timezone), analyticsTime(report.To, report.Timezone), analyticsValue(report.Timezone, "unknown"), analyticsValue(report.Resolution, "unknown"), analyticsValue(report.GroupBy, "source"))
	if len(report.Rows) == 0 {
		out.WriteString("No observed rows. Missing history is not measured zero.\n")
	}
	for _, row := range report.Rows {
		up, down, connections, active := analyticsMetricLabels(row)
		fmt.Fprintf(&out, "%s [%s / %s] · %s\n  ↑/TX %s · ↓/RX %s · connections %s · observed activity %s\n",
			analyticsValue(row.SourceID, "unknown source"), analyticsValue(row.Scope, "unknown scope"), analyticsValue(row.Kind, "unknown kind"), analyticsValue(row.Key, "unattributed"), up, down, connections, active)
	}
	for _, coverage := range report.Coverage {
		out.WriteString("Coverage · " + analyticsCoverage(coverage) + "\n")
		if coverage.Status.Message != "" {
			out.WriteString("  " + analyticsText(coverage.Status.Message) + "\n")
		}
	}
	if len(report.Coverage) == 0 {
		out.WriteString("Coverage: unknown; no collected source matches this report.\n")
	}
	if report.Truncated {
		out.WriteString("More groups exist; refine the source or exact filters.\n")
	}
	for _, warning := range report.Warnings {
		out.WriteString("Note: " + analyticsText(warning) + "\n")
	}
	out.WriteString("Sources are separate observation points. Connections are not page visits; active minutes are not human browsing time.")
	return out.String()
}

func (m *analyticsBrowser) filterSummary() string {
	parts := []string{}
	for _, pair := range [][2]string{{"source", m.query.SourceID}, {"domain", m.query.Domain}, {"process", m.query.Process}, {"route", m.query.Route}, {"ip", m.query.IP}, {"principal", m.query.Principal}} {
		if pair[1] != "" {
			parts = append(parts, pair[0]+"="+analyticsText(pair[1]))
		}
	}
	if len(parts) == 0 {
		return "all sources, kept separate"
	}
	return "exact " + strings.Join(parts, " · ")
}

func (m *analyticsBrowser) details() string {
	if m.diagPending {
		return "Manual diagnosis\nClient target: " + analyticsText(m.diagTarget) + "\nDomain: " + analyticsText(m.diagDomain) + "\nCompare policy: " + analyticsValue(m.diagVia, "current route") + "\nWorking… Esc cancels."
	}
	if m.diagBody != "" {
		return m.diagBody + "\n\nOptional rule preview (choose an existing policy):\nlazyclash --target " + m.diagTarget + " rules add-domain " + m.diagDomain + " --via POLICY\nThis browser never applies rules. Esc returns to history."
	}
	row, ok := m.selected()
	if !ok {
		return FormatAnalyticsReport(analytics.Report{From: m.report.From, To: m.report.To, Timezone: m.report.Timezone, GroupBy: m.report.GroupBy, Resolution: m.report.Resolution, Coverage: m.report.Coverage, Warnings: m.report.Warnings})
	}
	up, down, connections, active := analyticsMetricLabels(row)
	var out strings.Builder
	fmt.Fprintf(&out, "%s\nSource: %s\nScope: %s · kind: %s\n↑ / TX: %s\n↓ / RX: %s\nConnections: %s\nObserved activity: %s\nFirst: %s\nLast: %s\n",
		analyticsValue(row.Key, "unattributed"), analyticsValue(row.SourceID, "unknown source"), analyticsValue(row.Scope, "unknown scope"), analyticsValue(row.Kind, "unknown kind"), up, down, connections, active, analyticsTime(row.First, m.report.Timezone), analyticsTime(row.Last, m.report.Timezone))
	found := false
	for _, coverage := range m.report.Coverage {
		if coverage.SourceID == row.SourceID {
			found = true
			out.WriteString("\nCoverage: " + analyticsCoverage(coverage) + "\n")
			out.WriteString(analyticsText(coverage.Status.Message) + "\n")
			out.WriteString("Last success: " + analyticsTime(coverage.Status.LastSuccess, m.report.Timezone) + "\n")
		}
	}
	if !found {
		out.WriteString("\nCoverage: unknown; no source coverage evidence.\n")
	}
	out.WriteString("\nConnections are not visits. Active minutes measure network activity, not human attention.\n")
	for _, warning := range m.report.Warnings {
		out.WriteString("\n" + analyticsText(warning))
	}
	return out.String()
}

func (m *analyticsBrowser) View() tea.View {
	width, height := max(1, m.width), max(1, m.height)
	header := "Historical analytics · " + analyticsText(m.query.GroupBy) + " · " + m.period
	if m.opts.ReadOnly {
		header += " · read-only"
	}
	if m.pending {
		header += " · loading"
	} else if m.stale {
		header += " · STALE"
	}
	if m.help {
		return topologyView(header+"\n↑↓ / j/k select · Tab list/details · PgUp/PgDn scroll\nEnter: source → domain → process → route → IP (exact filters)\ng group: source/domain/process/route/IP\nw calendar day/week/month, anchored to report end\n/ filter displayed rows (not a database filter) · Esc clears\nr refresh retains prior rows on failure\nd explicitly diagnose a domain using a registered client target\nDiagnosis is disabled in read-only mode; no automatic rule changes\nEsc: close prompt/result, clear search, previous drill, then exit\nq or Ctrl+C exits and cancels pending reads\nMissing/unsupported data is unknown, not measured zero\nConnections ≠ visits; activity ≠ human browsing time\nEsc/? closes help", width, height)
	}
	lines := []string{fit(header, width)}
	if m.inputMode != "" {
		lines = append(lines, fit(m.input.View(), width))
	} else {
		lines = append(lines, fit(m.filterSummary(), width))
	}
	from, to := m.query.From, m.query.To
	if m.hasReport {
		from, to = m.report.From, m.report.To
	}
	rangeLine := analyticsTime(from, m.query.Timezone) + " → " + analyticsTime(to, m.query.Timezone) + " · " + analyticsValue(m.report.Resolution, "unknown resolution")
	if m.hasReport && m.reportQuery != m.query {
		rangeLine = "RETAINED " + analyticsText(m.report.GroupBy) + " snapshot · " + rangeLine
	}
	lines = append(lines, fit(rangeLine, width))
	rows := m.rows()
	contentHeight := max(0, height-6)
	listWidth := min(48, max(24, width*45/100))
	narrow := width < 85
	if narrow {
		listWidth = width
	}
	offset := m.listOffset
	if m.index < offset {
		offset = m.index
	}
	if m.index >= offset+contentHeight {
		offset = max(0, m.index-contentHeight+1)
	}
	details := strings.Split(m.details(), "\n")
	for i := 0; i < contentHeight; i++ {
		left, right := "", ""
		if i+offset < len(rows) {
			row := rows[i+offset]
			prefix := "  "
			if i+offset == m.index {
				prefix = "> "
			}
			left = prefix + analyticsValue(row.Key, "unattributed") + " [" + analyticsValue(row.SourceID, "unknown source") + "/" + analyticsValue(row.Scope, "unknown scope") + "]"
		} else if i == 0 && len(rows) == 0 {
			left = "No observed rows; not measured zero"
		}
		if i+m.scroll < len(details) {
			right = details[i+m.scroll]
		}
		if narrow {
			if m.pane == 1 {
				left = right
			}
			lines = append(lines, fit(left, width))
		} else {
			lines = append(lines, fit(left, listWidth)+" │ "+fit(right, max(1, width-listWidth-3)))
		}
	}
	status := m.notice
	if m.filter != "" {
		status = "Local filter " + analyticsText(m.filter) + " · " + status
	}
	lines = append(lines, fit(analyticsText(status), width))
	lines = append(lines, fit(fmt.Sprintf("%d visible rows · Tab %s · %d drill levels", len(rows), []string{"details", "list"}[m.pane], len(m.history)), width))
	lines = append(lines, fit("Enter drill · g group · w window · / filter · r refresh · d diagnose · ? help · Esc back", width))
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], width, "")
	}
	v := tea.NewView(strings.Join(lines, "\n"))
	v.AltScreen = true
	v.WindowTitle = "lazyclash · analytics"
	return v
}
