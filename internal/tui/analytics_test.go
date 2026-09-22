package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/analytics"
)

func analyticsTestQuery() analytics.Query {
	return analytics.Query{From: time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC), Timezone: "UTC", GroupBy: "source", Limit: 100}
}

func analyticsTestReport(q analytics.Query) analytics.Report {
	key := "client-a"
	if q.GroupBy == "domain" {
		key = "example.com"
	}
	if q.GroupBy == "process" {
		key = "/Applications/Browser.app"
	}
	return analytics.Report{
		From: q.From, To: q.To, Timezone: q.Timezone, GroupBy: q.GroupBy, Resolution: "minute",
		Rows:     []analytics.ReportRow{{SourceID: "client-a", Kind: "mihomo", Scope: "client", Key: key, UploadBytes: 1024, DownloadBytes: 2048, Connections: 8, ActiveMinutes: 3, ActiveMinutesAvailable: true}},
		Coverage: []analytics.Coverage{{SourceID: "client-a", ObservedSeconds: 1800, ExpectedSeconds: 3600, Partial: true, Status: analytics.SourceStatus{State: "ready", GapCount: 1}}},
	}
}

func loadAnalyticsFixture(t *testing.T, options AnalyticsOptions) *analyticsBrowser {
	t.Helper()
	if options.Query.To.IsZero() {
		options.Query = analyticsTestQuery()
	}
	if options.Load == nil {
		options.Load = func(_ context.Context, q analytics.Query) (analytics.Report, error) {
			return analyticsTestReport(q), nil
		}
	}
	m := newAnalyticsBrowser(context.Background(), options)
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("missing initial reader")
	}
	m.Update(cmd())
	t.Cleanup(m.close)
	return m
}

func TestAnalyticsCancelsStaleGenerationsAndRetainsUsefulSnapshot(t *testing.T) {
	var contexts []context.Context
	fail := false
	m := loadAnalyticsFixture(t, AnalyticsOptions{Load: func(ctx context.Context, q analytics.Query) (analytics.Report, error) {
		contexts = append(contexts, ctx)
		if fail {
			return analytics.Report{}, errors.New("collector unreachable")
		}
		return analyticsTestReport(q), nil
	}})
	first := m.reload()
	second := m.reload()
	m.Update(first())
	if !m.pending || !m.hasReport || len(m.report.Rows) != 1 {
		t.Fatal("late result was accepted")
	}
	m.Update(second())
	if m.pending || m.stale || contexts[len(contexts)-2].Err() == nil {
		t.Fatal("superseded request not canceled")
	}
	fail = true
	cmd := m.reload()
	m.Update(cmd())
	if !m.stale || !m.hasReport || len(m.report.Rows) != 1 || !strings.Contains(m.notice, "prior snapshot retained") {
		t.Fatal("failed refresh erased history")
	}
	if m.drill() != nil {
		t.Fatal("stale rows drove a new exact filter")
	}
	m.close()
	m.Update(analyticsLoaded{serial: m.serial, report: analytics.Report{Rows: []analytics.ReportRow{{Key: "late"}}}})
	if m.report.Rows[0].Key == "late" {
		t.Fatal("closed browser accepted late read")
	}
}

func TestAnalyticsDrillPreservesExactFiltersAndEscRestores(t *testing.T) {
	q := analyticsTestQuery()
	q.IP, q.Route = "192.0.2.10", "PROXY → node one"
	m := loadAnalyticsFixture(t, AnalyticsOptions{Query: q})
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || m.query.SourceID != "client-a" || m.query.GroupBy != "domain" || m.query.IP != q.IP || m.query.Route != q.Route {
		t.Fatal("source drill lost exact scope", m.query)
	}
	// The old source rows remain visible until the domain read completes, but
	// cannot be misinterpreted as domain rows for a second drill.
	if next := m.drill(); next != nil || len(m.history) != 1 {
		t.Fatal("pending drill reused stale rows")
	}
	m.Update(cmd())
	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || m.query.Domain != "example.com" || m.query.GroupBy != "process" || m.query.SourceID != "client-a" {
		t.Fatal("domain drill failed", m.query)
	}
	m.Update(cmd())
	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if cmd == nil || m.query.GroupBy != "domain" || m.query.Domain != "" || len(m.history) != 1 {
		t.Fatal("back did not restore prior query")
	}
	m.Update(cmd())
	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if cmd == nil || m.query != q || len(m.history) != 0 {
		t.Fatal("second back did not restore entry query")
	}
}

func TestAnalyticsSearchAndTargetPromptOwnKeystrokes(t *testing.T) {
	m := loadAnalyticsFixture(t, AnalyticsOptions{})
	serial, query := m.serial, m.query
	m.Update(tea.KeyPressMsg{Code: '/'})
	m.Update(tea.PasteMsg{Content: "qjkgwdr/"})
	for _, r := range "rwgdkq" {
		m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	if m.closed || m.inputMode != "search" || m.serial != serial || m.query != query || len(m.rows()) != 0 {
		t.Fatal("search input triggered navigation or network work")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	if m.filter != "" || m.inputMode != "" || len(m.rows()) != 1 {
		t.Fatal("search cancellation lost original rows")
	}
}

func TestAnalyticsManualDiagnosisRequiresExplicitTargetAndDoesNotMutate(t *testing.T) {
	q := analyticsTestQuery()
	q.GroupBy = "domain"
	calls := 0
	m := loadAnalyticsFixture(t, AnalyticsOptions{Query: q, Diagnose: func(_ context.Context, target, domain, via string) (string, error) {
		calls++
		if target != "registered-client" || domain != "example.com" || via != "DIRECT" {
			t.Fatal("source was mistaken for a client target", target, domain)
		}
		return "diagnostic evidence", nil
	}})
	m.Update(tea.KeyPressMsg{Code: 'd'})
	if m.inputMode != "target" || calls != 0 || m.input.Value() != "" {
		t.Fatal("diagnosis skipped explicit target selection")
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil || calls != 0 || m.inputMode != "target" {
		t.Fatal("empty target launched diagnosis")
	}
	m.Update(tea.PasteMsg{Content: "registered-client"})
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.inputMode != "policy" || calls != 0 {
		t.Fatal("target submission skipped the optional policy prompt")
	}
	m.Update(tea.PasteMsg{Content: "DIRECT"})
	_, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil || calls != 0 || !m.diagPending {
		t.Fatal("diagnosis must remain asynchronous")
	}
	m.Update(cmd())
	if calls != 1 || !strings.Contains(m.details(), "rules add-domain example.com --via POLICY") || strings.Contains(m.details(), "--yes") {
		t.Fatal("manual preview hint missing or applies a rule", m.details())
	}
	// These are browse-only keys: the only injected callback capable of network
	// work must not run again while reading, grouping, or opening help.
	for _, key := range []rune{'?', '?', 'g', 'w', 'r', 'j', 'k'} {
		m.Update(tea.KeyPressMsg{Code: key})
	}
	if calls != 1 {
		t.Fatal("browse-only action invoked diagnosis")
	}
	m.opts.ReadOnly = true
	m.Update(tea.KeyPressMsg{Code: 'd'})
	if m.inputMode == "target" || calls != 1 || !strings.Contains(m.notice, "Read-only") {
		t.Fatal("read-only diagnosis was enabled")
	}
}

func TestAnalyticsDiagnosisRejectsUnknownProvenanceAndLateResults(t *testing.T) {
	q := analyticsTestQuery()
	q.GroupBy = "domain"
	m := loadAnalyticsFixture(t, AnalyticsOptions{Query: q, TargetID: "client", Diagnose: func(context.Context, string, string, string) (string, error) { return "late", nil }})
	for _, row := range []analytics.ReportRow{
		{Key: "example.com", Scope: "client"},
		{Key: "example.com", SourceID: "source"},
		{Key: "(unattributed)", SourceID: "source", Scope: "server"},
		{Key: "192.0.2.1", SourceID: "source", Scope: "server"},
	} {
		m.report.Rows = []analytics.ReportRow{row}
		if m.promptDiagnosis() != nil || m.inputMode == "target" {
			t.Fatal("ambiguous/non-domain row opened diagnosis", row)
		}
	}
	m.report = analyticsTestReport(q)
	m.promptDiagnosis()
	m.promptDiagnosisPolicy()
	cmd := m.runDiagnosis()
	if cmd == nil {
		t.Fatal("expected explicit seeded target diagnosis")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyEscape})
	m.Update(cmd())
	if m.diagBody != "" || m.diagPending {
		t.Fatal("canceled diagnosis applied a late result")
	}
}

func TestAnalyticsCalendarWindowsUseTimezoneAndExclusiveBoundaries(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 3, 9, 0, 0, 0, 0, loc)
	start, err := analyticsPeriodStart(end, "day", loc.String())
	if err != nil || start.Day() != 8 || end.Sub(start) != 23*time.Hour {
		t.Fatal("calendar day mishandled DST or end exclusivity", start, err)
	}
	q := analyticsTestQuery()
	m := loadAnalyticsFixture(t, AnalyticsOptions{Query: q})
	m.cycleWindow()
	if m.period != "week" || m.query.From.Weekday() != time.Monday || !m.query.To.Equal(q.To) {
		t.Fatal("week window should be Monday and keep historical anchor")
	}
	m.cycleWindow()
	if m.period != "month" || m.query.From.Day() != 1 || !m.query.To.Equal(q.To) {
		t.Fatal("month window")
	}
}

func TestAnalyticsFormatsUnknownCapabilitiesCoverageAndSmallScreens(t *testing.T) {
	r := analyticsTestReport(analyticsTestQuery())
	r.Rows = []analytics.ReportRow{
		{SourceID: "vps", Kind: "xray-access", Scope: "server", Key: "example.com", Connections: 3},
		{SourceID: "host", Kind: "interface", Scope: "host", Key: "eth0", UploadBytes: 2048},
		{Key: "東京 👩🏽‍💻 é\x1b[31mtext\x1b[0m\nnext"},
	}
	r.Coverage = append(r.Coverage, analytics.Coverage{SourceID: "host", Status: analytics.SourceStatus{State: "unavailable", Message: "Cannot read source"}})
	r.Truncated = true
	text := FormatAnalyticsReport(r)
	for _, want := range []string{"unknown scope", "unavailable", "50.0% observed", "PARTIAL", "host: unknown observed", "connections 3", "Sources are separate", "More groups exist"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, "\x1b") {
		t.Fatal("remote terminal control escaped sanitization")
	}
	m := loadAnalyticsFixture(t, AnalyticsOptions{})
	m.report = r
	for _, size := range []tea.WindowSizeMsg{{Width: 1, Height: 1}, {Width: 22, Height: 7}, {Width: 80, Height: 24}, {Width: 130, Height: 36}} {
		m.Update(size)
		for _, pane := range []int{0, 1} {
			m.pane = pane
			for _, help := range []bool{false, true} {
				m.help = help
				lines := strings.Split(m.View().Content, "\n")
				if len(lines) > size.Height {
					t.Fatal("analytics view overflowed height")
				}
				for _, line := range lines {
					if ansi.StringWidth(line) > size.Width {
						t.Fatalf("analytics view overflowed width %d: %q", size.Width, line)
					}
				}
			}
		}
	}
	if err := RunAnalytics(context.Background(), AnalyticsOptions{}, nil, nil); err == nil {
		t.Fatal("missing report reader accepted")
	}
}

func TestAnalyticsNarrowPromptsLeaveRoomForTypedPolicy(t *testing.T) {
	m := loadAnalyticsFixture(t, AnalyticsOptions{})
	m.inputMode = "policy"
	m.input.SetValue("DIRECT")
	for _, width := range []int{12, 24, 40, 80} {
		m.Update(tea.WindowSizeMsg{Width: width, Height: 12})
		m.input.Focus()
		if ansi.StringWidth(m.input.Prompt)+6 >= width {
			t.Fatalf("prompt leaves no room for policy at width %d: %q", width, m.input.Prompt)
		}
		if !strings.Contains(ansi.Strip(m.View().Content), "DIRECT") {
			t.Fatalf("typed policy is invisible at width %d", width)
		}
	}
}
