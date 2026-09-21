package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/dashboard"
)

// overviewLayout is pure: rendering and hit testing consume the same lines and regions.
func (m *Model) overviewLayout(width int) ([]string, []hitRegion) {
	s := m.state()
	now := time.Now()
	snap := s.metrics.Snapshot(now)
	lines, hits := m.overviewStatusLayout(width)
	add := func(text string) { lines = append(lines, fit(text, width)) }
	value := func(sample dashboard.Sample, rate bool) string {
		if !sample.Valid {
			return "?"
		}
		v := bytesLabel(sample.Value)
		if rate {
			v += "/s"
		}
		if sample.Stale(now) {
			v += " STALE"
		}
		return v
	}
	count := "?"
	if !snap.ConnectionsAt.IsZero() {
		count = fmt.Sprint(snap.Connections.Count)
		if now.Sub(snap.ConnectionsAt) > 5*time.Second {
			count += " STALE"
		}
	}
	memory := value(snap.Memory, false)
	if snap.MemoryWarmup {
		memory = "warming up"
	}
	cards := []struct{ title, value string }{{"Upload", value(snap.Upload, true)}, {"Download", value(snap.Download, true)}, {"Uploaded", value(snap.UploadTotal, false)}, {"Downloaded", value(snap.DownloadTotal, false)}, {"Connections", count}, {"Core RSS", memory}}
	columns := 3
	if width >= 120 {
		columns = 6
	} else if width < 60 {
		columns = 2
	}
	for start := 0; start < len(cards); start += columns {
		widths := columnWidths(width, columns)
		parts := [][]string{}
		cardHeight := 3
		compact := width >= 60 && width < 120
		if compact {
			cardHeight = 1
		}
		for i := 0; i < columns && start+i < len(cards); i++ {
			c := cards[start+i]
			if compact {
				parts = append(parts, []string{fit(c.title+" "+m.accent(c.value), widths[i])})
			} else {
				parts = append(parts, panel(c.title, []string{m.accent(c.value)}, widths[i]))
			}
		}
		lines = append(lines, strings.Split(joinColumns(parts, widths, cardHeight), "\n")...)
	}
	if s.lastOperation != "" {
		add("Last operation: " + s.lastOperation)
	}
	add(fmt.Sprintf("History %s · %s · w window · v style · gaps = no sample", historyWindowLabel(m.historyWindow), m.graphStyle))
	chart := func(title, metric string, w, h int) []string {
		points := s.metrics.Series(metric, now, m.historyWindow)
		title += " · " + chartScale(points, metric)

		body := strings.Split(dashboard.Chart(points, now.Add(-m.historyWindow), now, max(1, w-2), max(1, h-3), m.graphStyle), "\n")
		body = append(body, now.Add(-m.historyWindow).Format("15:04:05")+"  →  "+now.Format("15:04:05"))
		return panel(title, body, w)
	}
	if width >= 100 {
		widths := []int{width * 62 / 100, width - width*62/100 - 3}
		traffic := chart("Download /s", "download", widths[0], 7)
		memoryChart := chart("Core RSS", "memory", widths[1], 7)
		lines = append(lines, strings.Split(joinColumns([][]string{traffic, memoryChart}, widths, 7), "\n")...)
		traffic = chart("Upload /s", "upload", widths[0], 5)
		conn := chart("Active connections", "connections", widths[1], 5)
		lines = append(lines, strings.Split(joinColumns([][]string{traffic, conn}, widths, 5), "\n")...)
	} else {
		for _, c := range []struct{ title, metric string }{{"Down", "download"}, {"Up", "upload"}, {"RSS", "memory"}, {"Active", "connections"}} {
			points := s.metrics.Series(c.metric, now, m.historyWindow)
			label := fit(c.title+" "+chartScale(points, c.metric), min(25, max(8, width/3)))
			add(label + " " + dashboard.Sparkline(points, now.Add(-m.historyWindow), now, max(1, width-ansi.StringWidth(label)-1), m.graphStyle))
		}
		add(now.Add(-m.historyWindow).Format("15:04:05") + "  →  " + now.Format("15:04:05"))
	}

	add("Sources · " + sampleAge("traffic", snap.TrafficAt, now) + " · " + sampleAge("memory", snap.MemoryAt, now) + " · " + sampleAge("connections", snap.ConnectionsAt, now))
	if !snap.TotalsResetAt.IsZero() {
		add("Core totals reset detected at " + snap.TotalsResetAt.Format("15:04:05"))
	}
	appendBucket := func(kind string, b dashboard.Bucket, total int) {
		id := kind + ":" + b.Key
		mark := "  "
		if m.overviewSelection == id {
			mark = "> "
		}
		barWidth := max(3, min(20, width/6))
		filled := 0
		if total > 0 {
			filled = b.Count * barWidth / total
		}
		text := fmt.Sprintf("%s%s %s %d", mark, core.Sanitize(b.Label), strings.Repeat(barFill(m.graphStyle), filled)+strings.Repeat("·", barWidth-filled), b.Count)
		if kind == "outbound" {
			text += " · ↑ " + bytesLabel(b.Upload) + " ↓ " + bytesLabel(b.Download)
		}
		hits = append(hits, hitRegion{rect: rect{0, len(lines), width, 1}, kind: "overview", id: id})
		add(text)
	}
	add(m.accent("Network types · active connections (Enter / Inspect button)"))
	for _, b := range snap.Connections.Protocols {
		appendBucket("protocol", b, snap.Connections.Count)
	}
	add(m.accent("Top outbounds · active-connection totals"))
	for i, b := range snap.Connections.Outbounds {
		if i >= 6 {
			break
		}
		appendBucket("outbound", b, snap.Connections.Count)
	}
	add(m.accent("Observed routes · rule → groups → outbound"))
	groups := map[string]bool{}
	for i, b := range snap.Connections.Routes {
		if i >= 6 {
			break
		}
		appendBucket("route", b, snap.Connections.Count)
		for _, g := range b.Groups {
			groups[g] = true
		}
	}
	if len(groups) > 0 {
		add(m.accent("Observed groups · Enter opens Proxies"))
	}
	for _, g := range sortedKeys(groups) {
		id := "group:" + g
		mark := "  "
		if m.overviewSelection == id {
			mark = "> "
		}
		hits = append(hits, hitRegion{rect: rect{0, len(lines), width, 1}, kind: "overview", id: id})
		add(mark + core.Sanitize(g))
	}
	if snap.ConnectionsAt.IsZero() {
		add("Waiting for connections…")
	}
	add("")
	add(m.accent("IP.SB egress / website latency · manual probes"))
	if m.target.ProbeProxy == "" {
		add("Configure target Data proxy URL before testing · : Edit current target")
	} else {
		add("Data proxy: " + m.target.ProbeProxy + " · i IP.SB · L websites")
	}
	if s.probePending != "" {
		add("Testing " + s.probePending + "…")
	}
	for _, text := range []string{s.probeIP, s.probeLatency} {
		if text != "" {
			for _, line := range strings.Split(core.Sanitize(text), "\n") {
				add(line)
			}
		}
	}
	add("Rule mode can send different destinations through different outbounds.")
	add("")
	add(m.accent("Controller summary"))
	version := object(s.snap("version").data)
	cfg := m.configData()
	add("Controller: " + m.target.Controller)
	add("SSH: " + defaultString(m.target.SSHHost, "local / direct"))
	add("Core version: " + defaultString(str(version, "version"), "unknown"))
	add("Mode: " + defaultString(str(cfg, "mode"), "unknown") + " · TUN (core report): " + boolLabel(object(cfg["tun"]), "enable") + " · Allow LAN: " + boolLabel(cfg, "allow-lan"))
	add(m.freshness(overview))
	for _, key := range []string{"traffic", "memory", "logs"} {
		if e := s.streamErrors[key]; e != "" {
			add(key + " stream stale: " + e)
		}
	}
	if s.lastOperation != "" {
		add("Last operation: " + s.lastOperation)
	}
	if s.lastApplied != "" {
		add("Last applied by lazyclash: " + s.lastApplied)
	}
	return lines, hits
}
func columnWidths(width, n int) []int {
	out := make([]int, n)
	space := max(n, width-(n-1)*3)
	for i := range out {
		out[i] = space / n
	}
	out[n-1] += space % n
	return out
}
func panel(title string, body []string, width int) []string {
	if width < 4 {
		return fitLines(strings.Join(append([]string{title}, body...), "\n"), width, len(body)+2)
	}
	inner := width - 2
	title = fit(" "+title+" ", inner)
	out := []string{"┌" + title + "┐"}
	for _, line := range body {
		out = append(out, "│"+fit(line, inner)+"│")
	}
	return append(out, "└"+strings.Repeat("─", inner)+"┘")
}
func sampleAge(name string, at, now time.Time) string {
	if at.IsZero() {
		return name + " unknown"
	}
	age := max(0, now.Sub(at).Seconds())
	prefix := ""
	if age > 5 {
		prefix = "STALE "
	}
	return fmt.Sprintf("%s %s%.0fs", name, prefix, age)
}
func (m *Model) overviewView(width, height int) string {
	lines, _ := m.overviewLayout(width)
	offset := max(0, min(m.state().view(overview).detailOffset, max(0, len(lines)-height)))
	return strings.Join(fitLines(strings.Join(lines[offset:], "\n"), width, height), "\n")
}
func (m *Model) activateOverview(id string) tea.Cmd {
	kind, key, ok := strings.Cut(id, ":")
	if !ok {
		return nil
	}
	if kind == "group" {
		v := m.state().view(proxies)
		v.query = ""
		v.focus = 0
		v.positions[0].selected = key
		return m.changePage(int(proxies))
	}
	snap := m.state().metrics.Snapshot(time.Now())
	var buckets []dashboard.Bucket
	switch kind {
	case "protocol":
		buckets = snap.Connections.Protocols
	case "outbound":
		buckets = snap.Connections.Outbounds
	case "route":
		buckets = snap.Connections.Routes
	}
	for _, b := range buckets {
		if b.Key == key {
			v := m.state().view(connections)
			v.query = ""
			v.exactFilter = b.Filter
			v.focus = 0
			v.positions[0] = position{}
			return m.changePage(int(connections))
		}
	}
	return nil
}

func barFill(style string) string {
	if style == "ascii" {
		return "#"
	}
	return "█"
}

func historyWindowLabel(window time.Duration) string {
	return fmt.Sprintf("%dm", int(window/time.Minute))
}
func chartScale(points []dashboard.Point, metric string) string {
	peak := float64(0)
	valid := false
	for _, point := range points {
		if point.Valid {
			valid = true
			if point.Value > peak {
				peak = point.Value
			}
		}
	}
	if !valid {
		return "no samples"
	}
	scale := bytesLabel(peak)
	if metric == "connections" {
		scale = fmt.Sprintf("%.0f", peak)
	} else if metric == "upload" || metric == "download" {
		scale += "/s"
	}
	return "0–" + scale
}
