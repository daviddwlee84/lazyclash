package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/analytics"
)

// analyticsCollector is a report reader, not a transport or a shared ingestion
// endpoint. Each load owns its host-local database and observation scopes.
type analyticsCollector struct {
	ID   string
	Load func(context.Context, analytics.Query) (analytics.Report, error)
}

type collectorReportResult struct {
	index  int
	report analytics.Report
	err    error
}

// federatedAnalytics juxtaposes independently measured sources. It never adds
// bytes across collectors or attempts to infer matching client/server flows.
func federatedAnalytics(ctx context.Context, q analytics.Query, collectors []analyticsCollector) (analytics.Report, error) {
	out := analytics.Report{From: q.From, To: q.To, Timezone: q.Timezone, GroupBy: q.GroupBy, Rows: []analytics.ReportRow{}, Coverage: []analytics.Coverage{}, Warnings: []string{}}
	if q.GroupBy == "" {
		q.GroupBy = "source"
		out.GroupBy = "source"
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 1000 {
		return out, errors.New("analytics query limit must be 1–1000")
	}
	seen := map[string]bool{}
	selected := make([]analyticsCollector, 0, len(collectors))
	for _, collector := range collectors {
		id := collector.ID
		if id == "" || len(id) > 256 || strings.TrimSpace(id) != id || strings.Contains(id, "::") || strings.ContainsAny(id, "\x00\r\n\t") {
			return out, errors.New("collector IDs must be nonempty labels without :: or control characters; use an SSH alias")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		selected = append(selected, collector)
	}
	if len(selected) > 8 {
		return out, errors.New("analytics reports support at most 8 distinct collectors")
	}
	if id, source, namespaced := strings.Cut(q.SourceID, "::"); namespaced {
		if id == "" || source == "" {
			return out, errors.New("source selector must be collector::source")
		}
		match := false
		for _, collector := range selected {
			if collector.ID == id {
				selected = []analyticsCollector{collector}
				match = true
				break
			}
		}
		if !match {
			return out, errors.New("no configured collector matches the namespaced source selector")
		}
		q.SourceID = source
	}
	if len(selected) == 0 {
		return out, errors.New("no analytics collectors selected")
	}
	results := make(chan collectorReportResult, len(selected))
	sem := make(chan struct{}, 4)
	for index, collector := range selected {
		index, collector := index, collector
		go func() {
			select {
			case <-ctx.Done():
				results <- collectorReportResult{index: index, err: ctx.Err()}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				results <- collectorReportResult{index: index, err: err}
				return
			}
			if collector.Load == nil {
				results <- collectorReportResult{index: index, err: errors.New("collector has no report reader")}
				return
			}
			r, err := collector.Load(ctx, q)
			results <- collectorReportResult{index: index, report: r, err: err}
		}()
	}
	loaded := make(map[int]collectorReportResult, len(selected))
	var canceled error
	for len(loaded) < len(selected) {
		select {
		case result := <-results:
			loaded[result.index] = result
		case <-ctx.Done():
			canceled = ctx.Err()
			goto aggregate
		}
	}
aggregate:
	// Include already completed loads when cancellation races their result. The
	// buffered channel lets remaining bounded workers finish without a receiver.
	for {
		select {
		case result := <-results:
			loaded[result.index] = result
		default:
			goto drained
		}
	}
drained:
	if canceled == nil {
		canceled = ctx.Err()
	}
	resolutions := map[string]bool{}
	successful := 0
	for index, collector := range selected {
		result, ok := loaded[index]
		if !ok {
			result.err = canceled
			if result.err == nil {
				result.err = errors.New("collector did not return a report")
			}
		}
		r := result.report
		prefix := collector.ID + "::"
		if result.err == nil {
			successful++
		}
		if r.Resolution != "" {
			resolutions[r.Resolution] = true
		}
		if out.Timezone == "" && r.Timezone != "" {
			out.Timezone = r.Timezone
		}
		if r.Timezone != "" && out.Timezone != r.Timezone {
			out.Warnings = append(out.Warnings, "["+collector.ID+"] original report timezone: "+r.Timezone)
		}
		for _, row := range r.Rows {
			if q.SourceID != "" && row.SourceID != q.SourceID {
				continue
			}
			original := row.SourceID
			row.SourceID = prefix + original
			if q.GroupBy == "source" && row.Key == original {
				row.Key = row.SourceID
			}
			out.Rows = append(out.Rows, row)
		}
		for _, coverage := range r.Coverage {
			if q.SourceID != "" && coverage.SourceID != q.SourceID {
				continue
			}
			original := coverage.SourceID
			coverage.SourceID = prefix + original
			if coverage.Status.SourceID == "" {
				coverage.Status.SourceID = original
			}
			coverage.Status.SourceID = prefix + coverage.Status.SourceID
			if coverage.Status.Source != nil {
				source := *coverage.Status.Source
				if source.ID == "" {
					source.ID = original
				}
				source.ID = prefix + source.ID
				coverage.Status.Source = &source
			}
			out.Coverage = append(out.Coverage, coverage)
		}
		for _, warning := range r.Warnings {
			out.Warnings = append(out.Warnings, "["+collector.ID+"] "+warning)
		}
		out.Truncated = out.Truncated || r.Truncated
		if result.err != nil {
			message := "collector unavailable; no zero traffic is inferred"
			if errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded) {
				message = "collector query canceled or timed out; no zero traffic is inferred"
			}
			out.Warnings = append(out.Warnings, "["+collector.ID+"] "+message)
			out.Coverage = append(out.Coverage, analytics.Coverage{SourceID: prefix + "(unavailable)", ExpectedSeconds: max(float64(0), q.To.Sub(q.From).Seconds()), Partial: true, Status: analytics.SourceStatus{SourceID: prefix + "(unavailable)", State: "unavailable", Message: message, LastAttempt: time.Now()}})
		}
	}
	if out.Timezone == "" {
		out.Timezone = analytics.DefaultTimezone
	}
	if len(resolutions) > 1 || resolutions["mixed"] {
		out.Resolution = "mixed"
	} else {
		for resolution := range resolutions {
			out.Resolution = resolution
		}
	}
	if out.Resolution == "" {
		out.Resolution = "unknown"
	}
	sort.SliceStable(out.Rows, func(i, j int) bool {
		a, b := out.Rows[i], out.Rows[j]
		at, bt := uint64(a.UploadBytes)+uint64(a.DownloadBytes), uint64(b.UploadBytes)+uint64(b.DownloadBytes)
		if at != bt {
			return at > bt
		}
		if a.Connections != b.Connections {
			return a.Connections > b.Connections
		}
		return a.SourceID+"\x00"+a.Key < b.SourceID+"\x00"+b.Key
	})
	sort.SliceStable(out.Coverage, func(i, j int) bool { return out.Coverage[i].SourceID < out.Coverage[j].SourceID })
	if len(out.Rows) > q.Limit {
		out.Rows = out.Rows[:q.Limit]
		out.Truncated = true
		out.Warnings = append(out.Warnings, fmt.Sprintf("Showing the first %d groups across collectors; refine source/filters for remaining rows.", q.Limit))
	}
	out.Warnings = append(out.Warnings, "Collector and client/server/host observation scopes remain independent; rows are not a combined bill or inferred end-to-end flow correlation.")
	if len(out.Rows) == 0 && len(out.Coverage) == 0 {
		out.Warnings = append(out.Warnings, "No matching collected sources were returned; missing observations are not measured zero.")
	}
	if canceled != nil {
		return out, canceled
	}
	if successful == 0 {
		return out, errors.New("all selected analytics collectors are unavailable")
	}
	return out, nil
}
