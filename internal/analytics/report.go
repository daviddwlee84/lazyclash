package analytics

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *Store) Report(ctx context.Context, q Query) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	r := Report{From: q.From, To: q.To, Timezone: q.Timezone, GroupBy: q.GroupBy, Rows: []ReportRow{}, Coverage: []Coverage{}, Warnings: []string{}}
	if q.From.IsZero() || !q.To.After(q.From) || q.To.Sub(q.From) > 3660*24*time.Hour {
		return r, errors.New("analytics report requires an increasing range no longer than 10 years")
	}
	if q.GroupBy == "" {
		q.GroupBy = "source"
	}
	column := map[string]string{"source": "source_id", "domain": "domain", "process": "process", "route": "route", "ip": "ip", "principal": "principal"}[q.GroupBy]
	if column == "" {
		return r, errors.New("analytics group_by must be source, domain, process, route, ip or principal")
	}
	r.GroupBy = q.GroupBy
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 1000 {
		return r, errors.New("analytics query limit must be 1–1000")
	}
	storedZone := s.timezone(ctx)
	if r.Timezone == "" {
		r.Timezone = storedZone
	}
	if _, err := time.LoadLocation(r.Timezone); err != nil {
		return r, errors.New("invalid report timezone")
	}
	loc, err := time.LoadLocation(storedZone)
	if err != nil {
		return r, err
	}
	status, err := s.Status(ctx)
	if err != nil {
		return r, err
	}
	var minuteCutoff int64
	_ = s.db.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM meta WHERE key='minute_cutoff'").Scan(&minuteCutoff)
	resolutions := map[string]bool{}
	for _, src := range status.Sources {
		if q.SourceID != "" && q.SourceID != src.SourceID {
			continue
		}
		res := "minute"
		var coarse int
		err = s.db.QueryRowContext(ctx, "SELECT coarse_day FROM sources WHERE id=?", src.SourceID).Scan(&coarse)
		if err != nil {
			return r, err
		}
		if coarse != 0 || q.From.UnixMilli() < minuteCutoff {
			res = "day"
		}
		resolutions[res] = true
		from, to := q.From.Truncate(time.Minute), q.To
		if !to.Equal(to.Truncate(time.Minute)) {
			to = to.Truncate(time.Minute).Add(time.Minute)
		}
		if res == "day" {
			from = dayStart(q.From, loc)
			to = dayStart(q.To, loc)
			if !q.To.Equal(to) {
				to = to.AddDate(0, 0, 1)
			}
			r.Warnings = appendUnique(r.Warnings, "Daily rows contain whole source-local calendar buckets; partial-day filters cannot split native or retained daily totals. Active minutes are unavailable at daily resolution.")
		}
		if !from.Equal(q.From) || !to.Equal(q.To) {
			r.Warnings = appendUnique(r.Warnings, "Range boundaries use complete available buckets; byte allocation inside sampled counter intervals is estimated by elapsed time.")
		}
		where := "resolution=? AND source_id=? AND bucket>=? AND bucket<?"
		args := []any{res, src.SourceID, from.UnixMilli(), to.UnixMilli()}
		for _, f := range []struct{ column, value string }{{"domain", normalizeHost(q.Domain)}, {"process", q.Process}, {"route", q.Route}, {"ip", q.IP}, {"principal", q.Principal}} {
			if f.value != "" {
				if len(f.value) > 2048 {
					return r, errors.New("analytics filter is too long")
				}
				where += " AND " + f.column + "=?"
				args = append(args, f.value)
			}
		}
		active := "COUNT(DISTINCT CASE WHEN up>0 OR down>0 THEN bucket ELSE NULL END)"
		if res == "day" {
			active = "0"
		}
		query := "SELECT " + column + ",SUM(up),SUM(down),SUM(events)," + active + ",MIN(first),MAX(last) FROM metrics WHERE " + where + " GROUP BY " + column + " ORDER BY SUM(up)+SUM(down) DESC,SUM(events) DESC," + column + " LIMIT ?"
		args = append(args, q.Limit+1)
		rows, x := s.db.QueryContext(ctx, query, args...)
		if x != nil {
			return r, x
		}
		for rows.Next() {
			bytesAvailable, connectionsAvailable := metricCapabilities(src.Kind)
			row := ReportRow{SourceID: src.SourceID, Kind: src.Kind, Scope: src.Scope, BytesAvailable: bytesAvailable, ConnectionsAvailable: connectionsAvailable, ActiveMinutesAvailable: res == "minute" && bytesAvailable}
			var first, last int64
			if x = rows.Scan(&row.Key, &row.UploadBytes, &row.DownloadBytes, &row.Connections, &row.ActiveMinutes, &first, &last); x != nil {
				rows.Close()
				return r, x
			}
			row.First, row.Last = fromMillis(first), fromMillis(last)
			if row.Key == "" {
				row.Key = "(unattributed)"
			}
			r.Rows = append(r.Rows, row)
		}
		x = rows.Err()
		rows.Close()
		if x != nil {
			return r, x
		}
		var observed int64
		if err = s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(millis),0) FROM coverage WHERE resolution=? AND source_id=? AND bucket>=? AND bucket<?", res, src.SourceID, from.UnixMilli(), to.UnixMilli()).Scan(&observed); err != nil {
			return r, err
		}
		expected := q.To.Sub(q.From).Seconds()
		seconds := min(float64(observed)/1000, expected)
		r.Coverage = append(r.Coverage, Coverage{SourceID: src.SourceID, ObservedSeconds: seconds, ExpectedSeconds: expected, Partial: seconds+0.001 < expected, Status: src})
	}
	if len(r.Coverage) == 0 {
		r.Warnings = append(r.Warnings, "No collected source matches this query; missing data is not measured zero.")
	}
	if len(resolutions) > 1 {
		r.Resolution = "mixed"
	} else if resolutions["day"] {
		r.Resolution = "day"
	} else {
		r.Resolution = "minute"
	}
	sort.Slice(r.Rows, func(i, j int) bool {
		a, b := r.Rows[i], r.Rows[j]
		if uint64(a.UploadBytes)+uint64(a.DownloadBytes) != uint64(b.UploadBytes)+uint64(b.DownloadBytes) {
			return uint64(a.UploadBytes)+uint64(a.DownloadBytes) > uint64(b.UploadBytes)+uint64(b.DownloadBytes)
		}
		if a.Connections != b.Connections {
			return a.Connections > b.Connections
		}
		return a.SourceID+"\x00"+a.Key < b.SourceID+"\x00"+b.Key
	})
	if len(r.Rows) > q.Limit {
		r.Rows = r.Rows[:q.Limit]
		r.Truncated = true
		r.Warnings = append(r.Warnings, fmt.Sprintf("Showing the first %d groups; refine source/filters for the remaining rows.", q.Limit))
	}
	for _, c := range r.Coverage {
		if c.Partial {
			r.Warnings = appendUnique(r.Warnings, "Collection has missing or unmeasured intervals; event counts and client bytes are observed values, not a complete request ledger.")
		}
	}
	r.Warnings = appendUnique(r.Warnings, "Observation scopes are independent. Connections are not page visits; active minutes are not human browsing time.")
	return r, nil
}

func metricCapabilities(kind string) (bytes, connections bool) {
	switch kind {
	case "mihomo":
		return true, true
	case "access", "xray-access", "v2ray-access":
		return false, true
	case "interface", "host-interface", "vnstat", "stats", "xray-stats", "v2ray-stats":
		return true, false
	default:
		return false, false
	}
}
func appendUnique(items []string, v string) []string {
	for _, s := range items {
		if strings.EqualFold(s, v) {
			return items
		}
	}
	return append(items, v)
}
