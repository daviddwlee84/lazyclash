package analytics

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"time"
)

type ImportResult struct {
	SourceID      string   `json:"source_id"`
	Interface     string   `json:"interface"`
	Buckets       int      `json:"buckets"`
	Skipped       int      `json:"skipped"`
	UploadBytes   int64    `json:"upload_bytes"`
	DownloadBytes int64    `json:"download_bytes"`
	Granularity   string   `json:"granularity"`
	Warnings      []string `json:"warnings,omitempty"`
}

type vnstatDate struct{ Year, Month, Day int }
type vnstatBucket struct {
	Date      vnstatDate  `json:"date"`
	Timestamp json.Number `json:"timestamp"`
	RX        json.Number `json:"rx"`
	TX        json.Number `json:"tx"`
}
type vnstatDocument struct {
	JSONVersion string `json:"jsonversion"`
	Interfaces  []struct {
		Name    string `json:"name"`
		Traffic struct {
			Day   []vnstatBucket `json:"day"`
			Month []vnstatBucket `json:"month"`
			Hour  []vnstatBucket `json:"hour"`
		} `json:"traffic"`
	} `json:"interfaces"`
}

// ImportVNStat imports only completed, native daily interface buckets. Monthly
// totals are never spread across days, and current partial days are not frozen
// into history. Re-import uses deterministic bucket IDs and stays idempotent.
func ImportVNStat(ctx context.Context, store *Store, cfg Config, sourceID string, r io.Reader) (ImportResult, error) {
	return importVNStatAt(ctx, store, cfg, sourceID, r, time.Now())
}

func importVNStatAt(ctx context.Context, store *Store, cfg Config, sourceID string, r io.Reader, now time.Time) (ImportResult, error) {
	result := ImportResult{SourceID: sourceID, Granularity: "day"}
	if err := ValidateConfig(cfg); err != nil {
		return result, err
	}
	var source SourceConfig
	found := false
	for _, s := range cfg.Sources {
		if s.ID == sourceID {
			source = s
			found = true
			break
		}
	}
	if !found || source.Kind != "vnstat" {
		return result, errors.New("import needs an explicitly configured vnstat source")
	}
	if !source.Enabled {
		return result, errors.New("vnstat source is disabled; enable it before importing")
	}
	if err := ValidateSource(source); err != nil {
		return result, err
	}
	result.Interface = source.Interface
	if store == nil {
		return result, errors.New("analytics store is required")
	}
	data, err := io.ReadAll(io.LimitReader(r, maxCommandBytes+1))
	if err != nil {
		return result, errors.New("cannot read vnStat JSON")
	}
	if len(data) > maxCommandBytes {
		return result, errors.New("vnStat import exceeds 8 MiB")
	}
	var doc vnstatDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err = dec.Decode(&doc); err != nil {
		return result, errors.New("invalid vnStat JSON")
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return result, errors.New("vnStat input must contain one JSON document")
	}
	if doc.JSONVersion != "2" {
		return result, errors.New("vnStat JSON version 2 is required (counters must be bytes)")
	}
	zone, _ := time.LoadLocation(cfg.Timezone)
	originZone := zone
	if source.Timezone != "" {
		originZone, _ = time.LoadLocation(source.Timezone)
	}
	cutoff := time.Date(now.In(zone).Year(), now.In(zone).Month(), now.In(zone).Day(), 0, 0, 0, 0, zone).AddDate(0, -cfg.Retention.DayMonths, 0)
	var deltas []Delta
	seen := map[int64]bool{}
	matched := false
	for _, iface := range doc.Interfaces {
		if iface.Name != source.Interface {
			continue
		}
		if matched {
			return result, errors.New("vnStat JSON repeats the selected interface")
		}
		matched = true
		if len(iface.Traffic.Day) > 5000 {
			return result, errors.New("vnStat import exceeds 5000 daily buckets")
		}
		if len(iface.Traffic.Day) == 0 {
			return result, errors.New("vnStat JSON has no daily buckets; export vnstat --json d for the selected interface")
		}
		for _, bucket := range iface.Traffic.Day {
			d := bucket.Date
			if d.Year < 1970 || d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 {
				return result, errors.New("invalid vnStat bucket date")
			}
			start := time.Date(d.Year, time.Month(d.Month), d.Day, 0, 0, 0, 0, originZone)
			if start.Day() != d.Day {
				return result, errors.New("invalid vnStat calendar date")
			}
			end := start.AddDate(0, 0, 1)
			if !start.Equal(time.Date(d.Year, time.Month(d.Month), d.Day, 0, 0, 0, 0, zone)) {
				return result, errors.New("vnStat native day timezone differs from analytics timezone; select its native timezone instead of shifting daily totals")
			}
			if bucket.Timestamp != "" {
				stamp, e := bucket.Timestamp.Int64()
				if e != nil || stamp != start.Unix() {
					return result, errors.New("vnStat native day timezone differs from analytics timezone; select its native timezone instead of shifting daily totals")
				}
			}
			if end.After(now) || start.Before(cutoff) {
				result.Skipped++
				continue
			}
			up, e1 := strconv.ParseInt(string(bucket.TX), 10, 64)
			down, e2 := strconv.ParseInt(string(bucket.RX), 10, 64)
			if e1 != nil || e2 != nil || up < 0 || down < 0 {
				return result, errors.New("vnStat byte counters must be nonnegative integers")
			}
			if seen[start.Unix()] {
				return result, errors.New("vnStat daily buckets overlap")
			}
			seen[start.Unix()] = true
			deltas = append(deltas, Delta{ID: stableSourceID(sourceID, "vnstat-day", source.Interface, start.UTC().Format(time.RFC3339)), Start: start, End: end, UploadBytes: up, DownloadBytes: down, Granularity: "day"})
		}
	}
	if !matched {
		return result, errors.New("selected interface is absent from vnStat JSON")
	}
	if len(deltas) == 0 {
		return result, errors.New("no completed daily vnStat buckets to import")
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Start.Before(deltas[j].Start) })
	unlock, err := lockCollector(store.Path())
	if err != nil {
		return result, err
	}
	defer unlock()
	binding, err := resolvedSourceBinding(source, nil)
	if err != nil {
		return result, err
	}
	if err = store.ValidateSourceBinding(ctx, source, binding); err != nil {
		return result, err
	}
	if _, err = store.Prune(ctx, cfg, now); err != nil {
		return result, err
	}
	status := SourceStatus{SourceID: source.ID, Kind: source.Kind, Scope: sourceScope(source), State: "imported", LastAttempt: now, LastSuccess: now, Message: "native daily buckets; historical collection coverage is unknown"}
	for _, delta := range deltas {
		// Deduplication is durable, including after detail retention. Count only
		// newly imported native buckets in the command's result.
		var found int
		e := store.db.QueryRowContext(ctx, "SELECT 1 FROM imports WHERE source_id=? AND id=?", source.ID, delta.ID).Scan(&found)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return result, e
		}
		if e == nil {
			result.Skipped++
			continue
		}
		if delta.UploadBytes > math.MaxInt64-result.UploadBytes || delta.DownloadBytes > math.MaxInt64-result.DownloadBytes {
			return result, errors.New("vnStat imported byte total exceeds integer range")
		}
		value := json.RawMessage(fmt.Sprintf(`{"end":%d}`, delta.End.Unix()))
		batch := Batch{SourceID: source.ID, Kind: source.Kind, Scope: sourceScope(source), Timezone: cfg.Timezone, At: now, Deltas: []Delta{delta}, Checkpoint: &Checkpoint{Key: "vnstat", Value: value, UpdatedAt: now}, Status: &status, Source: &source, Binding: binding}
		if err = store.Ingest(ctx, batch); err != nil {
			return result, err
		}
		result.Buckets++
		result.UploadBytes += delta.UploadBytes
		result.DownloadBytes += delta.DownloadBytes
	}
	result.Warnings = []string{"daily totals have no site, client, process or active-minute attribution; hour/month records were not combined", "native buckets do not prove continuous historical collector coverage"}
	return result, nil
}
