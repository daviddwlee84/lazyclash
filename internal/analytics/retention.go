package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Prune enforces retention and bounds SQLite's main database with headroom for
// its rollback journal. Reads never create a database or perform maintenance.
func (s *Store) Prune(ctx context.Context, c Config, now time.Time) (RetentionResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r := RetentionResult{}
	if s.readOnly {
		return r, ErrReadOnly
	}
	if err := ValidateConfig(c); err != nil {
		return r, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loc, err := time.LoadLocation(c.Timezone)
	if err != nil {
		return r, err
	}
	detail := now.AddDate(0, 0, -c.Retention.DetailDays).UnixMilli()
	minute := now.AddDate(0, 0, -c.Retention.MinuteDays).Truncate(time.Minute).UnixMilli()
	day := dayStart(now, loc).AddDate(0, -c.Retention.DayMonths, 0).UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	for _, op := range []struct {
		query string
		arg   int64
		count *int64
	}{{"DELETE FROM details WHERE at<?", detail, &r.DeletedDetails}, {"DELETE FROM metrics WHERE resolution='minute' AND bucket<?", minute, &r.DeletedMinutes}, {"DELETE FROM metrics WHERE resolution='day' AND bucket<?", day, &r.DeletedDays}, {"DELETE FROM coverage WHERE resolution='minute' AND bucket<?", minute, nil}, {"DELETE FROM coverage WHERE resolution='day' AND bucket<?", day, nil}, {"DELETE FROM alerts WHERE created<?", day, nil}, {"DELETE FROM imports WHERE bucket<?", day, nil}} {
		result, e := tx.ExecContext(ctx, op.query, op.arg)
		if e != nil {
			return r, e
		}
		if op.count != nil {
			*op.count, _ = result.RowsAffected()
		}
	}
	for key, value := range map[string]int64{"detail_cutoff": detail, "minute_cutoff": minute, "day_cutoff": day} {
		if _, err = tx.ExecContext(ctx, "INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=MAX(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER))", key, fmt.Sprint(value)); err != nil {
			return r, err
		}
	}
	if err = tx.Commit(); err != nil {
		return r, err
	}
	// Drop a bounded number of free pages, never a blocking full VACUUM.
	if _, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(4096)"); err != nil {
		return r, err
	}
	var pageSize, pageCount, freePages int64
	if err = s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return r, err
	}
	if err = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return r, err
	}
	if err = s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		return r, err
	}
	// Count owned service artifacts and any other files already inside the chosen
	// state directory. They consume budget but are never removed by retention.
	totalBytes := s.fileBytes()
	externalBytes := max(int64(0), totalBytes-pageCount*pageSize)
	pageLimit := int64(1)
	if externalBytes < c.MaxBytes {
		pageLimit = max(int64(1), ((c.MaxBytes-externalBytes)*45/100)/pageSize)
	}
	wantPressure := s.pressure || pageCount-freePages >= pageLimit*9/10 || totalBytes > c.MaxBytes
	target := pageLimit * 8 / 10
	for pass := 0; wantPressure && pageCount-freePages > target && pass < 32; pass++ {
		removed, e := s.evictOldest(ctx, loc, &r)
		if e != nil {
			return r, e
		}
		if !removed {
			break
		}
		if _, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(4096)"); err != nil {
			return r, err
		}
		if err = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
			return r, err
		}
		if err = s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
			return r, err
		}
	}
	for pass := 0; pageCount > pageLimit && freePages > 0 && pass < 32; pass++ {
		if _, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(4096)"); err != nil {
			return r, err
		}
		if err = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
			return r, err
		}
		if err = s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
			return r, err
		}
	}
	r.Pressure = pageCount > pageLimit || pageCount-freePages >= pageLimit*9/10 || s.fileBytes() > c.MaxBytes
	s.maxBytes = c.MaxBytes
	s.pressure = r.Pressure
	if pageLimit < pageCount {
		pageLimit = pageCount
	}
	if _, err = s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", pageLimit)); err != nil {
		return r, err
	}
	r.Bytes = s.fileBytes()
	return r, nil
}

// Evict one bounded age-ordered chunk. The watermarks and deletion commit
// together, so a replay cannot restore aggregates whose dedupe details expired.
func (s *Store) evictOldest(ctx context.Context, loc *time.Location, r *RetentionResult) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var cutoff sql.NullInt64
	if err = tx.QueryRowContext(ctx, "SELECT MAX(at) FROM (SELECT at FROM details ORDER BY at LIMIT 4096)").Scan(&cutoff); err != nil {
		return false, err
	}
	key := "detail_cutoff"
	next := int64(0)
	if cutoff.Valid {
		result, e := tx.ExecContext(ctx, "DELETE FROM details WHERE at<=?", cutoff.Int64)
		if e != nil {
			return false, e
		}
		n, _ := result.RowsAffected()
		r.DeletedDetails += n
		next = cutoff.Int64 + 1
	} else {
		for _, res := range []string{"minute", "day"} {
			if err = tx.QueryRowContext(ctx, "SELECT MIN(bucket) FROM metrics WHERE resolution=?", res).Scan(&cutoff); err != nil {
				return false, err
			}
			if !cutoff.Valid {
				continue
			}
			result, e := tx.ExecContext(ctx, "DELETE FROM metrics WHERE resolution=? AND bucket=?", res, cutoff.Int64)
			if e != nil {
				return false, e
			}
			n, _ := result.RowsAffected()
			key = res + "_cutoff"
			if res == "minute" {
				r.DeletedMinutes += n
				next = cutoff.Int64 + time.Minute.Milliseconds()
			} else {
				r.DeletedDays += n
				next = fromMillis(cutoff.Int64).In(loc).AddDate(0, 0, 1).UnixMilli()
				if _, e = tx.ExecContext(ctx, "DELETE FROM imports WHERE bucket<?", next); e != nil {
					return false, e
				}
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM coverage WHERE resolution=? AND bucket<=?", res, cutoff.Int64); e != nil {
				return false, e
			}
			break
		}
	}
	if !cutoff.Valid {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=MAX(CAST(value AS INTEGER),CAST(excluded.value AS INTEGER))", key, fmt.Sprint(next)); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
