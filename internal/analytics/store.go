package analytics

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/bits"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	_ "modernc.org/sqlite"
)

var ErrReadOnly = errors.New("analytics store is read-only")
var ErrStorageLimit = errors.New("analytics storage limit reached; collection is incomplete")

type Store struct {
	db       *sql.DB
	path     string
	readOnly bool
	mu       sync.Mutex
	maxBytes int64
	pressure bool
}

func (s *Store) Path() string { return s.path }
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT OR IGNORE INTO meta VALUES('schema','1');
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY,kind TEXT NOT NULL,scope TEXT NOT NULL,status BLOB,coverage_end INTEGER NOT NULL DEFAULT 0,coarse_day INTEGER NOT NULL DEFAULT 0,identity TEXT NOT NULL DEFAULT '',config_identity TEXT NOT NULL DEFAULT '',retention_drops INTEGER NOT NULL DEFAULT 0,source_config BLOB);
CREATE TABLE IF NOT EXISTS checkpoints (source_id TEXT NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(source_id,key));
CREATE TABLE IF NOT EXISTS details (source_id TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,at INTEGER NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(source_id,id,kind));
CREATE INDEX IF NOT EXISTS details_at ON details(at);
CREATE TABLE IF NOT EXISTS imports (source_id TEXT NOT NULL,id TEXT NOT NULL,bucket INTEGER NOT NULL,PRIMARY KEY(source_id,id));
CREATE TABLE IF NOT EXISTS metrics (resolution TEXT NOT NULL,bucket INTEGER NOT NULL,source_id TEXT NOT NULL,ip TEXT NOT NULL,domain TEXT NOT NULL,process TEXT NOT NULL,route TEXT NOT NULL,principal TEXT NOT NULL,up INTEGER NOT NULL,down INTEGER NOT NULL,events INTEGER NOT NULL,first INTEGER NOT NULL,last INTEGER NOT NULL,PRIMARY KEY(resolution,bucket,source_id,ip,domain,process,route,principal));
CREATE INDEX IF NOT EXISTS metrics_time ON metrics(resolution,bucket);
CREATE TABLE IF NOT EXISTS coverage (resolution TEXT NOT NULL,bucket INTEGER NOT NULL,source_id TEXT NOT NULL,millis INTEGER NOT NULL,PRIMARY KEY(resolution,bucket,source_id));
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY,source_id TEXT NOT NULL,day TEXT NOT NULL,threshold INTEGER NOT NULL,payload BLOB NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL,lease_until INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS alerts_source_day ON alerts(source_id,day);
`

func OpenStore(path string, readOnly bool) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("analytics database path must be absolute")
	}
	existing := false
	if st, err := os.Lstat(path); err == nil {
		existing = st.Size() > 0
		if !st.Mode().IsRegular() {
			return nil, errors.New("analytics database must be a regular file")
		}
		if st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("analytics database must be private (0600)")
		}
	} else if !os.IsNotExist(err) || readOnly {
		return nil, err
	}
	if !readOnly {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	if readOnly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
	}
	q.Add("_pragma", "busy_timeout(3000)")
	q.Add("_pragma", "foreign_keys(1)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, path: path, readOnly: readOnly}
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	if err = db.Ping(); err != nil {
		return fail(err)
	}
	if existing {
		var version string
		if err = db.QueryRow("SELECT value FROM meta WHERE key='schema'").Scan(&version); err != nil || version != "1" {
			return fail(errors.New("unsupported or invalid analytics database schema; no migration was attempted"))
		}
	}
	if readOnly {
		var version string
		if err = db.QueryRow("SELECT value FROM meta WHERE key='schema'").Scan(&version); err != nil {
			return fail(err)
		}
		if version != "1" {
			return fail(errors.New("unsupported analytics database schema"))
		}
		if _, err = db.Exec("PRAGMA query_only=ON"); err != nil {
			return fail(err)
		}
	} else {
		if _, err = db.Exec("PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;"); err != nil {
			return fail(err)
		}
		if _, err = db.Exec(schema); err != nil {
			return fail(err)
		}
		var version string
		if err = db.QueryRow("SELECT value FROM meta WHERE key='schema'").Scan(&version); err != nil || version != "1" {
			return fail(errors.New("unsupported analytics database schema"))
		}
		for _, suffix := range []string{"", "-journal"} {
			if err = os.Chmod(path+suffix, 0600); err != nil && !os.IsNotExist(err) {
				return fail(err)
			}
		}
	}
	return s, nil
}
func (s *Store) Checkpoint(ctx context.Context, sourceID, key string) (Checkpoint, bool, error) {
	cp := Checkpoint{Key: key}
	var at int64
	err := s.db.QueryRowContext(ctx, "SELECT value,updated FROM checkpoints WHERE source_id=? AND key=?", sourceID, key).Scan(&cp.Value, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return cp, false, nil
	}
	cp.UpdatedAt = fromMillis(at)
	return cp, err == nil, err
}
func (s *Store) SourceStatus(ctx context.Context, id string) (SourceStatus, bool, error) {
	var b, source []byte
	var dropped int64
	v := SourceStatus{}
	err := s.db.QueryRowContext(ctx, "SELECT status,retention_drops,kind,scope,source_config FROM sources WHERE id=?", id).Scan(&b, &dropped, &v.Kind, &v.Scope, &source)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	if len(b) > 0 {
		err = json.Unmarshal(b, &v)
	}
	v.DroppedEvents += max(int64(0), dropped-v.RetentionDropped)
	v.RetentionDropped = dropped
	v.SourceID = id
	v.Source = &SourceConfig{ID: id, Kind: v.Kind, Scope: v.Scope}
	if len(source) > 0 {
		if e := json.Unmarshal(source, v.Source); e != nil {
			return v, false, e
		}
	}
	return v, err == nil, err
}
func fromMillis(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.UnixMilli(n).UTC()
}
func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}
func storageError(err error) error {
	if err != nil && (strings.Contains(err.Error(), "SQLITE_FULL") || strings.Contains(err.Error(), "database or disk is full")) {
		return ErrStorageLimit
	}
	return err
}

func (s *Store) Ingest(ctx context.Context, b Batch) (err error) {
	if s.readOnly {
		return ErrReadOnly
	}
	if !sourceIDPattern.MatchString(b.SourceID) || b.Kind == "" || len(b.Kind) > 64 {
		return errors.New("invalid analytics batch source")
	}
	if len(b.Events)+len(b.Deltas) > 5000 {
		return errors.New("analytics batch exceeds 5000 observations")
	}
	if b.Compact {
		if len(b.Events)+len(b.Deltas) > 4 {
			return errors.New("compact fallback allows at most four source totals")
		}
		for _, e := range b.Events {
			if e.ClientIP != "" || e.Domain != "" || e.Process != "" || e.Route != "" || e.Principal != "" {
				return errors.New("compact fallback must omit attribution")
			}
		}
		for _, d := range b.Deltas {
			if d.ClientIP != "" || d.Domain != "" || d.Process != "" || d.Route != "" || d.Principal != "" {
				return errors.New("compact fallback must omit attribution")
			}
		}
	}
	if b.At.IsZero() {
		return errors.New("analytics batch requires observation time")
	}
	if b.Timezone == "" {
		b.Timezone = DefaultTimezone
	}
	loc, err := time.LoadLocation(b.Timezone)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pressure && !b.Compact || s.maxBytes > 0 && s.fileBytes() >= s.maxBytes {
		return ErrStorageLimit
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	defer func() {
		err = storageError(err)
		if errors.Is(err, ErrStorageLimit) {
			s.pressure = true
		}
	}()
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO meta(key,value) VALUES('timezone',?)", b.Timezone); err != nil {
		return err
	}
	var zone string
	if err = tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='timezone'").Scan(&zone); err != nil {
		return err
	}
	if zone != b.Timezone {
		return errors.New("collector timezone differs from existing day rollups; use the recorded timezone")
	}
	var oldKind, oldScope, oldIdentity string
	var coverageEnd, retentionDrops int64
	err = tx.QueryRowContext(ctx, "SELECT kind,scope,coverage_end,identity,retention_drops FROM sources WHERE id=?", b.SourceID).Scan(&oldKind, &oldScope, &coverageEnd, &oldIdentity, &retentionDrops)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && (oldKind != b.Kind || oldScope != b.Scope) {
		return errors.New("analytics source kind/scope changed; use a new source ID")
	}
	identity := ""
	if b.Source != nil {
		if b.Source.ID != b.SourceID || b.Source.Kind != b.Kind || sourceScope(*b.Source) != b.Scope {
			return errors.New("analytics source metadata differs from batch identity")
		}
		identity = sourceFingerprint(*b.Source, b.Binding)
	}
	if oldIdentity != "" && oldIdentity != identity {
		return errors.New("analytics source binding changed; use a new source ID before collecting")
	}
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sources").Scan(&count); err != nil {
			return err
		}
		if count >= 128 {
			return errors.New("analytics store supports at most 128 sources")
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO sources(id,kind,scope) VALUES(?,?,?)", b.SourceID, b.Kind, b.Scope); err != nil {
		return err
	}
	if identity != "" {
		if _, err = tx.ExecContext(ctx, "UPDATE sources SET identity=?,config_identity=? WHERE id=? AND identity=''", identity, sourceFingerprint(*b.Source, ""), b.SourceID); err != nil {
			return err
		}
	}
	if b.Source != nil {
		raw, e := json.Marshal(b.Source)
		if e != nil {
			return e
		}
		if _, err = tx.ExecContext(ctx, "UPDATE sources SET source_config=? WHERE id=?", raw, b.SourceID); err != nil {
			return err
		}
	}
	var cutoff, dayCutoff int64
	skipped := int64(0)
	_ = tx.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM meta WHERE key='detail_cutoff'").Scan(&cutoff)
	_ = tx.QueryRowContext(ctx, "SELECT CAST(value AS INTEGER) FROM meta WHERE key='day_cutoff'").Scan(&dayCutoff)
	for _, e := range b.Events {
		if e.ID == "" || len(e.ID) > 512 || e.At.IsZero() || e.Count < 0 || !validDims(e.ClientIP, e.Domain, e.Process, e.Route, e.Principal) {
			return errors.New("invalid analytics event")
		}
		if e.Count == 0 {
			e.Count = 1
		}
		if e.At.UnixMilli() < cutoff {
			skipped += e.Count
			continue
		}
		ok, x := insertDetail(ctx, tx, b.SourceID, e.ID, "event", e.At, e)
		if x != nil {
			return x
		}
		if !ok {
			continue
		}
		d := dimensions{e.ClientIP, normalizeHost(e.Domain), e.Process, e.Route, e.Principal}
		minute := e.At.Truncate(time.Minute).UnixMilli()
		day := dayStart(e.At, loc).UnixMilli()
		if err = addMetric(ctx, tx, "minute", minute, b.SourceID, d, 0, 0, e.Count, millis(e.At), millis(e.At)); err != nil {
			return err
		}
		if err = addMetric(ctx, tx, "day", day, b.SourceID, d, 0, 0, e.Count, millis(e.At), millis(e.At)); err != nil {
			return err
		}
	}
	for _, d := range b.Deltas {
		if d.ID == "" || len(d.ID) > 512 || d.Start.IsZero() || !d.End.After(d.Start) || d.End.Sub(d.Start) > 32*24*time.Hour || d.UploadBytes < 0 || d.DownloadBytes < 0 || !validDims(d.ClientIP, d.Domain, d.Process, d.Route, d.Principal) {
			return errors.New("invalid analytics counter delta")
		}
		if d.Granularity != "" && d.Granularity != "interval" && d.Granularity != "day" {
			return errors.New("unsupported delta granularity")
		}
		dims := dimensions{d.ClientIP, normalizeHost(d.Domain), d.Process, d.Route, d.Principal}
		if d.Granularity == "day" {
			start := dayStart(d.Start, loc)
			if !d.Start.Equal(start) || !d.End.Equal(start.AddDate(0, 0, 1)) {
				return errors.New("native daily delta must align with its source timezone day")
			}
			if start.UnixMilli() < dayCutoff {
				skipped++
				continue
			}
			result, x := tx.ExecContext(ctx, "INSERT OR IGNORE INTO imports VALUES(?,?,?)", b.SourceID, d.ID, start.UnixMilli())
			if x != nil {
				return x
			}
			n, x := result.RowsAffected()
			if x != nil {
				return x
			}
			if n == 0 {
				continue
			}
			if err = addMetric(ctx, tx, "day", start.UnixMilli(), b.SourceID, dims, d.UploadBytes, d.DownloadBytes, 0, millis(d.Start), millis(d.End)); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE sources SET coarse_day=1 WHERE id=?", b.SourceID); err != nil {
				return err
			}
			continue
		}
		if d.End.UnixMilli() <= cutoff {
			skipped++
			continue
		}
		ok, x := insertDetail(ctx, tx, b.SourceID, d.ID, "delta", d.End, d)
		if x != nil {
			return x
		}
		if !ok {
			continue
		}
		for _, res := range []string{"minute", "day"} {
			err = splitInterval(d.Start, d.End, res, loc, func(start, end, bucket time.Time) error {
				up := allocated(d.UploadBytes, d.Start, d.End, start, end)
				down := allocated(d.DownloadBytes, d.Start, d.End, start, end)
				if e := addMetric(ctx, tx, res, bucket.UnixMilli(), b.SourceID, dims, up, down, 0, millis(start), millis(end)); e != nil {
					return e
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if !b.CoverageStart.IsZero() {
		start := b.CoverageStart
		if millis(start) < coverageEnd {
			start = fromMillis(coverageEnd)
		}
		if b.At.Sub(start) > 32*24*time.Hour {
			return errors.New("coverage interval exceeds 32 days")
		}
		if start.Before(b.At) {
			for _, res := range []string{"minute", "day"} {
				if err = splitInterval(start, b.At, res, loc, func(a, z, bucket time.Time) error {
					_, e := tx.ExecContext(ctx, "INSERT INTO coverage VALUES(?,?,?,?) ON CONFLICT(resolution,bucket,source_id) DO UPDATE SET millis=millis+excluded.millis", res, bucket.UnixMilli(), b.SourceID, z.Sub(a).Milliseconds())
					return e
				}); err != nil {
					return err
				}
			}
			if _, err = tx.ExecContext(ctx, "UPDATE sources SET coverage_end=? WHERE id=?", millis(b.At), b.SourceID); err != nil {
				return err
			}
		}
	}
	if b.Checkpoint != nil {
		cp := b.Checkpoint
		if cp.Key == "" || len(cp.Key) > 128 || len(cp.Value) > 1<<20 || !json.Valid(cp.Value) {
			return errors.New("invalid analytics checkpoint")
		}
		at := cp.UpdatedAt
		if at.IsZero() {
			at = b.At
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO checkpoints VALUES(?,?,?,?) ON CONFLICT(source_id,key) DO UPDATE SET value=excluded.value,updated=excluded.updated", b.SourceID, cp.Key, []byte(cp.Value), millis(at)); err != nil {
			return err
		}
	}
	if b.Status != nil {
		st := *b.Status
		st.SourceID, st.Kind, st.Scope = b.SourceID, b.Kind, b.Scope
		st.Source = b.Source
		st.DroppedEvents += max(int64(0), retentionDrops+skipped-st.RetentionDropped)
		st.RetentionDropped = retentionDrops + skipped
		if len(st.Message) > 4096 {
			st.Message = st.Message[:4096]
		}
		raw, x := json.Marshal(st)
		if x != nil {
			return x
		}
		if _, err = tx.ExecContext(ctx, "UPDATE sources SET status=? WHERE id=?", raw, b.SourceID); err != nil {
			return err
		}
	}
	if skipped > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE sources SET retention_drops=retention_drops+? WHERE id=?", skipped, b.SourceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func sourceFingerprint(source SourceConfig, binding string) string {
	// Enabled and poll frequency do not change the measured source. Credentials
	// are resolved by the collector and never become part of the stored identity.
	v := struct{ Kind, Scope, Target, Interface, Path, Format, Binary, Address, Timezone, Binding string }{source.Kind, sourceScope(source), source.Target, source.Interface, source.Path, source.Format, source.Binary, source.Address, source.Timezone, binding}
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum)
}

// ValidateSourceBinding must run before loading a saved source checkpoint. The
// first successful Ingest transaction pins this same identity atomically.
func (s *Store) ValidateSourceBinding(ctx context.Context, source SourceConfig, binding string) error {
	var kind, scope, identity string
	err := s.db.QueryRowContext(ctx, "SELECT kind,scope,identity FROM sources WHERE id=?", source.ID).Scan(&kind, &scope, &identity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if kind != source.Kind || scope != sourceScope(source) || identity != "" && identity != sourceFingerprint(source, binding) {
		return errors.New("analytics source binding changed; use a new source ID before restoring checkpoints")
	}
	return nil
}

// ValidateSourceConfig is the CLI's config-only preflight; collector startup
// additionally validates the resolved endpoint through ValidateSourceBinding.
func (s *Store) ValidateSourceConfig(ctx context.Context, source SourceConfig) error {
	var kind, scope, identity string
	err := s.db.QueryRowContext(ctx, "SELECT kind,scope,config_identity FROM sources WHERE id=?", source.ID).Scan(&kind, &scope, &identity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if kind != source.Kind || scope != sourceScope(source) || identity != "" && identity != sourceFingerprint(source, "") {
		return errors.New("analytics source configuration changed; use a new source ID to preserve historical identity")
	}
	return nil
}

type dimensions struct{ ip, domain, process, route, principal string }

func (d dimensions) args() []any { return []any{d.ip, d.domain, d.process, d.route, d.principal} }
func validDims(v ...string) bool {
	for _, s := range v {
		if len(s) > 2048 || strings.ContainsRune(s, '\x00') {
			return false
		}
	}
	return true
}
func normalizeHost(v string) string { return strings.ToLower(strings.TrimSuffix(v, ".")) }
func insertDetail(ctx context.Context, tx *sql.Tx, source, id, kind string, at time.Time, v any) (bool, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	r, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO details VALUES(?,?,?,?,?)", source, id, kind, millis(at), raw)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n > 0, err
}
func addMetric(ctx context.Context, tx *sql.Tx, res string, bucket int64, source string, d dimensions, up, down, events, first, last int64) error {
	args := []any{res, bucket, source}
	args = append(args, d.args()...)
	args = append(args, up, down, events, first, last)
	r, err := tx.ExecContext(ctx, `INSERT INTO metrics VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(resolution,bucket,source_id,ip,domain,process,route,principal) DO UPDATE SET up=up+excluded.up,down=down+excluded.down,events=events+excluded.events,first=MIN(first,excluded.first),last=MAX(last,excluded.last) WHERE up<=9223372036854775807-excluded.up AND down<=9223372036854775807-excluded.down AND events<=9223372036854775807-excluded.events`, args...)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n == 0 {
		return errors.New("analytics integer counter overflow")
	}
	return err
}
func dayStart(at time.Time, loc *time.Location) time.Time {
	t := at.In(loc)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
}
func splitInterval(start, end time.Time, res string, loc *time.Location, fn func(time.Time, time.Time, time.Time) error) error {
	for at := start; at.Before(end); {
		var bucket, next time.Time
		if res == "day" {
			bucket = dayStart(at, loc)
			next = bucket.AddDate(0, 0, 1)
		} else {
			bucket = at.Truncate(time.Minute)
			next = bucket.Add(time.Minute)
		}
		if next.After(end) {
			next = end
		}
		if err := fn(at, next, bucket); err != nil {
			return err
		}
		at = next
	}
	return nil
}

// The cumulative allocation preserves every byte without multiplying int64s.
// Allocation within an observed counter interval is a time-based estimate.
func allocated(total int64, start, end, a, z time.Time) int64 {
	den := uint64(end.Sub(start))
	part := func(t time.Time) uint64 {
		hi, lo := bits.Mul64(uint64(total), uint64(t.Sub(start)))
		q, _ := bits.Div64(hi, lo, den)
		return q
	}
	return int64(part(z) - part(a))
}
func (s *Store) timezone(ctx context.Context) string {
	var zone string
	if s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key='timezone'").Scan(&zone) != nil || zone == "" {
		return DefaultTimezone
	}
	return zone
}
func (s *Store) fileBytes() int64 {
	var n int64
	count := 0
	err := filepath.WalkDir(filepath.Dir(s.path), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 10000 {
			return errors.New("analytics state directory exceeds bounded inventory")
		}
		if d.Type().IsRegular() {
			info, e := d.Info()
			if e != nil {
				return e
			}
			n += info.Size()
		}
		return nil
	})
	if err != nil {
		return math.MaxInt64
	}
	return n
}
func (s *Store) Status(ctx context.Context) (Status, error) {
	r := Status{Path: s.path, SchemaVersion: 1, Timezone: s.timezone(ctx), Bytes: s.fileBytes(), Sources: []SourceStatus{}}
	rows, err := s.db.QueryContext(ctx, "SELECT id,kind,scope,status,retention_drops,source_config FROM sources ORDER BY id LIMIT 129")
	if err != nil {
		return r, err
	}
	for rows.Next() {
		var id, kind, scope string
		var raw, source []byte
		var dropped int64
		if err = rows.Scan(&id, &kind, &scope, &raw, &dropped, &source); err != nil {
			rows.Close()
			return r, err
		}
		v := SourceStatus{SourceID: id, Kind: kind, Scope: scope, State: "unknown"}
		if len(raw) > 0 {
			if err = json.Unmarshal(raw, &v); err != nil {
				rows.Close()
				return r, err
			}
		}
		v.DroppedEvents += max(int64(0), dropped-v.RetentionDropped)
		v.RetentionDropped = dropped
		v.Source = &SourceConfig{ID: id, Kind: kind, Scope: scope}
		if len(source) > 0 {
			if err = json.Unmarshal(source, v.Source); err != nil {
				rows.Close()
				return r, err
			}
		}
		r.Sources = append(r.Sources, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	for _, item := range []struct {
		sql string
		to  *time.Time
	}{{"SELECT MIN(at) FROM details", &r.OldestDetail}, {"SELECT MIN(bucket) FROM metrics WHERE resolution='minute'", &r.OldestMinute}, {"SELECT MIN(bucket) FROM metrics WHERE resolution='day'", &r.OldestDay}} {
		var n sql.NullInt64
		if err = s.db.QueryRowContext(ctx, item.sql).Scan(&n); err != nil {
			return r, err
		}
		if n.Valid {
			*item.to = fromMillis(n.Int64)
		}
	}
	return r, nil
}
