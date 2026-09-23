package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "analytics.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func testAt(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
func ingest(t *testing.T, s *Store, b Batch) {
	t.Helper()
	if err := s.Ingest(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}
func report(t *testing.T, s *Store, q Query) Report {
	t.Helper()
	r, err := s.Report(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestConfigPrivateRoundtripAndReadDoesNotCreate(t *testing.T) {
	c := DefaultConfig()
	if c.Alerts.Enabled || c.MaxBytes != 1<<30 || c.Retention != (RetentionConfig{30, 90, 13}) {
		t.Fatalf("defaults: %+v", c)
	}
	root := t.TempDir()
	path := filepath.Join(root, "new", "analytics.toml")
	if _, err := LoadConfig(path); !os.IsNotExist(err) {
		t.Fatalf("missing config: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("read created a directory")
	}
	c.Sources = []SourceConfig{{ID: "local", Kind: "mihomo", Enabled: false, Target: "desktop"}}
	if err := SaveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("roundtrip=%+v err=%v", got, err)
	}
	st, _ := os.Stat(path)
	if !st.Mode().IsRegular() || !privatefs.Private(path) {
		t.Fatal(st.Mode())
	}
	link := filepath.Join(root, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadConfig(link); err == nil {
		t.Fatal("symlink config accepted")
	}
	missing := filepath.Join(root, "absent", "analytics.db")
	if _, err = OpenStore(missing, true); !os.IsNotExist(err) {
		t.Fatalf("readonly missing: %v", err)
	}
	if _, err = os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatal("readonly created directory")
	}
}
func TestReadOnlyQueriesCreateNoFilesAndRejectWrites(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00+08:00")
	ingest(t, s, Batch{SourceID: "one", Kind: "interface", Scope: "host", At: at, Status: &SourceStatus{State: "baseline"}})
	before, err := os.ReadDir(filepath.Dir(s.Path()))
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenStore(s.Path(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = r.Ingest(context.Background(), Batch{}); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	if _, err = r.Prune(context.Background(), DefaultConfig(), at); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(filepath.Dir(s.Path()))
	if len(before) != len(after) {
		t.Fatalf("read created files: %v -> %v", before, after)
	}
}
func TestIntervalBoundaryConservationReplayAndSourceIsolation(t *testing.T) {
	s := testStore(t)
	a := testAt("2026-09-21T23:59:30+08:00")
	z := a.Add(time.Minute)
	b := Batch{SourceID: "client", Kind: "mihomo", Scope: "client", At: z, CoverageStart: a, Checkpoint: &Checkpoint{Key: "poll", Value: json.RawMessage(`{"counter":5}`)}, Events: []Event{{ID: "event", At: a, Domain: "EXAMPLE.COM.", Count: 1}}, Deltas: []Delta{{ID: "flow", Start: a, End: z, UploadBytes: 5, DownloadBytes: 9, Domain: "example.com", ClientIP: "127.0.0.1", Process: "browser", Route: "Proxy"}}}
	ingest(t, s, b)
	ingest(t, s, b)
	other := b
	other.SourceID = "server"
	other.Kind = "stats"
	other.Scope = "server"
	ingest(t, s, other)
	r := report(t, s, Query{From: a.Truncate(time.Minute), To: z.Add(time.Minute).Truncate(time.Minute), GroupBy: "domain", Limit: 20})
	if len(r.Rows) != 2 {
		t.Fatalf("scopes merged: %+v", r.Rows)
	}
	for _, row := range r.Rows {
		if row.UploadBytes != 5 || row.DownloadBytes != 9 || row.Connections != 1 || row.ActiveMinutes != 2 {
			t.Fatalf("row %+v", row)
		}
	}
	var up1, up2 int64
	loc, _ := time.LoadLocation(DefaultTimezone)
	if err := s.db.QueryRow("SELECT SUM(up) FROM metrics WHERE resolution='day' AND source_id='client' AND bucket=?", dayStart(a, loc).UnixMilli()).Scan(&up1); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT SUM(up) FROM metrics WHERE resolution='day' AND source_id='client' AND bucket=?", dayStart(z, loc).UnixMilli()).Scan(&up2); err != nil {
		t.Fatal(err)
	}
	if up1 != 2 || up2 != 3 {
		t.Fatalf("day split=%d,%d", up1, up2)
	}
	if len(r.Coverage) != 2 || r.Coverage[0].ObservedSeconds != 60 || !r.Coverage[0].Partial {
		t.Fatalf("coverage %+v", r.Coverage)
	}
	r = report(t, s, Query{From: a.Truncate(time.Minute), To: z.Add(time.Minute), SourceID: "client", GroupBy: "domain", IP: "127.0.0.1", Domain: "EXAMPLE.COM.", Process: "browser", Route: "Proxy"})
	if len(r.Rows) != 1 || r.Rows[0].UploadBytes != 5 || r.Rows[0].Connections != 0 {
		t.Fatalf("exact filters: %+v", r)
	}
}
func TestBatchFailureDoesNotAdvanceCheckpointOrPartialRollups(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	b := Batch{SourceID: "one", Kind: "interface", Scope: "host", At: at, Events: []Event{{ID: "one", At: at, Count: 1}}, Deltas: []Delta{{ID: "bad", Start: at.Add(-time.Second), End: at, UploadBytes: -1}}, Checkpoint: &Checkpoint{Key: "cursor", Value: json.RawMessage(`1`)}}
	if err := s.Ingest(context.Background(), b); err == nil {
		t.Fatal("negative delta accepted")
	}
	if _, ok, err := s.Checkpoint(context.Background(), "one", "cursor"); err != nil || ok {
		t.Fatalf("checkpoint advanced %v %v", ok, err)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM metrics").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial rows %d %v", count, err)
	}
}
func TestBaselineGapAndResetAreNotZeroActivity(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	ingest(t, s, Batch{SourceID: "one", Kind: "interface", Scope: "host", At: at, Status: &SourceStatus{State: "baseline", LastAttempt: at, LastSuccess: at, ResetCount: 1, GapCount: 2}})
	r := report(t, s, Query{From: at.Add(-time.Hour), To: at})
	if len(r.Rows) != 0 || len(r.Coverage) != 1 || !r.Coverage[0].Partial || r.Coverage[0].Status.ResetCount != 1 {
		t.Fatalf("baseline invented metrics: %+v", r)
	}
	ingest(t, s, Batch{SourceID: "access", Kind: "access", Scope: "server", At: at, Events: []Event{{ID: "a", At: at, Domain: "example.test"}}})
	r = report(t, s, Query{From: at, To: at.Add(time.Minute), SourceID: "access"})
	if len(r.Rows) != 1 || r.Rows[0].ActiveMinutes != 0 || r.Rows[0].ActiveMinutesAvailable {
		t.Fatalf("events became byte activity %+v", r.Rows)
	}
}
func TestNativeDailyImportSurvivesDetailRetentionAndReplay(t *testing.T) {
	s := testStore(t)
	now := testAt("2026-09-22T12:00:00+08:00")
	cfg := DefaultConfig()
	if _, err := s.Prune(context.Background(), cfg, now); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation(cfg.Timezone)
	a := dayStart(now.AddDate(0, 0, -60), loc)
	b := Batch{SourceID: "old", Kind: "vnstat", Scope: "host", At: now, Deltas: []Delta{{ID: "native-day-1", Granularity: "day", Start: a, End: a.AddDate(0, 0, 1), UploadBytes: 700, DownloadBytes: 300}}}
	ingest(t, s, b)
	if _, err := s.Prune(context.Background(), cfg, now); err != nil {
		t.Fatal(err)
	}
	ingest(t, s, b)
	r := report(t, s, Query{From: a, To: a.AddDate(0, 0, 1), SourceID: "old"})
	if r.Resolution != "day" || len(r.Rows) != 1 || r.Rows[0].UploadBytes != 700 || r.Rows[0].ActiveMinutesAvailable {
		t.Fatalf("native day %+v", r)
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM metrics WHERE resolution='minute'").Scan(&count)
	if count != 0 {
		t.Fatal("native daily total was smeared into minute samples")
	}
}
func TestRetentionKeepsDailyAndPreventsPrunedReplay(t *testing.T) {
	s := testStore(t)
	now := testAt("2026-09-22T12:00:00Z")
	old := now.AddDate(0, 0, -120)
	b := Batch{SourceID: "one", Kind: "access", Scope: "server", At: old, Events: []Event{{ID: "old", At: old, Domain: "old.test"}}}
	ingest(t, s, b)
	res, err := s.Prune(context.Background(), DefaultConfig(), now)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedDetails != 1 || res.DeletedMinutes != 1 || res.DeletedDays != 0 {
		t.Fatalf("prune %+v", res)
	}
	b.At = now
	ingest(t, s, b)
	r := report(t, s, Query{From: old.Add(-time.Hour), To: old.Add(time.Hour)})
	if r.Resolution != "day" || len(r.Rows) != 1 || r.Rows[0].Connections != 1 {
		t.Fatalf("retention/replay %+v", r)
	}
}
func TestStorageCapFailsAtomicallyAndCanRecover(t *testing.T) {
	s := testStore(t)
	now := testAt("2026-09-22T12:00:00Z")
	cfg := DefaultConfig()
	cfg.MaxBytes = 16 << 20
	if _, err := s.Prune(context.Background(), cfg, now); err != nil {
		t.Fatal(err)
	}
	b := Batch{SourceID: "flood", Kind: "access", Scope: "server", At: now, Checkpoint: &Checkpoint{Key: "cursor", Value: json.RawMessage(`10`)}}
	for i := 0; i < 3000; i++ {
		b.Events = append(b.Events, Event{ID: fmt.Sprint(i), At: now, Domain: fmt.Sprintf("%d.%s", i, strings.Repeat("a", 1200))})
	}
	if err := s.Ingest(context.Background(), b); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("cap error=%v", err)
	}
	if _, ok, err := s.Checkpoint(context.Background(), "flood", "cursor"); err != nil || ok {
		t.Fatalf("failed batch checkpoint %v %v", ok, err)
	}
	if got := s.fileBytes(); got > cfg.MaxBytes {
		t.Fatalf("disk cap exceeded after rollback %d", got)
	}
	if _, err := s.Prune(context.Background(), cfg, now); err != nil {
		t.Fatal(err)
	}
	b.Events = b.Events[:1]
	ingest(t, s, b)
}
func TestBytePrecisionOverflowAndUnknownSchema(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	b := Batch{SourceID: "precision", Kind: "interface", Scope: "host", At: at, Deltas: []Delta{{ID: "max", Start: at.Add(-time.Minute), End: at, UploadBytes: math.MaxInt64}}}
	ingest(t, s, b)
	r := report(t, s, Query{From: at.Add(-time.Minute), To: at})
	if len(r.Rows) != 1 || r.Rows[0].UploadBytes != math.MaxInt64 {
		t.Fatal("integer byte precision lost")
	}
	b.Deltas[0].ID = "overflow"
	b.Deltas[0].UploadBytes = 1
	if err := s.Ingest(context.Background(), b); err == nil {
		t.Fatal("integer aggregate overflow accepted")
	}
	if _, err := s.db.Exec("UPDATE meta SET value='999' WHERE key='schema'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TABLE coverage"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(s.Path(), false); err == nil {
		t.Fatal("unknown schema accepted")
	}
	var version string
	s.db.QueryRow("SELECT value FROM meta WHERE key='schema'").Scan(&version)
	if version != "999" {
		t.Fatal("unknown schema mutated")
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='coverage'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unknown schema migration wrote a table: %d %v", count, err)
	}
}

func TestPressureEvictsDetailsFirstAndIncludesServiceFiles(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	b := Batch{SourceID: "one", Kind: "access", Scope: "server", At: at}
	for i := 0; i < 1200; i++ {
		b.Events = append(b.Events, Event{ID: fmt.Sprint(i), At: at.Add(time.Duration(i) * time.Millisecond), Domain: fmt.Sprintf("%d.%s", i, strings.Repeat("a", 450))})
	}
	ingest(t, s, b)
	// Reserving most of a small budget for the service executable forces retention
	// pressure before the configured thirty days have passed.
	service := filepath.Join(filepath.Dir(s.Path()), "service")
	if err := os.Mkdir(service, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(service, "lazyclash")
	if err := os.WriteFile(binary, make([]byte, 9<<20), 0700); err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.MaxBytes = 16 << 20
	res, err := s.Prune(context.Background(), c, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedDetails == 0 {
		t.Fatalf("pressure did not evict details %+v", res)
	}
	if _, err = os.Stat(binary); err != nil {
		t.Fatal("retention removed owned service file")
	}
	if res.Bytes < 9<<20 {
		t.Fatalf("service excluded from budget: %+v", res)
	}
	var cutoff int64
	if err = s.db.QueryRow("SELECT CAST(value AS INTEGER) FROM meta WHERE key='detail_cutoff'").Scan(&cutoff); err != nil || cutoff < at.UnixMilli() {
		t.Fatalf("pressure replay watermark %d %v", cutoff, err)
	}
}

func TestSourceBindingPinnedBeforeCheckpointRestore(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	source := SourceConfig{ID: "client", Kind: "mihomo", Target: "desktop"}
	b := Batch{Source: &source, SourceID: source.ID, Kind: source.Kind, Scope: "client", Binding: "controller-a", At: at, Checkpoint: &Checkpoint{Key: "state", Value: json.RawMessage(`{"offset":5}`)}, Status: &SourceStatus{State: "baseline"}}
	ingest(t, s, b)
	if err := s.ValidateSourceBinding(context.Background(), source, "controller-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateSourceBinding(context.Background(), source, "controller-b"); err == nil {
		t.Fatal("controller target rebinding accepted")
	}
	copy := source
	copy.PollSeconds = 30
	copy.Enabled = true
	if err := s.ValidateSourceConfig(context.Background(), copy); err != nil {
		t.Fatalf("routine controls changed identity %v", err)
	}
	copy.Target = "other"
	if err := s.ValidateSourceConfig(context.Background(), copy); err == nil {
		t.Fatal("different target allowed under same source")
	}
	b.Source = &copy
	b.Checkpoint.Value = json.RawMessage(`{"offset":99}`)
	if err := s.Ingest(context.Background(), b); err == nil {
		t.Fatal("binding drift ingested")
	}
	cp, ok, err := s.Checkpoint(context.Background(), source.ID, "state")
	if err != nil || !ok || string(cp.Value) != `{"offset":5}` {
		t.Fatalf("checkpoint changed %+v %v", cp, err)
	}
	b.Source = nil
	if err := s.Ingest(context.Background(), b); err == nil {
		t.Fatal("omitting source metadata bypassed identity")
	}
}

func TestReportMetricAvailabilityAndProvenance(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	for _, entry := range []struct {
		kind, scope   string
		bytes, events bool
	}{{"access", "server", false, true}, {"interface", "host", true, false}, {"mihomo", "client", true, true}, {"future-kind", "host", false, false}} {
		source := SourceConfig{ID: entry.kind, Kind: entry.kind, Scope: entry.scope, HostID: "vm-1"}
		b := Batch{Source: &source, SourceID: source.ID, Kind: source.Kind, Scope: source.Scope, At: at, Events: []Event{{ID: "event", At: at}}, Deltas: []Delta{{ID: "counter", Start: at, End: at.Add(time.Second), UploadBytes: 1}}}
		ingest(t, s, b)
		r := report(t, s, Query{From: at, To: at.Add(time.Minute), SourceID: source.ID})
		if len(r.Rows) != 1 || r.Rows[0].BytesAvailable != entry.bytes || r.Rows[0].ConnectionsAvailable != entry.events {
			t.Fatalf("%s flags %+v", entry.kind, r.Rows)
		}
		st, ok, err := s.SourceStatus(context.Background(), source.ID)
		if err != nil || !ok || st.Source == nil || st.Source.HostID != "vm-1" {
			t.Fatalf("provenance absent %+v %v", st, err)
		}
	}
}

func TestCompactFallbackPreservesMeasuredTotalWithoutBypassingCap(t *testing.T) {
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	cfg := DefaultConfig()
	cfg.MaxBytes = 16 << 20
	if _, err := s.Prune(context.Background(), cfg, at); err != nil {
		t.Fatal(err)
	}
	s.pressure = true
	b := Batch{SourceID: "client", Kind: "mihomo", Scope: "client", At: at, Deltas: []Delta{{ID: "fallback", Start: at.Add(-time.Minute), End: at, UploadBytes: 99}}, Status: &SourceStatus{State: "storage-pressure", DroppedEvents: 400}}
	if err := s.Ingest(context.Background(), b); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("normal details passed pressure %v", err)
	}
	b.Compact = true
	ingest(t, s, b)
	r := report(t, s, Query{From: at.Add(-time.Minute), To: at, GroupBy: "domain"})
	if len(r.Rows) != 1 || r.Rows[0].Key != "(unattributed)" || r.Rows[0].UploadBytes != 99 || r.Coverage[0].Status.DroppedEvents != 400 {
		t.Fatalf("fallback %+v", r)
	}
	b.Deltas[0].Domain = "invented.test"
	if err := s.Ingest(context.Background(), b); err == nil {
		t.Fatal("compact source-total fallback accepted attribution")
	}
}

func TestConfigRejectsAliasDuplicatesAndReportIsBounded(t *testing.T) {
	c := DefaultConfig()
	c.Sources = []SourceConfig{{ID: "one", Kind: "interface", Interface: "eth0", Enabled: true}, {ID: "two", Kind: "host-interface", Interface: "eth0", Enabled: true}}
	if err := ValidateConfig(c); err == nil {
		t.Fatal("duplicate aliased source allowed")
	}
	s := testStore(t)
	at := testAt("2026-09-22T12:00:00Z")
	ingest(t, s, Batch{SourceID: "source", Kind: "access", Scope: "server", At: at, Events: []Event{{ID: "one", At: at, Domain: "one.test"}, {ID: "two", At: at, Domain: "two.test"}}})
	r := report(t, s, Query{From: at, To: at.Add(time.Minute), GroupBy: "domain", Limit: 1})
	if !r.Truncated || len(r.Rows) != 1 {
		t.Fatalf("limit %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Report(ctx, Query{From: at, To: at.Add(time.Minute)}); err == nil {
		t.Fatal("canceled report proceeded")
	}
}
