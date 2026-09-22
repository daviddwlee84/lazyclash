package analytics

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func collectorTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "analytics.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestVNStatImportsNativeDaysIdempotently(t *testing.T) {
	store := collectorTestStore(t)
	cfg := DefaultConfig()
	cfg.Timezone = "UTC"
	cfg.Sources = []SourceConfig{{ID: "vps-vnstat", Kind: "vnstat", Interface: "eth0", Enabled: true}}
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	data := `{"jsonversion":"2","interfaces":[{"name":"eth0","traffic":{"day":[{"date":{"year":2026,"month":9,"day":21},"tx":100,"rx":200},{"date":{"year":2026,"month":9,"day":22},"tx":50,"rx":75}],"month":[{"date":{"year":2026,"month":9},"tx":99999,"rx":99999}]}}]}`
	r, err := importVNStatAt(context.Background(), store, cfg, "vps-vnstat", strings.NewReader(data), now)
	if err != nil || r.Buckets != 1 || r.Skipped != 1 || r.UploadBytes != 100 {
		t.Fatalf("bad import: %#v %v", r, err)
	}
	r, err = importVNStatAt(context.Background(), store, cfg, "vps-vnstat", strings.NewReader(data), now)
	if err != nil || r.Buckets != 0 || r.Skipped != 2 {
		t.Fatalf("not idempotent: %#v %v", r, err)
	}
	var n int
	if err = store.db.QueryRow("SELECT COUNT(*) FROM metrics WHERE resolution='minute'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("daily bytes fabricated minute rows: %d %v", n, err)
	}
	var up int64
	if err = store.db.QueryRow("SELECT COALESCE(SUM(up),0) FROM metrics WHERE resolution='day'").Scan(&up); err != nil || up != 100 {
		t.Fatalf("native daily total wrong: %d %v", up, err)
	}
}

func TestVNStatRejectsOverlapsAndTimezoneShift(t *testing.T) {
	store := collectorTestStore(t)
	cfg := DefaultConfig()
	cfg.Timezone = "UTC"
	cfg.Sources = []SourceConfig{{ID: "s", Kind: "vnstat", Interface: "eth0", Enabled: true}}
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	bucket := `{"date":{"year":2026,"month":9,"day":21},"tx":1,"rx":2}`
	data := fmt.Sprintf(`{"jsonversion":"2","interfaces":[{"name":"eth0","traffic":{"day":[%s,%s]}}]}`, bucket, bucket)
	if _, err := importVNStatAt(context.Background(), store, cfg, "s", strings.NewReader(data), now); err == nil {
		t.Fatal("overlapping days accepted")
	}
	data = `{"jsonversion":"2","interfaces":[{"name":"eth0","traffic":{"day":[{"date":{"year":2026,"month":9,"day":21},"timestamp":1,"tx":1,"rx":2}]}}]}`
	if _, err := importVNStatAt(context.Background(), store, cfg, "s", strings.NewReader(data), now); err == nil {
		t.Fatal("native timezone silently shifted")
	}
	var n int
	_ = store.db.QueryRow("SELECT COUNT(*) FROM metrics").Scan(&n)
	if n != 0 {
		t.Fatal("invalid import changed the store")
	}
}
