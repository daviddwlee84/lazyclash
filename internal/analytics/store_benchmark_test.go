package analytics

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkIngest1000(b *testing.B)  { benchmarkIngest(b, 1000) }
func BenchmarkIngest10000(b *testing.B) { benchmarkIngest(b, 10000) }
func benchmarkIngest(b *testing.B, count int) {
	root := b.TempDir()
	at := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	events := make([]Event, count)
	for i := range events {
		events[i] = Event{ID: fmt.Sprint(i), At: at, Domain: fmt.Sprintf("domain-%d.test", i), ClientIP: fmt.Sprintf("10.0.%d.%d", i/256%256, i%256), Count: 1}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s, err := OpenStore(filepath.Join(root, fmt.Sprintf("%d.db", i)), false)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		for start := 0; start < count; start += 2000 {
			if err = s.Ingest(context.Background(), Batch{SourceID: "bench", Kind: "access", Scope: "server", At: at, Events: events[start:min(start+2000, count)]}); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		s.Close()
		b.StartTimer()
	}
}
