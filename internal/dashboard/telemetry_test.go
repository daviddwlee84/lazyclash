package dashboard

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

func epoch() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }

func TestIndependentSourcesWarmupAndStaleness(t *testing.T) {
	var state State
	start := epoch()
	state.AddTraffic(start, core.Object{"up": 0, "down": 15})
	state.AddMemory(start, core.Object{"inuse": 0, "oslimit": 64 << 30})
	state.AddConnections(start.Add(time.Second), core.Object{"connections": []any{}, "uploadTotal": 100, "downloadTotal": 200})
	first := state.Snapshot(start.Add(time.Second))
	if !first.Upload.Valid || first.Upload.Value != 0 || first.Memory.Valid || !first.MemoryWarmup {
		t.Fatalf("observed zero and memory warmup confused: %+v", first)
	}
	if first.UploadTotal.Value != 100 || first.DownloadTotal.Value != 200 {
		t.Fatalf("connection totals fallback missing: %+v", first)
	}
	state.AddMemory(start.Add(2*time.Second), core.Object{"inuse": 1234})
	state.AddConnections(start.Add(5*time.Second), core.Object{"connections": []any{core.Object{"id": "one"}}, "uploadTotal": 150, "downloadTotal": 300})
	later := state.Snapshot(start.Add(6 * time.Second))
	if !later.Upload.Stale(start.Add(6*time.Second)) || later.Memory.Stale(start.Add(6*time.Second)) || later.ConnectionsStale(start.Add(6*time.Second)) {
		t.Fatalf("source ages must remain independent: %+v", later)
	}
	if later.MemoryWarmup || later.Memory.Value != 1234 || later.Connections.Count != 1 {
		t.Fatalf("valid sources not retained: %+v", later)
	}
	state.AddMemory(start.Add(7*time.Second), core.Object{"inuse": 0})
	warm := state.Snapshot(start.Add(7 * time.Second))
	if !warm.MemoryWarmup || warm.Memory.Value != 1234 || !warm.Memory.At.Equal(start.Add(2*time.Second)) {
		t.Fatalf("reconnected warmup must not overwrite RSS with zero: %+v", warm)
	}
}

func TestCountersResetWithoutFalseCrossSourceReset(t *testing.T) {
	var state State
	start := epoch()
	state.AddTraffic(start, core.Object{"up": 10, "down": 20, "upTotal": 1100, "downTotal": 2200})
	state.AddConnections(start.Add(time.Second), core.Object{"uploadTotal": 1000, "downloadTotal": 2000})
	snapshot := state.Snapshot(start.Add(time.Second))
	if !snapshot.TotalsResetAt.IsZero() || snapshot.UploadTotal.Value != 1100 {
		t.Fatalf("asynchronously sampled sources caused false reset: %+v", snapshot)
	}
	state.AddConnections(start.Add(7*time.Second), core.Object{"uploadTotal": 1300, "downloadTotal": 2300})
	snapshot = state.Snapshot(start.Add(7 * time.Second))
	if snapshot.UploadTotal.Value != 1300 || !snapshot.TotalsResetAt.IsZero() {
		t.Fatalf("stale traffic totals did not fall back: %+v", snapshot)
	}
	state.AddTraffic(start.Add(8*time.Second), core.Object{"up": 0, "down": 0, "upTotal": 5, "downTotal": 10})
	snapshot = state.Snapshot(start.Add(8 * time.Second))
	if snapshot.UploadTotal.Value != 5 || !snapshot.TotalsResetAt.Equal(start.Add(8*time.Second)) {
		t.Fatalf("counter reset not recorded: %+v", snapshot)
	}
	state.AddTraffic(start.Add(9*time.Second), core.Object{"up": 0, "down": 0})
	if snapshot = state.Snapshot(start.Add(time.Hour)); snapshot.UploadTotal.Value != 5 {
		t.Fatalf("both stale totals must retain the newer source: %+v", snapshot)
	}
}

func TestTimestampWindowsGapsAndReadPurity(t *testing.T) {
	var state State
	start := epoch()
	for i := 0; i <= 960; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		state.AddTraffic(at, core.Object{"up": i, "down": i * 2})
	}
	now := start.Add(960 * time.Second)
	for window, want := range map[time.Duration]int{time.Minute: 61, 5 * time.Minute: 301, 15 * time.Minute: 901, 30 * time.Minute: 901, 0: 301} {
		got := state.Series("upload", now, window)
		if len(got) != want {
			t.Errorf("window %v: got %d points, want %d", window, len(got), want)
		}
	}
	state.Gap(now.Add(time.Second))
	state.AddTraffic(now.Add(2*time.Second), core.Object{"up": 3, "down": 4})
	points := state.Series("upload", now.Add(2*time.Second), time.Minute)
	if len(points) < 3 || points[len(points)-2].Valid || !points[len(points)-1].Valid {
		t.Fatalf("gap was lost: %v", points[len(points)-3:])
	}
	// Reads made by View may neither prune nor otherwise mutate the model.
	before := append([]Point(nil), state.uploadHistory.points...)
	_ = state.Series("upload", now.Add(time.Hour), time.Minute)
	_ = state.Snapshot(now.Add(time.Hour))
	if !reflect.DeepEqual(before, state.uploadHistory.points) {
		t.Fatal("rendering read mutated retained history")
	}
	state.Prune(now.Add(time.Hour))
	if len(state.uploadHistory.points) != 0 {
		t.Fatal("inactive target history was not pruned")
	}
}

func TestSampleCapOutOfOrderAndInvalidNumbers(t *testing.T) {
	var state State
	start := epoch()
	for i := 0; i < MaxPoints+100; i++ {
		state.AddTraffic(start.Add(time.Duration(i)*time.Millisecond), core.Object{"up": i, "down": i})
	}
	if len(state.uploadHistory.points) != MaxPoints {
		t.Fatalf("high-rate stream is unbounded: %d", len(state.uploadHistory.points))
	}
	latest := state.Snapshot(start.Add(time.Minute))
	state.AddTraffic(start, core.Object{"up": 9999999, "down": 9999999})
	if state.Snapshot(start).Upload != latest.Upload {
		t.Fatal("late sample overwrote current value")
	}
	state.AddTraffic(start.Add(time.Minute), core.Object{"up": math.NaN(), "down": -1})
	if state.Snapshot(start.Add(time.Minute)).Upload != latest.Upload {
		t.Fatal("invalid frame replaced last valid value")
	}
	for _, invalid := range []any{nil, "0", json.Number("bad"), math.Inf(1), math.NaN(), -1} {
		if _, ok := numeric(invalid); ok {
			t.Fatalf("accepted invalid telemetry number %v", invalid)
		}
	}
	if value, ok := numeric(json.Number("1234")); !ok || value != 1234 {
		t.Fatal("JSON number not supported")
	}
}

func TestGapAndResumeAtSameTimestamp(t *testing.T) {
	var state State
	start := epoch()
	state.AddTraffic(start, core.Object{"up": 1, "down": 2})
	state.Gap(start.Add(time.Second))
	state.AddTraffic(start.Add(time.Second), core.Object{"up": 2, "down": 3})
	points := state.Series("upload", start.Add(time.Second), time.Minute)
	if len(points) != 3 || points[1].Valid || !points[2].Valid {
		t.Fatalf("same-time resume erased gap: %+v", points)
	}
}

func TestSourceGapDoesNotInterruptOtherSourcesOrResetAges(t *testing.T) {
	var state State
	start := epoch()
	state.AddTraffic(start, core.Object{"up": 1, "down": 2})
	state.AddMemory(start, core.Object{"inuse": 100})
	state.AddConnections(start, core.Object{"connections": []any{}})
	before := state.Snapshot(start)
	state.SourceGap(start.Add(time.Second), "traffic")
	after := state.Snapshot(start.Add(time.Second))
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("source gap altered last measured values/ages: before %+v after %+v", before, after)
	}
	if got := state.Series("memory", start.Add(time.Second), time.Minute); len(got) != 1 || !got[0].Valid {
		t.Fatalf("traffic gap interrupted memory: %+v", got)
	}
	state.AddTraffic(start.Add(3*time.Second), core.Object{"up": 1, "down": 2})
	for _, metric := range []string{"upload", "download"} {
		points := state.Series(metric, start.Add(3*time.Second), time.Minute)
		if got := Chart(points, start, start.Add(3*time.Second), 4, 1, "ascii"); got != "*  *" {
			t.Fatalf("quick %s reconnect bridged known gap: %q", metric, got)
		}
	}
	for _, metric := range []string{"memory", "connections"} {
		state.SourceGap(start.Add(4*time.Second), metric)
		points := state.Series(metric, start.Add(4*time.Second), time.Minute)
		if len(points) != 2 || points[1].Valid {
			t.Fatalf("%s gap missing: %+v", metric, points)
		}
	}
}
