// Package dashboard contains the telemetry and rendering calculations used by
// the terminal overview. It has no timers, network access, or terminal state.
package dashboard

import (
	"encoding/json"
	"math"
	"sort"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/core"
)

const (
	Retention  = 15 * time.Minute
	StaleAfter = 5 * time.Second
	// MaxPoints also bounds memory if a controller sends faster than expected.
	MaxPoints = 4096
)

// Sample distinguishes an observed zero from an absent measurement. At is the
// local receive time; it does not imply that the core's own clock is in sync.
type Sample struct {
	At    time.Time
	Value float64
	Valid bool
}

type Point = Sample

func (s Sample) Stale(now time.Time) bool { return !s.Valid || now.Sub(s.At) > StaleAfter }

type Snapshot struct {
	Upload, Download, Memory            Sample
	UploadTotal, DownloadTotal          Sample
	Connections                         ConnectionSummary
	ConnectionsAt, TotalsResetAt        time.Time
	TrafficAt, MemoryAt, DisconnectedAt time.Time
	MemoryWarmup                        bool
}

func (s Snapshot) ConnectionsStale(now time.Time) bool {
	return s.ConnectionsAt.IsZero() || now.Sub(s.ConnectionsAt) > StaleAfter
}

// State belongs to one target. The zero value is ready to receive observations.
// Callers serialize updates with rendering, as in Bubble Tea's Update method.
type State struct {
	upload, download, memory Sample
	trafficAt, memoryAt      time.Time
	connections              ConnectionSummary
	connectionsAt            time.Time
	disconnectedAt           time.Time
	memoryWarmup             bool
	trafficTotals            totals
	connectionTotals         totals
	resetAt                  time.Time
	uploadHistory            series
	downloadHistory          series
	memoryHistory            series
	connectionHistory        series
}

type totals struct{ upload, download Sample }

// AddTraffic accepts Mihomo byte-per-second rates and optional newer-core
// upTotal/downTotal counters. Missing counters fall back to /connections.
func (s *State) AddTraffic(at time.Time, data core.Object) {
	if at.Before(s.trafficAt) {
		return
	}
	s.trafficAt = at
	upload, download := measured(at, data["up"]), measured(at, data["down"])
	if upload.Valid {
		s.upload = upload
	}
	if download.Valid {
		s.download = download
	}
	s.uploadHistory.add(upload)
	s.downloadHistory.add(download)
	s.recordTotals(&s.trafficTotals, at, data["upTotal"], data["downTotal"])
	s.prune(at)
}

// AddMemory handles the zero warmup frame emitted by Mihomo when a memory
// stream starts. It neither displays that frame as zero RSS nor links across it.
func (s *State) AddMemory(at time.Time, data core.Object) {
	if at.Before(s.memoryAt) {
		return
	}
	s.memoryAt = at
	value := measured(at, data["inuse"])
	s.memoryWarmup = value.Valid && value.Value == 0
	if !value.Valid || value.Value == 0 {
		s.memoryHistory.add(Point{At: at})
	} else {
		s.memory = value
		s.memoryHistory.add(value)
	}
	s.prune(at)
}

// AddConnections must receive the complete response, before any browsing-list
// cap. Summaries and active count therefore describe all active connections.
func (s *State) AddConnections(at time.Time, data core.Object) {
	if at.Before(s.connectionsAt) {
		return
	}
	s.connections = SummarizeConnections(data)
	s.connectionsAt = at
	s.connectionHistory.add(Point{At: at, Value: float64(s.connections.Count), Valid: true})
	s.recordTotals(&s.connectionTotals, at, data["uploadTotal"], data["downloadTotal"])
	s.prune(at)
}

// Gap marks disconnects or target inactivity without inventing zero values.
// The last observed card values remain available with their original ages.
func (s *State) Gap(at time.Time) {
	s.disconnectedAt = at
	for _, history := range []*series{&s.uploadHistory, &s.downloadHistory, &s.memoryHistory, &s.connectionHistory} {
		history.add(Point{At: at})
	}
	s.prune(at)
}

// SourceGap records a failed stream or refresh without interrupting unrelated
// measurements. Latest values and their observed ages remain unchanged, and a
// quick reconnect cannot interpolate across the known missing interval.
func (s *State) SourceGap(at time.Time, resource string) {
	var histories []*series
	switch resource {
	case "traffic":
		histories = []*series{&s.uploadHistory, &s.downloadHistory}
	case "memory":
		histories = []*series{&s.memoryHistory}
	case "connections":
		histories = []*series{&s.connectionHistory}
	default:
		return
	}
	for _, history := range histories {
		history.add(Point{At: at})
	}
	s.prune(at)
}

// Snapshot retains source timestamps. Its summary slices should be treated as
// read-only; they are replaced, rather than mutated, on the next observation.
func (s *State) Snapshot(now time.Time) Snapshot {
	choose := func(traffic, connection Sample) Sample {
		if traffic.Valid && (!traffic.Stale(now) || !connection.Valid || traffic.At.After(connection.At)) {
			return traffic
		}
		return connection
	}
	return Snapshot{
		Upload: s.upload, Download: s.download, Memory: s.memory,
		UploadTotal:   choose(s.trafficTotals.upload, s.connectionTotals.upload),
		DownloadTotal: choose(s.trafficTotals.download, s.connectionTotals.download),
		Connections:   s.connections, ConnectionsAt: s.connectionsAt,
		TrafficAt: s.trafficAt, MemoryAt: s.memoryAt, TotalsResetAt: s.resetAt,
		MemoryWarmup: s.memoryWarmup, DisconnectedAt: s.disconnectedAt,
	}
}

// Series returns a detached chronological window for upload, download, memory,
// or connections. Unsupported metrics return no points. Windows are at most
// 15 minutes; a non-positive window uses the default five minutes.
func (s *State) Series(metric string, now time.Time, window time.Duration) []Point {
	window = Window(window)
	var points []Point
	switch metric {
	case "upload":
		points = s.uploadHistory.points
	case "download":
		points = s.downloadHistory.points
	case "memory":
		points = s.memoryHistory.points
	case "connections":
		points = s.connectionHistory.points
	default:
		return nil
	}
	start := now.Add(-window)
	first := sort.Search(len(points), func(i int) bool { return !points[i].At.Before(start) })
	last := sort.Search(len(points), func(i int) bool { return points[i].At.After(now) })
	return append([]Point(nil), points[first:last]...)
}

func Window(window time.Duration) time.Duration {
	if window <= 0 {
		return 5 * time.Minute
	}
	return min(window, Retention)
}

// Prune may be called during an update tick for inactive targets. Read paths
// (Snapshot and Series) never mutate the model, so terminal rendering is pure.
func (s *State) Prune(now time.Time) { s.prune(now) }

func (s *State) recordTotals(previous *totals, at time.Time, up, down any) {
	nextUp, nextDown := measured(at, up), measured(at, down)
	// Compare a source only with itself: switching between asynchronously
	// sampled /traffic and /connections must not produce a false reset.
	if (nextUp.Valid && previous.upload.Valid && nextUp.Value < previous.upload.Value) ||
		(nextDown.Valid && previous.download.Valid && nextDown.Value < previous.download.Value) {
		s.resetAt = at
	}
	if nextUp.Valid {
		previous.upload = nextUp
	}
	if nextDown.Valid {
		previous.download = nextDown
	}
}

func (s *State) prune(now time.Time) {
	for _, history := range []*series{&s.uploadHistory, &s.downloadHistory, &s.memoryHistory, &s.connectionHistory} {
		history.prune(now.Add(-Retention))
	}
}

type series struct{ points []Point }

func (s *series) add(point Point) {
	if n := len(s.points); n > 0 {
		last := s.points[n-1]
		if point.At.Before(last.At) {
			return
		}
		if point.At.Equal(last.At) && point.Valid == last.Valid {
			s.points[n-1] = point
			return
		}
	}
	s.points = append(s.points, point)
	if len(s.points) > MaxPoints {
		s.points = s.points[len(s.points)-MaxPoints:]
	}
}

func (s *series) prune(before time.Time) {
	first := sort.Search(len(s.points), func(i int) bool { return !s.points[i].At.Before(before) })
	if first == len(s.points) {
		s.points = nil
	} else if first > 0 {
		// Drop references to old storage after enough points expire. Normal
		// one-second streams retain at most twice the live slice allocation.
		s.points = s.points[first:]
		if cap(s.points) > max(64, 2*len(s.points)) {
			s.points = append([]Point(nil), s.points...)
		}
	}
}

func measured(at time.Time, value any) Sample {
	number, ok := numeric(value)
	return Sample{At: at, Value: number, Valid: ok}
}

func numeric(value any) (float64, bool) {
	var result float64
	switch value := value.(type) {
	case float64:
		result = value
	case float32:
		result = float64(value)
	case int:
		result = float64(value)
	case int64:
		result = float64(value)
	case int32:
		result = float64(value)
	case uint:
		result = float64(value)
	case uint64:
		result = float64(value)
	case uint32:
		result = float64(value)
	case json.Number:
		var err error
		result, err = value.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	if result < 0 || math.IsNaN(result) || math.IsInf(result, 0) {
		return 0, false
	}
	return result, true
}
