package analytics

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

type CollectorSourceHealth struct {
	SourceID       string    `json:"source_id"`
	State          string    `json:"state"`
	LastPoll       time.Time `json:"last_poll"`
	Polls          int64     `json:"polls"`
	DurationMillis int64     `json:"duration_millis"`
	LagMillis      int64     `json:"lag_millis"`
	DroppedEvents  int64     `json:"dropped_events"`
	Gaps           int64     `json:"gaps"`
}

type CollectorHealthStatus struct {
	PID           int                     `json:"pid"`
	State         string                  `json:"state"`
	Message       string                  `json:"message,omitempty"`
	StartedAt     time.Time               `json:"started_at"`
	Heartbeat     time.Time               `json:"heartbeat"`
	StoppedAt     time.Time               `json:"stopped_at,omitempty"`
	UptimeSeconds float64                 `json:"uptime_seconds"`
	HeapBytes     uint64                  `json:"heap_bytes"`
	PeakRSSBytes  int64                   `json:"peak_rss_bytes"`
	CPUSeconds    float64                 `json:"cpu_seconds"`
	Goroutines    int                     `json:"goroutines"`
	ActiveSources int                     `json:"active_sources"`
	Polls         int64                   `json:"polls"`
	DroppedEvents int64                   `json:"dropped_events"`
	Sources       []CollectorSourceHealth `json:"sources"`
	Stale         bool                    `json:"stale"`
}

type collectorHealthRecorder struct {
	mu      sync.Mutex
	status  CollectorHealthStatus
	sources map[string]CollectorSourceHealth
}

func newCollectorHealth(n int) *collectorHealthRecorder {
	return &collectorHealthRecorder{status: CollectorHealthStatus{PID: os.Getpid(), State: "running", StartedAt: time.Now(), ActiveSources: n}, sources: map[string]CollectorSourceHealth{}}
}

func (h *collectorHealthRecorder) record(s *collectionSource, started time.Time, lag time.Duration, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.sources[s.config.ID]
	v.SourceID = s.config.ID
	v.State = s.status.State
	v.LastPoll = time.Now()
	v.Polls++
	v.DurationMillis = time.Since(started).Milliseconds()
	v.LagMillis = max(int64(0), lag.Milliseconds())
	v.DroppedEvents = s.status.DroppedEvents
	v.Gaps = s.status.GapCount
	if errors.Is(err, ErrStorageLimit) || v.State == "storage-pressure" {
		v.State = "storage-pressure"
		h.status.State = "storage-pressure"
		h.status.Message = "storage budget reached; gaps are recorded and retention is retried"
	}
	h.sources[s.config.ID] = v
}

func (h *collectorHealthRecorder) pressure() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status.State == "storage-pressure"
}
func (h *collectorHealthRecorder) recovered() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.State = "running"
	h.status.Message = ""
}
func (h *collectorHealthRecorder) stop(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status.State = "stopped"
	h.status.ActiveSources = 0
	h.status.StoppedAt = time.Now()
	if err != nil {
		h.status.State = "error"
		h.status.Message = "collector stopped after a persistence or configuration failure"
	}
}

func (h *collectorHealthRecorder) write(dbPath string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.status
	v.Heartbeat = time.Now()
	v.UptimeSeconds = v.Heartbeat.Sub(v.StartedAt).Seconds()
	v.Goroutines = runtime.NumGoroutine()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	v.HeapBytes = mem.HeapAlloc
	v.CPUSeconds, v.PeakRSSBytes = collectorResources()
	for _, s := range h.sources {
		v.Sources = append(v.Sources, s)
		v.Polls += s.Polls
		v.DroppedEvents += s.DroppedEvents
	}
	sort.Slice(v.Sources, func(i, j int) bool { return v.Sources[i].SourceID < v.Sources[j].SourceID })
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writePrivateFile(dbPath+".collector-health.json", b)
}

// CollectorHealth reads a bounded atomic health snapshot without creating files.
// Stale means no heartbeat in 15 seconds; it is not proof the PID is still ours.
func CollectorHealth(dbPath string) (CollectorHealthStatus, error) {
	path := dbPath + ".collector-health.json"
	info, err := os.Lstat(path)
	if err != nil {
		return CollectorHealthStatus{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return CollectorHealthStatus{}, errors.New("invalid collector health file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return CollectorHealthStatus{}, err
	}
	var v CollectorHealthStatus
	if json.Unmarshal(b, &v) != nil {
		return v, errors.New("invalid collector health data")
	}
	v.Stale = time.Since(v.Heartbeat) > 15*time.Second && v.StoppedAt.IsZero()
	return v, nil
}
