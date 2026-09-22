package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

type CollectorOptions struct {
	Duration time.Duration
	Open     func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)
}

type collectionSource struct {
	config  SourceConfig
	binding string
	next    time.Time
	status  SourceStatus
	tracker counterTracker
	tail    *accessTail
	client  *core.Client
	closer  io.Closer
}

func (s *collectionSource) close() {
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.closer != nil {
		_ = s.closer.Close()
		s.closer = nil
		s.client = nil
	}
	if s.tail != nil {
		s.tail.close()
	}
}

// RunCollector is foreground and user scoped. A filesystem lock prevents a
// service and an interactive collector from writing overlapping observations.
// Polling failures are persisted as gaps and retried without borrowing bytes
// from the unavailable interval. No source is activated implicitly.
func RunCollector(ctx context.Context, cfg Config, store *Store, targets []config.Target, opts CollectorOptions) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if opts.Duration < 0 {
		return errors.New("collection duration must be nonnegative")
	}
	if store == nil {
		return errors.New("analytics store is required")
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	var sources []*collectionSource
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		if err := ValidateSource(source); err != nil {
			return err
		}
		if source.Kind == "vnstat" {
			continue
		}
		if source.Kind == "mihomo" {
			t, err := findSourceTarget(source.Target, targets)
			if err != nil {
				return err
			}
			if t.SSHHost != "" {
				return errors.New("analytics is node-local: run the collector on the SSH target host with local target and secret references")
			}
		}
		binding, err := resolvedSourceBinding(source, targets)
		if err != nil {
			return err
		}
		if err = store.ValidateSourceBinding(ctx, source, binding); err != nil {
			return err
		}
		s := &collectionSource{config: source, status: SourceStatus{SourceID: source.ID, Kind: source.Kind, Scope: sourceScope(source)}}
		s.binding = binding
		if prior, ok, err := store.SourceStatus(ctx, source.ID); err != nil {
			return err
		} else if ok {
			s.status = prior
		}
		switch source.Kind {
		case "access", "xray-access", "v2ray-access":
			zone := time.Local
			if source.Timezone != "" {
				zone, _ = time.LoadLocation(source.Timezone)
			}
			s.tail = &accessTail{source: source, zone: zone}
			cp, ok, err := store.Checkpoint(ctx, source.ID, "access")
			if err != nil {
				return err
			}
			if ok {
				if json.Unmarshal(cp.Value, &s.tail.position) != nil {
					return errors.New("invalid access checkpoint")
				}
				s.tail.restored = true
			}
		}
		sources = append(sources, s)
	}
	if len(sources) == 0 {
		return errors.New("no enabled live analytics sources; enable a source or use import-vnstat")
	}
	unlock, err := lockCollector(store.Path())
	if err != nil {
		return err
	}
	defer unlock()
	health := newCollectorHealth(len(sources))
	if _, err = store.Prune(ctx, cfg, time.Now()); err != nil && !errors.Is(err, ErrStorageLimit) {
		return err
	}
	parentCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if opts.Duration > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, opts.Duration)
		defer timeoutCancel()
	}
	failures := make(chan error, 1)
	fail := func(err error) {
		select {
		case failures <- err:
		default:
		}
		cancel()
	}
	sem := make(chan struct{}, 4)
	var workers sync.WaitGroup
	for _, source := range sources {
		s := source
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer s.close()
			scheduled := time.Now()
			for {
				timer := time.NewTimer(max(time.Duration(0), time.Until(scheduled)))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				started := time.Now()
				err := pollCollectionSource(ctx, cfg, store, s, targets, open)
				<-sem
				health.record(s, started, started.Sub(scheduled), err)
				if err != nil && ctx.Err() == nil && !errors.Is(err, ErrStorageLimit) {
					fail(err)
					return
				}
				scheduled = scheduled.Add(sourceInterval(s.config))
				if scheduled.Before(time.Now()) {
					scheduled = time.Now().Add(sourceInterval(s.config))
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		nextPrune := time.Now().Add(time.Hour)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if health.pressure() || !time.Now().Before(nextPrune) {
				result, err := store.Prune(ctx, cfg, time.Now())
				if err != nil && !errors.Is(err, ErrStorageLimit) && ctx.Err() == nil {
					fail(err)
					return
				}
				if err == nil && !result.Pressure {
					health.recovered()
				}
				nextPrune = time.Now().Add(time.Hour)
			}
			if cfg.Alerts.Enabled {
				if _, err := store.EvaluateAlerts(ctx, cfg.Alerts, time.Now()); err != nil && !errors.Is(err, ErrStorageLimit) && ctx.Err() == nil {
					fail(err)
					return
				}
				_ = store.DeliverAlerts(ctx, cfg.Alerts)
			}
		}
	}()
	// Health is independent from database writes and alert delivery, so a slow
	// source or full store remains visible without producing growing log files.
	_ = health.write(store.Path())
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()
	var result error
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case err := <-failures:
			result = err
			cancel()
			running = false
		case <-heartbeat.C:
			_ = health.write(store.Path())
		}
	}
	workers.Wait()
	if result == nil {
		select {
		case result = <-failures:
		default:
		}
	}
	health.stop(result)
	_ = health.write(store.Path())
	if result != nil {
		return result
	}
	return parentCtx.Err()
}

func pollCollectionSource(ctx context.Context, cfg Config, store *Store, s *collectionSource, targets []config.Target, open func(context.Context, config.Target, bool) (*core.Client, io.Closer, error)) error {
	now := time.Now()
	readCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	batch := Batch{SourceID: s.config.ID, Kind: s.config.Kind, Scope: sourceScope(s.config), Timezone: cfg.Timezone, At: now}
	var err error
	var gaps, dropped, resets int64
	var mismatch bool
	var oldPosition accessCheckpoint
	var oldRestored bool
	if s.tail != nil {
		oldPosition = s.tail.position
		oldRestored = s.tail.restored
	}
	if s.tail != nil {
		batch, gaps, dropped, err = s.tail.poll(readCtx, now)
		batch.Timezone = cfg.Timezone
	} else {
		var counters map[string]observedCounter
		var totals *observedCounter
		switch s.config.Kind {
		case "mihomo":
			if s.client == nil {
				var target config.Target
				target, err = findSourceTarget(s.config.Target, targets)
				if err == nil {
					s.client, s.closer, err = open(readCtx, target, true)
				}
			}
			if err == nil {
				var data core.Object
				data, err = s.client.Connections(readCtx)
				if err == nil {
					counters, dropped, err = parseMihomoCounters(data)
					up, uok := sourceInt(data["uploadTotal"])
					down, dok := sourceInt(data["downloadTotal"])
					if uok && dok {
						totals = &observedCounter{Upload: up, Download: down}
					}
				}
			}
		case "interface", "host-interface":
			var tx, rx int64
			tx, rx, err = readInterfaceCounters(s.config.Interface)
			if err == nil {
				counters = map[string]observedCounter{s.config.Interface: {Upload: tx, Download: rx, Identity: s.config.Interface}}
			}
		case "stats", "xray-stats", "v2ray-stats":
			var data []byte
			data, err = runStatsCommand(readCtx, s.config)
			if err == nil {
				counters, err = parseStatsCounters(data)
			}
		}
		if err == nil {
			now = time.Now()
			batch.At = now
			if !s.tracker.last.IsZero() && (!now.After(s.tracker.last) || now.Sub(s.tracker.last) > 3*sourceInterval(s.config)) {
				gaps++
			}
			if s.config.Kind == "mihomo" {
				batch.Deltas, batch.Events, batch.CoverageStart, resets, mismatch = s.tracker.observeConnections(s.config.ID, now, counters, totals, 3*sourceInterval(s.config))
			} else {
				batch.Deltas, batch.Events, batch.CoverageStart, resets = s.tracker.observe(s.config.ID, now, counters, 3*sourceInterval(s.config), false)
			}
			if mismatch {
				gaps++
			}
			// This bounded normalized checkpoint is deliberately not a replayable
			// baseline: a restart starts a new interval instead of backcharging downtime.
			value, _ := json.Marshal(struct {
				At       time.Time `json:"at"`
				Counters int       `json:"counters"`
				Mode     string    `json:"mode"`
			}{now, len(counters), "baseline-on-restart"})
			batch.Checkpoint = &Checkpoint{Key: "counters", Value: value, UpdatedAt: now}
		}
	}
	priorState := s.status.State
	s.status.LastAttempt = now
	s.status.GapCount += gaps
	s.status.ResetCount += resets
	s.status.DroppedEvents += dropped
	if err != nil {
		if priorState != "unavailable" {
			s.status.GapCount++
		}
		s.status.State = "unavailable"
		s.status.Message = safeSourceError(s.config.Kind, err)
		s.tracker.reset()
		if s.tail != nil {
			s.tail.last = time.Time{}
		}
		if s.client != nil {
			s.close()
		}
		batch = Batch{SourceID: s.config.ID, Kind: s.config.Kind, Scope: sourceScope(s.config), Timezone: cfg.Timezone, At: now}
	} else {
		s.status.LastSuccess = now
		s.status.State = "collecting"
		s.status.Message = ""
		if batch.CoverageStart.IsZero() {
			s.status.State = "baseline"
			s.status.Message = "observation baseline; unavailable intervals are not backfilled"
		}
		if dropped > 0 || resets > 0 || gaps > 0 {
			s.status.State = "partial"
			s.status.Message = "some observations were dropped or counters reset; affected bytes are not estimated"
		}
		if mismatch {
			s.status.State = "partial"
			s.status.Message = "connection attribution is incomplete; valid aggregate bytes are unattributed, and missing aggregate counters remain a lower bound"
		}
	}
	batch.Status = &s.status
	batch.Source = &s.config
	batch.Binding = s.binding
	err = store.Ingest(ctx, batch)
	if errors.Is(err, ErrStorageLimit) && s.tail == nil {
		if compact, ok := compactCounterBatch(batch); ok {
			s.status.State = "storage-pressure"
			s.status.Message = "storage budget reached; only compact observed counter bytes retained, connection and attribution detail dropped"
			s.status.DroppedEvents += int64(len(batch.Events))
			for _, d := range batch.Deltas {
				if d.ClientIP != "" || d.Domain != "" || d.Process != "" || d.Route != "" || d.Principal != "" {
					s.status.DroppedEvents++
				}
			}
			compact.Status = &s.status
			err = store.Ingest(ctx, compact)
		}
	}
	if err != nil {
		s.tracker.reset()
		s.status.GapCount++
		if s.tail != nil {
			s.tail.close()
			s.tail.position = oldPosition
			s.tail.restored = oldRestored
			s.tail.last = time.Time{}
		}
		if errors.Is(err, ErrStorageLimit) {
			s.status.State = "storage-pressure"
			s.status.Message = "storage budget reached; collection is incomplete"
		}
	}
	return err
}

// Compact fallback preserves only already measured deltas. It never substitutes
// zero for missing counters or sums client/server/host accounting planes.
func compactCounterBatch(b Batch) (Batch, bool) {
	switch b.Kind {
	case "mihomo", "interface", "host-interface", "stats", "xray-stats", "v2ray-stats":
	default:
		return Batch{}, false
	}
	out := b
	out.Compact = true
	out.Events = nil
	out.Deltas = nil
	if len(b.Deltas) == 0 {
		return out, true
	}
	var up, down int64
	start, end := b.Deltas[0].Start, b.Deltas[0].End
	ids := []string{b.SourceID, "compact"}
	for _, d := range b.Deltas {
		if d.Granularity != "" && d.Granularity != "interval" || d.UploadBytes < 0 || d.DownloadBytes < 0 || d.UploadBytes > math.MaxInt64-up || d.DownloadBytes > math.MaxInt64-down {
			return Batch{}, false
		}
		up += d.UploadBytes
		down += d.DownloadBytes
		if d.Start.Before(start) {
			start = d.Start
		}
		if d.End.After(end) {
			end = d.End
		}
		ids = append(ids, d.ID)
	}
	if !end.After(start) {
		return Batch{}, false
	}
	out.Deltas = []Delta{{ID: stableSourceID(ids...), Start: start, End: end, UploadBytes: up, DownloadBytes: down}}
	return out, true
}
