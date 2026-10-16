// Package rulediscovery owns a bounded observation session. Controller events
// are supplied by either the dashboard's existing stream or the CLI collector.
package rulediscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
)

const DefaultDuration = 30 * time.Minute

// TargetIdentity prevents applying a saved observation to a reused target name.
// It contains no credential.
func TargetIdentity(t config.Target) string {
	b, _ := json.Marshal([]string{t.ID, t.Controller, t.SSHHost, t.HostOS, t.CAFile, t.SecretEnv, t.SecretFile, t.SourceConfig})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type Options struct {
	SettingsPath string
	StateDir     string
	Duration     time.Duration
	Direct       bool
	Plan         discoveryguard.Plan
}

type Session struct {
	mu        sync.Mutex
	saveMu    sync.Mutex
	acc       *ruleobserve.Accumulator
	meta      ruleobserve.Snapshot
	stateDir  string
	guard     *discoveryguard.Handle
	deadline  time.Time
	done      chan struct{}
	stop      chan struct{}
	once      sync.Once
	lastSaved time.Time
	err       error
}

// Start persists a snapshot before changing routing. Failed helper activation
// still returns a session and persists GuardID while independent cleanup runs.
func Start(ctx context.Context, target config.Target, opts Options) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.Duration <= 0 {
		return nil, errors.New("discovery duration must be positive")
	}
	if target.ID == "" || target.Transient || target.TransportOverride {
		return nil, errors.New("discovery requires a saved target without transport overrides")
	}
	now := time.Now()
	acc := ruleobserve.New(target.ID, now)
	s := &Session{acc: acc, stateDir: opts.StateDir, done: make(chan struct{}), stop: make(chan struct{}), deadline: now.Add(opts.Duration)}
	s.meta = acc.Snapshot(now)
	s.meta.Mode, s.meta.Status, s.meta.TargetIdentity = "normal", "preparing", TargetIdentity(target)
	if opts.Direct {
		s.meta.Mode, s.meta.FallbackPolicy, s.meta.PreviousSelection = "fallback_direct", opts.Plan.FallbackPolicy, opts.Plan.Previous
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	if opts.Direct {
		h, err := discoveryguard.Start(ctx, opts.SettingsPath, target, opts.Plan, time.Until(s.deadline))
		s.guard = h
		if h != nil {
			s.meta.GuardID = h.ID()
		}
		if err != nil {
			s.failStart(err)
			return s, err
		}
	}
	s.meta.Status = "collecting"
	s.acc.Gap(time.Now(), "collection started; log coverage is unconfirmed until an event arrives")
	if err := s.Save(); err != nil {
		s.failStart(nil)
		return s, err
	}
	go s.run(ctx)
	return s, nil
}

func (s *Session) failStart(err error) {
	s.addError(err)
	s.mu.Lock()
	s.meta.Status = "failed"
	if s.guard != nil && s.guard.Status().Pending() {
		s.meta.Status = "restoring"
	}
	s.meta.FinishedAt = time.Now()
	s.mu.Unlock()
	s.RequestStop()
	_ = s.Save() // Link GuardID before waiting for restoration.
	go s.finish()
}

func (s *Session) run(ctx context.Context) {
	timer := time.NewTimer(time.Until(s.deadline))
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var guardDone <-chan struct{}
	if s.guard != nil {
		guardDone = s.guard.Done()
	}
	for {
		select {
		case <-ctx.Done():
			s.finish()
			return
		case <-s.stop:
			s.finish()
			return
		case <-timer.C:
			s.finish()
			return
		case <-guardDone:
			s.finish()
			return
		case <-tick.C:
			if err := s.Save(); err != nil {
				s.finish()
				return
			}
		}
	}
}

func (s *Session) Observe(record core.Object, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.Status != "collecting" || s.stopping() {
		return
	}
	// Serialize acceptance with finish: a final snapshot cannot miss an accepted event.
	s.acc.Observe(record, at)
}
func (s *Session) Gap(at time.Time, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.Status == "collecting" && !s.stopping() {
		s.acc.Gap(at, reason)
	}
}
func (s *Session) stopping() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}
func (s *Session) Snapshot() ruleobserve.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := time.Now()
	if !s.meta.FinishedAt.IsZero() {
		at = s.meta.FinishedAt
	}
	v := s.acc.Snapshot(at)
	v.Mode, v.Status, v.TargetIdentity = s.meta.Mode, s.meta.Status, s.meta.TargetIdentity
	v.GuardID, v.FallbackPolicy, v.PreviousSelection, v.FinishedAt = s.meta.GuardID, s.meta.FallbackPolicy, s.meta.PreviousSelection, s.meta.FinishedAt
	return v
}

// Save serializes checkpoints. A failure ends collection and releases DIRECT
// immediately, without waiting for another timer tick or disk write.
func (s *Session) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	v := s.Snapshot()
	if v.UpdatedAt.Before(s.lastSaved) {
		return nil
	}
	_, err := ruleobserve.Save(s.stateDir, v)
	if err == nil {
		s.lastSaved = v.UpdatedAt
	} else {
		s.addError(err)
		s.RequestStop()
	}
	return err
}
func (s *Session) addError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.err = errors.Join(s.err, err)
	s.mu.Unlock()
}
func (s *Session) ID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.ID
}
func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Deadline() time.Time   { return s.deadline }

// RequestStop is nonblocking; restoration is independent of the caller.
func (s *Session) RequestStop() {
	s.once.Do(func() { close(s.stop) })
	s.mu.Lock()
	guard := s.guard
	s.mu.Unlock()
	if guard != nil {
		guard.RequestStop()
	}
}
func (s *Session) Stop(ctx context.Context) (ruleobserve.Snapshot, error) {
	s.RequestStop()
	select {
	case <-s.done:
		s.mu.Lock()
		err := s.err
		s.mu.Unlock()
		return s.Snapshot(), err
	case <-ctx.Done():
		return s.Snapshot(), ctx.Err()
	}
}
func (s *Session) finish() {
	s.RequestStop() // End the helper lease before any disk I/O.
	s.mu.Lock()
	if s.meta.FinishedAt.IsZero() {
		s.meta.FinishedAt = time.Now()
	}
	s.meta.Status = "stopping"
	if s.guard != nil {
		s.meta.Status = "restoring"
	}
	s.mu.Unlock()
	_ = s.Save()
	phase := "completed"
	if s.guard != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
		status, err := s.guard.Stop(ctx)
		cancel()
		s.addError(err)
		if !status.Restored {
			phase = status.Phase
			if phase == "" || phase == "preparing" || phase == "armed" || phase == "active" || phase == "restoring" {
				phase = "recovery_pending"
			}
		}
	}
	s.mu.Lock()
	if phase == "completed" && s.err != nil {
		phase = "failed"
	}
	s.meta.Status = phase
	s.mu.Unlock()
	if err := s.Save(); err != nil {
		s.mu.Lock()
		if s.meta.Status == "completed" {
			s.meta.Status = "failed"
		}
		s.mu.Unlock()
	}
	close(s.done)
}
