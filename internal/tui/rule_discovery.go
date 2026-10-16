package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
	"github.com/daviddwlee84/lazyclash/internal/rulediscovery"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
)

type observationSession interface {
	Observe(core.Object, time.Time)
	Gap(time.Time, string)
	Snapshot() ruleobserve.Snapshot
	RequestStop()
	Stop(context.Context) (ruleobserve.Snapshot, error)
	Done() <-chan struct{}
}
type discoveryUI struct {
	target              config.Target
	session             observationSession
	cancel              context.CancelFunc
	startDone           chan struct{}
	startResult         discoveryStartResult
	stopping, quitAfter bool
	afterTarget         *config.Target
}
type discoveryStartResult struct {
	session *rulediscovery.Session
	err     error
}
type discoveryPreviewMsg struct {
	generation uint64
	duration   time.Duration
	plan       discoveryguard.Plan
	err        error
}
type discoveryStartedMsg struct{ state *discoveryUI }
type discoveryFinishedMsg struct {
	state    *discoveryUI
	snapshot ruleobserve.Snapshot
	err      error
}
type discoveryPendingMsg struct {
	statuses []discoveryguard.Status
	err      error
}

func observationKeys(p page, key string) []string {
	if p == rules || p == logs {
		return []string{key}
	}
	return nil
}
func (m *Model) observed() *ruleobserve.Accumulator {
	s := m.state()
	identity := rulediscovery.TargetIdentity(m.target)
	if s.observed == nil || s.observedIdentity != identity {
		s.observed = ruleobserve.New(m.target.ID, time.Now())
		s.observedIdentity = identity
	}
	return s.observed
}
func (m *Model) observeLog(record core.Object) {
	now := time.Now()
	m.observed().Observe(record, now)
	if d := m.discovery; d != nil && d.session != nil && d.target.ID == m.target.ID {
		d.session.Observe(record, now)
	}
}
func (m *Model) observationGap(reason string) {
	if m.state().observed != nil {
		m.state().observed.Gap(time.Now(), reason)
	}
	if d := m.discovery; d != nil && d.session != nil {
		d.session.Gap(time.Now(), reason)
	}
}
func (m *Model) reviewObservation(s ruleobserve.Snapshot) tea.Cmd {
	if m.options.RuleReview == nil {
		return nil
	}
	if m.review != nil {
		m.review.close()
	}
	if s.TargetIdentity == "" {
		s.TargetIdentity = rulediscovery.TargetIdentity(m.target)
	}
	opts := m.options.RuleReview(m.ctx, m.target, s)
	if m.discovery != nil {
		opts.BlockedReason = "Discovery is still running or restoring. Stop it before previewing or applying rules."
	}
	m.review = newRuleReview(m.ctx, opts, true)
	m.review.width, m.review.height = m.width, m.height
	m.overlay = ""
	return m.review.Init()
}
func (m *Model) startObservedReview() tea.Cmd {
	s := m.observed().Snapshot(time.Now())
	s.TargetIdentity = m.state().observedIdentity
	s.Mode = "normal"
	if d := m.discovery; d != nil && d.session != nil {
		s = d.session.Snapshot()
	}
	return m.reviewObservation(s)
}
func (m *Model) startDiscoveryForm() tea.Cmd {
	return m.startForm("discovery-duration", "Temporarily observe fallback via DIRECT", "", []field{{"Duration (e.g. 30m, maximum 24h)", "30m"}})
}
func (m *Model) previewDiscovery(value string) tea.Cmd {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || duration <= 0 || duration > 24*time.Hour {
		m.status = "Duration must be positive and at most 24h"
		return nil
	}
	if m.options.ReadOnly || m.target.Transient || m.target.TransportOverride || m.discovery != nil {
		return nil
	}
	m.form = nil
	m.overlay = ""
	m.input.Blur()
	m.pending = "Inspecting fallback and restoration prerequisites…"
	ctx, target, generation := m.ctx, m.target, m.generation
	return func() tea.Msg {
		plan, err := discoveryguard.Preview(ctx, target)
		return discoveryPreviewMsg{generation, duration, plan, err}
	}
}
func (m *Model) receiveDiscoveryPreview(msg discoveryPreviewMsg) tea.Cmd {
	if msg.generation != m.generation {
		return nil
	}
	m.pending = ""
	if msg.err != nil {
		m.status = safeError(msg.err)
		return nil
	}
	body := fmt.Sprintf("Target: %s\nFallback: %s\nSelection: %s → DIRECT\nDuration: %s\nAn independent helper attempts restoration on timeout, stop or parent exit.", core.Sanitize(m.target.ID), core.Sanitize(msg.plan.FallbackPolicy), core.Sanitize(msg.plan.Previous), msg.duration)
	if len(msg.plan.Warnings) > 0 {
		body += "\n" + strings.Join(msg.plan.Warnings, "\n")
	}
	m.ask("Start DIRECT discovery", body, func() tea.Cmd { return m.activateDiscovery(msg.plan, msg.duration) })
	m.confirm.defaultNegative = true
	return nil
}
func (m *Model) activateDiscovery(plan discoveryguard.Plan, duration time.Duration) tea.Cmd {
	if m.discovery != nil || m.options.ReadOnly {
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	d := &discoveryUI{target: m.target, cancel: cancel, startDone: make(chan struct{})}
	m.discovery = d
	m.overlay = ""
	m.status = "Starting independent restoration helper…"
	opts := rulediscovery.Options{SettingsPath: m.options.DiscoverySettings, Duration: duration, Direct: true, Plan: plan}
	return func() tea.Msg {
		d.startResult.session, d.startResult.err = rulediscovery.Start(ctx, d.target, opts)
		close(d.startDone)
		return discoveryStartedMsg{d}
	}
}
func (m *Model) receiveDiscoveryStarted(msg discoveryStartedMsg) tea.Cmd {
	d := msg.state
	if m.discovery != d {
		if d.startResult.session != nil {
			d.startResult.session.RequestStop()
		}
		return nil
	}
	if d.startResult.err != nil && d.startResult.session == nil {
		d.cancel()
		m.discovery = nil
		m.status = "Discovery failed: " + safeError(d.startResult.err)
		if d.quitAfter {
			return tea.Quit
		}
		if d.afterTarget != nil {
			return m.connect(*d.afterTarget)
		}
		return m.checkPendingDiscovery()
	}
	d.session = d.startResult.session
	if d.startResult.err != nil {
		d.stopping = true
	}
	if d.stopping {
		d.session.RequestStop()
	}
	m.status = "DIRECT discovery running · D stops and restores · R reviews observations"
	if d.stopping {
		m.status = "Discovery stopping; waiting for restoration before returning…"
	}
	return func() tea.Msg {
		<-d.session.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s, err := d.session.Stop(ctx)
		return discoveryFinishedMsg{d, s, err}
	}
}
func (m *Model) stopDiscovery() tea.Cmd {
	if d := m.discovery; d != nil {
		d.stopping = true
		if d.session != nil {
			d.session.RequestStop()
		} else {
			d.cancel()
		}
		m.status = "Stopping observation and restoring the original selection…"
	}
	return nil
}
func (m *Model) receiveDiscoveryFinished(msg discoveryFinishedMsg) tea.Cmd {
	if m.discovery != msg.state {
		return nil
	}
	d := m.discovery
	d.cancel()
	m.discovery = nil
	m.status = "Observation saved: " + msg.snapshot.ID + " · " + msg.snapshot.Status
	if msg.err != nil {
		m.status += " · " + safeError(msg.err)
	}
	if d.quitAfter {
		return tea.Quit
	}
	if d.afterTarget != nil {
		return m.connect(*d.afterTarget)
	}
	if m.review != nil && m.review.opts.Snapshot.ID == msg.snapshot.ID {
		// Ending collection must not discard choices being edited in review.
		// Keep that frozen evidence window; only unblock the reviewed operation
		// after the service's fresh recovery checks allow it.
		frozen := m.review.opts.Snapshot
		frozen.Status, frozen.FinishedAt = msg.snapshot.Status, msg.snapshot.FinishedAt
		m.review.opts = m.options.RuleReview(m.ctx, m.target, frozen)
		m.review.notice = "Observation saved · " + msg.snapshot.Status + ". Existing choices retained."
		return m.refresh(true)
	}
	return tea.Batch(m.refresh(true), m.reviewObservation(msg.snapshot))
}
func (m *Model) closeDiscovery() error {
	d := m.discovery
	if d == nil {
		return nil
	}
	d.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 135*time.Second)
	defer cancel()
	if d.session == nil && d.startDone != nil {
		select {
		case <-d.startDone:
			if d.startResult.session != nil {
				d.session = d.startResult.session
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if d.session != nil {
		_, err := d.session.Stop(ctx)
		return err
	}
	return d.startResult.err
}
func (m *Model) checkPendingDiscovery() tea.Cmd {
	path := m.options.DiscoverySettings
	if path == "" {
		return nil
	}
	return func() tea.Msg { statuses, err := discoveryguard.List(path); return discoveryPendingMsg{statuses, err} }
}
