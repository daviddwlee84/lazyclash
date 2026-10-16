package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/discoveryguard"
	"github.com/daviddwlee84/lazyclash/internal/ruleobserve"
)

func observationLog() core.Object {
	return core.Object{"type": "warning", "payload": "[TCP] dial FINAL (match Match/) 127.0.0.1:12345 --> missing.example:443 error: i/o timeout"}
}

func TestDashboardObservationsContinueAcrossPagesAndReview(t *testing.T) {
	m := testModel(t)
	m.options.RuleReview = func(_ context.Context, _ config.Target, s ruleobserve.Snapshot) RuleReviewOptions {
		return RuleReviewOptions{Snapshot: s}
	}
	for _, p := range []page{rules, logs, overview} {
		m.page = p
		m.Update(streamMsg{generation: m.generation, resource: "logs", data: observationLog()})
	}
	if s := m.observed().Snapshot(time.Now()); s.Observed != 3 || len(s.Groups) != 1 {
		t.Fatalf("observations not accumulated: %+v", s)
	}
	m.page = rules
	sendKey(m, "R")
	if m.review == nil {
		t.Fatal("review action unavailable")
	}
	m.Update(streamMsg{generation: m.generation, resource: "logs", data: observationLog()})
	if m.observed().Snapshot(time.Now()).Observed != 4 {
		t.Fatal("review stopped collection")
	}
	if m.review.opts.Snapshot.Observed != 3 {
		t.Fatal("review mutated its frozen evidence")
	}
	sendKey(m, "/")
	sendKey(m, "q")
	sendKey(m, "j")
	if m.review == nil || m.review.input.Value() != "qj" {
		t.Fatal("typing escaped nested review")
	}
	m.Update(tea.PasteMsg{Content: "/k"})
	if m.review.input.Value() != "qj/k" {
		t.Fatal("paste did not reach nested review")
	}
	sendKey(m, "esc")
	sendKey(m, "esc")
	if m.review != nil {
		t.Fatal("review did not return to dashboard")
	}
}

func TestDashboardObservationTargetIsolationAndStaleEvents(t *testing.T) {
	m := testModel(t)
	m.Update(streamMsg{generation: m.generation, resource: "logs", data: observationLog()})
	oldTarget, oldGeneration := m.target, m.generation
	m.connect(config.Target{ID: "second", Controller: "http://127.0.0.1:1"})
	m.Update(streamMsg{generation: oldGeneration, resource: "logs", data: observationLog()})
	if m.observed().Snapshot(time.Now()).Observed != 0 {
		t.Fatal("stale target event was collected")
	}
	m.Update(streamMsg{generation: m.generation, resource: "logs", data: observationLog()})
	if m.observed().Snapshot(time.Now()).Observed != 1 {
		t.Fatal("target counters were mixed")
	}
	old := m.states[oldTarget.ID].observed.Snapshot(time.Now())
	if old.Observed != 1 || old.Gaps == 0 {
		t.Fatal("old target missing its observation boundary")
	}
	m.Update(streamMsg{generation: m.generation, resource: "logs", err: errors.New("offline")})
	if m.observed().Snapshot(time.Now()).Gaps == 0 {
		t.Fatal("disconnect missing from evidence")
	}
}

type fakeObservationSession struct {
	acc  *ruleobserve.Accumulator
	stop bool
	done chan struct{}
}

func (f *fakeObservationSession) Observe(r core.Object, at time.Time) { f.acc.Observe(r, at) }
func (f *fakeObservationSession) Gap(at time.Time, reason string)     { f.acc.Gap(at, reason) }
func (f *fakeObservationSession) Snapshot() ruleobserve.Snapshot      { return f.acc.Snapshot(time.Now()) }
func (f *fakeObservationSession) RequestStop()                        { f.stop = true }
func (f *fakeObservationSession) Stop(context.Context) (ruleobserve.Snapshot, error) {
	f.stop = true
	return f.Snapshot(), nil
}
func (f *fakeObservationSession) Done() <-chan struct{} { return f.done }

func TestDashboardDiscoveryStopsBeforeTargetSwitchAndBlocksWrites(t *testing.T) {
	m := testModel(t)
	f := &fakeObservationSession{acc: ruleobserve.New(m.target.ID, time.Now()), done: make(chan struct{})}
	d := &discoveryUI{target: m.target, session: f, cancel: func() {}}
	m.discovery = d
	m.options.Workbench = func(context.Context, WorkRequest) (WorkResult, error) {
		t.Fatal("write during discovery")
		return WorkResult{}, nil
	}
	if m.launchWork(WorkRequest{Kind: "quick-rule-apply"}) != nil {
		t.Fatal("batch was allowed before restore")
	}
	m.Update(streamMsg{generation: m.generation, resource: "logs", data: observationLog()})
	if f.Snapshot().Observed != 1 {
		t.Fatal("active session did not receive logs")
	}
	next := config.Target{ID: "other", Controller: "http://127.0.0.1:1"}
	if m.connect(next) != nil || !f.stop || m.target.ID == next.ID || d.afterTarget == nil {
		t.Fatal("target switched before restoration")
	}
	m.receiveDiscoveryFinished(discoveryFinishedMsg{state: d, snapshot: f.Snapshot()})
	if m.discovery != nil || m.target.ID != next.ID {
		t.Fatal("target switch did not resume after restoration")
	}
}

func TestDashboardDiscoveryQuitAndDisconnectRequestRestore(t *testing.T) {
	for _, event := range []string{"quit", "disconnect"} {
		t.Run(event, func(t *testing.T) {
			m := testModel(t)
			f := &fakeObservationSession{acc: ruleobserve.New(m.target.ID, time.Now()), done: make(chan struct{})}
			m.discovery = &discoveryUI{target: m.target, session: f, cancel: func() {}}
			if event == "quit" {
				if sendKey(m, "q") != nil {
					t.Fatal("quit occurred before restore")
				}
				if !m.discovery.quitAfter {
					t.Fatal("quit intent lost")
				}
			} else {
				m.Update(streamMsg{generation: m.generation, resource: "logs", err: errors.New("offline")})
			}
			if !f.stop || !m.discovery.stopping {
				t.Fatal("restoration not requested")
			}
		})
	}
}

func TestDashboardDiscoveryDurationAndReadOnlyActions(t *testing.T) {
	m := testModel(t)
	m.page = rules
	m.options.DiscoverySettings = "/fixture/settings.toml"
	m.startDiscoveryForm()
	m.input.SetValue("0")
	m.form.fields[0].value = "0"
	m.previewDiscovery("0")
	if m.discovery != nil || !strings.Contains(m.status, "positive") {
		t.Fatal("invalid duration accepted")
	}
	m.options.ReadOnly = true
	for _, a := range m.actions() {
		if a.id == "observe-discovery" && a.enabled {
			t.Fatal("read-only DIRECT action enabled")
		}
	}
}

func TestDiscoveryCompletionRetainsOpenReviewChoices(t *testing.T) {
	m := testModel(t)
	m.options.RuleReview = func(_ context.Context, _ config.Target, s ruleobserve.Snapshot) RuleReviewOptions {
		return RuleReviewOptions{Snapshot: s}
	}
	f := &fakeObservationSession{acc: ruleobserve.New(m.target.ID, time.Now()), done: make(chan struct{})}
	f.Observe(observationLog(), time.Now())
	d := &discoveryUI{target: m.target, session: f, cancel: func() {}}
	m.discovery = d
	m.startObservedReview()
	review := m.review
	group := review.opts.Snapshot.Groups[0]
	draft := review.drafts[group.Key]
	draft.checked = true
	draft.policy = "Proxy"
	review.drafts[group.Key] = draft
	review.inputMode = "policy"
	review.input.SetValue("unfinished")
	snapshot := f.Snapshot()
	snapshot.Status = "completed"
	snapshot.FinishedAt = time.Now()
	m.receiveDiscoveryFinished(discoveryFinishedMsg{state: d, snapshot: snapshot})
	if m.review != review || !review.drafts[group.Key].checked || review.drafts[group.Key].policy != "Proxy" || review.input.Value() != "unfinished" {
		t.Fatal("finishing collection discarded an open review draft")
	}
	if review.opts.BlockedReason != "" {
		t.Fatal("finished discovery left stale active-session block")
	}
}

func TestPendingRestorationNoticeSurvivesOrdinaryStatusUpdates(t *testing.T) {
	m := testModel(t)
	m.Update(discoveryPendingMsg{statuses: []discoveryguard.Status{{ID: "pending-recovery", Phase: "recovery_pending"}}})
	m.status = "Connected"
	if !strings.Contains(m.View().Content, "Pending discovery restoration") {
		t.Fatal("ordinary refresh hid pending restoration")
	}
	m.Update(discoveryPendingMsg{})
	if m.discoveryRecoveryNotice != "" {
		t.Fatal("resolved recovery notice was retained")
	}
}

func TestNormalObservationsResetWhenSavedTargetIsRebound(t *testing.T) {
	m := testModel(t)
	m.Update(streamMsg{generation: m.generation, resource: "logs", data: observationLog()})
	oldID := m.observed().Snapshot(time.Now()).ID
	rebound := m.target
	rebound.Controller = "http://127.0.0.1:2"
	m.connect(rebound)
	s := m.observed().Snapshot(time.Now())
	if s.Observed != 0 || s.ID == oldID {
		t.Fatal("old controller observations survived target rebinding")
	}
}

func TestDiscoveryProtectsSavedTargetBeforePersistence(t *testing.T) {
	m := testModel(t)
	f := &fakeObservationSession{acc: ruleobserve.New(m.target.ID, time.Now()), done: make(chan struct{})}
	m.discovery = &discoveryUI{target: m.target, session: f, cancel: func() {}}
	m.options.SaveTargets = func(config.Config) error { t.Fatal("changed recovery binding was saved"); return nil }
	for _, id := range []string{"target-edit", "target-remove"} {
		m.runAction(id)
		if m.overlay != "" {
			t.Fatal("active recovery binding editor opened")
		}
	}
	changed := cloneSettings(m.settings)
	changed.Targets[0].Controller = "http://127.0.0.1:2"
	if m.save(changed, m.target.ID) != nil {
		t.Fatal("connection edit allowed during discovery")
	}
	removed := cloneSettings(m.settings)
	removed.Targets = nil
	if m.save(removed, "") != nil {
		t.Fatal("target removal allowed during discovery")
	}
}
