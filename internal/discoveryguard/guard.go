package discoveryguard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

const helperArgument = "__lazyclash-discovery-guard"
const heartbeatInterval = 2 * time.Second
const leaseDuration = 15 * time.Second
const recoveryDuration = 2 * time.Minute

type request struct {
	Mode         string    `json:"mode"`
	ID           string    `json:"id"`
	SettingsPath string    `json:"settings_path"`
	Plan         Plan      `json:"plan"`
	Deadline     time.Time `json:"deadline"`
}

// Handle owns only a lease, never the fallback write or restoration itself.
type Handle struct {
	mu        sync.Mutex
	status    Status
	err       error
	input     io.WriteCloser
	done      chan struct{}
	ready     chan struct{}
	stop      chan struct{}
	stopOnce  sync.Once
	readyOnce sync.Once
}

func (h *Handle) ID() string { return h.Status().ID }
func (h *Handle) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}
func (h *Handle) Done() <-chan struct{} { return h.done }

// RequestStop relinquishes the lease without waiting for restoration.
func (h *Handle) RequestStop() { h.endLease() }

func (h *Handle) endLease() {
	h.stopOnce.Do(func() {
		close(h.stop)
		_ = h.input.Close()
	})
}

// Stop requests restoration immediately. Canceling ctx stops waiting only;
// the detached helper retains its independent restoration deadline.
func (h *Handle) Stop(ctx context.Context) (Status, error) {
	h.endLease()
	select {
	case <-h.done:
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.status, h.err
	case <-ctx.Done():
		return h.Status(), ctx.Err()
	}
}

// Start returns after the independently authenticated helper has switched and
// read back the reviewed selection. On a startup failure, a non-nil Handle may
// still identify pending recovery; its helper is never killed by caller cancel.
func Start(ctx context.Context, settingsPath string, target config.Target, expected Plan, duration time.Duration) (*Handle, error) {
	if err := supported(); err != nil {
		return nil, err
	}
	if err := savedShape(target); err != nil {
		return nil, err
	}
	if duration <= 0 || duration > 24*time.Hour {
		return nil, errors.New("DIRECT discovery duration must be greater than zero and at most 24 hours")
	}
	path, err := filepath.Abs(settingsPath)
	if err != nil {
		return nil, err
	}
	saved, err := loadTarget(path, target.ID)
	if err != nil {
		return nil, err
	}
	if bindingDigest(saved) != bindingDigest(target) || expected.BindingDigest != bindingDigest(saved) || expected.TargetID != target.ID {
		return nil, errors.New("DIRECT discovery target differs from its saved settings or reviewed plan")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	h, err := launch(ctx, request{Mode: "start", ID: id, SettingsPath: path, Plan: expected, Deadline: time.Now().Add(duration)})
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	select {
	case <-h.ready:
		return h, nil
	case <-h.done:
		if err := statusError(h.Status()); err != nil {
			return h, err
		}
		return h, fmt.Errorf("discovery guard %s restored safely before activation could complete", id)
	case <-ctx.Done():
		h.endLease()
		return h, fmt.Errorf("discovery startup canceled; recovery journal %s: %w", id, ctx.Err())
	case <-timer.C:
		h.endLease()
		return h, fmt.Errorf("discovery helper startup timed out; inspect recovery journal %s", id)
	}
}

// Recover launches the same independent helper; it refuses a controller still
// locked by a live session and never relies on the caller's SSH transport.
func Recover(ctx context.Context, settingsPath, id string) (Status, error) {
	if err := supported(); err != nil {
		return Status{}, err
	}
	if !validID(id) {
		return Status{}, errors.New("invalid discovery guard ID")
	}
	path, err := filepath.Abs(settingsPath)
	if err != nil {
		return Status{}, err
	}
	h, err := launch(ctx, request{Mode: "recover", ID: id, SettingsPath: path})
	if err != nil {
		return Status{}, err
	}
	select {
	case <-h.done:
		status := h.Status()
		return status, statusError(status)
	case <-ctx.Done():
		h.endLease()
		return h.Status(), ctx.Err()
	}
}

func statusError(s Status) error {
	if s.Restored && s.Phase == "restored" {
		return nil
	}
	message := s.Message
	if message == "" {
		message = "helper did not complete the requested operation"
	}
	return fmt.Errorf("discovery guard %s (%s): %s", s.ID, s.Phase, message)
}

func launch(ctx context.Context, r request) (*Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Deliberately not CommandContext: cancellation must close the lease and
	// leave enough independent process lifetime for rollback.
	cmd := exec.Command(exe, helperArgument)
	detach(cmd)
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	h := &Handle{input: input, done: make(chan struct{}), ready: make(chan struct{}), stop: make(chan struct{}), status: Status{ID: r.ID, TargetID: r.Plan.TargetID, Phase: "preparing", Deadline: r.Deadline}}
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 4096), 128<<10)
		for scanner.Scan() {
			var s Status
			if json.Unmarshal(scanner.Bytes(), &s) != nil || s.ID != r.ID {
				continue
			}
			h.mu.Lock()
			h.status = s
			h.mu.Unlock()
			if s.Phase == "active" {
				h.readyOnce.Do(func() { close(h.ready) })
			}
		}
		waitErr := cmd.Wait()
		h.endLease()
		h.mu.Lock()
		if h.status.Pending() && h.status.Phase != "conflict" && h.status.Phase != "recovery_pending" {
			h.status.Phase = "recovery_pending"
			h.status.Message = "helper exited before restoration was confirmed; run recovery"
		}
		h.err = statusError(h.status)
		if h.err == nil && waitErr != nil {
			h.err = errors.New("recovery completed but helper exit could not be confirmed")
		}
		h.mu.Unlock()
		close(h.done)
	}()
	if err := json.NewEncoder(input).Encode(r); err != nil {
		h.endLease()
		return h, err
	}
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				h.endLease()
				return
			case <-h.stop:
				return
			case <-ticker.C:
				if _, err := io.WriteString(input, "heartbeat\n"); err != nil {
					h.endLease()
					return
				}
			}
		}
	}()
	return h, nil
}
