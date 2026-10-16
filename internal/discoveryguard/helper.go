package discoveryguard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// HandleHelper is dispatched before normal CLI or terminal initialization.
func HandleHelper() (int, bool) {
	if len(os.Args) < 2 || os.Args[1] != helperArgument {
		return 0, false
	}
	if len(os.Args) != 2 {
		return 2, true
	}
	if err := supported(); err != nil {
		return 2, true
	}
	protectHelper()
	return runHelper(os.Stdin, os.Stdout), true
}

func runHelper(input io.Reader, output io.Writer) int {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	var r request
	if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &r) != nil || !validID(r.ID) || !filepath.IsAbs(r.SettingsPath) {
		return 2
	}
	emit := func(s Status) { _ = json.NewEncoder(output).Encode(s) }
	fail := func(message string) int {
		emit(Status{ID: r.ID, TargetID: r.Plan.TargetID, Phase: "failed", UpdatedAt: time.Now(), Message: core.Sanitize(message)})
		return 1
	}
	if err := helperIndependent(); err != nil {
		return fail(err.Error())
	}
	root, err := stateRoot(true)
	if err != nil {
		return fail(err.Error())
	}
	if r.Mode == "recover" {
		j, err := readJournal(root, r.ID)
		if err != nil {
			return fail(err.Error())
		}
		if j.SettingsPath != r.SettingsPath {
			return fail("recovery journal belongs to a different settings file")
		}
		lock, err := takeLock(root, j.Plan.ControllerKey)
		if err != nil {
			return fail(err.Error())
		}
		defer lock.Close()
		j, err = readJournal(root, r.ID)
		if err != nil {
			return fail(err.Error())
		}
		if !j.Status.Pending() {
			emit(j.Status)
			if j.Status.Restored {
				return 0
			}
			return 1
		}
		return restore(root, &j, emit, nil)
	}
	if r.Mode != "start" || time.Until(r.Deadline) <= 0 || time.Until(r.Deadline) > 24*time.Hour {
		return fail("invalid or expired discovery request")
	}
	pulses := make(chan struct{}, 1)
	eof := make(chan struct{})
	go func() {
		defer close(eof)
		for scanner.Scan() {
			if scanner.Text() != "heartbeat" {
				return
			}
			select {
			case pulses <- struct{}{}:
			default:
			}
		}
	}()
	leaseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchLease(leaseCtx, cancel, pulses, eof, r.Deadline, leaseDuration)
	startupCtx, cancelStartup := context.WithTimeout(leaseCtx, 40*time.Second)
	defer cancelStartup()
	target, err := loadTarget(r.SettingsPath, r.Plan.TargetID)
	if err != nil {
		return fail(err.Error())
	}
	if bindingDigest(target) != r.Plan.BindingDigest {
		return fail("saved target changed since the discovery preview")
	}
	lock, err := takeLock(root, controllerKey(target))
	if err != nil {
		return fail(err.Error())
	}
	defer lock.Close()
	older, err := journals(root)
	if err != nil {
		return fail(err.Error())
	}
	for _, old := range older {
		if old.Plan.ControllerKey == controllerKey(target) && old.Status.Pending() {
			return fail("an earlier discovery journal needs recovery before starting another DIRECT session: " + old.Status.ID)
		}
	}
	// This opener runs inside the detached process. A foreground-only private
	// SSH authentication session cannot accidentally authorize this preflight.
	transportCtx, cancelTransport := context.WithCancel(context.Background())
	defer cancelTransport()
	startupDone := make(chan struct{})
	var startupOnce sync.Once
	finishStartup := func() { startupOnce.Do(func() { close(startupDone) }) }
	defer finishStartup()
	go func() {
		select {
		case <-startupDone:
		case <-startupCtx.Done():
			select {
			case <-startupDone:
				// Activation completed before its request context was released.
			default:
				cancelTransport()
			}
		}
	}()
	c, closer, err := connection.Open(transportCtx, target, false)
	if err != nil {
		return fail(err.Error())
	}
	defer closer.Close()
	actual, err := inspect(startupCtx, c, target)
	if err != nil {
		return fail(err.Error())
	}
	if actual.Digest != r.Plan.Digest || startupCtx.Err() != nil {
		return fail("runtime fallback changed or collection ended since the discovery preview")
	}
	j := journal{Version: 1, SettingsPath: r.SettingsPath, Plan: actual, Status: Status{ID: r.ID, TargetID: actual.TargetID, Group: actual.Group, Previous: actual.Previous, Deadline: r.Deadline}}
	if err := transition(root, &j, "preparing", "", emit); err != nil {
		return fail("cannot persist private recovery journal; no fallback change was made")
	}
	// Arm durable recovery before any controller write, including one whose
	// response could be lost. An original DIRECT selection never needs a write.
	j.NeedRestore = !actual.AlreadyDirect
	if err := transition(root, &j, "armed", "", emit); err != nil {
		return fail("cannot arm private recovery journal; no fallback change was made")
	}
	// Recheck after journal preparation, as it can involve filesystem latency.
	freshTarget, err := loadTarget(r.SettingsPath, actual.TargetID)
	if err == nil && bindingDigest(freshTarget) != actual.BindingDigest {
		err = errors.New("saved target changed before activation")
	}
	var fresh Plan
	if err == nil {
		fresh, err = inspect(startupCtx, c, target)
	}
	if err == nil && fresh.Digest != actual.Digest {
		err = errors.New("runtime fallback changed before activation")
	}
	if err == nil {
		err = startupCtx.Err()
	}
	if err != nil {
		j.NeedRestore = false // No selection write was attempted.
		_ = transition(root, &j, "failed", "discovery activation canceled or preview became stale; no fallback change was made", emit)
		return 1
	}
	if j.NeedRestore {
		if err := c.Select(startupCtx, actual.Group, "DIRECT"); err != nil {
			finishStartup()
			return restore(root, &j, emit, c)
		}
	}
	if err := transition(root, &j, "active", "", emit); err != nil {
		finishStartup()
		return restore(root, &j, emit, c)
	}
	finishStartup()
	cancelStartup()
	<-leaseCtx.Done()
	return restore(root, &j, emit, c)
}

func watchLease(ctx context.Context, cancel context.CancelFunc, pulses <-chan struct{}, eof <-chan struct{}, deadline time.Time, lease time.Duration) {
	timer := time.NewTimer(lease)
	defer timer.Stop()
	deadlineTimer := time.NewTimer(time.Until(deadline))
	defer deadlineTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-eof:
			cancel()
			return
		case <-deadlineTimer.C:
			cancel()
			return
		case <-timer.C:
			cancel()
			return
		case <-pulses:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(lease)
		}
	}
}

func transition(root string, j *journal, phase, message string, emit func(Status)) error {
	j.Status.Phase, j.Status.Message, j.Status.UpdatedAt = phase, core.Sanitize(message), time.Now()
	j.Status.Restored = phase == "restored"
	err := saveJournal(root, *j)
	if err == nil {
		emit(j.Status)
	}
	return err
}

func restore(root string, j *journal, emit func(Status), retained *core.Client) int {
	// Restoration never inherits a canceled parent, lease or activation context.
	ctx, cancel := context.WithTimeout(context.Background(), recoveryDuration)
	defer cancel()
	_ = transition(root, j, "restoring", "", emit)
	if !j.NeedRestore {
		if transition(root, j, "restored", "original fallback was already DIRECT; no selection write was needed", emit) != nil {
			emit(Status{ID: j.Status.ID, TargetID: j.Status.TargetID, Phase: "recovery_pending", Message: "fallback unchanged, but recovery journal could not be saved"})
			return 1
		}
		return 0
	}
	for {
		attempt, stop := context.WithTimeout(ctx, 20*time.Second)
		phase, message := restoreAttempt(attempt, *j, retained)
		stop()
		// An unavailable retained transport may have lost its SSH forward.
		// Retries independently resolve the same saved credential references.
		retained = nil
		if phase == "restored" || phase == "conflict" {
			if phase == "restored" {
				j.NeedRestore = false
			}
			if err := transition(root, j, phase, message, emit); err != nil {
				emit(Status{ID: j.Status.ID, TargetID: j.Status.TargetID, Phase: "recovery_pending", Message: "recovery result could not be saved; inspect the controller and recover again"})
				return 1
			}
			if phase == "restored" {
				return 0
			}
			return 1
		}
		select {
		case <-ctx.Done():
			message = "controller could not be safely restored within two minutes; retry explicit recovery"
			if transition(root, j, "recovery_pending", message, emit) != nil {
				j.Status.Phase, j.Status.Message = "recovery_pending", message
				emit(j.Status)
			}
			return 1
		case <-time.After(2 * time.Second):
		}
	}
}

// A retry can observe the original member after an uncertain write; that is
// completion. Visible external changes are conflicts and are never overwritten.
func restoreAttempt(ctx context.Context, j journal, retained *core.Client) (string, string) {
	target, err := loadTarget(j.SettingsPath, j.Plan.TargetID)
	if err != nil {
		return "recovery_pending", "saved target could not be read"
	}
	if bindingDigest(target) != j.Plan.BindingDigest {
		return "conflict", "saved controller or credential references changed; no restoration write was made"
	}
	c := retained
	if c == nil {
		opened, closer, err := connection.Open(ctx, target, false)
		if err != nil {
			return "recovery_pending", "independent controller connection is unavailable"
		}
		defer closer.Close()
		c = opened
	}
	current, err := inspect(ctx, c, target)
	if err != nil {
		var controllerErr *core.Error
		if errors.As(err, &controllerErr) || ctx.Err() != nil {
			return "recovery_pending", "controller state is temporarily unavailable"
		}
		return "conflict", "runtime routing mode, fallback or group changed; no restoration write was made"
	}
	if !sameIdentity(j.Plan, current) {
		return "conflict", "runtime rules, core version or fallback group changed; no restoration write was made"
	}
	if current.Previous == j.Plan.Previous {
		return "restored", "original fallback selection verified"
	}
	if current.Previous != "DIRECT" {
		return "conflict", "fallback selection was changed externally; no restoration write was made"
	}
	if err := c.Select(ctx, j.Plan.Group, j.Plan.Previous); err != nil {
		return "recovery_pending", "restoration result requires another read-back"
	}
	return "restored", "original fallback selection restored and verified"
}
