package connection

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Only these three non-secret fields survive ssh -G. OpenSSH performs Include,
// Match, tilde and token expansion; the application never parses SSH config.
type multiplexPolicy struct{ path, master, persist string }

func (p multiplexPolicy) persistent() bool {
	if p.path == "" || p.master == "" || p.master == "no" || p.persist == "" || p.persist == "no" {
		return false
	}
	return true
}

type policyEntry struct {
	policy  multiplexPolicy
	expires time.Time
	ready   chan struct{}
	err     error
}

var multiplexPolicies = struct {
	sync.Mutex
	entries map[string]*policyEntry
}{entries: map[string]*policyEntry{}}

// The cache is process-local and bounded. Failed/canceled config reads are not
// cached, so fixing SSH config or retrying authentication can recover promptly.
func resolveMultiplexPolicy(ctx context.Context, host string) (multiplexPolicy, error) {
	if err := ctx.Err(); err != nil {
		return multiplexPolicy{}, err
	}
	if err := validateHost(host); err != nil {
		return multiplexPolicy{}, err
	}
	multiplexPolicies.Lock()
	if entry := multiplexPolicies.entries[host]; entry != nil {
		if entry.ready != nil {
			ready := entry.ready
			multiplexPolicies.Unlock()
			select {
			case <-ctx.Done():
				return multiplexPolicy{}, ctx.Err()
			case <-ready:
				return entry.policy, entry.err
			}
		}
		if time.Now().Before(entry.expires) {
			p := entry.policy
			multiplexPolicies.Unlock()
			return p, nil
		}
		delete(multiplexPolicies.entries, host)
	}
	if len(multiplexPolicies.entries) >= 64 {
		oldest := ""
		var at time.Time
		for h, entry := range multiplexPolicies.entries {
			if entry.ready == nil && (oldest == "" || entry.expires.Before(at)) {
				oldest, at = h, entry.expires
			}
		}
		if oldest != "" {
			delete(multiplexPolicies.entries, oldest)
		}
	}
	entry := &policyEntry{ready: make(chan struct{})}
	cached := len(multiplexPolicies.entries) < 64
	if cached {
		multiplexPolicies.entries[host] = entry
	}
	multiplexPolicies.Unlock()
	p, err := readMultiplexPolicy(ctx, host)
	multiplexPolicies.Lock()
	entry.policy, entry.err, entry.expires = p, err, time.Now().Add(time.Minute)
	ready := entry.ready
	entry.ready = nil
	if err != nil && cached && multiplexPolicies.entries[host] == entry {
		delete(multiplexPolicies.entries, host)
	}
	close(ready)
	multiplexPolicies.Unlock()
	return p, err
}

func readMultiplexPolicy(ctx context.Context, host string) (multiplexPolicy, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := commandContext(queryCtx, "ssh", "-G", "-o", "BatchMode=yes", "--", host)
	var output, diagnostic limitedBuffer
	output.limit, diagnostic.limit = 1<<20, 8192
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	configureHelperProcess(cmd)
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if queryCtx.Err() != nil {
			return multiplexPolicy{}, queryCtx.Err()
		}
		if needsAuthentication(diagnostic.String()) {
			return multiplexPolicy{}, &AuthRequiredError{Host: host}
		}
		return multiplexPolicy{}, errors.New("cannot inspect SSH configuration; check this host alias and SSH config")
	}
	return parseMultiplexPolicy(output.String())
}

func parseMultiplexPolicy(output string) (multiplexPolicy, error) {
	p := multiplexPolicy{master: "no", persist: "no"}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), " ")
		if !ok {
			continue
		}
		switch key {
		case "controlpath":
			if value == "none" || value == "" {
				continue
			}
			if len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.Contains(value, "${") {
				return p, errors.New("SSH ControlPath could not be resolved safely")
			}
			path, err := filepath.Abs(value)
			if err != nil {
				return p, errors.New("SSH ControlPath must resolve to a local path")
			}
			p.path = path
		case "controlmaster":
			p.master = strings.TrimSpace(value)
		case "controlpersist":
			p.persist = strings.TrimSpace(value)
		}
	}
	if p.master == "false" {
		p.master = "no"
	}
	if p.master == "true" {
		p.master = "yes"
	}
	if p.persist == "false" {
		p.persist = "no"
	}
	if p.persist == "true" {
		p.persist = "yes"
	}
	switch p.master {
	case "no", "yes", "auto", "ask", "autoask":
	default:
		return p, errors.New("unsupported SSH ControlMaster policy")
	}
	if p.persist != "no" && p.persist != "yes" {
		if _, err := strconv.ParseUint(p.persist, 10, 64); err != nil {
			return p, errors.New("unsupported SSH ControlPersist policy")
		}
	}
	return p, nil
}

// ssh expands percent tokens even for -S. Escape the already expanded -G path
// so later forwarding/cancel requests address the exact same socket.
func controlSocketArgument(path string) string { return strings.ReplaceAll(path, "%", "%%") }

func masterControlArgs(path, operation string) []string {
	// The socket already identifies an authenticated connection. Reading the
	// user's config here could add or cancel unrelated LocalForward entries.
	return []string{"-F", os.DevNull, "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-S", controlSocketArgument(path), "-O", operation}
}

func configuredMasterAlive(ctx context.Context, host, path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := commandContext(checkCtx, "ssh", append(masterControlArgs(path, "check"), "--", host)...)
	var output limitedBuffer
	output.limit = 8192
	cmd.Stdout, cmd.Stderr = &output, &output
	configureHelperProcess(cmd)
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// -O check never authenticates or falls back to a network connection.
		// Missing, expired or unresponsive sockets are not reusable masters.
		return false, nil
	}
	return true, nil
}

func clearMultiplexPolicies() {
	multiplexPolicies.Lock()
	multiplexPolicies.entries = map[string]*policyEntry{}
	multiplexPolicies.Unlock()
}
