package connection

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// VerifyFreshSSH verifies a new authenticated SSH transport after a remote
// routing change. A channel on an existing ControlMaster is not this evidence.
func VerifyFreshSSH(ctx context.Context, host string) error {
	if host == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd, err := freshSSHCommand(ctx, host, false)
	if err != nil {
		return err
	}
	var diagnostic limitedBuffer
	diagnostic.limit = 8192
	cmd.Stdout = io.Discard
	cmd.Stderr = &diagnostic
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if needsAuthentication(diagnostic.String()) {
			return &AuthRequiredError{Host: host}
		}
		return errors.New("a new SSH management connection could not be verified; network rollback remains armed")
	}
	return nil
}

// FreshSSHAuthenticationCommand is an explicit native terminal handoff. It
// establishes the same independent transport as VerifyFreshSSH without saving
// a password or creating/closing any shared authentication session.
func FreshSSHAuthenticationCommand(ctx context.Context, host string) (*exec.Cmd, error) {
	return freshSSHCommand(ctx, host, true)
}
func freshSSHCommand(ctx context.Context, host string, interactive bool) (*exec.Cmd, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	batch := "yes"
	if interactive {
		batch = "no"
	}
	args := []string{"-o", "BatchMode=" + batch, "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2", "-T", "--", host, "true"}
	cmd := commandContext(ctx, "ssh", args...)
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}
