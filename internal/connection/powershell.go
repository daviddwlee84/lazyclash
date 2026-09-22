package connection

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

func encodedPowerShell(script string) string {
	words := utf16.Encode([]rune(script))
	raw := make([]byte, len(words)*2)
	for i, v := range words {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// ExecutePowerShell uses no stdin. Trusted helper code and JSON travel through
// private SFTP files; process arguments contain only bounded RPC metadata.
// The caller's deadline covers preparation, uploads and dispatch. An unknown
// dispatch result is never retried and may retain its private remote staging.
func ExecutePowerShell(ctx context.Context, host, script string, input []byte, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(input) == 0 || len(input) > 256<<20 || len(script) == 0 || len(script) > 1<<20 || limit <= 0 || limit > 48<<20 {
		return nil, errors.New("Windows helper request or result exceeds its limit")
	}
	if !json.Valid(input) {
		return nil, errors.New("Windows helper input must be JSON")
	}
	if host == "" && runtime.GOOS != "windows" {
		return nil, errors.New("local Windows helper requires Windows; select the saved Windows SSH host")
	}
	if host != "" {
		if err := validateHost(host); err != nil {
			return nil, err
		}
	}
	return executePowerShellRPC(ctx, host, script, input, limit)
}

// VerifyFreshWindowsSSH opens an independent authenticated transport after a
// proxy takeover. It bypasses multiplexed sessions and uses no POSIX commands.
func VerifyFreshWindowsSSH(ctx context.Context, host string) error {
	if host == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd, err := freshWindowsSSHCommand(ctx, host)
	if err != nil {
		return err
	}
	var output, diagnostic limitedBuffer
	output.limit = 1024
	diagnostic.limit = 8192
	cmd.Stdout = &output
	cmd.Stderr = &diagnostic
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if needsAuthentication(diagnostic.String()) {
			return &AuthRequiredError{Host: host}
		}
		return errors.New("a new Windows SSH management connection could not be verified; inspect the saved proxy takeover receipt")
	}
	if strings.TrimSpace(output.String()) != "lazyclash-fresh-windows-ssh" {
		return errors.New("new Windows SSH management response was not verified; inspect the saved proxy takeover receipt")
	}
	return nil
}
func freshWindowsSSHCommand(ctx context.Context, host string) (*exec.Cmd, error) {
	if err := validateHost(host); err != nil {
		return nil, err
	}
	remote := "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encodedPowerShell(`[Console]::Out.WriteLine('lazyclash-fresh-windows-ssh')`)
	args := []string{"-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2", "-T", "--", host, remote}
	cmd := commandContext(ctx, "ssh", args...)
	cmd.WaitDelay = 2 * time.Second
	return cmd, nil
}
