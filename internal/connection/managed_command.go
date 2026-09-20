package connection

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ManagedPrivilegedCommand executes the reviewed operation itself under native
// sudo, in the same terminal as its prompt. JSON lives in a private staged file;
// neither sudo -S nor application password collection is used.
func ManagedPrivilegedCommand(ctx context.Context, host, script, path, digest string) (*exec.Cmd, error) {
	return managedPrivilegedCommand(ctx, host, script, path, digest, true)
}

func ManagedPrivilegedBatchCommand(ctx context.Context, host, script, path, digest string) (*exec.Cmd, error) {
	return managedPrivilegedCommand(ctx, host, script, path, digest, false)
}

func managedPrivilegedCommand(ctx context.Context, host, script, path, digest string, interactive bool) (*exec.Cmd, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(digest) {
		return nil, errors.New("invalid privileged managed request reference")
	}
	if host == "" {
		python := "/usr/bin/python3"
		if info, err := os.Stat(python); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return nil, ErrPythonUnavailable
		}
		if os.Geteuid() == 0 {
			return exec.CommandContext(ctx, python, "-I", "-c", script, path, digest), nil
		}
		args := []string{"--", python, "-I", "-c", script, path, digest}
		if !interactive {
			args = append([]string{"-n"}, args...)
		}
		return exec.CommandContext(ctx, "/usr/bin/sudo", args...), nil
	}
	if err := validateHost(host); err != nil {
		return nil, err
	}
	args, err := sshArgsContext(ctx, host)
	if err != nil {
		return nil, err
	}
	for i := range args {
		if interactive && args[i] == "BatchMode=yes" {
			args[i] = "BatchMode=no"
		}
	}
	sudo := "/usr/bin/sudo --"
	tty := "-tt"
	if !interactive {
		sudo = "/usr/bin/sudo -n --"
		tty = "-T"
	}
	command := sudo + " /usr/bin/python3 -I -c " + shellQuote(script) + " " + shellQuote(path) + " " + shellQuote(digest)
	return commandContext(ctx, "ssh", append(args, tty, "--", host, command)...), nil
}
