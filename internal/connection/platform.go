package connection

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"
)

// DetectHostOS only runs fixed, read-only platform commands through the same
// OpenSSH identity and host-key policy used for the target's normal connection.
func DetectHostOS(ctx context.Context, host string) (string, error) {
	if host == "" {
		return runtime.GOOS, nil
	}
	if err := validateHost(host); err != nil {
		return "", err
	}
	for _, command := range []string{"uname -s", "cmd.exe /c ver"} {
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		args, err := sshArgsContext(probeCtx, host)
		if err != nil {
			cancel()
			return "", err
		}
		cmd := commandContext(probeCtx, "ssh", append(args, "-T", "--", host, command)...)
		var stdout, stderr limitedBuffer
		stdout.limit, stderr.limit = 2048, 8192
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		configureHelperProcess(cmd)
		cmd.WaitDelay = 2 * time.Second
		err = cmd.Run()
		if err != nil {
			if needsAuthentication(stderr.String()) {
				cancel()
				return "", &AuthRequiredError{Host: host}
			}
			if transport := classifySSHTransport(err, stderr.String()); transport != nil {
				cancel()
				return "", transport
			}
			if probeCtx.Err() != nil {
				err = probeCtx.Err()
				cancel()
				return "", err
			}
			cancel()
			continue
		}
		cancel()
		if stdout.Exceeded() || stderr.Exceeded() {
			return "", ErrHelperOutputLimit
		}
		result := strings.ToLower(strings.TrimSpace(stdout.String()))
		switch {
		case result == "linux":
			return "linux", nil
		case result == "darwin":
			return "darwin", nil
		case strings.Contains(result, "windows"), strings.HasPrefix(result, "mingw"), strings.HasPrefix(result, "msys"), strings.HasPrefix(result, "cygwin"):
			return "windows", nil
		}
	}
	return "", errors.New("cannot identify SSH host OS; Windows OpenSSH or a POSIX SSH shell is required")
}
