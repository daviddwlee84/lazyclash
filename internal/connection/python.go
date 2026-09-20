package connection

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

var ErrPythonUnavailable = errors.New("Python 3 is unavailable on this host")

// ExecutePython runs caller-owned fixed helper code, with all request data on
// stdin. An empty host means local execution. It never installs a helper or
// exposes stderr, which may contain source/configuration data.
func ExecutePython(ctx context.Context, host, script string, input []byte, limit int) ([]byte, error) {
	if len(input) > 32<<20 || limit <= 0 || limit > 32<<20 {
		return nil, errors.New("helper request or output limit is invalid")
	}
	var cmd *exec.Cmd
	if host == "" {
		path, err := exec.LookPath("python3")
		if err != nil {
			return nil, ErrPythonUnavailable
		}
		cmd = commandContext(ctx, path, "-c", script)
	} else {
		if err := validateHost(host); err != nil {
			return nil, err
		}
		args, err := sshArgsContext(ctx, host)
		if err != nil {
			return nil, err
		}
		cmd = commandContext(ctx, "ssh", append(args, "-T", "--", host, "python3 -c "+shellQuote(script))...)
	}
	var output, diagnostic limitedBuffer
	output.limit, diagnostic.limit = limit, 8192
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(input), &output, &diagnostic
	configureHelperProcess(cmd)
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if host != "" && needsAuthentication(diagnostic.String()) {
			return nil, &AuthRequiredError{Host: host}
		}
		message := strings.ToLower(diagnostic.String())
		if strings.Contains(message, "python3") && (strings.Contains(message, "not found") || strings.Contains(message, "no such file")) {
			return nil, ErrPythonUnavailable
		}
		return nil, errors.New("host helper failed or exceeded its output limit")
	}
	return output.Bytes(), nil
}
