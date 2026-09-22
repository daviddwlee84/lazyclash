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
var ErrHelperOutputLimit = errors.New("host helper exceeded its output limit; inspect the helper before retrying")
var ErrHelperFailed = errors.New("host helper failed; inspect Python availability, permissions and helper prerequisites")

// SSHTransportError classifies known transport failures without retaining raw
// stderr, host names or command text, any of which may contain private data.
type SSHTransportError struct{ Kind string }

func (e *SSHTransportError) Error() string {
	switch e.Kind {
	case "timeout":
		return "SSH connection timed out; inspect the route, proxy/TUN routing and SSH ingress firewall"
	case "refused":
		return "SSH connection was refused; inspect the SSH listener, selected port and firewall"
	case "unreachable":
		return "SSH host has no reachable network route; inspect local routing, proxy/TUN routing and the remote network"
	case "resolve":
		return "SSH hostname could not be resolved; inspect the saved SSH alias and DNS"
	case "closed":
		return "SSH connection closed before the helper completed; inspect transport and SSH service logs"
	default:
		return "SSH transport did not complete; inspect the selected host's SSH route and firewall"
	}
}
func classifySSHTransport(err error, diagnostic string) *SSHTransportError {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 255 {
		return nil
	}
	message := strings.ToLower(diagnostic)
	switch {
	case strings.Contains(message, "could not resolve hostname"):
		return &SSHTransportError{Kind: "resolve"}
	case strings.Contains(message, "connection timed out during banner exchange"):
		return &SSHTransportError{Kind: "timeout"}
	case strings.Contains(message, "connect to host") && (strings.Contains(message, "connection timed out") || strings.Contains(message, "operation timed out")):
		return &SSHTransportError{Kind: "timeout"}
	case strings.Contains(message, "connect to host") && strings.Contains(message, "connection refused"):
		return &SSHTransportError{Kind: "refused"}
	case strings.Contains(message, "connect to host") && (strings.Contains(message, "no route to host") || strings.Contains(message, "network is unreachable")):
		return &SSHTransportError{Kind: "unreachable"}
	case strings.Contains(message, "connection closed by") || strings.Contains(message, "connection reset by") || strings.Contains(message, "kex_exchange_identification:"):
		return &SSHTransportError{Kind: "closed"}
	}
	return nil
}

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
		if output.Exceeded() || diagnostic.Exceeded() {
			return nil, ErrHelperOutputLimit
		}
		if host != "" && needsAuthentication(diagnostic.String()) {
			return nil, &AuthRequiredError{Host: host}
		}
		if host != "" {
			if transport := classifySSHTransport(err, diagnostic.String()); transport != nil {
				return nil, transport
			}
		}
		message := strings.ToLower(diagnostic.String())
		if strings.Contains(message, "python3") && (strings.Contains(message, "not found") || strings.Contains(message, "no such file")) {
			return nil, ErrPythonUnavailable
		}
		return nil, ErrHelperFailed
	}
	return output.Bytes(), nil
}
