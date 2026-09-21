package connection

import (
	"context"
	"errors"
	"net"
	"net/url"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

// LocalControllerCredentials resolves only a confirmed local target's existing
// secret reference, for private runtime recovery. Callers must never print the
// returned secret or send it to a remote host.
func LocalControllerCredentials(ctx context.Context, target config.Target) (string, error) {
	if err := config.ValidateTarget(target); err != nil {
		return "", err
	}
	if target.SSHHost != "" {
		return "", errors.New("TUN handoff requires a local controller")
	}
	u, err := url.Parse(target.Controller)
	if err != nil {
		return "", err
	}
	if u.Scheme != "unix" {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("TUN handoff controller must be loopback or a local Unix socket")
		}
	}
	return resolveSecret(ctx, target)
}
