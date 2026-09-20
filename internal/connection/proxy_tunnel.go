package connection

import (
	"context"
	"errors"
	"io"
	"net/url"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

// OpenProxyTunnel owns a separate forward for a target's explicit data-plane
// proxy. The proxy address is resolved by the SSH host. Callers keep the
// original proxy URL for HTTP Host and TLS verification, but dial this local
// address. Close releases only this forward, never the user's SSH session.
func OpenProxyTunnel(ctx context.Context, host, proxyURL string) (string, io.Closer, error) {
	if err := config.ValidateProbe(config.Target{ProbeProxy: proxyURL}); err != nil {
		return "", nil, err
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.Hostname() == "" {
		return "", nil, errors.New("an explicit data proxy URL is required for SSH forwarding")
	}
	t, err := openTunnel(ctx, host, u)
	if err != nil {
		return "", nil, err
	}
	return t.address, t, nil
}
