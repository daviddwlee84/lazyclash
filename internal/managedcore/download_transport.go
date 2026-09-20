package managedcore

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

type downloadContextKey struct{}
type downloadRoute struct {
	client *http.Client
	target string
}

func safeDownloadRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("download redirect limit reached")
	}
	if len(via) > 0 {
		origin := via[0].URL
		if origin.Scheme == "https" && request.URL.Scheme != "https" {
			return errors.New("download refused an HTTPS downgrade")
		}
		if request.URL.Host != origin.Host || request.URL.Scheme != origin.Scheme {
			for _, key := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
				request.Header.Del(key)
			}
		}
	}
	return nil
}

func downloadHTTPClient(ctx context.Context) *http.Client {
	if route, ok := ctx.Value(downloadContextKey{}).(downloadRoute); ok {
		return route.client
	}
	// No HTTP_PROXY/HTTPS_PROXY fallback. The setup review names its explicit
	// bootstrap target, otherwise downloads use an application-direct transport.
	return &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 128 << 10, DisableKeepAlives: true}, Timeout: 60 * time.Second, CheckRedirect: safeDownloadRedirect}
}

func withDownloadClient(ctx context.Context, request Request, opts Options) (context.Context, func(), error) {
	if route, ok := ctx.Value(downloadContextKey{}).(downloadRoute); ok {
		if route.target != request.BootstrapTarget {
			return ctx, func() {}, errors.New("bootstrap route changed during one reviewed operation")
		}
		return ctx, func() {}, nil
	}
	if request.BootstrapTarget == "" {
		return ctx, func() {}, nil
	}
	if request.BootstrapTarget == request.ID {
		return ctx, func() {}, errors.New("bootstrap proxy must already exist; it cannot be the core being installed or reconfigured")
	}
	if opts.DownloadClient == nil {
		return ctx, func() {}, errors.New("explicit bootstrap proxy resolver is unavailable")
	}
	client, closer, err := opts.DownloadClient(ctx, request.BootstrapTarget)
	cleanup := func() {
		if closer != nil {
			_ = closer.Close()
		}
	}
	if err != nil {
		cleanup()
		return ctx, func() {}, err
	}
	if client == nil {
		cleanup()
		return ctx, func() {}, errors.New("bootstrap resolver returned no HTTP client")
	}
	copy := *client
	copy.CheckRedirect = safeDownloadRedirect
	if copy.Timeout <= 0 || copy.Timeout > 60*time.Second {
		copy.Timeout = 60 * time.Second
	}
	return context.WithValue(ctx, downloadContextKey{}, downloadRoute{&copy, request.BootstrapTarget}), cleanup, nil
}
