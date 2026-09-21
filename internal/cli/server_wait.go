package cli

import (
	"context"
	"errors"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

// Only observations are retried after cloud creation. The provider resource is
// already saved, and this function never submits another create operation.
func waitForServerHost(ctx context.Context, host serverstate.Host, refresh func(context.Context, string) (serverstate.Host, error), probe func(context.Context, serverstate.Host) error, interval time.Duration) (serverstate.Host, error) {
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return host, errors.Join(err, lastErr)
		}
		if host.PublicHost != "" && host.SSHHost != "" {
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			lastErr = probe(attempt, host)
			cancel()
			if lastErr == nil {
				return host, nil
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
		updated, err := refresh(attempt, host.ID)
		cancel()
		if err == nil {
			host = updated
		} else {
			lastErr = err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return host, errors.Join(ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}
