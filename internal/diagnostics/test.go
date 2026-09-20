package diagnostics

import (
	"context"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
)

// Test checks controller identity, authentication and /configs readability.
// It never sends a core write or a data-plane request, even in control mode.
func Test(ctx context.Context, target config.Target, opts Options) (TestResult, error) {
	result := TestResult{TargetID: target.ID, SampledAt: opts.now()}
	if err := config.ValidateTarget(target); err != nil {
		return result, err
	}
	result.Route = route(target, target.Controller)
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	started := time.Now()
	client, closer, err := open(ctx, target, true)
	if err != nil {
		result.Milliseconds = float64(time.Since(started)) / float64(time.Millisecond)
		return result, err
	}
	if closer != nil {
		defer closer.Close()
	}
	defer client.Close()
	version, err := client.Version(ctx)
	if err == nil {
		result.Version, _ = version["version"].(string)
		result.Version = strings.Join(strings.Fields(core.Sanitize(result.Version)), " ")
		if result.Version == "" {
			err = &core.Error{Kind: core.KindInvalid, Operation: "identify controller"}
		}
	}
	if err == nil {
		result.Connected = true
		_, err = client.Config(ctx)
		result.ConfigsReadable = err == nil
	}
	result.Milliseconds = float64(time.Since(started)) / float64(time.Millisecond)
	return result, err
}
