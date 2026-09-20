package cli

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/diagnostics"
	"github.com/daviddwlee84/lazyclash/internal/managedcore"
	"github.com/spf13/cobra"
)

func (o *options) configureBootstrapDownloads(cmd *cobra.Command, opts *managedcore.Options) {
	if opts.DownloadClient != nil {
		return
	}
	opts.DownloadClient = func(ctx context.Context, id string) (*http.Client, io.Closer, error) {
		cfg, _, err := o.load(cmd)
		if err != nil {
			return nil, nil, err
		}
		index, err := targetIndex(cfg, id)
		if err != nil {
			return nil, nil, err
		}
		target := cfg.Targets[index]
		if target.ProbeProxy == "" {
			return nil, nil, usage("bootstrap target %q needs an explicit --probe-proxy; the controller API is not a data proxy", id)
		}
		return diagnostics.OpenProxyClient(ctx, target, 60*time.Second)
	}
}
