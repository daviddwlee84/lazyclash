package cli

import (
	"os"
	"path/filepath"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/spf13/cobra"
)

func (o *options) serverStore(cmd *cobra.Command) (serverstate.Store, error) {
	s := o.deps.ServerStore
	if s.Path == "" && s.StateDir == "" {
		s = o.deps.Servers.Store
	}
	p := o.serversPath
	if p == "" {
		p = os.Getenv("LAZYCLASH_SERVERS_CONFIG")
	}
	if p != "" {
		var err error
		s.Path, err = filepath.Abs(p)
		return s, err
	}
	if s.Path != "" {
		return s, nil
	}
	// Workbench callbacks use a lightweight command without the original flag
	// metadata. A nonempty parsed --config still outranks the environment there.
	if o.path != "" {
		var err error
		s.Path, err = serverstate.DefaultPath(o.path)
		return s, err
	}
	settings, _, err := o.settingsPath(cmd)
	if err != nil {
		return s, err
	}
	s.Path, err = serverstate.DefaultPath(settings)
	return s, err
}
