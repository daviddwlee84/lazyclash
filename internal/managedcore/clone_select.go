package managedcore

import (
	"context"
	"errors"
	"sort"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// applyCloneSelections is an initial-deployment action only. Later lifecycle
// actions retain the destination user's choices instead of replaying the source.
func applyCloneSelections(ctx context.Context, target config.Target, selections map[string]string, opts Options) error {
	if len(selections) == 0 {
		return nil
	}
	open := opts.Open
	if open == nil {
		open = connection.Open
	}
	client, closer, err := open(ctx, target, false)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		return err
	}
	if client == nil {
		return errors.New("clone selection verification requires a controller")
	}
	defer client.Close()
	proxies, err := client.Proxies(ctx)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(selections))
	for group, member := range selections {
		proxy, ok := proxies[group]
		if !ok || proxy.Type != "Selector" {
			return errors.New("a cloned manual selector is absent from the destination")
		}
		found := false
		for _, candidate := range proxy.All {
			if candidate == member {
				found = true
				break
			}
		}
		if !found {
			return errors.New("a cloned selection is unavailable in the destination group")
		}
		names = append(names, group)
	}
	sort.Strings(names)
	for _, group := range names {
		if proxies[group].Now != selections[group] {
			if err = client.Select(ctx, group, selections[group]); err != nil {
				return err
			}
		}
	}
	return nil
}
