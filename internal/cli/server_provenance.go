package cli

import (
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/spf13/cobra"
)

// A local-only startup snapshot keeps rendering independent of SSH/cloud calls.
func (o *options) nodeProvenance(cmd *cobra.Command, cfg config.Config) map[string]map[string]string {
	result := map[string]map[string]string{}
	store, err := o.serverStore(cmd)
	if err != nil {
		return result
	}
	inv, err := store.Load()
	if err != nil {
		return result
	}
	rows, err := storedServerConnections(store, inv, cfg.Targets)
	if err != nil {
		return result
	}
	for _, row := range rows {
		if row.Status == "restored" {
			continue
		}
		if result[row.TargetID] == nil {
			result[row.TargetID] = map[string]string{}
		}
		result[row.TargetID][row.NodeName] += fmt.Sprintf("\nServer: %s\nVPS: %s\nProvider: %s %s\nRecorded import: %s (%s)\nCurrent source/runtime not rechecked; use servers connections.\nUsage: Servers / VPS → u Usage", row.ServerID, row.HostID, row.Provider, row.Region, row.ReceiptStatus, usageTime(row.RecordedAt))
	}
	return result
}
