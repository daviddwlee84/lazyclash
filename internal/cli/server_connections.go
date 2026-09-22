package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/core"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/daviddwlee84/lazyclash/internal/tui"
	"github.com/spf13/cobra"
)

type ServerConnectionInfo struct {
	TargetID                string    `json:"target_id"`
	NodeName                string    `json:"node_name"`
	ServerID                string    `json:"server_id"`
	HostID                  string    `json:"host_id"`
	Provider                string    `json:"provider"`
	Region                  string    `json:"region,omitempty"`
	ResourceID              string    `json:"resource_id,omitempty"`
	Status                  string    `json:"status"`
	ReceiptStatus           string    `json:"receipt_status"`
	RecordedAt              time.Time `json:"recorded_at"`
	SourceVerified          bool      `json:"source_verified"`
	RecordedRuntimeObserved bool      `json:"recorded_runtime_observed"`
}

type ServerConnectionsReport struct {
	Connections []ServerConnectionInfo `json:"connections"`
	Warnings    []string               `json:"warnings,omitempty"`
}

func storedServerConnections(store serverstate.Store, inv serverstate.Inventory, targets []config.Target) ([]ServerConnectionInfo, error) {
	result := []ServerConnectionInfo{}
	for _, target := range targets {
		for _, d := range inv.Deployments {
			path, err := serverConnectionPath(store, d.ID, target)
			if err != nil {
				return nil, err
			}
			record, found, err := readServerConnection(path)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if record.Status == "failed-before-write" {
				continue
			}
			if record.ServerID != d.ID || record.TargetID != target.ID || record.Binding != configwork.Binding(target) {
				return nil, fmt.Errorf("server-client connection record differs from its source binding")
			}
			opts := configwork.Options{StateDir: filepath.Join(filepath.Dir(path), "receipts"), ReadOnly: true}
			receiptID, err := recoverConnectionReceipt(record, opts.StateDir)
			if err != nil {
				return nil, err
			}
			receipt, err := configwork.InspectReceipt(target, receiptID, opts)
			if err != nil {
				return nil, err
			}
			h, err := inv.Host(d.HostID)
			if err != nil {
				return nil, err
			}
			provider, region, resource := h.Provider, h.Region, h.ResourceID
			if h.Observation != nil {
				provider, region, resource = h.Observation.Provider, h.Observation.Region, h.Observation.ResourceID
			}
			defs := receipt.Definitions
			if len(defs) == 0 && receipt.Kind == "proxy" && receipt.Name != "" {
				defs = map[string]string{"proxy/" + receipt.Name: receipt.DefinitionSHA256}
			}
			for key, fingerprint := range defs {
				name, proxy := strings.CutPrefix(key, "proxy/")
				if !proxy {
					continue
				}
				hash, err := hex.DecodeString(fingerprint)
				if err != nil || len(hash) != 32 || name == "" {
					return nil, fmt.Errorf("saved proxy receipt has an invalid semantic fingerprint")
				}
				status := "recorded"
				if receipt.Restored {
					status = "restored"
				}
				result = append(result, ServerConnectionInfo{TargetID: target.ID, NodeName: name, ServerID: d.ID, HostID: h.ID, Provider: provider, Region: region, ResourceID: resource, Status: status, ReceiptStatus: receipt.Status, RecordedAt: receipt.UpdatedAt, RecordedRuntimeObserved: receipt.RuntimeObserved})
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].TargetID+"\x00"+result[i].NodeName+"\x00"+result[i].ServerID < result[j].TargetID+"\x00"+result[j].NodeName+"\x00"+result[j].ServerID
	})
	return result, nil
}

func (o *options) serverConnectionsCommand() *cobra.Command {
	return &cobra.Command{Use: "connections", Short: "Verify saved client-node provenance against the current persistent source", Args: argsExact(0), RunE: func(cmd *cobra.Command, _ []string) error {
		defer connection.CloseAuthentications()
		target, err := o.configWorkTarget(cmd)
		if err != nil {
			return err
		}
		store, err := o.serverStore(cmd)
		if err != nil {
			return err
		}
		inv, err := store.Load()
		if err != nil {
			return err
		}
		rows, err := storedServerConnections(store, inv, []config.Target{target})
		if err != nil {
			return err
		}
		report := ServerConnectionsReport{Connections: rows}
		if len(rows) > 0 {
			var catalog configwork.Catalog
			err = o.authenticatedDiagnostic(cmd, target, func() error {
				var e error
				catalog, e = configwork.Inspect(cmd.Context(), target, o.configWorkOptions(cmd))
				return e
			})
			if err != nil {
				report.Warnings = append(report.Warnings, "Current source could not be inspected; showing saved import provenance: "+err.Error())
				for i := range report.Connections {
					if report.Connections[i].Status != "restored" {
						report.Connections[i].Status = "source-unavailable"
					}
				}
			} else {
				if err = verifyServerConnectionSources(store, inv, target, catalog, report.Connections); err != nil {
					return err
				}
			}
		}
		return o.output(cmd, report)
	}}
}

func verifyServerConnectionSources(store serverstate.Store, inv serverstate.Inventory, target config.Target, catalog configwork.Catalog, rows []ServerConnectionInfo) error {
	definitions := map[string]string{}
	for _, d := range catalog.Proxies {
		definitions[d.Name] = configwork.DefinitionDigest(d)
	}
	for i := range rows {
		row := &rows[i]
		row.SourceVerified = false
		if row.Status == "restored" {
			continue
		}
		path, err := serverConnectionPath(store, row.ServerID, target)
		if err != nil {
			return err
		}
		record, found, err := readServerConnection(path)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("server-client connection disappeared during source inspection")
		}
		if record.ServerID != row.ServerID || record.TargetID != target.ID || record.Binding != configwork.Binding(target) {
			return fmt.Errorf("server-client connection changed during source inspection")
		}
		opts := configwork.Options{StateDir: filepath.Join(filepath.Dir(path), "receipts"), ReadOnly: true}
		receiptID, err := recoverConnectionReceipt(record, opts.StateDir)
		if err != nil {
			return err
		}
		receipt, err := configwork.InspectReceipt(target, receiptID, opts)
		if err != nil {
			return err
		}
		want := receipt.Definitions["proxy/"+row.NodeName]
		if want == "" && receipt.Name == row.NodeName {
			want = receipt.DefinitionSHA256
		}
		actual, found := definitions[row.NodeName]
		switch {
		case !found:
			row.Status = "node-missing"
		case actual == "" || actual != want:
			row.Status = "definition-changed"
		default:
			row.Status = "source-matches"
			row.SourceVerified = true
		}
	}
	return nil
}

// appendRecordedServerConnections performs only local receipt reads. A TUI
// inventory refresh must not trigger source SSH reads or cloud API queries.
func (o *options) appendRecordedServerConnections(ctx context.Context, store serverstate.Store, inv serverstate.Inventory, result *tui.WorkResult) {
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cfg, _, err := o.load(cmd)
	if err != nil {
		result.Summary += " Connection provenance unavailable: " + err.Error()
		return
	}
	rows, err := storedServerConnections(store, inv, cfg.Targets)
	if err != nil {
		result.Summary += " Connection provenance unavailable: " + err.Error()
		return
	}
	for i := range result.Rows {
		kind, id, _ := strings.Cut(result.Rows[i].ID, ":")
		if kind != "server" {
			continue
		}
		for _, row := range rows {
			if row.ServerID == id {
				result.Rows[i].Detail += core.Sanitize(fmt.Sprintf("\n\nClient: %s / %s\nImport: %s · %s\nCloud: %s · %s · %s\nRecorded %s; current source/runtime not rechecked here.", row.TargetID, row.NodeName, row.ReceiptStatus, row.Status, row.Provider, row.Region, row.ResourceID, usageTime(row.RecordedAt)))
			}
		}
	}
}
