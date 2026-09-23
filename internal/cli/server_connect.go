package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/daviddwlee84/lazyclash/internal/privatefs"
	"os"
	"path/filepath"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/configwork"
	"github.com/daviddwlee84/lazyclash/internal/serverstate"
	"github.com/spf13/cobra"
)

// The connection record is saved before a client write. A scoped configwork
// receipt directory lets an interrupted process recover its receipt without
// guessing whether it should perform the import again.
type serverConnection struct {
	ServerID  string    `json:"server_id"`
	TargetID  string    `json:"target_id"`
	Binding   string    `json:"binding"`
	Digest    string    `json:"digest"`
	Status    string    `json:"status"`
	ReceiptID string    `json:"receipt_id,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

func serverConnectionPath(store serverstate.Store, id string, target config.Target) (string, error) {
	return clientConnectionPath(store, "server", id, target)
}

func clientConnectionPath(store serverstate.Store, kind, id string, target config.Target) (string, error) {
	if err := serverstate.ValidateID(id); err != nil {
		return "", err
	}
	root, err := store.StateRoot()
	if err != nil {
		return "", err
	}
	identity := id // Preserve receipts written before Tailnet support.
	if kind != "server" {
		identity = kind + "\x00" + id
	}
	sum := sha256.Sum256([]byte(identity + "\x00" + target.ID + "\x00" + configwork.Binding(target)))
	return filepath.Join(root, "connections", hex.EncodeToString(sum[:]), "connection.json"), nil
}

func readServerConnection(path string) (serverConnection, bool, error) {
	var record serverConnection
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if !info.Mode().IsRegular() || !privatefs.Private(path) || info.Size() > 1<<20 {
		return record, false, errors.New("saved server-client import record is not a private regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return record, false, err
	}
	if err = json.Unmarshal(data, &record); err != nil {
		return record, false, errors.New("invalid saved server-client import record")
	}
	if record.ServerID == "" || record.TargetID == "" || record.Binding == "" || record.StartedAt.IsZero() {
		return record, false, errors.New("incomplete saved server-client import record")
	}
	return record, true, nil
}

func saveServerConnection(path string, record serverConnection) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return serverstate.WritePrivate(path, data)
}

func applyServerConnection(ctx context.Context, store serverstate.Store, id string, target config.Target, req configwork.Request, expected, path string, opts configwork.Options) (configwork.Receipt, error) {
	return applyClientConnection(ctx, store, "server", id, target, req, expected, path, opts)
}

func applyClientConnection(ctx context.Context, store serverstate.Store, kind, id string, target config.Target, req configwork.Request, expected, path string, opts configwork.Options) (configwork.Receipt, error) {
	command := "servers connect"
	if kind == "tailnet-proxy" {
		command = "tailnet proxy connect"
	}

	if opts.ReadOnly {
		return configwork.Receipt{}, errors.New("client import is disabled in read-only mode")
	}
	unlock, err := serverstate.Lock(path + ".lock")
	if err != nil {
		return configwork.Receipt{}, err
	}
	defer unlock()
	previous, found, err := readServerConnection(path)
	if err != nil {
		return configwork.Receipt{}, err
	}
	if found && previous.Status != "failed-before-write" {
		return configwork.Receipt{}, usage("an import is already recorded; run %s %s --verify --target %s", command, id, target.ID)
	}
	record := serverConnection{ServerID: id, TargetID: target.ID, Binding: configwork.Binding(target), Digest: expected, Status: "applying", StartedAt: time.Now().UTC()}
	if err = saveServerConnection(path, record); err != nil {
		return configwork.Receipt{}, err
	}
	result, applyErr := configwork.Apply(ctx, target, req, expected, opts)
	if result.ID == "" {
		record.Status = "failed-before-write"
	} else {
		record.ReceiptID = result.ID
		record.Status = result.Status
	}
	if err = saveServerConnection(path, record); err != nil {
		return result, errors.Join(applyErr, fmt.Errorf("save client import result: %w; use %s --verify before retrying", err, command))
	}
	return result, applyErr
}

func recoverConnectionReceipt(record serverConnection, stateDir string) (string, error) {
	if record.ReceiptID != "" {
		return record.ReceiptID, nil
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return "", errors.New("import outcome is unknown and no receipt is available; inspect the client source before another import")
	}
	var candidate string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(stateDir, entry.Name(), "receipt.json")
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() || !privatefs.Private(path) || info.Size() > 1<<20 {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var receipt configwork.Receipt
		if json.Unmarshal(data, &receipt) != nil {
			continue
		}
		if receipt.ID != entry.Name() || receipt.TargetID != record.TargetID || receipt.Binding != record.Binding || receipt.CreatedAt.Before(record.StartedAt) {
			continue
		}
		if candidate != "" {
			return "", errors.New("multiple client import receipts found; inspect the saved receipts before retrying")
		}
		candidate = receipt.ID
	}
	if candidate == "" {
		return "", errors.New("import outcome is unknown and no matching receipt is available; inspect the client source before another import")
	}
	return candidate, nil
}

func (o *options) verifyServerConnection(cmd *cobra.Command, target config.Target, record serverConnection, path string, opts configwork.Options) error {
	unlock, err := serverstate.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	record, found, err := readServerConnection(path)
	if err != nil {
		return err
	}
	if !found {
		return usage("saved import disappeared; reload before retrying")
	}
	if record.TargetID != target.ID || record.Binding != configwork.Binding(target) {
		return usage("client source binding changed; saved import does not apply")
	}
	id, err := recoverConnectionReceipt(record, opts.StateDir)
	if err != nil {
		return err
	}
	var receipt configwork.Receipt
	err = o.authenticatedDiagnostic(cmd, target, func() error { var e error; receipt, e = configwork.Verify(cmd.Context(), target, id, opts); return e })
	if receipt.ID != "" {
		record.ReceiptID = receipt.ID
		record.Status = receipt.Status
		if saveErr := saveServerConnection(path, record); saveErr != nil {
			return errors.Join(err, saveErr)
		}
		if outErr := o.output(cmd, receipt); outErr != nil {
			return outErr
		}
	}
	return err
}
