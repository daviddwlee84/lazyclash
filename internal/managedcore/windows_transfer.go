package managedcore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

// Large requests use OpenSSH's SFTP data channel. Only the small authenticated
// descriptor uses the private file RPC; all data stays within a private transfer
// directory separate from the not-yet-created managed instance.
func transferWindowsRequest(ctx context.Context, host string, r windowsRequest, raw []byte, opts Options) (windowsResponse, error) {
	beforeDispatch := func(err error) (windowsResponse, error) {
		response := windowsResponse{}
		if r.Op == "install" {
			response.Status = "not_installed"
		}
		return response, err
	}
	if host == "" {
		return beforeDispatch(errors.New("large Windows requests require the registered SSH/SFTP host"))
	}
	if r.Op != "install" && r.Op != "source" {
		return beforeDispatch(errors.New("unsupported large Windows operation"))
	}
	if len(raw) > 256<<20 {
		return beforeDispatch(errors.New("private Windows request exceeds 256 MiB"))
	}
	nonce, err := randomHex(16)
	if err != nil {
		return beforeDispatch(err)
	}
	dir, err := instanceDir(r.ID, opts)
	if err != nil {
		return beforeDispatch(err)
	}
	local := filepath.Join(dir, "transfer-"+nonce+".json")
	if err = writePrivate(local, raw); err != nil {
		return beforeDispatch(err)
	}
	transfer := windowsRequest{HostOS: "windows", Op: "prepare-transfer", ID: r.ID, Client: r.Client, ClientVersion: r.ClientVersion, Root: r.Root, UserSID: r.UserSID, OwnerToken: r.OwnerToken, Expected: r.Expected, ControllerPort: r.ControllerPort, MixedPort: r.MixedPort, TransferOperation: r.Op, TransferID: nonce, TransferSHA256: hashBytes(raw), TransferSize: int64(len(raw))}
	prepared, err := callWindows(ctx, host, transfer, opts)
	if err != nil {
		return beforeDispatch(err)
	}
	expected := winJoin(hostpath.Dir("windows", hostpath.Dir("windows", r.Root)), "transfers", r.ID+"-"+nonce, "payload.json")
	if !sameWindowsPath(prepared.TransferPath, expected) {
		return beforeDispatch(errors.New("Windows transfer path differs from its private owned directory"))
	}
	transfer.TransferPath = prepared.TransferPath
	upload := opts.Upload
	if upload == nil {
		upload = connection.CopyPrivateFile
	}
	if err = upload(ctx, host, local, transfer.TransferPath); err != nil {
		cleanupWindowsTransfer(host, transfer, opts)
		return beforeDispatch(err)
	}
	// From this point the operation may have begun. A disconnect must preserve
	// the ordinary unknown-result receipt, never trigger an installer retry.
	transfer.Op = "dispatch-transfer"
	response, err := callWindows(ctx, host, transfer, opts)
	if err != nil {
		return response, err
	}
	cleanupWindowsTransfer(host, transfer, opts)
	_ = os.Remove(local)
	return response, nil
}
func cleanupWindowsTransfer(host string, r windowsRequest, opts Options) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r.Op = "cleanup-transfer"
	_, _ = callWindows(ctx, host, r, opts)
}
