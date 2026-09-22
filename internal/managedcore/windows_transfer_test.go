package managedcore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

func largeWindowsFixture(t *testing.T, failure string) (Request, Options, *[]string) {
	t.Helper()
	r, o, _ := newWindowsFixture(t)
	body := []byte(strings.Repeat("public artifact", 30000))
	ops := []string{}
	o.ResolveArtifact = func(_ context.Context, r Request, h HostFacts) (Artifact, error) {
		return Artifact{Kind: "zip", Version: DefaultVersion, SHA256: hashBytes(body), Size: int64(len(body)), Platform: "windows/amd64"}, nil
	}
	o.FetchArtifact = func(context.Context, Artifact) ([]byte, error) { return body, nil }
	base := o.Execute
	var descriptor windowsRequest
	var uploaded []byte
	o.Execute = func(ctx context.Context, host string, priv bool, raw []byte) ([]byte, error) {
		var request windowsRequest
		if err := json.Unmarshal(raw, &request); err != nil {
			return nil, err
		}
		ops = append(ops, request.Op)
		switch request.Op {
		case "prepare-transfer":
			descriptor = request
			if len(raw) > 4096 || request.Artifact != nil || request.Profile != nil || request.Resources != nil {
				t.Fatal("bulk secret data leaked onto control descriptor")
			}
			path := winJoin(hostpath.Dir("windows", hostpath.Dir("windows", request.Root)), "transfers", request.ID+"-"+request.TransferID, "payload.json")
			return json.Marshal(windowsResponse{Status: "transfer_prepared", TransferPath: path})
		case "dispatch-transfer":
			if failure == "dispatch" {
				return nil, errors.New("connection closed after dispatch")
			}
			if descriptor.TransferSHA256 != hashBytes(uploaded) || int64(len(uploaded)) != descriptor.TransferSize {
				t.Fatal("transferred payload identity changed")
			}
			return base(ctx, host, priv, uploaded)
		case "cleanup-transfer":
			return json.Marshal(windowsResponse{Status: "transfer_removed"})
		default:
			return base(ctx, host, priv, raw)
		}
	}
	o.Upload = func(_ context.Context, host, local, remote string) error {
		ops = append(ops, "sftp-upload")
		info, e := os.Stat(local)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("payload spool is not private", e)
		}
		if host != r.SSHHost || !strings.HasSuffix(remote, "payload.json") {
			t.Fatal("wrong transfer destination")
		}
		uploaded, e = os.ReadFile(local)
		if e != nil {
			return e
		}
		if failure == "upload" {
			return errors.New("SFTP fixture failure")
		}
		return nil
	}
	return r, o, &ops
}
func TestWindowsLargeRequestUsesPrivateSFTPAndSmallDispatch(t *testing.T) {
	r, o, ops := largeWindowsFixture(t, "")
	receipt := installWindowsFixture(t, r, o)
	if receipt.Status != "running_verified" {
		t.Fatal(receipt.Status)
	}
	joined := strings.Join(*ops, ",")
	if !strings.Contains(joined, "prepare-transfer,sftp-upload,dispatch-transfer,cleanup-transfer") {
		t.Fatal("wrong transfer order", joined)
	}
	dir, _ := instanceDir(r.ID, o)
	files, _ := filepath.Glob(filepath.Join(dir, "transfer-*.json"))
	if len(files) != 0 {
		t.Fatal("known-success private spool was not cleaned")
	}
}
func TestWindowsSFTPFailureArchivesKnownNotInstalledDraft(t *testing.T) {
	r, o, ops := largeWindowsFixture(t, "upload")
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e == nil || receipt.Status != "not_installed" {
		t.Fatal(e, receipt.Status)
	}
	for _, op := range *ops {
		if op == "dispatch-transfer" {
			t.Fatal("failed transfer dispatched installer")
		}
	}
	if _, e = loadInstance(r.ID, o); !os.IsNotExist(e) {
		t.Fatal("failed draft still blocks same ID", e)
	}
	if _, e = os.Stat(filepath.Join(o.StateDir, "failed", receipt.ID, "instance.json")); e != nil {
		t.Fatal("failed private draft not retained", e)
	}
}
func TestWindowsDispatchDisconnectPreservesUnknownState(t *testing.T) {
	r, o, _ := largeWindowsFixture(t, "dispatch")
	p, e := PreviewWindows(context.Background(), r, o)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := ApplyWindows(context.Background(), r, p.Digest, o)
	if e == nil || receipt.Status != "unknown_host_result" {
		t.Fatal(e, receipt.Status)
	}
	if _, e = loadInstance(r.ID, o); e != nil {
		t.Fatal("unknown installation draft was archived", e)
	}
	dir, _ := instanceDir(r.ID, o)
	files, _ := filepath.Glob(filepath.Join(dir, "transfer-*.json"))
	if len(files) != 1 {
		t.Fatal("unknown result lost private payload for inspection")
	}
}
