package managedcore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// Opt-in proof creates a private transfer plus temporary RPC staging, verifies
// a synthetic request without dispatch, then removes the owned test files.
// It never invokes Install, changes a proxy, or stops/starts an application.
func TestWindowsPrivateTransferLive(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_TRANSFER_LIVE")
	if host == "" {
		t.Skip("set explicit Windows SSH alias to authorize private transfer fixture creation and cleanup")
	}
	sizes := []int{32 << 10}
	if os.Getenv("LAZYCLASH_WINDOWS_TRANSFER_LARGE") == "1" {
		sizes = append(sizes, 70<<20)
	}
	for _, size := range sizes {
		ok := t.Run(sizeLabel(size), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			suffix, err := randomHex(8)
			if err != nil {
				t.Fatal(err)
			}
			id := "transfer-proof-" + suffix
			basic := windowsRequest{HostOS: "windows", Op: "facts", ID: id, Client: "mihomo", ControllerPort: 19098, MixedPort: 17898}
			memoryBefore := privateTransferHostResources(t, ctx, host)
			before, err := callWindows(ctx, host, basic, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if before.Facts.Existing || before.Facts.UserSID == "" || before.Facts.LocalAppData == "" {
				t.Fatal("fresh private transfer prerequisites unavailable")
			}
			owner, err := randomHex(24)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := randomHex(16)
			if err != nil {
				t.Fatal(err)
			}
			root := winJoin(before.Facts.LocalAppData, "lazyclash", "cores", id)
			padding := make([]byte, size)
			if _, err = rand.Read(padding); err != nil {
				t.Fatal(err)
			}
			const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			for i := range padding {
				padding[i] = alphabet[padding[i]&63]
			}
			raw, err := json.Marshal(map[string]any{"host_os": "windows", "op": "install", "id": id, "client": "mihomo", "root": root, "user_sid": before.Facts.UserSID, "owner_token": owner, "padding": string(padding)})
			if err != nil {
				t.Fatal(err)
			}
			local := filepath.Join(t.TempDir(), "payload [fixture].json")
			if err = os.WriteFile(local, raw, 0600); err != nil {
				t.Fatal(err)
			}
			descriptor := basic
			descriptor.Op = "prepare-transfer"
			descriptor.Root = root
			descriptor.UserSID = before.Facts.UserSID
			descriptor.OwnerToken = owner
			descriptor.Expected = before.Facts.WindowsStateDigest
			descriptor.TransferOperation = "install"
			descriptor.TransferID = nonce
			descriptor.TransferSHA256 = hashBytes(raw)
			descriptor.TransferSize = int64(len(raw))
			prepared, err := callWindows(ctx, host, descriptor, Options{})
			if err != nil {
				t.Fatal(err)
			}
			wantPath := winJoin(before.Facts.LocalAppData, "lazyclash", "transfers", id+"-"+nonce, "payload.json")
			if !sameWindowsPath(prepared.TransferPath, wantPath) {
				t.Fatal("helper returned a different private transfer destination")
			}
			descriptor.TransferPath = prepared.TransferPath
			cleaned := false
			transferRemoved := false
			cleanup := func() error {
				cleanupCtx, stop := context.WithTimeout(context.Background(), 45*time.Second)
				defer stop()
				var e error
				if !transferRemoved {
					request := descriptor
					request.Op = "cleanup-transfer"
					result, err := callWindows(cleanupCtx, host, request, Options{})
					e = err
					if e == nil && result.Status != "transfer_removed" {
						t.Errorf("private transfer cleanup did not confirm removal")
					}
					if e == nil {
						transferRemoved = true
					}
				}
				if e == nil {
					lockInput, _ := json.Marshal(map[string]string{"id": id, "sid": before.Facts.UserSID, "nonce": nonce})
					out, lockErr := connection.ExecutePowerShell(cleanupCtx, host, transferTestLockCleanup, lockInput, 1024)
					var observed struct {
						Removed bool `json:"removed"`
					}
					if lockErr != nil {
						return lockErr
					}
					if json.Unmarshal(out, &observed) != nil || !observed.Removed {
						t.Errorf("private fixture lock cleanup was not confirmed")
					}
					cleaned = true
				}
				return e
			}
			t.Cleanup(func() {
				if !cleaned {
					if e := cleanup(); e != nil {
						t.Errorf("exact private fixture cleanup failed: %v", e)
					}
				}
			})
			started := time.Now()
			if err = connection.CopyPrivateFile(ctx, host, local, descriptor.TransferPath); err != nil {
				t.Fatal(err)
			}
			uploadTime := time.Since(started)
			descriptor.Op = "verify-transfer"
			started = time.Now()
			verified, err := callWindows(ctx, host, descriptor, Options{})
			if err != nil || !verified.TransferVerified {
				t.Fatalf("inert payload verification failed: %v", err)
			}
			verifyTime := time.Since(started)
			wrong := descriptor
			wrong.TransferSHA256 = strings.Repeat("0", 64)
			if _, err = callWindows(ctx, host, wrong, Options{}); err == nil {
				t.Fatal("altered SHA256 descriptor was accepted")
			}
			wrong = descriptor
			wrong.OwnerToken = strings.Repeat("0", 48)
			if _, err = callWindows(ctx, host, wrong, Options{}); err == nil {
				t.Fatal("different transfer owner was accepted")
			}
			verified, err = callWindows(ctx, host, descriptor, Options{})
			if err != nil || !verified.TransferVerified {
				t.Fatal("rejected descriptors changed the private payload")
			}
			if err = cleanup(); err != nil {
				t.Fatal(err)
			}
			if _, err = callWindows(ctx, host, descriptor, Options{}); err == nil {
				t.Fatal("removed private transfer still verified")
			}
			after, err := callWindows(ctx, host, basic, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if after.Facts.Existing || after.Facts.WindowsStateDigest != before.Facts.WindowsStateDigest {
				t.Fatal("Windows application/proxy state changed during the inert transfer proof")
			}
			memoryAfter := privateTransferHostResources(t, ctx, host)
			t.Logf("verified %d-byte JSON via private SFTP in %s; hash/identity check %s; tampered descriptors rejected; exact transfer removed; app/proxy facts unchanged", len(raw), uploadTime.Round(time.Millisecond), verifyTime.Round(time.Millisecond))
			t.Logf("Windows free RAM before/after: %d/%d MiB of %d MiB; local-app-data disk free before/after: %d/%d MiB", memoryBefore.FreeRAM>>20, memoryAfter.FreeRAM>>20, memoryBefore.TotalRAM>>20, memoryBefore.FreeDisk>>20, memoryAfter.FreeDisk>>20)
		})
		if !ok {
			break
		}
	}
}
func sizeLabel(size int) string {
	if size >= 1<<20 {
		return "artifact_70MiB"
	}
	return "small_32KiB"
}

// Only the cryptographically unique test namespace is accepted. The instance
// and transfer must already be absent; an exclusive open proves no operation
// is holding the zero-byte lock before this exact fixture file is removed.
const transferTestLockCleanup = `param([string]$RequestJson)
$ErrorActionPreference='Stop'
try {
 $v=$RequestJson|ConvertFrom-Json
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if($v.id -cnotmatch '^transfer-proof-[0-9a-f]{16}$' -or $v.nonce -cnotmatch '^[0-9a-f]{32}$' -or $v.sid -cne $sid){throw 'identity'}
 $base=Join-Path $env:LOCALAPPDATA 'lazyclash'
 $instance=Join-Path $base ('cores\'+$v.id)
 $transfer=Join-Path $base ('transfers\'+$v.id+'-'+$v.nonce)
 $lock=Join-Path $base ('locks\'+$v.id+'.lock')
 if((Test-Path -LiteralPath $instance) -or (Test-Path -LiteralPath $transfer)){throw 'active fixture'}
 $walk=$lock
 while($walk){if(Test-Path -LiteralPath $walk){if((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse'}};$next=[IO.Path]::GetDirectoryName($walk);if($next -eq $walk){break};$walk=$next}
 if(Test-Path -LiteralPath $lock){
  $info=Get-Item -LiteralPath $lock -Force
  if($info.PSIsContainer -or $info.Length -ne 0){throw 'file'}
  $acl=Get-Acl -LiteralPath $lock;$trusted=@($sid,'S-1-5-18','S-1-5-32-544')
  if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'owner'}
  foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $ace.IdentityReference.Value -notin $trusted){throw 'acl'}}
  $stream=[IO.File]::Open($lock,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{if($stream.Length -ne 0){throw 'size'}}finally{$stream.Dispose()}
  Remove-Item -LiteralPath $lock -Force
 }
 [Console]::Out.WriteLine('{"removed":true}')
}catch{[Console]::Out.WriteLine('{"removed":false}')}
`

type privateTransferResources struct {
	FreeRAM  uint64 `json:"free_ram"`
	TotalRAM uint64 `json:"total_ram"`
	FreeDisk uint64 `json:"free_disk"`
}

func privateTransferHostResources(t *testing.T, ctx context.Context, host string) privateTransferResources {
	t.Helper()
	const script = `param([string]$RequestJson);$ErrorActionPreference='Stop';$os=Get-CimInstance Win32_OperatingSystem;$volume=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($env:LOCALAPPDATA));[Console]::Out.WriteLine((ConvertTo-Json -Compress @{free_ram=([uint64]$os.FreePhysicalMemory*1024);total_ram=([uint64]$os.TotalVisibleMemorySize*1024);free_disk=[uint64]$volume.AvailableFreeSpace}))`
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := connection.ExecutePowerShell(probeCtx, host, script, []byte(`{}`), 1024)
	if err != nil {
		t.Fatalf("read-only memory/disk observation failed: %v", err)
	}
	var result privateTransferResources
	if json.Unmarshal(raw, &result) != nil || result.TotalRAM == 0 {
		t.Fatal("invalid memory/disk observation")
	}
	return result
}
