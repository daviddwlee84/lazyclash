package managedcore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/connection"
)

// Explicit, narrow recovery for an installed but never activated staging task.
// This never runs an installer, starts a task, or changes system proxy settings.
func TestWindowsRepairStagedLauncherExplicit(t *testing.T) {
	host, payload := os.Getenv("LAZYCLASH_WINDOWS_REPAIR_HOST"), os.Getenv("LAZYCLASH_WINDOWS_REPAIR_PAYLOAD")
	if host == "" || payload == "" {
		t.Skip("requires explicit staged launcher recovery host and original private install payload")
	}
	info, err := os.Lstat(payload)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 256<<20 {
		t.Fatal("original install payload must be a bounded private regular file")
	}
	bytes, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	var original windowsRequest
	if json.Unmarshal(bytes, &original) != nil || original.Op != "install" || len(original.Helper) == 0 {
		t.Fatal("original install request is invalid")
	}
	instance, err := loadInstance(original.ID, Options{})
	if err != nil || instance.SSHHost != host || instance.ID != "windows-laptop" || instance.OS != "windows" || instance.OwnerToken != original.OwnerToken || instance.Root != original.Root || instance.UserSID != original.UserSID {
		t.Fatal("repair differs from the private owned install request")
	}
	request, err := LoadRequest(instance.ID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := windowsHostRequest(instance, request, "status")
	r.Expected = ""
	before, err := callWindows(ctx, host, r, Options{})
	if err != nil || before.Status != "running_unverified" || before.Running {
		t.Fatal("staged owner status is not eligible for helper repair", err)
	}
	r.Expected, r.Helper = before.Digest, []byte(windowsHostScript)
	repair := struct {
		windowsRequest
		OriginalSHA256 string `json:"repair_original_sha256"`
		NewSHA256      string `json:"repair_new_sha256"`
	}{r, hashBytes(original.Helper), hashBytes(r.Helper)}
	raw, _ := json.Marshal(repair)
	script := windowsHostScript[:strings.Index(windowsHostScript, "\ntry{\n $script:SID=")]
	script += `
try{
 $script:SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $r=Map ($RequestJson|ConvertFrom-Json)
 AcquireMutationLock
 $m=Owned
 if($m.phase -ne 'running_unverified' -or -not $m.stage_core -or $m.gui_activated -or $m.proxy_active -or $m.takeover_started -or $m.gui_activation_started -or $m.rollback_task){Fail 'Repair requires the untouched installed staging phase'}
 $task=Get-ScheduledTask -TaskName $m.task
 if($task.State -eq 'Running' -or @(OwnedProcesses $m).Count -ne 0){Fail 'Repair requires an idle owned staging task'}
 if(-not(ProxyEqual (ProxyState) $m.before_proxy) -or (HashText (JSON (CFW))) -ne (HashText (JSON $m.before_cfw))){Fail 'Original CFW or system proxy state changed before repair'}
 $helper=Join-Path $m.root 'host.ps1';$manifest=Join-Path $m.root 'instance.json'
 $old=ReadBytes $helper;$oldManifest=ReadBytes $manifest;$next=[Convert]::FromBase64String($r.helper)
 if($r.repair_original_sha256 -notmatch '^[a-f0-9]{64}$' -or $r.repair_new_sha256 -notmatch '^[a-f0-9]{64}$' -or $m.helper_sha256 -ne $r.repair_original_sha256 -or (HashBytes $old) -ne $r.repair_original_sha256 -or (HashBytes $next) -ne $r.repair_new_sha256){Fail 'Repair helper hashes differ from the original private install payload'}
 $backup=Join-Path $m.root ('host.before-'+$r.repair_original_sha256+'.ps1')
 $manifestBackup=Join-Path $m.root ('instance.before-helper-'+$r.repair_original_sha256+'.json')
 $journal=Join-Path $m.root 'helper-repair.json'
 foreach($path in @($backup,$manifestBackup,$journal)){if(Test-Path -LiteralPath $path){Fail 'A previous helper repair exists; inspect before another repair'}}
 Atomic $backup $old;Atomic $manifestBackup $oldManifest
 SafeACL $backup;SafeACL $manifestBackup
 if((HashBytes (ReadBytes $backup)) -ne $r.repair_original_sha256 -or (HashBytes (ReadBytes $manifestBackup)) -ne $r.expected){Fail 'Repair backup readback changed'}
 $entry=@{id=$m.id;root=$m.root;user_sid=$m.user_sid;original_helper_sha256=$r.repair_original_sha256;new_helper_sha256=$r.repair_new_sha256;original_manifest_sha256=$r.expected;helper_backup=$backup;manifest_backup=$manifestBackup;task_sha256=$m.task_sha256;binary_hashes=$m.binary_hashes;phase='prepared'}
 SaveJSON $journal $entry;SafeACL $journal
 try{
  Atomic $helper $next
  if((HashBytes (ReadBytes $helper)) -ne $r.repair_new_sha256){Fail 'Repair helper readback changed'}
  $m.helper_sha256=$r.repair_new_sha256;SaveManifest $m
  $r.expected='';[void](Owned)
  $entry.phase='complete';$entry.manifest_sha256=HashBytes (ReadBytes $manifest);SaveJSON $journal $entry
 }catch{
  Atomic $helper $old;Atomic $manifest $oldManifest
  $entry.phase='reverted';SaveJSON $journal $entry
  throw
 }
 $out=Result $m
 [Console]::Out.WriteLine((JSON @{status=$out.status;running=$out.running;digest=$out.digest;old_helper_sha256=$r.repair_original_sha256;new_helper_sha256=$r.repair_new_sha256;repair='complete';cfw_and_proxy_preserved=$true}))
}catch{[Console]::Out.WriteLine((JSON @{error='Staged helper repair refused or failed';line=$_.InvocationInfo.ScriptLineNumber;class=$_.Exception.GetType().FullName}))}finally{ReleaseMutationLock}`
	result, err := connection.ExecutePowerShell(ctx, host, script, raw, 16384)
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if json.Unmarshal(result, &summary) != nil || summary["repair"] != "complete" {
		t.Fatalf("repair did not complete: %s", result)
	}
	// Keep only the safe repair summary locally, alongside the original receipt.
	dir, _ := instanceDir(instance.ID, Options{})
	if err := writePrivate(filepath.Join(dir, "helper-repair-result.json"), result); err != nil {
		t.Fatal(err)
	}
	t.Log(string(result))
}
