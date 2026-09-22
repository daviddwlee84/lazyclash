package managedcore

import (
	"context"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWindowsOwnedFailureReadOnlyInspection(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_DIAG_LIVE")
	if host == "" {
		t.Skip("explicit owned Windows failure inspection")
	}
	script := `param([string]$RequestJson)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$r=$RequestJson|ConvertFrom-Json
$root=Join-Path $env:LOCALAPPDATA 'lazyclash\cores\windows-laptop'
$out=@{instance_exists=(Test-Path -LiteralPath $root);manifest_exists=(Test-Path -LiteralPath (Join-Path $root 'instance.json'))}
if($out.manifest_exists){$m=Get-Content -LiteralPath (Join-Path $root 'instance.json') -Raw|ConvertFrom-Json;$out.manifest=@{};foreach($k in @('phase','client','root','app_root','app_path','core_path','home','task','stage_core','gui_activated','proxy_active','takeover_started','installer_pid','core_version','profile_uid')){$out.manifest[$k]=$m.$k}}
$out.files=@();if($out.instance_exists){$out.files=@(Get-ChildItem -LiteralPath $root -Force|Select-Object Name,Length,PSIsContainer)}
$out.app_exists=(Test-Path -LiteralPath 'C:\Program Files\lazyclash\windows-laptop\Clash Verge\clash-verge.exe')
$out.data_exists=(Test-Path -LiteralPath (Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'))
$out.tasks=@(Get-ScheduledTask -TaskName 'lazyclash-windows-laptop','lazyclash-rollback-windows-laptop' -ErrorAction SilentlyContinue|Select-Object TaskName,State)
$out.processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -in @('Clash for Windows.exe','clash-win64.exe','clash-verge.exe','verge-mihomo.exe')}|ForEach-Object {@{name=$_.Name;pid=$_.ProcessId;session=$_.SessionId;path=$_.ExecutablePath}})
$p=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';$out.proxy=@{enabled=[int]$p.ProxyEnable;old_cfw=([string]$p.ProxyServer -eq '127.0.0.1:7891');new_verge=([string]$p.ProxyServer -eq '127.0.0.1:7897');pac_present=([bool]$p.AutoConfigURL)}
$out.transfers=@();$base=Join-Path $env:LOCALAPPDATA 'lazyclash\transfers';if(Test-Path -LiteralPath $base){foreach($d in @(Get-ChildItem -LiteralPath $base -Directory -Filter 'windows-laptop-*')){$meta=Get-Content -LiteralPath (Join-Path $d.FullName 'transfer.json') -Raw|ConvertFrom-Json;$out.transfers+=@{name=$d.Name;dispatched=$meta.dispatched;operation=$meta.transfer_operation;size=$meta.transfer_size}}}
[Console]::Out.WriteLine(($out|ConvertTo-Json -Depth 8 -Compress))`
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	raw, err := connection.ExecutePowerShell(ctx, host, script, []byte(`{}`), 16384)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("invalid inspection")
	}
	t.Log(string(raw))
}

func TestWindowsOwnedPathFailureReadOnly(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_DIAG_LIVE")
	if host == "" {
		t.Skip("explicit owned Windows path failure inspection")
	}
	instance, err := loadInstance("windows-laptop", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if instance.SSHHost != host {
		t.Fatal("diagnostic SSH host differs from the saved owned instance")
	}
	req, err := LoadRequest(instance.ID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := windowsHostRequest(instance, req, "status")
	r.Expected = ""
	request, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	script := windowsHostScript[:strings.Index(windowsHostScript, "\ntry{\n $script:SID=")]
	script = strings.Replace(script, "function Full([string]$Path){", "function StrictFull([string]$Path){", 1)
	script += `
function Full([string]$Path){try{return StrictFull $Path}catch{$script:FailedFrames=@(Get-PSCallStack|Select-Object -First 8|ForEach-Object {@{function=$_.Command;line=$_.ScriptLineNumber}});throw}}
$script:SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$r=Map ($RequestJson|ConvertFrom-Json)
$out=@{unsupported_paths=@();task_info=@{}}
$counts=@{}
foreach($p in @(Get-CimInstance Win32_Process)){
 $path=[string]$p.ExecutablePath;if(-not $path){continue}
 try{[void](StrictFull $path)}catch{
  $kind=if($path -match '^\\\\\?\\'){'extended'}elseif($path -match '^\\\\\.\\'){'device'}elseif($path -notmatch '^[A-Za-z]:[/\\]'){'non-drive'}elseif($path.Substring(2).Contains(':')){'extra-colon'}else{'control-or-quote'}
  $key=$kind+':session'+[string]$p.SessionId
  if(-not $counts.ContainsKey($key)){$counts[$key]=0};$counts[$key]++
 }
}

$out.unsupported_paths=$counts
$i=Get-ScheduledTaskInfo -TaskName 'lazyclash-windows-laptop' -ErrorAction SilentlyContinue
if($i){$out.task_info=@{last_result=$i.LastTaskResult;last_run=$i.LastRunTime.ToUniversalTime().ToString('o')}}
try{$m=Owned;$result=Result $m;$out.result=@{status=$result.status;running=$result.running}}catch{$out.failure=@{class=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber;frames=$script:FailedFrames}}
[Console]::Out.WriteLine((JSON $out))`
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	raw, err := connection.ExecutePowerShell(ctx, host, script, request, 16384)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("invalid readonly path diagnostic")
	}
	t.Log(string(raw))
}

func TestWindowsCFWDescendantsReadOnly(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_DIAG_LIVE")
	if host == "" {
		t.Skip("explicit read-only CFW descendant inspection")
	}
	instance, err := loadInstance("windows-laptop", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if instance.SSHHost != host {
		t.Fatal("diagnostic SSH host differs from the saved owned instance")
	}
	request, err := LoadRequest(instance.ID, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := windowsHostRequest(instance, request, "status")
	r.Expected = ""
	raw, _ := json.Marshal(r)
	script := windowsHostScript[:strings.Index(windowsHostScript, "\ntry{\n $script:SID=")]
	script += `
$script:SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$r=Map ($RequestJson|ConvertFrom-Json);$m=Owned
$all=@(Get-CimInstance Win32_Process);$rows=@();$seen=@{};$session=Session
foreach($old in $m.before_cfw){
 $queue=@($all|Where-Object {[int]$_.ProcessId -eq [int]$old.pid});$directory=[IO.Path]::GetDirectoryName($old.path)
 while($queue.Count -gt 0){
  $p=$queue[0];if($queue.Count -gt 1){$queue=@($queue[1..($queue.Count-1)])}else{$queue=@()}
  if($seen.ContainsKey([int]$p.ProcessId)){continue};$seen[[int]$p.ProcessId]=$true
  $o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
  $inside=$false;try{$inside=Within $p.ExecutablePath $directory}catch{}
  $rows+=@{pid=[int]$p.ProcessId;parent=[int]$p.ParentProcessId;name=$p.Name;path=$p.ExecutablePath;created=$p.CreationDate.ToUniversalTime().ToString('o');same_owner=($o.Sid -eq $script:SID);session=[int]$p.SessionId;reviewed_session=$session;inside_installation=$inside}
  $queue+=@($all|Where-Object {[int]$_.ParentProcessId -eq [int]$p.ProcessId -and $_.CreationDate.ToUniversalTime() -ge $p.CreationDate.ToUniversalTime()})
 }
}
$plan=CFWStopPlan $m
[Console]::Out.WriteLine((JSON @{phase=$m.phase;stage_core=[bool]$m.stage_core;gui_activated=[bool]$m.gui_activated;takeover_started=[bool]$m.takeover_started;rollback_armed=[bool]$m.rollback_task;original_proxy_unchanged=(ProxyEqual (ProxyState) $m.before_proxy);stop_plan_pids=@($plan|ForEach-Object {$_.pid});rows=$rows}))`
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, err := connection.ExecutePowerShell(ctx, host, script, raw, 16384)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(result) {
		t.Fatal("invalid descendant summary")
	}
	t.Log(string(result))
}
