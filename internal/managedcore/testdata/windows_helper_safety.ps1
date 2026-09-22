param([string]$Helper)
$ErrorActionPreference='Stop'
$tok=$null;$err=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($Helper,[ref]$tok,[ref]$err)
if($err.Count){throw ($err|Out-String)}
foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
function Check($okay,$message){if(-not $okay){throw $message}}
function Reject($action,$text){try{& $action}catch{if($_.Exception.Message -like ('*'+$text+'*')){return};throw};throw ('Expected failure: '+$text)}
Check ((JSON @{z=@(1);a=@{x=$true;b=1}}) -eq '{"a":{"b":1,"x":true},"z":[1]}') 'Canonical JSON failed'
foreach($p in @('C:relative','\relative','C:\a:stream','C:\a"b','\\host\share\a')){Reject { Full $p } 'Windows path'}
if(Test-Path -LiteralPath '/bin/echo'){
Check ((CoreCommand '/bin/echo' 'bounded-output' '/tmp' 2).Trim() -eq 'bounded-output') 'Bounded process runner failed'
Reject { CoreCommand '/usr/bin/yes' '' '/tmp' 2 } 'output exceeded'
Reject { CoreCommand '/usr/bin/false' '' '/tmp' 2 } 'validation failed'
}
$before=@{enabled=0;server='old';override='local';auto_config_url='pac'};$applied=@{enabled=1;server='new';override='local';auto_config_url=''}
foreach($state in @($before,$applied,@{enabled=1;server='old';override='local';auto_config_url=''})){Check (ProxyRecoverable $state $before $applied) 'Partial proxy state not recoverable'}
Check (-not(ProxyRecoverable @{enabled=1;server='foreign';override='local';auto_config_url=''} $before $applied)) 'Foreign state accepted'
$script:current=$applied.Clone()
function ProxyState(){return $script:current}
$m=@{proxy_active=$true;applied_proxy=$applied;before_proxy=$before}
AssertStartup $m
$script:current=$before.Clone();Reject { AssertStartup $m } 'changed externally'
$script:current=$applied.Clone();$m.takeover_started=$true;$m.rollback_task='guard';$m.rollback_deadline=[DateTime]::UtcNow.AddMinutes(1).ToString('o')
Reject { AssertStartup $m } 'requires recovery'
AssertStartup $m $false $true
$m.rollback_deadline=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');Reject { AssertStartup $m $false $true } 'requires recovery'
$script:SID='owner';$script:processes=@(
 [pscustomobject]@{ProcessId=1;ExecutablePath='/owned/app';SessionId=1;Owner='owner'},
 [pscustomobject]@{ProcessId=2;ExecutablePath='/owned/app';SessionId=1;Owner='other'},
 [pscustomobject]@{ProcessId=3;ExecutablePath='/owned/app';SessionId=0;Owner='owner'},
 [pscustomobject]@{ProcessId=4;ExecutablePath='/owned/app';SessionId=2;Owner='owner'},
 [pscustomobject]@{ProcessId=5;ExecutablePath='/other/app';SessionId=1;Owner='owner'})
function Session(){return 1}
function Same($a,$b){return $a -eq $b}
function ProcessPathSame($a,$b){return Same $a $b}
function Get-CimInstance {param($ClassName,$Filter) return $script:processes}
function Invoke-CimMethod {param([Alias('InputObject')]$p,[Alias('MethodName')]$method) return @{Sid=$p.Owner}}
$owned=@(OwnedProcesses @{app_path='/owned/app';core_path='/owned/app'})
Check ($owned.Count -eq 1 -and $owned[0].ProcessId -eq 1) 'Process ownership/session filtering failed'
$script:task=$null;$script:taskXML='owned'
function Get-ScheduledTask {param($TaskName,$ErrorAction) return $script:task}
function Export-ScheduledTask {param($TaskName) return $script:taskXML}
AssertTask @{task='task'}
$script:task=@{TaskName='task'};Reject { AssertTask @{task='task'} } 'different scheduled task'
AssertTask @{task='task';task_sha256=(HashText 'owned')}
$script:taskXML='foreign';Reject { AssertTask @{task='task';task_sha256=(HashText 'owned')} } 'identity changed'
$script:events=New-Object 'System.Collections.Generic.List[string]'
function StopOwned($m){$script:events.Add('stop')}
function TaskRegister($m,$boot){Check ($m.stage_core -and -not $m.gui_activated) 'Rollback task was not reset to staging';$script:events.Add('task')}
function VergeProxyPreference($m,$enable){Check (-not $enable) 'Rollback left Verge auto-proxy enabled';$script:events.Add('preference:false')}
function SetProxy($value){$script:current=$value.Clone();$script:events.Add('registry')}
function CFWRestore($m){$script:events.Add('cfw')}
function SaveManifest($m){$script:events.Add('save')}
function DisarmGuard($m){$script:events.Add('disarm');$m.Remove('rollback_task')}
$m=@{client='verge';proxy_active=$false;takeover_started=$true;cfw_stop_started=$true;before_proxy=$before;applied_proxy=$applied;rollback_task='guard'}
$script:current=@{enabled=1;server='old';override='local';auto_config_url=''}
RestoreProxy $m
Check (ProxyEqual $script:current $before) 'Partial rollback failed'
Check (-not $m.proxy_active -and -not $m.takeover_started -and -not $m.rollback_task) 'Rollback ownership not cleared'
Check (($script:events -join ',') -eq 'save,stop,preference:false,task,save,registry,cfw,registry,save,disarm,save') 'Unsafe rollback order'
$script:events.Clear();$m.proxy_active=$true;$script:current=@{enabled=1;server='foreign';override='local';auto_config_url=''}
Reject { RestoreProxy $m } 'changed externally'
Check ($script:events.Count -eq 0) 'Foreign proxy modified before refusal'
$script:current=$before.Clone();Reject { RestoreProxy $m } 'changed externally';Check ($script:events.Count -eq 0) 'Acknowledged proxy accepted an external revert'
'PASS: AST, deterministic JSON, path rejection, bounded core process/output, partial proxy rollback, startup ownership, task identity, SID/session process filtering'
# Guarded commit test uses only a private local temporary directory and mocked ACL/Windows path plumbing.
function Full($path){return [IO.Path]::GetFullPath($path)}
function NoReparse($path){}
function SafeACL($path,$private=$true){}
function PrivateDir($path){[void][IO.Directory]::CreateDirectory($path)}
function SourceAllowed($m,$path,$write=$false){}
$script:mutateDependency=''
function Atomic($path,[byte[]]$bytes){[IO.File]::WriteAllBytes($path,$bytes);if($script:mutateDependency){[IO.File]::WriteAllText($script:mutateDependency,'foreign');$script:mutateDependency=''}}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('lc-win-check-'+[Guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($fixture)
try{
 $base=Join-Path $fixture 'base.yaml';$dep=Join-Path $fixture 'dep.yaml';[IO.File]::WriteAllText($base,'before');[IO.File]::WriteAllText($dep,'dependency')
 $m=@{home=$fixture};$baseGuard=@{path=$base;fingerprint=(SourceRead $m $base).fingerprint};$depGuard=@{path=$dep;fingerprint=(SourceRead $m $dep).fingerprint}
 Reject { WriteSource $m @{path=$base;guards=@()} ([Text.Encoding]::UTF8.GetBytes('after')) } 'before-image guard'
 Check ([IO.File]::ReadAllText($base) -eq 'before') 'Unguarded write changed source'
 $script:mutateDependency=$dep
 Reject { WriteSource $m @{path=$base;guards=@($baseGuard,$depGuard)} ([Text.Encoding]::UTF8.GetBytes('after')) } 'changed after preview'
 Check ([IO.File]::ReadAllText($base) -eq 'before') 'Dependency conflict changed source'
 $result=WriteSource $m @{path=$base;guards=@($baseGuard)} ([Text.Encoding]::UTF8.GetBytes('after'))
 Check ($result.sha256 -eq (HashText 'after') -and [IO.File]::ReadAllText($base) -eq 'after') 'Guarded commit readback failed'
 Check (@(Get-ChildItem -LiteralPath $fixture -Force|Where-Object Name -like '.lazyclash-*').Count -eq 0) 'Temporary source leaked'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
function Result($m){return @{manifest=@{}}}
$script:validated=0
function ValidateProfile($m,$document){$script:validated++}
function CoreVersion($binary,$ownedHome){return 'v1.2.3'}
$m=@{core_path='C:/owned/mihomo.exe';home='C:/owned/home';core_version='v1.2.3'}
$r=@{source=@{op='validate';binary=$m.core_path;home=$m.home;version=$m.core_version;document=@{rules=@('MATCH,DIRECT')}}}
foreach($key in @('binary','home','version')){$old=$r.source[$key];$r.source[$key]='foreign';Reject { Source $m } 'validator differs';$r.source[$key]=$old}
Check ($script:validated -eq 0) 'Unpinned validator ran'
[void](Source $m);Check ($script:validated -eq 1) 'Pinned validator did not run'
'PASS: guarded before-image commit, dependency race refusal, source readback/cleanup, validator identity'
# Re-load the real process-plan functions replaced by prior rollback mocks.
foreach($name in @('CFWStopPlan','StopCFW','ProcessRecord','ProcessMatches')){$f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$false);Invoke-Expression $f.Extent.Text}
$created=[DateTime]::UtcNow.AddMinutes(-10)
$script:processes=@(
 [pscustomobject]@{ProcessId=10;ParentProcessId=1;ExecutablePath='/cfw/app';SessionId=1;Owner='owner';CreationDate=$created},
 [pscustomobject]@{ProcessId=11;ParentProcessId=10;ExecutablePath='/cfw/core';SessionId=1;Owner='owner';CreationDate=$created.AddSeconds(1)},
 [pscustomobject]@{ProcessId=12;ParentProcessId=1;ExecutablePath='/cfw/app';SessionId=2;Owner='owner';CreationDate=$created},
 [pscustomobject]@{ProcessId=13;ParentProcessId=1;ExecutablePath='/cfw/app';SessionId=1;Owner='other';CreationDate=$created},
 [pscustomobject]@{ProcessId=14;ParentProcessId=10;ExecutablePath='/cfw/core';SessionId=1;Owner='owner';CreationDate=$created.AddSeconds(-1)},
 [pscustomobject]@{ProcessId=15;ParentProcessId=11;ExecutablePath='/windows/conhost';SessionId=1;Owner='owner';CreationDate=$created.AddSeconds(2)},
 [pscustomobject]@{ProcessId=16;ParentProcessId=10;ExecutablePath='/browser/app';SessionId=1;Owner='owner';CreationDate=$created.AddSeconds(2)},
 [pscustomobject]@{ProcessId=17;ParentProcessId=16;ExecutablePath='/cfw/child-of-unowned';SessionId=1;Owner='owner';CreationDate=$created.AddSeconds(3)})
function Get-CimInstance {param($ClassName,$Filter) if($Filter){return $script:processes|Where-Object ProcessId -eq ([int]($Filter -replace 'ProcessId=',''))};return $script:processes}
function Get-FileHash {param($LiteralPath,$Algorithm) return @{Hash='abcd'}}
function Within($path,$parent){return $path.StartsWith($parent+'/') -or $path -eq $parent}
$m=@{before_cfw=@((ProcessRecord $script:processes[0]))}
$plan=CFWStopPlan $m
Check ($plan.Count -eq 2 -and $plan[0].pid -eq 10 -and $plan[1].pid -eq 11) 'CFW plan crossed owner, external executable branch, or reused parent PID'
$script:processes[1].Owner='other';Reject { CFWStopPlan $m } 'descendant identity';$script:processes[1].Owner='owner'
# The unrelated old core exits independently before takeover; it was never in
# the stop plan. A still-running same-owner core would correctly block readback.
$script:processes=@($script:processes|Where-Object ProcessId -ne 14)
$script:stopped=@()
function Stop-Process {param($Id,[switch]$Force,$ErrorAction) $script:stopped+= $Id}
function Start-Sleep {param($Milliseconds) $script:stopWaits++;$script:processes=@($script:processes|Where-Object {$_.ProcessId -notin $script:stopped})}
$m.cfw_stop_plan=$plan
$beforeStop=@($script:processes)
$script:stopWaits=0
StopCFW $m
Check (($script:stopped -join ',') -eq '10,11') 'CFW stop crossed plan boundaries'
Check ($script:stopWaits -eq 1) 'CFW stop did not wait for observed process exit'
Check (@($script:processes|Where-Object {$_.ProcessId -in @(15,16,17)}).Count -eq 3) 'External descendants were stopped'
Remove-Item Function:Start-Sleep
$script:stopped=@();$script:processes=$beforeStop;$script:processes[0].CreationDate=$created.AddSeconds(3)
Reject { StopCFW $m } 'identity changed'
Check ($script:stopped.Count -eq 0) 'Reused PID was stopped'
'PASS: CFW tree scope, owner/session separation, parent PID reuse and stop identity checks'
# Post-start socket ownership proof remains read-only and rejects broad or foreign listeners.
$script:processes=@([pscustomobject]@{ProcessId=20;ParentProcessId=1;ExecutablePath='/owned/core';SessionId=1;Owner='owner';CreationDate=$created})
$script:listeners=@([pscustomobject]@{LocalPort=19097;LocalAddress='127.0.0.1';OwningProcess=20},[pscustomobject]@{LocalPort=17897;LocalAddress='::1';OwningProcess=20})
function Get-NetTCPConnection {param($State,$ErrorAction) return $script:listeners}
$m=@{controller_port=19097;mixed_port=17897;core_path='/owned/core';binary_hashes=@{core_path='abcd'}}
Check ((VerifyRuntime $m).manifest.loopback_listeners_verified) 'Owned listener verification failed'
$script:listeners[0].LocalAddress='0.0.0.0';Reject { VerifyRuntime $m } 'loopback only';$script:listeners[0].LocalAddress='127.0.0.1'
$script:processes[0].Owner='foreign';Reject { VerifyRuntime $m } 'pinned core';$script:processes[0].Owner='owner'
$script:processes[0].SessionId=0;Reject { VerifyRuntime $m } 'desktop session';$script:processes[0].SessionId=1
$script:listeners=@($script:listeners[0]);Reject { VerifyRuntime $m } 'listener is missing'
# Every task, including GUI startup after logon, passes through the pinned owner launcher.
$f=$ast.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'TaskRegister'},$false);Invoke-Expression $f.Extent.Text
function AssertTask($m){}
function SaveJSON($path,$value){$script:launchRequest=$value}
function ReadBytes($path,$limit=8388608){return ,[Text.Encoding]::UTF8.GetBytes((JSON $script:launchRequest))}
function New-ScheduledTaskPrincipal {return @{}}
function New-ScheduledTaskAction {param($Execute,$Argument,$WorkingDirectory) return @{execute=$Execute;arguments=$Argument}}
function New-ScheduledTaskSettingsSet {return @{}}
function New-ScheduledTask {param($Action,$Principal,$Settings) return [pscustomobject]@{Actions=@($Action);Triggers=@()}}
function Register-ScheduledTask {param($TaskName,$InputObject,[switch]$Force) $script:registered=$InputObject}
function Export-ScheduledTask {param($TaskName) return JSON $script:registered}
$env:SystemRoot='/windows'
foreach($case in @(@{client='mihomo';stage_core=$false;expected='launch-core'},@{client='verge';stage_core=$true;expected='launch-core'},@{client='verge';stage_core=$false;expected='launch-gui'})){
 $m=@{client=$case.client;stage_core=$case.stage_core;root='/owner';home='/home';id='owned';owner_token='fixture';task='owner-task'}
 TaskRegister $m $false
 Check ($script:launchRequest.op -eq $case.expected) 'Task launched GUI before reviewed activation'
 Check ($script:registered.Actions[0].execute -like '*powershell.exe' -and $script:registered.Actions[0].arguments -like '*-WindowStyle Hidden*') 'Task bypassed pinned hidden launcher'
}
# No-takeover GUI activation refuses an active proxy or automatic configuration before any stop/start.
function AssertGUIEnvironment(){}
$script:events.Clear();$m=@{client='verge';system_proxy_requested=$false;before_proxy=@{flags=3;enabled=1;server='old';override='local';auto_config_url=''}};$script:current=$m.before_proxy.Clone()
Reject { ActivateGUI $m } 'remain inactive';Check ($script:events.Count -eq 0) 'Active proxy modified during GUI staging'
$m.before_proxy=@{flags=9;enabled=0;server='old';override='local';auto_config_url=''};$script:current=$m.before_proxy.Clone()
Reject { ActivateGUI $m } 'remain inactive'
'PASS: socket loopback/PID/SID/session verification, staged task roles, guarded GUI launcher, inactive-only GUI activation'
