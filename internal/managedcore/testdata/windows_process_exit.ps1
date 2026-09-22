param([string]$Helper)
$ErrorActionPreference='Stop'
$tok=$null;$err=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($Helper,[ref]$tok,[ref]$err)
if($err.Count){throw 'Helper parse failed'}
foreach($name in @('Fail','ProcessOwner','ProcessRecord','ProcessMatches','OwnedProcesses','StopOwned')){
 $f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$false)
 Invoke-Expression $f.Extent.Text
}
function Check($okay,$message){if(-not $okay){throw $message}}
function Reject($action,$fragment){try{& $action}catch{if($_.Exception.Message -like ('*'+$fragment+'*')){return};throw};throw ('Expected failure: '+$fragment)}
function CimFailure($code){
 $error=[Microsoft.Management.Infrastructure.CimException]::new('CIM fixture '+$code)
 [Microsoft.Management.Infrastructure.CimException].GetProperty('NativeErrorCode').SetValue($error,([Microsoft.Management.Infrastructure.NativeErrorCode]$code))
 return $error
}
$script:SID='owner';$created=[DateTime]::UtcNow.AddMinutes(-1)
$p=[pscustomobject]@{ProcessId=7;ExecutablePath='C:/owned/core.exe';SessionId=1;CreationDate=$created}
$record=@{pid=7;path=$p.ExecutablePath;session=1;created=$created.ToUniversalTime().ToString('o');user_sid='owner';sha256='abcd'}
function Full($path){return $path}
function ProcessPathSame($a,$b){return $a -eq $b}
function NoReparse($path){}
function Get-FileHash {param($LiteralPath,$Algorithm) return @{Hash='abcd'}}
function Session(){return 1}
$script:lookupFailure='NotFound';$script:current=$null;$script:queries=0
function Invoke-CimMethod {param($InputObject,$MethodName,$ErrorAction) if($script:lookupFailure){throw (CimFailure $script:lookupFailure)};return @{Sid='owner';ReturnValue=0}}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) $script:queries++;return $script:current}
Check ($null -eq (ProcessOwner $p)) 'Disappeared process was not recognized'
Check ($null -eq (ProcessRecord $p $true)) 'Stop snapshot did not allow confirmed exit'
Reject {ProcessRecord $p} 'exited during identity verification'
Check (-not(ProcessMatches $p $record)) 'Exited process matched a live identity'
$script:current=$p
Reject {ProcessOwner $p} 'CIM fixture NotFound'
$script:current=[pscustomobject]@{ProcessId=7;CreationDate=$created.AddSeconds(10)}
Check ($null -eq (ProcessOwner $p)) 'Reused PID was treated as the former process'
$script:lookupFailure='AccessDenied';$script:current=$null;$script:queries=0
Reject {ProcessOwner $p} 'CIM fixture AccessDenied'
Check ($script:queries -eq 0) 'Permission error was treated as an exit race'
$script:lookupFailure='Failed'
Reject {ProcessOwner $p} 'CIM fixture Failed'
$script:lookupFailure='';Check ((ProcessOwner $p).Sid -eq 'owner') 'Valid SID lookup failed'

# StopScheduledTask can make a process vanish between any of the three owner
# checks. A fresh PID query confirms exit; no broad stop or mutation retry occurs.
function AssertTask($m){}
function Stop-ScheduledTask {param($TaskName,$ErrorAction) $script:taskStops++}
function Get-ScheduledTask {param($TaskName,$ErrorAction) return @{State='Ready'}}
function Stop-Process {param($Id,[switch]$Force,$ErrorAction) $script:processStops++;$script:gone=$true}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) if(-not $script:gone){return $p};return $null}
function Invoke-CimMethod {param($InputObject,$MethodName,$ErrorAction)
 $script:ownerChecks++
 if($script:ownerChecks -eq $script:disappearAt){$script:gone=$true;throw (CimFailure 'NotFound')}
 return @{Sid='owner';ReturnValue=0}
}
$m=@{task='owned';task_sha256='fixture';core_path=$p.ExecutablePath}
foreach($at in @(1,2,3)){
 $script:disappearAt=$at;$script:ownerChecks=0;$script:gone=$false;$script:taskStops=0;$script:processStops=0
 StopOwned $m
 Check ($script:taskStops -eq 1 -and $script:processStops -eq 0 -and $script:gone) 'Exit race retried or stopped a different process'
}
$script:disappearAt=0;$script:ownerChecks=0;$script:gone=$false;$script:taskStops=0;$script:processStops=0
StopOwned $m
Check ($script:taskStops -eq 1 -and $script:processStops -eq 1) 'Live pinned process was not stopped exactly once'
foreach($name in @('Map','Canonical','JSON')){
 $f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$false)
 Invoke-Expression $f.Extent.Text
}
$outerTry=@($ast.EndBlock.Statements|Where-Object {$_ -is [System.Management.Automation.Language.TryStatementAst]})[-1]
$r=@{op='restart';owner_token='PRIVATE-REQUEST-TOKEN'};$m=@{phase='running_verified'};$RequestPath=''
$diagnosticError=[Microsoft.Management.Infrastructure.CimException]::new('PRIVATE-EXCEPTION-DETAIL')
[Microsoft.Management.Infrastructure.CimException].GetProperty('NativeErrorCode').SetValue($diagnosticError,[Microsoft.Management.Infrastructure.NativeErrorCode]::NotFound)
$capture=New-Object IO.StringWriter
$originalOut=[Console]::Out
try{
 [Console]::SetOut($capture)
 Invoke-Expression ('try{throw $diagnosticError}catch'+$outerTry.CatchClauses[0].Body.Extent.Text)
}finally{[Console]::SetOut($originalOut)}
$diagnostic=$capture.ToString();$capture.Dispose()
Check ($diagnostic -match 'cim_native=6; cim_status=[0-9]+; hresult=-?[0-9]+') 'Safe numeric CIM diagnostic is missing'
Check ($diagnostic -notmatch 'PRIVATE-EXCEPTION|PRIVATE-REQUEST') 'CIM diagnostic leaked exception or request content'
'PASS: CIM exit races, precise NotFound classification, PID reuse, permission errors, bounded stop readback'
