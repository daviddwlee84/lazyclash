param([string]$Helper)
$ErrorActionPreference='Stop'
$tok=$null;$err=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($Helper,[ref]$tok,[ref]$err)
if($err.Count){throw 'Helper parse failed'}
foreach($name in @('Fail','Full','Same','ProcessPathSame','ProcessOwner','OwnedProcesses','Running','ProcessMatches')){
 $f=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$false)
 Invoke-Expression $f.Extent.Text
}
function Check($okay,$message){if(-not $okay){throw $message}}
function Reject($action){try{& $action}catch{return};throw 'Invalid owned path was accepted'}
foreach($unrelated in @('\\?\C:\unrelated.exe','\\.\device','\Device\HarddiskVolume1\app.exe','C:\a:stream','C:\a"b','relative','')){
 Check (-not(ProcessPathSame $unrelated 'C:/owned/core.exe')) 'Unrelated process path matched the owner'
}
Check (ProcessPathSame 'c:/OWNED/core.exe' 'C:/owned/core.exe') 'Ordinary case-insensitive process path no longer matches'
Reject {ProcessPathSame 'C:/owned/core.exe' '\\?\C:\owned\core.exe'}
$script:SID='owner'
function Session(){return 1}
$script:processes=@(
 [pscustomobject]@{ProcessId=1;ExecutablePath='\\?\C:\unrelated.exe';SessionId=1;Owner='owner'},
 [pscustomobject]@{ProcessId=2;ExecutablePath='C:/owned/core.exe';SessionId=1;Owner='owner'},
 [pscustomobject]@{ProcessId=3;ExecutablePath='C:/owned/core.exe';SessionId=1;Owner='foreign'},
 [pscustomobject]@{ProcessId=4;ExecutablePath='C:/owned/core.exe';SessionId=2;Owner='owner'})
function Get-CimInstance {param($ClassName,$Filter) return $script:processes}
function Invoke-CimMethod {param($InputObject,$MethodName) return @{Sid=$InputObject.Owner}}
$m=@{app_path='C:/owned/app.exe';core_path='C:/owned/core.exe'}
$found=@(OwnedProcesses $m)
Check ($found.Count -eq 1 -and $found[0].ProcessId -eq 2) 'External path disrupted owned SID/session filtering'
Check (Running $m) 'Valid core was not observed after unrelated extended path'
$script:processes=@($script:processes[0])
Check (-not(Running $m)) 'Unrelated extended process was reported as running owner'
Check (-not(ProcessMatches $script:processes[0] @{path=$m.core_path})) 'PID reuse with unrelated extended path was accepted'
'PASS: unrelated process paths, strict owner paths, SID/session filtering, PID reuse'
