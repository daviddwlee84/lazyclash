param([string]$RequestJson,[string]$RequestPath)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
function Fail([string]$Reason){throw ('LCWIN:'+ $Reason)}
function Map($Value){
 if($null -eq $Value){return $null}
 if($Value -is [System.Collections.IDictionary]){$h=@{};foreach($k in $Value.Keys){$h[$k]=Map $Value[$k]};return $h}
 if($Value -is [System.Management.Automation.PSCustomObject]){$h=@{};foreach($p in $Value.PSObject.Properties){$h[$p.Name]=Map $p.Value};return $h}
 if($Value -is [array]){return ,@($Value|ForEach-Object {Map $_})};return $Value
}
function Canonical($Value){
 if($null -eq $Value){return $null}
 if($Value -is [System.Collections.IDictionary]){$o=[ordered]@{};foreach($k in @($Value.Keys|Sort-Object)){$o[$k]=Canonical $Value[$k]};return $o}
 if($Value -is [System.Management.Automation.PSCustomObject]){return Canonical (Map $Value)}
 if($Value -is [array]){return ,@($Value|ForEach-Object {Canonical $_})};return $Value
}
function JSON($Value){return ConvertTo-Json -InputObject (Canonical $Value) -Depth 100 -Compress}
function HashBytes([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function HashText([string]$Text){return HashBytes ([Text.Encoding]::UTF8.GetBytes($Text))}
function Full([string]$Path){
 if([string]::IsNullOrWhiteSpace($Path) -or $Path -match '[\x00-\x1f"]' -or $Path -match '^\\\\[.?]\\' -or $Path.Substring([Math]::Min(2,$Path.Length)).Contains(':')){Fail 'Invalid Windows path'}
 if($Path -notmatch '^[A-Za-z]:[/\\]'){Fail 'Windows paths must use an absolute local drive'}
 return [IO.Path]::GetFullPath($Path.Replace('/','\')).TrimEnd('\')
}
function Same([string]$A,[string]$B){return [string]::Equals((Full $A),(Full $B),[StringComparison]::OrdinalIgnoreCase)}
# ExecutablePath is untrusted inventory. Unrelated device/extended paths must
# not abort an owned process scan, while the recorded owner remains strict.
function ProcessPathSame([string]$Observed,[string]$OwnedPath){
 $expected=Full $OwnedPath
 try{$candidate=Full $Observed}catch{return $false}
 return [string]::Equals($candidate,$expected,[StringComparison]::OrdinalIgnoreCase)
}
function Within([string]$Path,[string]$Parent){$p=Full $Path;$b=Full $Parent;return (Same $p $b) -or $p.StartsWith($b+'\',[StringComparison]::OrdinalIgnoreCase)}
function NoReparse([string]$Path){
 $p=Full $Path
 while($p){if(Test-Path -LiteralPath $p){$i=Get-Item -LiteralPath $p -Force;if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail 'Owned paths cannot traverse reparse points'}};$parent=[IO.Path]::GetDirectoryName($p);if($parent -eq $p){break};$p=$parent}
}

function SafeACL([string]$Path,[bool]$Private=$true){
 NoReparse $Path
 $acl=Get-Acl -LiteralPath $Path
 $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 $trusted=@($script:SID,'S-1-5-18','S-1-5-32-544')
 if($owner -notin $trusted){Fail 'Owned path has an unexpected ACL owner'}
 $write=[int64]([Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,DeleteSubdirectoriesAndFiles,Delete,ChangePermissions,TakeOwnership')
 foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $ace.IdentityReference.Value -notin $trusted -and ($Private -or ([int64]$ace.FileSystemRights -band $write))){Fail 'Owned path grants access outside its reviewed owner'}
 }
}
function PrivateDir([string]$Path){
 NoReparse $Path
 if(Test-Path -LiteralPath $Path){if(-not(Get-Item -LiteralPath $Path -Force).PSIsContainer){Fail 'Owned directory is not a directory'};SafeACL $Path;return}
 [void][IO.Directory]::CreateDirectory($Path)
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false);$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($script:SID)))
 foreach($sid in @($script:SID,'S-1-5-18','S-1-5-32-544')){$rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);[void]$acl.AddAccessRule($rule)}
 Set-Acl -LiteralPath $Path -AclObject $acl;SafeACL $Path
}
function AcquireMutationLock(){
 $dir=Join-Path $env:LOCALAPPDATA 'lazyclash\locks';PrivateDir $dir
 $path=Join-Path $dir ($r.id+'.lock');NoReparse $path
 $deadline=[DateTime]::UtcNow.AddSeconds(60)
 while($true){
  try{$script:MutationLock=[IO.File]::Open($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);break}
  catch [IO.IOException]{if([DateTime]::UtcNow -ge $deadline){Fail 'Another Windows owner operation holds the mutation lock'};Start-Sleep -Milliseconds 200}
 }
 SafeACL $path
}
function ReleaseMutationLock(){if($script:MutationLock){$script:MutationLock.Dispose();$script:MutationLock=$null}}
function ReadBytes([string]$Path,[long]$Limit=8388608){
 NoReparse $Path;$i=Get-Item -LiteralPath $Path -Force
 if($i.PSIsContainer -or $i.Length -gt $Limit){Fail 'Source must be a bounded regular file'}
 $bytes=[IO.File]::ReadAllBytes($i.FullName);$after=Get-Item -LiteralPath $Path -Force
 if($i.Length -ne $after.Length -or $i.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks){Fail 'Source changed while reading'}
 return ,$bytes
}
function Atomic([string]$Path,[byte[]]$Bytes){
 NoReparse $Path;$dir=[IO.Path]::GetDirectoryName((Full $Path));PrivateDir $dir
 $tmp=Join-Path $dir ('.lazyclash-'+[Guid]::NewGuid().ToString('N'))
 try{[IO.File]::WriteAllBytes($tmp,$Bytes);if(Test-Path -LiteralPath $Path){[IO.File]::Replace($tmp,$Path,[NullString]::Value)}else{[IO.File]::Move($tmp,$Path)}}finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}}
}
function SaveJSON([string]$Path,$Value){Atomic $Path ([Text.Encoding]::UTF8.GetBytes((JSON $Value)))}
function ReadJSON([string]$Path){return Map (([Text.Encoding]::UTF8.GetString((ReadBytes $Path)))|ConvertFrom-Json)}
function NetworkInterop(){
 if('Lazyclash.WindowsNetworkState' -as [type]){return}
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Lazyclash {
 public static class WindowsNetworkState {
  [StructLayout(LayoutKind.Sequential)] struct Option { public uint kind; public IntPtr value; }
  [StructLayout(LayoutKind.Sequential)] struct OptionList { public uint size; public IntPtr connection; public uint count; public uint error; public IntPtr options; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct EntryName { public uint size; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string name; public uint flags; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=261)] public string phonebook; }
  [DllImport("wininet.dll",EntryPoint="InternetQueryOptionW",SetLastError=true)] static extern bool Query(IntPtr internet,uint option,IntPtr buffer,ref uint size);
  [DllImport("wininet.dll",EntryPoint="InternetSetOptionW",SetLastError=true)] static extern bool Set(IntPtr internet,uint option,IntPtr buffer,uint size);
  [DllImport("rasapi32.dll",EntryPoint="RasEnumEntriesW",CharSet=CharSet.Unicode)] static extern uint Entries(string reserved,string phonebook,IntPtr entries,ref uint size,out uint count);
  public static uint ProxyFlags(bool write,uint flags) {
   int os=Marshal.SizeOf(typeof(Option)), ls=Marshal.SizeOf(typeof(OptionList));
   IntPtr op=Marshal.AllocHGlobal(os), list=Marshal.AllocHGlobal(ls);
   try {
    Marshal.StructureToPtr(new Option{kind=1,value=new IntPtr((long)flags)},op,false);
    Marshal.StructureToPtr(new OptionList{size=(uint)ls,connection=IntPtr.Zero,count=1,error=0,options=op},list,false);
    uint size=(uint)ls;
    bool okay=write?Set(IntPtr.Zero,75,list,size):Query(IntPtr.Zero,75,list,ref size);
    if(!okay) throw new InvalidOperationException("WinInet flags operation failed");
    if(write){Set(IntPtr.Zero,39,IntPtr.Zero,0);Set(IntPtr.Zero,37,IntPtr.Zero,0);return flags;}
    return unchecked((uint)((Option)Marshal.PtrToStructure(op,typeof(Option))).value.ToInt64());
   } finally {Marshal.FreeHGlobal(op);Marshal.FreeHGlobal(list);}
  }
  public static uint RASEntryCount() {
   uint size=(uint)Marshal.SizeOf(typeof(EntryName)), count=0;
   IntPtr p=Marshal.AllocHGlobal((int)size);
   try {
    Marshal.WriteInt32(p,(int)size);
    uint result=Entries(null,null,p,ref size,out count);
    if(result==603){if(size>16777216)throw new InvalidOperationException("RAS enumeration exceeds bound");Marshal.FreeHGlobal(p);p=IntPtr.Zero;p=Marshal.AllocHGlobal((int)size);Marshal.WriteInt32(p,Marshal.SizeOf(typeof(EntryName)));result=Entries(null,null,p,ref size,out count);}
    if(result!=0)throw new InvalidOperationException("RAS enumeration failed");
    return count;
   } finally {if(p!=IntPtr.Zero)Marshal.FreeHGlobal(p);}
  }
 }
}
'@ | Out-Null
}
function RASCount(){NetworkInterop;return [Lazyclash.WindowsNetworkState]::RASEntryCount()}
function AssertGUIEnvironment(){if((RASCount) -gt 0){Fail 'Native Verge proxy control cannot safely restore existing RAS or VPN connection settings'};if(Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue){Fail 'An unowned Verge service appeared; native GUI startup refused'}}
function ProxyState(){
 NetworkInterop;$flags=[Lazyclash.WindowsNetworkState]::ProxyFlags($false,0)
 $key=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
 return @{flags=$flags;enabled=[int]$key.ProxyEnable;server=[string]$key.ProxyServer;override=[string]$key.ProxyOverride;auto_config_url=[string]$key.AutoConfigURL}
}
function ProxyEqual($A,$B){return [uint32]$A.flags -eq [uint32]$B.flags -and [int]$A.enabled -eq [int]$B.enabled -and [string]$A.server -ceq [string]$B.server -and [string]$A.override -ceq [string]$B.override -and [string]$A.auto_config_url -ceq [string]$B.auto_config_url}
function SetProxy($Value){
 $path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
 Set-ItemProperty $path ProxyEnable ([int]$Value.enabled) -Type DWord
 Set-ItemProperty $path ProxyServer ([string]$Value.server) -Type String
 Set-ItemProperty $path ProxyOverride ([string]$Value.override) -Type String
 if($Value.auto_config_url){Set-ItemProperty $path AutoConfigURL ([string]$Value.auto_config_url) -Type String}else{Remove-ItemProperty $path AutoConfigURL -ErrorAction SilentlyContinue}
 if(-not('Lazyclash.WinInet' -as [type])){Add-Type -TypeDefinition 'namespace Lazyclash { public static class WinInet { [System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(System.IntPtr h,int o,System.IntPtr b,int n); }}' | Out-Null}
 [void][Lazyclash.WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0);[void][Lazyclash.WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)
 NetworkInterop;$flags=if($Value.ContainsKey('flags')){[uint32]$Value.flags}elseif([int]$Value.enabled -ne 0){[uint32]3}else{[uint32]1};[void][Lazyclash.WindowsNetworkState]::ProxyFlags($true,$flags)
 if(-not(ProxyEqual (ProxyState) $Value)){Fail 'System proxy write was not observed'}
}
function Session(){
 $ids=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {$o=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid;if($o.Sid -eq $script:SID -and $_.SessionId -gt 0){[int]$_.SessionId}}|Sort-Object -Unique)
 if($ids.Count -eq 1){return $ids[0]};return 0
}

function ProcessOwner($p){
 try{
  $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
  if(-not $owner.Sid -or ($owner.ReturnValue -and [int]$owner.ReturnValue -ne 0)){Fail 'Process owner lookup did not return a verified SID'}
  return $owner
 }catch [Microsoft.Management.Infrastructure.CimException]{
  if($_.Exception.NativeErrorCode -ne [Microsoft.Management.Infrastructure.NativeErrorCode]::NotFound){throw}
  # A task stop may reap a process after enumeration. Only a recognized
  # NotFound plus absence of that exact process generation is an ordinary exit.
  $current=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$p.ProcessId) -ErrorAction Stop
  if(-not $current -or $current.CreationDate.ToUniversalTime() -ne $p.CreationDate.ToUniversalTime()){return $null}
  throw
 }
}
function ProcessRecord($p,[bool]$AllowExited=$false){
 if(-not $p.ExecutablePath){Fail 'Process executable identity is unavailable'}
 $o=ProcessOwner $p
 if(-not $o){if($AllowExited){return $null};Fail 'Process exited during identity verification'}
 return @{pid=[int]$p.ProcessId;path=(Full $p.ExecutablePath);sha256=(Get-FileHash -LiteralPath $p.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant();created=$p.CreationDate.ToUniversalTime().ToString('o');user_sid=$o.Sid;session=[int]$p.SessionId}
}
function ProcessMatches($p,$record){
 if(-not $p -or -not $record -or -not $p.ExecutablePath -or -not(ProcessPathSame $p.ExecutablePath $record.path) -or $p.CreationDate.ToUniversalTime().ToString('o') -ne $record.created -or [int]$p.SessionId -ne [int]$record.session){return $false}
 $owner=ProcessOwner $p
 if(-not $owner){return $false}
 if($owner.Sid -ne $script:SID -or $record.user_sid -ne $script:SID){return $false}
 NoReparse $p.ExecutablePath
 return (Get-FileHash -LiteralPath $p.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -eq $record.sha256
}
function OwnedProcesses($m){
 $session=Session;if($session -eq 0){return}
 $items=@();foreach($p in @(Get-CimInstance Win32_Process)){
  if(-not $p.ExecutablePath -or [int]$p.SessionId -ne $session){continue}
  if(($m.app_path -and (ProcessPathSame $p.ExecutablePath $m.app_path)) -or ($m.core_path -and (ProcessPathSame $p.ExecutablePath $m.core_path))){$o=ProcessOwner $p;if($o -and $o.Sid -eq $script:SID){$items+=$p}}
 };return $items
}
function AssertTask($m){
 $task=Get-ScheduledTask -TaskName $m.task -ErrorAction SilentlyContinue
 if($m.task_sha256){if(-not $task -or (HashText (Export-ScheduledTask -TaskName $m.task)) -ne $m.task_sha256){Fail 'Owned scheduled task identity changed'}}
 elseif($task){Fail 'A different scheduled task owns this name'}
}
function CFW(){
 $items=@();foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='Clash for Windows.exe'"|Sort-Object ProcessId)){
  if(-not $p.ExecutablePath -or $p.CommandLine -match '--type='){continue};$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
  if($o.Sid -eq $script:SID){$items+=@{pid=[int]$p.ProcessId;path=$p.ExecutablePath;sha256=(Get-FileHash -LiteralPath $p.ExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant();created=$p.CreationDate.ToUniversalTime().ToString('o');user_sid=$o.Sid;session=[int]$p.SessionId}}
 };return ,$items
}
function ExpectedRoot(){return Join-Path $env:LOCALAPPDATA ('lazyclash\cores\'+$r.id)}
function DataRoot(){return Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'}
function Facts(){
 $root=ExpectedRoot;$verge=DataRoot;$busy=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object {$_.LocalPort -eq [int]$r.controller_port -or $_.LocalPort -eq [int]$r.mixed_port}|Select-Object -ExpandProperty LocalPort -Unique)
 $apps=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(clash-verge|verge-mihomo).*\.exe$'})
 $rasEntries=RASCount
 $vergeService=Get-Service -Name 'clash_verge_service' -ErrorAction SilentlyContinue
 $installed=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'Clash Verge'})
 $f=@{windows_ras_entries=$rasEntries;os='windows';arch=if(@(Get-CimInstance Win32_Processor)[0].Architecture -eq 9){'amd64'}elseif(@(Get-CimInstance Win32_Processor)[0].Architecture -eq 12){'arm64'}else{'386'};home=$env:USERPROFILE;local_app_data=$env:LOCALAPPDATA;program_files=$env:ProgramFiles;user_sid=$script:SID;interactive_session=(Session);task_scheduler=((Get-Service Schedule).Status -eq 'Running');is_root=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);busy_ports=$busy;existing=(Test-Path -LiteralPath $root);verge_existing=((Test-Path -LiteralPath $verge) -or $apps.Count -gt 0 -or $installed.Count -gt 0 -or $null -ne $vergeService);verge_data_dir=$verge;windows_proxy=(ProxyState);windows_cfw=(CFW)}
 $guard=@{ras_entries=$rasEntries;user_sid=$f.user_sid;session=$f.interactive_session;proxy=$f.windows_proxy;cfw=$f.windows_cfw;existing=$f.existing;verge_existing=$f.verge_existing;busy_ports=$f.busy_ports}
 $f.windows_state_digest=HashText (JSON $guard);return @{facts=$f;status='inspected'}
}

function Owned(){
 if(-not(Same $r.root (ExpectedRoot)) -or $r.user_sid -ne $script:SID){Fail 'Windows instance root or user SID differs from the reviewed owner'}
 SafeACL $r.root;$path=Join-Path $r.root 'instance.json';SafeACL $path;$raw=ReadBytes $path;$m=Map (([Text.Encoding]::UTF8.GetString($raw))|ConvertFrom-Json)
 if($m.id -ne $r.id -or $m.owner_token -ne $r.owner_token -or $m.user_sid -ne $script:SID -or -not(Same $m.root $r.root)){Fail 'Windows managed ownership does not match'}
 if($r.expected -and (HashBytes $raw) -ne $r.expected){Fail 'Windows owner state changed; review a fresh action'}
 foreach($key in @('app_path','core_path')){if($m[$key]){SafeACL $m[$key] $false;if((Get-FileHash -LiteralPath $m[$key] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $m.binary_hashes[$key]){Fail 'An owned executable changed; refuse service control'}}}
 if($m.helper_sha256){$helper=Join-Path $m.root 'host.ps1';SafeACL $helper;if((HashBytes (ReadBytes $helper)) -ne $m.helper_sha256){Fail 'Owned Windows launcher changed'}}
 AssertTask $m
 if($m.client -eq 'verge' -and $m.data_root){SafeACL $m.data_root;$marker=Join-Path $m.data_root 'lazyclash-owner.json';SafeACL $marker;$mark=ReadJSON $marker;if($mark.owner_token -ne $m.owner_token -or $mark.id -ne $m.id -or $mark.user_sid -ne $script:SID -or -not(Same $mark.root $m.root)){Fail 'Verge profile directory has a different owner'}}
 return $m
}
function SaveManifest($m){$m.updated_at=[DateTime]::UtcNow.ToString('o');SaveJSON (Join-Path $r.root 'instance.json') $m}

function Result($m){$raw=ReadBytes (Join-Path $r.root 'instance.json');return @{status=$m.phase;digest=(HashBytes $raw);running=(Running $m);core_version=$m.core_version;core_path=$m.core_path;app_path=$m.app_path;manifest=@{profile_sha256=$m.profile_sha256;phase=$m.phase;user_sid=$m.user_sid;client=$m.client;data_root=$m.data_root;rollback_armed=[bool]$m.rollback_task;rollback_deadline=$m.rollback_deadline;stage_core=[bool]$m.stage_core;gui_activated=[bool]$m.gui_activated}}}

function Running($m){if(-not $m.core_path){return $false};foreach($p in @(OwnedProcesses $m)){if(ProcessPathSame $p.ExecutablePath $m.core_path){return $true}};return $false}

function VerifyRuntime($m){
 $session=Session;if($session -eq 0){Fail 'Runtime listener verification requires the reviewed desktop session'}
 $listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {[int]$_.LocalPort -in @([int]$m.controller_port,[int]$m.mixed_port)})
 $corePID=0
 foreach($port in @([int]$m.controller_port,[int]$m.mixed_port)){
  $matches=@($listeners|Where-Object {[int]$_.LocalPort -eq $port})
  if($matches.Count -eq 0){Fail 'An owned runtime listener is missing'}
  foreach($listener in $matches){
   if([string]$listener.LocalAddress -notin @('127.0.0.1','::1')){Fail 'Owned Windows listeners must bind loopback only'}
   $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$listener.OwningProcess)
   if(-not $p -or -not $p.ExecutablePath -or -not(ProcessPathSame $p.ExecutablePath $m.core_path) -or [int]$p.SessionId -ne $session){Fail 'Runtime listener belongs to a different core or desktop session'}
   $record=ProcessRecord $p
   if($record.user_sid -ne $script:SID -or $record.sha256 -ne $m.binary_hashes.core_path -or ($corePID -ne 0 -and $corePID -ne [int]$p.ProcessId)){Fail 'Runtime listener owner differs from the pinned core'}
   $corePID=[int]$p.ProcessId
  }
 }
 $out=Result $m;$out.manifest.loopback_listeners_verified=$true
 if($r.verify_generated){if($m.client -ne 'verge' -or -not $m.gui_activated){Fail 'Generated profile verification requires the owned native GUI'};$out.source=@{file=(SourceRead $m (Join-Path $m.home 'clash-verge.yaml'))}}
 return $out
}

function TaskRegister($m,[bool]$Boot){
 if((Session) -eq 0){Fail 'The recorded Windows user must have one interactive desktop session'}
 AssertTask $m
 $principal=New-ScheduledTaskPrincipal -UserId $script:SID -LogonType Interactive -RunLevel Limited
 $launch=Join-Path $m.root 'launch.json'
 $op=if($m.client -eq 'verge' -and -not $m.stage_core){'launch-gui'}else{'launch-core'}
 SaveJSON $launch @{op=$op;id=$m.id;root=$m.root;user_sid=$script:SID;owner_token=$m.owner_token;client=$m.client}
 $m.launch_sha256=HashBytes (ReadBytes $launch)
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $m.root 'host.ps1')+'" -RequestPath "'+$launch+'"') -WorkingDirectory $m.home
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
 $task=New-ScheduledTask -Action $action -Principal $principal -Settings $settings
 if($Boot){$task.Triggers=@(New-ScheduledTaskTrigger -AtLogOn -User $script:SID)}
 AssertTask $m
 if($m.task_sha256){Register-ScheduledTask -TaskName $m.task -InputObject $task -Force | Out-Null}else{Register-ScheduledTask -TaskName $m.task -InputObject $task | Out-Null}
 $m.task_sha256=HashText (Export-ScheduledTask -TaskName $m.task);$m.boot=$Boot
}

function StopOwned($m){
 if((Session) -eq 0){Fail 'Stopping the owned client requires the reviewed desktop session'}
 AssertTask $m
 if($m.task_sha256){Stop-ScheduledTask -TaskName $m.task -ErrorAction SilentlyContinue}
 foreach($p in @(OwnedProcesses $m)){$record=ProcessRecord $p $true;if(-not $record){continue};$current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ProcessId);if(ProcessMatches $current $record){Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue}}
 $deadline=[DateTime]::UtcNow.AddSeconds(5)
 do{$remaining=@(OwnedProcesses $m);$task=Get-ScheduledTask -TaskName $m.task -ErrorAction SilentlyContinue;if($remaining.Count -eq 0 -and $task.State -ne 'Running'){return};if([DateTime]::UtcNow -ge $deadline){Fail 'Owned processes or startup task did not stop within five seconds'};Start-Sleep -Milliseconds 100}while($true)
}

function ProxyInactive($Value){return ([uint32]$Value.flags -band 14) -eq 0 -and [int]$Value.enabled -eq 0 -and [string]::IsNullOrEmpty([string]$Value.auto_config_url)}
function AssertStartup($m,[bool]$TakingOver=$false,[bool]$ResumePending=$false){
 if($m.restore_started){Fail 'Partial proxy restoration requires recovery before startup'}
 if($m.client -eq 'verge' -and -not $m.stage_core -and -not $m.system_proxy_requested -and -not(ProxyInactive (ProxyState))){Fail 'A different proxy or PAC is active; refusing to start the native GUI'}
 if($TakingOver){if(-not(ProxyRecoverable (ProxyState) $m.before_proxy $m.applied_proxy)){Fail 'System proxy changed during owned takeover'};return}
 if($m.proxy_active -and -not(ProxyEqual (ProxyState) $m.applied_proxy)){Fail 'System proxy changed externally; refusing to restart an owning client'}
 if($m.gui_activation_started -and -not $TakingOver -and (-not $ResumePending -or -not $m.rollback_task -or [DateTime]::UtcNow -ge [DateTimeOffset]::Parse($m.rollback_deadline).UtcDateTime)){Fail 'Partial or expired GUI activation requires recovery before startup'}
 if($m.takeover_started -and (-not $ResumePending -or -not $m.proxy_active -or -not $m.rollback_task -or [DateTime]::UtcNow -ge [DateTimeOffset]::Parse($m.rollback_deadline).UtcDateTime)){Fail 'Partial or expired proxy activation requires recovery before startup'}
}
function StartOwned($m,[bool]$TakingOver=$false,[bool]$ResumePending=$false){AssertStartup $m $TakingOver $ResumePending;if((Session) -eq 0){Fail 'The Windows user has no interactive desktop session'};AssertTask $m;if(-not $m.task_sha256){Fail 'Owned startup task is not registered'};Start-ScheduledTask -TaskName $m.task}
function LaunchCore($m){LaunchOwned $m $false}
function LaunchGUI($m){LaunchOwned $m $true}
function LaunchOwned($m,[bool]$GUI){
 AssertStartup $m $false $true
 if((Session) -eq 0 -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne (Session)){Fail 'Owned launcher must run in the reviewed desktop session'}
 if($GUI){AssertGUIEnvironment;if($m.client -ne 'verge' -or $m.stage_core -or -not $m.gui_activated){Fail 'Native GUI launch is not activated by the reviewed owner'}}
 elseif($m.client -ne 'mihomo' -and -not($m.client -eq 'verge' -and $m.stage_core)){Fail 'The owned instance is not staged for a standalone core'}
 if(-not $RequestPath -or -not(Same $RequestPath (Join-Path $m.root 'launch.json')) -or (HashBytes (ReadBytes $RequestPath)) -ne $m.launch_sha256){Fail 'Owned launch request identity changed'}
 if(Running $m){Fail 'Owned core is already running'}
 $info=New-Object Diagnostics.ProcessStartInfo
 if($GUI){$info.FileName=$m.app_path;$info.Arguments=$m.arguments;$info.WorkingDirectory=$m.working_directory}else{$info.FileName=$m.core_path;$info.Arguments=$m.core_arguments;$info.WorkingDirectory=$m.home}
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
 foreach($key in @($info.EnvironmentVariables.Keys)){if([string]$key -like 'CLASH_*' -or $key -in @('SAFE_PATHS','SKIP_SAFE_PATH_CHECK','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){$info.EnvironmentVariables.Remove($key)}}
 $script:LaunchProcess=New-Object Diagnostics.Process;$script:LaunchProcess.StartInfo=$info;[void]$script:LaunchProcess.Start()
 # The task observes the application exit, but never holds the owner lock for its lifetime.
 ReleaseMutationLock
}

function CoreCommand([string]$Binary,[string]$Arguments,[string]$OwnedHome,[int]$Seconds=30){
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$Binary;$info.Arguments=$Arguments;$info.WorkingDirectory=$OwnedHome;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 foreach($key in @($info.EnvironmentVariables.Keys)){if([string]$key -like 'CLASH_*' -or $key -in @('SAFE_PATHS','SKIP_SAFE_PATH_CHECK','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){$info.EnvironmentVariables.Remove($key)}}
 $p=New-Object Diagnostics.Process;$p.StartInfo=$info;[void]$p.Start()
 $outBuffer=New-Object char[] 4096;$errBuffer=New-Object char[] 4096
 $output=New-Object Text.StringBuilder;$errorOutput=New-Object Text.StringBuilder
 $outRead=$p.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length);$errRead=$p.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)
 $deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
 try{
  while($outRead -or $errRead -or -not $p.HasExited){
   if([DateTime]::UtcNow -ge $deadline){Fail 'Owned core command timed out'}
   if($outRead -and $outRead.IsCompleted){$n=$outRead.GetAwaiter().GetResult();if($n -eq 0){$outRead=$null}else{[void]$output.Append($outBuffer,0,$n);if($output.Length -gt 65536){Fail 'Owned core command output exceeded its limit'};$outRead=$p.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length)}}
   if($errRead -and $errRead.IsCompleted){$n=$errRead.GetAwaiter().GetResult();if($n -eq 0){$errRead=$null}else{[void]$errorOutput.Append($errBuffer,0,$n);if($errorOutput.Length -gt 65536){Fail 'Owned core command output exceeded its limit'};$errRead=$p.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)}}
   if($outRead -or $errRead -or -not $p.HasExited){Start-Sleep -Milliseconds 10}
  }
  if($p.ExitCode -ne 0){Fail 'Owned core validation failed; configuration and diagnostics remain private'}
  return $output.ToString()
 }finally{if(-not $p.HasExited){try{$p.Kill()}catch{}};$p.Dispose()}
}
function CoreVersion([string]$Binary,[string]$OwnedHome){$value=CoreCommand $Binary '-v' $OwnedHome 5;$match=[regex]::Match($value,'Mihomo Meta (v[0-9]+\.[0-9]+\.[0-9]+)');if(-not $match.Success){Fail 'Installed core is not an identified stable Mihomo release'};return $match.Groups[1].Value}

function ResourceName([string]$Name){if([string]::IsNullOrWhiteSpace($Name) -or $Name -match '(^[/\\]|(^|[/\\])\.\.([/\\]|$)|:|[\x00-\x1f"])'){Fail 'Resource path escapes its owned directory'}}
function WriteResources([string]$OwnedHome,$Resources){foreach($name in $Resources.Keys){ResourceName $name;$p=Join-Path $OwnedHome $name;if(-not(Within $p $OwnedHome)){Fail 'Resource path escapes its owned directory'};Atomic $p ([Convert]::FromBase64String($Resources[$name]))}}
function CopyValidationResource($m,[string]$Value,[bool]$Required=$true){
 if([IO.Path]::IsPathRooted($Value)){$source=Full $Value}else{ResourceName $Value;$source=Full (Join-Path $m.home $Value)}
 if(-not(Within $source $m.home)){Fail 'Validation resource is outside the owned profile directory'}
 NoReparse $source
 $script:ValidationIndex++
 $dest=Join-Path $script:ValidationStage ('resources\'+$script:ValidationIndex+'\'+[IO.Path]::GetFileName($source))
 if(Test-Path -LiteralPath $source){SafeACL $source;$bytes=ReadBytes $source 33554432;$script:ValidationBytes+=$bytes.Length;if($script:ValidationBytes -gt 134217728){Fail 'Validation resources exceed 128 MiB'};Atomic $dest $bytes}
 elseif($Required){Fail 'Owned validation resource is missing'}
 else{PrivateDir ([IO.Path]::GetDirectoryName($dest))}
 return $dest
}
function ValidationCertificates($m,$node){
 if($node -is [System.Collections.IDictionary]){
  foreach($key in @($node.Keys)){$v=$node[$key];$isFile=$key -in @('certificate','ca','certificate-path','private-key-path') -or ($key -eq 'private-key' -and $node.ContainsKey('certificate'))
   if($isFile -and $v -is [string] -and $v -and $v -notmatch '[\r\n]' -and -not $v.StartsWith('-----')){$node[$key]=CopyValidationResource $m $v}
   else{ValidationCertificates $m $v}
  }
 }elseif($node -is [array]){foreach($v in $node){ValidationCertificates $m $v}}
}

function ValidateProfile($m,$Document){
 if(-not($Document -is [System.Collections.IDictionary])){Fail 'Validation requires a parsed profile document'}
 foreach($key in @('post-up','post-down','interface-name','routing-mark')){if($Document.ContainsKey($key) -and $null -ne $Document[$key] -and [string]$Document[$key] -notin @('','0')){Fail 'Windows validation rejects host-specific executable and routing hooks'}}
 if($Document.tun -and $Document.tun.enable){Fail 'Owned Windows validation requires TUN disabled'}
 $stage=Join-Path $r.root ('validation-'+[Guid]::NewGuid().ToString('N'));PrivateDir $stage
 $script:ValidationStage=$stage;$script:ValidationBytes=0;$script:ValidationIndex=0
 try{
  foreach($name in $m.resources){ResourceName $name;$src=Join-Path $m.home $name;SafeACL $src;$bytes=ReadBytes $src 33554432;$script:ValidationBytes+=$bytes.Length;if($script:ValidationBytes -gt 134217728){Fail 'Validation resources exceed 128 MiB'};Atomic (Join-Path $stage $name) $bytes}
  foreach($section in @('proxy-providers','rule-providers')){if($Document[$section] -is [System.Collections.IDictionary]){foreach($provider in $Document[$section].Values){if($provider -is [System.Collections.IDictionary] -and $provider.path -is [string] -and $provider.path){$provider.path=CopyValidationResource $m $provider.path ($provider.type -eq 'file')}}}}
  ValidationCertificates $m $Document
  # This is a private resource copy, not an OS sandbox. Never give -d the live owner's directory.
  Atomic (Join-Path $stage 'config.yaml') ([Text.Encoding]::UTF8.GetBytes((JSON $Document)))
  [void](CoreCommand $m.core_path ('-t -d "'+$stage+'" -f "'+(Join-Path $stage 'config.yaml')+'"') $stage 30)
 }finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force};$script:ValidationStage=$null}
}
function Install(){
 if($null -eq $r.resources){$r.resources=@{}};if($null -eq $r.files){$r.files=@{}};if($null -eq $r.before_cfw){$r.before_cfw=@()}
 $facts=(Facts).facts
 if($facts.windows_state_digest -ne $r.expected){Fail 'Windows facts changed after preview'}
 if($r.client -eq 'verge' -and $facts.windows_ras_entries -gt 0){Fail 'Native Verge proxy control cannot safely restore existing RAS or VPN connection settings'}
 if($facts.existing -or ($r.client -eq 'verge' -and $facts.verge_existing)){Fail 'Refusing to overwrite an existing Windows installation or Verge profile'}
 if($facts.busy_ports.Count -gt 0 -or $facts.interactive_session -eq 0 -or -not $facts.task_scheduler){Fail 'Ports or interactive task prerequisites are not ready'}
 if($r.user_sid -ne $script:SID -or -not(Same $r.root (ExpectedRoot))){Fail 'Windows owner root or SID is not reviewed'}
 $task='lazyclash-'+$r.id
 if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){Fail 'A scheduled task already owns this name'}
 $artifact=[Convert]::FromBase64String($r.artifact);if((HashBytes $artifact) -ne $r.artifact_sha256){Fail 'Transferred artifact hash does not match the reviewed release'}
 PrivateDir $r.root
 $m=@{artifact_sha256=$r.artifact_sha256;artifact_kind=$r.artifact_kind;app_root=$r.app_root;protocol=1;id=$r.id;owner_token=$r.owner_token;user_sid=$script:SID;client=$r.client;client_version=$r.client_version;phase='staging';root=$r.root;task=$task;home=(Join-Path $r.root 'home');resources=@($r.resources.Keys);before_proxy=$r.before_proxy;before_cfw=$r.before_cfw;system_proxy_requested=$r.system_proxy;applied_bypass=$r.applied_bypass;stage_core=($r.client -eq 'verge');gui_activated=$false;proxy_active=$false;boot=$false;binary_hashes=@{};profile_uid=$r.profile_uid;controller_port=$r.controller_port;mixed_port=$r.mixed_port;profile_sha256=(HashBytes ([Convert]::FromBase64String($r.profile)));helper_sha256=(HashBytes ([Convert]::FromBase64String($r.helper)));source_files=@($r.files.Keys)}
 SaveManifest $m
 Atomic (Join-Path $r.root 'host.ps1') ([Convert]::FromBase64String($r.helper))
 if($r.client -eq 'mihomo'){
  $zip=Join-Path $r.root 'artifact.zip';Atomic $zip $artifact;Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive=[IO.Compression.ZipFile]::OpenRead($zip)
  try{$entries=@($archive.Entries|Where-Object {$_.Name -match '^mihomo.*\.exe$'});if($entries.Count -ne 1 -or $entries[0].Length -gt 268435456 -or $entries[0].FullName -match '[/\\:]'){Fail 'Windows core archive has an unexpected layout'};$stream=$entries[0].Open();$memory=New-Object IO.MemoryStream;try{$stream.CopyTo($memory);Atomic (Join-Path $r.root 'bin\mihomo.exe') $memory.ToArray()}finally{$stream.Dispose();$memory.Dispose()}}finally{$archive.Dispose()}
  $m.app_path=Join-Path $r.root 'bin\mihomo.exe';$m.core_path=$m.app_path;$m.arguments='-d "'+$m.home+'" -f "'+(Join-Path $m.home 'config.yaml')+'"';$m.working_directory=$m.home;$m.core_arguments=$m.arguments
 }elseif($r.client -eq 'verge'){
  if(-not $facts.is_root){Fail 'The reviewed Verge machine installer requires an administrator token'}
  $app=Join-Path $env:ProgramFiles ('lazyclash\'+$r.id+'\Clash Verge')
  if(-not(Same $app $r.app_root) -or (Test-Path -LiteralPath $app)){Fail 'Verge installation directory already exists or differs from review'}
  NoReparse $app;$installer=Join-Path $r.root 'verge-setup.exe';Atomic $installer $artifact
  $m.phase='installer_started';SaveManifest $m
  $p=Start-Process -FilePath $installer -ArgumentList ('/S /D='+$app) -PassThru
  $m.installer_pid=$p.Id;SaveManifest $m
  if(-not $p.WaitForExit(180000)){Fail 'Verge installer outcome is unknown after its time limit; inspect before any resume or retry'}
  if($p.ExitCode -ne 0){Fail 'Verge installer did not report success; inspect the staged installation before resuming'}
  $m.app_path=Join-Path $app 'clash-verge.exe';$m.core_path=Join-Path $app 'verge-mihomo.exe';$m.arguments='';$m.working_directory=$app;$m.data_root=DataRoot;$m.home=$m.data_root;$m.core_arguments='-d "'+$m.home+'" -f "'+(Join-Path $m.home ('profiles\'+$m.profile_uid+'.yaml'))+'"'
  if(-not(Test-Path -LiteralPath $m.app_path) -or -not(Test-Path -LiteralPath $m.core_path)){Fail 'Verge installed executable layout is not the reviewed 2.5.2 layout'}
  if(Test-Path -LiteralPath $m.data_root){Fail 'Verge profile directory appeared during installation; inspect before adoption'}
  PrivateDir $m.data_root;SaveJSON (Join-Path $m.data_root 'lazyclash-owner.json') @{id=$m.id;owner_token=$m.owner_token;root=$m.root;user_sid=$script:SID}
  WriteResources $m.data_root $r.files
 }else{Fail 'Unsupported Windows client'}
 PrivateDir $m.home;WriteResources $m.home $r.resources
 if($m.client -eq 'mihomo'){Atomic (Join-Path $m.home 'config.yaml') ([Convert]::FromBase64String($r.profile))}
 foreach($key in @('app_path','core_path')){SafeACL $m[$key] $false;$m.binary_hashes[$key]=(Get-FileHash -LiteralPath $m[$key] -Algorithm SHA256).Hash.ToLowerInvariant()}
 $m.core_version=CoreVersion $m.core_path $m.home
 if($r.client -eq 'mihomo' -and $m.core_version -ne $r.core_version){Fail 'Installed core version differs from the reviewed release'}
 ValidateProfile $m $r.profile_document
 TaskRegister $m $false;$m.phase='staged';SaveManifest $m;StartOwned $m;$m.phase='running_unverified';SaveManifest $m;return Result $m
}

function CFWStopPlan($m){
 $session=Session;if($session -eq 0){Fail 'Takeover requires the reviewed interactive desktop session'}
 $all=@(Get-CimInstance Win32_Process);$plan=@();$seen=@{}
 foreach($old in $m.before_cfw){
  if($old.user_sid -ne $script:SID -or [int]$old.session -ne $session){Fail 'Previous CFW belongs to a different desktop session'}
  $main=@($all|Where-Object {[int]$_.ProcessId -eq [int]$old.pid})
  if($main.Count -ne 1 -or -not(ProcessMatches $main[0] $old)){Fail 'Previous CFW process identity changed; review takeover again'}
  $queue=@($main[0]);$directory=[IO.Path]::GetDirectoryName($old.path)
  while($queue.Count -gt 0){
   $current=$queue[0];if($queue.Count -gt 1){$queue=@($queue[1..($queue.Count-1)])}else{$queue=@()}
   if($seen.ContainsKey([int]$current.ProcessId)){continue};$seen[[int]$current.ProcessId]=$true
   # Ancestry alone does not grant ownership of conhost, shells or applications
   # launched by CFW. Preserve external descendants and their entire branches.
   if(-not $current.ExecutablePath){continue}
   try{$candidate=Full $current.ExecutablePath}catch{continue}
   if(-not(Within $candidate $directory)){continue}
   $record=ProcessRecord $current
   if($record.user_sid -ne $script:SID -or $record.session -ne $session){Fail 'CFW descendant identity is outside the reviewed owner and installation'}
   $plan+=$record
   $queue+=@($all|Where-Object {[int]$_.ParentProcessId -eq [int]$current.ProcessId -and $_.CreationDate.ToUniversalTime() -ge $current.CreationDate.ToUniversalTime()})
  }
 };return ,$plan
}
function StopCFW($m){
 foreach($record in @($m.cfw_stop_plan)){
  $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$record.pid)
  if(-not $p){continue};if(-not(ProcessMatches $p $record)){Fail 'CFW process identity changed before stopping'}
  Stop-Process -Id $record.pid -Force -ErrorAction SilentlyContinue
 }
 $deadline=[DateTime]::UtcNow.AddSeconds(5)
 do{
  $remaining=$false
  $all=@(Get-CimInstance Win32_Process)
  foreach($record in @($m.cfw_stop_plan)){
   foreach($p in $all){
    if([int]$p.SessionId -ne [int]$record.session -or -not(ProcessPathSame $p.ExecutablePath $record.path)){continue}
    $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
    if($owner.Sid -eq $record.user_sid){$remaining=$true;break}
   }
   if($remaining){break}
  }
  if(-not $remaining){return}
  if([DateTime]::UtcNow -ge $deadline){Fail 'Reviewed CFW processes did not stop within five seconds'}
  Start-Sleep -Milliseconds 100
 }while($true)
}
function ClearRecoveryTask($m){
 if(-not $m.recovery_task){return}
 if((HashText (Export-ScheduledTask -TaskName $m.recovery_task)) -ne $m.recovery_task_sha256){Fail 'CFW recovery task identity changed'}
 Unregister-ScheduledTask -TaskName $m.recovery_task -Confirm:$false
 $m.Remove('recovery_task');$m.Remove('recovery_task_sha256');$m.Remove('recovery_path');SaveManifest $m
}
function CFWRestore($m){
 $restored=@()
 $session=Session;if($session -eq 0 -and $m.before_cfw){Fail 'Previous CFW recovery waits for the reviewed desktop user to log on'}
 foreach($old in $m.before_cfw){
  if(-not $old.path){continue};if($old.user_sid -ne $script:SID){Fail 'Previous CFW user identity differs'}
  NoReparse $old.path;if((Get-FileHash -LiteralPath $old.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $old.sha256){Fail 'Previous CFW executable changed; manual recovery required'}
  $exists=$false;foreach($p in @(Get-CimInstance Win32_Process)){if($p.ExecutablePath -and (ProcessPathSame $p.ExecutablePath $old.path) -and [int]$p.SessionId -eq $session -and $p.CommandLine -notmatch '--type='){$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;if($o.Sid -eq $script:SID){$exists=$true;$recovered=ProcessRecord $p}}};if($exists){ClearRecoveryTask $m;$restored+=$recovered;continue}
  $task='lazyclash-recover-'+$r.id
  $existing=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
  if($existing){if($m.recovery_task -ne $task -or -not(Same $m.recovery_path $old.path) -or (HashText (Export-ScheduledTask -TaskName $task)) -ne $m.recovery_task_sha256){Fail 'CFW recovery task name is occupied'}}
  $action=New-ScheduledTaskAction -Execute $old.path -WorkingDirectory ([IO.Path]::GetDirectoryName($old.path));$principal=New-ScheduledTaskPrincipal -UserId $script:SID -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  if(-not $existing){Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null;$m.recovery_task=$task;$m.recovery_task_sha256=HashText (Export-ScheduledTask -TaskName $task);$m.recovery_path=$old.path;SaveManifest $m}
  Start-ScheduledTask -TaskName $task
  $ready=$false;$deadline=[DateTime]::UtcNow.AddSeconds(10)
  do{foreach($p in @(Get-CimInstance Win32_Process)){if($p.ExecutablePath -and (ProcessPathSame $p.ExecutablePath $old.path) -and [int]$p.SessionId -eq $session -and $p.CommandLine -notmatch '--type='){$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;if($o.Sid -eq $script:SID){$ready=$true;$recovered=ProcessRecord $p}}};if(-not $ready){Start-Sleep -Milliseconds 200}}while(-not $ready -and [DateTime]::UtcNow -lt $deadline)
  if(-not $ready){Fail 'Previous CFW did not resume in the reviewed desktop session'}
  ClearRecoveryTask $m;$restored+=$recovered
 }
 $m.before_cfw=$restored
}
function ProxyRecoverable($Current,$Before,$Applied){
 foreach($key in @('flags','enabled','server','override','auto_config_url')){if([string]$Current[$key] -cne [string]$Before[$key] -and [string]$Current[$key] -cne [string]$Applied[$key]){return $false}};return $true
}
function VergeProxyPreference($m,[bool]$Enable){
 if($m.client -ne 'verge'){return}
 $path=Join-Path $m.data_root 'verge.yaml';SafeACL $path;$text=[Text.Encoding]::UTF8.GetString((ReadBytes $path))
 $matches=[regex]::Matches($text,'(?m)^enable_system_proxy:\s*(false|true)\s*$')
 if($matches.Count -ne 1){Fail 'Owned Verge proxy preference is not recognized'}
 $value=if($Enable){'true'}else{'false'};$text=[regex]::Replace($text,'(?m)^enable_system_proxy:\s*(false|true)\s*$',('enable_system_proxy: '+$value))
 Atomic $path ([Text.Encoding]::UTF8.GetBytes($text))
 if([Text.Encoding]::UTF8.GetString((ReadBytes $path)) -cne $text){Fail 'Verge proxy preference write was not observed'}
}
function DisarmGuard($m){
 if(-not $m.rollback_task){return}
 if((HashText (Export-ScheduledTask -TaskName $m.rollback_task)) -ne $m.rollback_task_sha256){Fail 'Rollback task identity changed'}
 Unregister-ScheduledTask -TaskName $m.rollback_task -Confirm:$false
 $m.Remove('rollback_task');$m.Remove('rollback_task_sha256');$m.Remove('rollback_deadline')
}

function RestoreProxy($m){
 if(-not $m.proxy_active -and -not $m.takeover_started -and -not $m.gui_activation_started -and -not $m.restore_started){if($m.rollback_task){DisarmGuard $m;SaveManifest $m};return}
 $current=ProxyState
 $partial=$m.restore_started -or $m.gui_activation_started -or ($m.takeover_started -and -not $m.proxy_active)
 if(($partial -and -not(ProxyRecoverable $current $m.before_proxy $m.applied_proxy)) -or (-not $partial -and -not(ProxyEqual $current $m.applied_proxy))){Fail 'System proxy was changed externally; automatic restoration refused'}
 $m.restore_started=$true;$m.phase='proxy_restore_started';SaveManifest $m
 StopOwned $m
 # Restore the persisted native preference before restarting any previous client.
 VergeProxyPreference $m $false
 if($m.client -eq 'verge'){$m.stage_core=$true;$m.gui_activated=$false;TaskRegister $m $false;SaveManifest $m}
 SetProxy $m.before_proxy
 if($m.cfw_stop_started){CFWRestore $m}
 if(-not(ProxyRecoverable (ProxyState) $m.before_proxy $m.applied_proxy)){Fail 'System proxy changed while restoring the previous client'}
 SetProxy $m.before_proxy
 $m.proxy_active=$false;$m.takeover_started=$false;$m.gui_activation_started=$false;$m.restore_started=$false;$m.cfw_stop_started=$false;$m.phase='proxy_restored';SaveManifest $m
 DisarmGuard $m;SaveManifest $m
}

function GuardTask($m){
 $name='lazyclash-rollback-'+$r.id
 if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){Fail 'Rollback task name is already occupied'}
 $guard=@{op='rollback';host_os='windows';id=$r.id;client=$r.client;root=$r.root;user_sid=$script:SID;owner_token=$r.owner_token}
 $path=Join-Path $r.root 'rollback.json';SaveJSON $path $guard;$m.rollback_request_sha256=HashBytes (ReadBytes $path)
 $action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+(Join-Path $r.root 'host.ps1')+'" -RequestPath "'+$path+'"')
 $principal=New-ScheduledTaskPrincipal -UserId $script:SID -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
 $deadline=[DateTime]::UtcNow.AddMinutes(2)
 $triggers=@((New-ScheduledTaskTrigger -Once -At $deadline.ToLocalTime()),(New-ScheduledTaskTrigger -AtLogOn -User $script:SID))
 Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Trigger $triggers | Out-Null
 $m.rollback_task=$name;$m.rollback_task_sha256=HashText (Export-ScheduledTask -TaskName $name);$m.rollback_deadline=$deadline.ToString('o')
}

function Takeover($m){
 if($m.restore_started){Fail 'Partial proxy restoration requires recovery before another takeover'}
 if($m.proxy_active){if(-not(ProxyEqual (ProxyState) $m.applied_proxy)){Fail 'Owned system proxy differs from its acknowledged state'};if($m.takeover_started -and (-not $m.rollback_task -or [DateTime]::UtcNow -ge [DateTimeOffset]::Parse($m.rollback_deadline).UtcDateTime)){Fail 'Proxy acknowledgement deadline expired; recover the armed takeover before retrying'};return Result $m}
 if($m.takeover_started){Fail 'A partial proxy takeover requires rollback before another attempt'}
 if(-not(ProxyEqual (ProxyState) $m.before_proxy)){Fail 'Current system proxy differs from the reviewed pre-install state'}
 $m.cfw_stop_plan=CFWStopPlan $m
 if($m.client -eq 'verge'){AssertGUIEnvironment}
 $m.applied_proxy=@{flags=[uint32]3;enabled=1;server=('127.0.0.1:'+$m.mixed_port);override=[string]$m.applied_bypass;auto_config_url=''}
 GuardTask $m;$m.takeover_started=$true;$m.phase='proxy_activation_started';SaveManifest $m
 try{
  $m.cfw_stop_started=$true;SaveManifest $m;StopCFW $m
  if($m.client -eq 'verge'){StopOwned $m;VergeProxyPreference $m $true;$m.stage_core=$false;$m.gui_activated=$true;TaskRegister $m $false;SaveManifest $m;StartOwned $m $true}
  SetProxy $m.applied_proxy;$m.proxy_active=$true;$m.phase='proxy_pending_verification';SaveManifest $m
 }catch{
  try{RestoreProxy $m}catch{Fail 'Proxy activation and recovery are unconfirmed; the armed rollback task and private receipt require inspection'}
  Fail 'Proxy activation failed; the previous client and proxy were restored'
 }
 return Result $m
}

function ActivateGUI($m){
 if($m.client -ne 'verge' -or $m.system_proxy_requested){Fail 'Native GUI activation without takeover requires an explicit proxy-disabled deployment'}
 if($m.gui_activated -and -not $m.stage_core){AssertStartup $m $false $true;return Result $m}
 if($m.takeover_started -or $m.restore_started -or $m.gui_activation_started){Fail 'A partial activation requires recovery before another GUI startup'}
 if(-not(ProxyInactive $m.before_proxy) -or -not(ProxyInactive (ProxyState)) -or -not(ProxyEqual (ProxyState) $m.before_proxy)){Fail 'Native GUI staging requires the reviewed system proxy and PAC to remain inactive'}
 AssertGUIEnvironment
 $m.applied_proxy=$m.before_proxy.Clone();$m.applied_proxy.flags=[uint32]1;$m.applied_proxy.enabled=0;$m.applied_proxy.auto_config_url=''
 GuardTask $m;$m.gui_activation_started=$true;$m.phase='gui_activation_started';SaveManifest $m
 try{
  StopOwned $m;VergeProxyPreference $m $false;$m.stage_core=$false;$m.gui_activated=$true;TaskRegister $m $false;SaveManifest $m;StartOwned $m $true
  $m.phase='gui_pending_verification';SaveManifest $m
 }catch{
  try{RestoreProxy $m}catch{Fail 'Native GUI activation and recovery are unconfirmed; inspect the armed rollback task'}
  Fail 'Native GUI activation failed; previous proxy state was restored'
 }
 return Result $m
}

function Ack($m){
 if($m.rollback_task -and [DateTime]::UtcNow -ge [DateTimeOffset]::Parse($m.rollback_deadline).UtcDateTime){Fail 'Proxy acknowledgement deadline expired; rollback remains armed'}
 if(($m.proxy_active -or $m.gui_activation_started) -and -not(ProxyEqual (ProxyState) $m.applied_proxy)){Fail 'System proxy ownership changed before acknowledgement'}
 # Keep rollback armed while changing the startup task; failure must not strand takeover.
 TaskRegister $m ([bool]$r.boot);$m.phase='running_verified';$m.takeover_started=$false;$m.gui_activation_started=$false;SaveManifest $m
 DisarmGuard $m;SaveManifest $m;return Result $m
}

function SourceAllowed($m,[string]$Path,[bool]$Write=$false){
 if(-not(Within $Path $m.home)){Fail 'Source path is outside the owned profile directory'}
 NoReparse $Path
 if($m.client -eq 'mihomo'){$allowed=Same $Path (Join-Path $m.home 'config.yaml')}
 elseif($Write){
  $allowed=Same $Path (Join-Path $m.home ('profiles\'+$m.profile_uid+'.yaml'))
  foreach($kind in @('rules','proxies','groups')){if(Same $Path (Join-Path $m.home ('profiles\'+$m.profile_uid+'_'+$kind+'.yaml'))){$allowed=$true}}
 }else{
  $allowed=Same $Path (Join-Path $m.home 'clash-verge.yaml')
  foreach($name in @($m.source_files)+@($m.resources)){ResourceName $name;if(Same $Path (Join-Path $m.home $name)){$allowed=$true}}
 }
 if(-not $Write){foreach($name in $m.resources){ResourceName $name;if(Same $Path (Join-Path $m.home $name)){$allowed=$true}}}
 if(-not $allowed){Fail 'Source operation is outside the owned native profile and supported companions'}
 if(Test-Path -LiteralPath $Path){SafeACL $Path}
}

function SourceRead($m,[string]$Path){SourceAllowed $m $Path;$limit=8388608;foreach($name in $m.resources){ResourceName $name;if(Same $Path (Join-Path $m.home $name)){$limit=33554432}};$bytes=ReadBytes $Path $limit;$info=Get-Item -LiteralPath $Path;$sha=HashBytes $bytes;$fingerprint=HashText ((Full $Path).ToLowerInvariant()+'|'+$info.Length+'|'+$info.LastWriteTimeUtc.Ticks+'|'+$sha);return @{path=$Path;resolved=(Full $Path);data=[Convert]::ToBase64String($bytes);sha256=$sha;fingerprint=$fingerprint;mode=384}}
function SourceGuards($m,$Guards){
 foreach($g in @($Guards)){if(-not $g.path -or -not $g.fingerprint -or (SourceRead $m $g.path).fingerprint -ne $g.fingerprint){Fail 'Owned source changed after preview'}}
}
function WriteSource($m,$s,[byte[]]$Bytes){
 SourceAllowed $m $s.path $true
 $ownGuard=$false;foreach($g in @($s.guards)){if(Same $g.path $s.path){$ownGuard=$true}}
 if(-not $ownGuard){Fail 'Owned source write requires its exact before-image guard'}
 $tmp=Join-Path ([IO.Path]::GetDirectoryName((Full $s.path))) ('.lazyclash-'+[Guid]::NewGuid().ToString('N'))
 try{
  Atomic $tmp $Bytes
  # Re-read all dependent inputs after preparing the temporary file and immediately before replacement.
  SourceGuards $m $s.guards;SourceAllowed $m $s.path $true
  [IO.File]::Replace($tmp,$s.path,[NullString]::Value)
  $written=SourceRead $m $s.path
  if($written.sha256 -ne (HashBytes $Bytes)){Fail 'Owned source write was not observed'}
  return $written
 }finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}}
}

function Source($m){
 $s=$r.source;$result=@{}
 if($s.op -eq 'read'){$result.file=SourceRead $m $s.path}
 elseif($s.op -in @('check','write')){
  SourceGuards $m $s.guards
  if($s.op -eq 'write'){
   $bytes=[Convert]::FromBase64String($s.data);if($bytes.Length -gt 8388608){Fail 'Source exceeds its size limit'}
   $result.file=WriteSource $m $s $bytes
   $base=if($m.client -eq 'verge'){Join-Path $m.home ('profiles\'+$m.profile_uid+'.yaml')}else{Join-Path $m.home 'config.yaml'}
   if(Same $s.path $base){$m.profile_sha256=$result.file.sha256}
   $m.phase='source_persisted';SaveManifest $m
  }
 }elseif($s.op -eq 'validate'){
  if(-not(Same $s.binary $m.core_path) -or -not(Same $s.home $m.home) -or $s.version -ne $m.core_version -or (CoreVersion $m.core_path $m.home) -ne $m.core_version){Fail 'Source validator differs from the owned running core identity'}
  ValidateProfile $m $s.document
 }else{Fail 'Unsupported Windows source operation'}
 $out=Result $m;$out.source=$result;return $out
}

function TransferDirectory(){
 if($r.transfer_id -notmatch '^[0-9a-f]{32}$' -or $r.transfer_sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$r.transfer_size -lt 1 -or [long]$r.transfer_size -gt 268435456){Fail 'Invalid private Windows transfer descriptor'}
 if($r.transfer_operation -notin @('install','source') -or $r.owner_token -notmatch '^[0-9a-f]{48}$' -or $r.user_sid -ne $script:SID -or -not(Same $r.root (ExpectedRoot))){Fail 'Private Windows transfer owner does not match'}
 return Join-Path $env:LOCALAPPDATA ('lazyclash\transfers\'+$r.id+'-'+$r.transfer_id)
}
function TransferMetadata(){
 $dir=TransferDirectory;SafeACL $dir;$path=Join-Path $dir 'transfer.json';SafeACL $path;$meta=ReadJSON $path
 foreach($key in @('id','user_sid','owner_token','transfer_operation','transfer_id','transfer_sha256','transfer_size')){if([string]$meta[$key] -cne [string]$r[$key]){Fail 'Private Windows transfer metadata changed'}}
 if(-not(Same $meta.root $r.root)){Fail 'Private Windows transfer root changed'}
 $payload=Join-Path $dir 'payload.json'
 if($r.transfer_path -and -not(Same $r.transfer_path $payload)){Fail 'Private Windows transfer payload path changed'}
 return $meta
}
function PrepareTransfer(){
 $dir=TransferDirectory
 if($r.transfer_operation -eq 'install'){
  $facts=(Facts).facts
  if($facts.existing -or $facts.windows_state_digest -ne $r.expected){Fail 'Windows pre-install facts changed before private transfer'}
 }else{[void](Owned)}
 if(Test-Path -LiteralPath $dir){Fail 'Private Windows transfer directory already exists'}
 PrivateDir $dir
 $meta=@{id=$r.id;root=$r.root;user_sid=$script:SID;owner_token=$r.owner_token;transfer_operation=$r.transfer_operation;transfer_id=$r.transfer_id;transfer_sha256=$r.transfer_sha256;transfer_size=[long]$r.transfer_size;dispatched=$false}
 SaveJSON (Join-Path $dir 'transfer.json') $meta
 return @{status='transfer_prepared';transfer_path=(Join-Path $dir 'payload.json')}
}
function VerifyTransfer(){
 $meta=TransferMetadata;$dir=TransferDirectory;$path=Join-Path $dir 'payload.json';SafeACL $path
 $bytes=ReadBytes $path 268435456
 if($bytes.Length -ne [long]$r.transfer_size -or (HashBytes $bytes) -ne $r.transfer_sha256){Fail 'Private Windows payload size or SHA256 does not match'}
 $decoded=Map (([Text.Encoding]::UTF8.GetString($bytes))|ConvertFrom-Json)
 if(-not($decoded -is [System.Collections.IDictionary])){Fail 'Private Windows payload is not a request object'}
 foreach($key in @('id','user_sid','owner_token')){if([string]$decoded[$key] -cne [string]$r[$key]){Fail 'Private Windows payload owner identity differs'}}
 if($decoded.host_os -ne 'windows' -or $decoded.op -ne $r.transfer_operation -or $decoded.transfer_id -or $decoded.transfer_operation -or -not(Same $decoded.root $r.root)){Fail 'Private Windows payload operation or root differs'}
 return $decoded
}
function CleanupTransfer(){
 [void](TransferMetadata);$dir=TransferDirectory
 foreach($item in @(Get-ChildItem -LiteralPath $dir -Force)){if($item.PSIsContainer -or $item.Name -notin @('payload.json','transfer.json')){Fail 'Private transfer contains unexpected files; automatic cleanup refused'};SafeACL $item.FullName}
 foreach($name in @('payload.json','transfer.json')){$path=Join-Path $dir $name;if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}}
 [IO.Directory]::Delete($dir,$false)
 return @{status='transfer_removed'}
}

try{
 $script:SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if($RequestPath){SafeACL $RequestPath;$RequestJson=[Text.Encoding]::UTF8.GetString((ReadBytes $RequestPath))}
 $r=Map ($RequestJson|ConvertFrom-Json)
 if($r.id -notmatch '^[a-z0-9][a-z0-9_-]{0,47}$'){Fail 'Invalid Windows instance ID'}
 if($r.op -in @('prepare-transfer','verify-transfer','cleanup-transfer')){
  if($r.op -ne 'verify-transfer'){AcquireMutationLock}
  switch($r.op){
   'prepare-transfer' {$out=PrepareTransfer}
   'verify-transfer' {[void](VerifyTransfer);$out=@{status='transfer_verified';transfer_verified=$true}}
   'cleanup-transfer' {$out=CleanupTransfer}
  }
 }else{
  if($r.op -eq 'dispatch-transfer'){
   AcquireMutationLock;$decoded=VerifyTransfer;$meta=TransferMetadata
   if($meta.dispatched){Fail 'This private request was already dispatched; inspect its result before retrying'}
   $meta.dispatched=$true;SaveJSON (Join-Path (TransferDirectory) 'transfer.json') $meta
   $r=$decoded
  }
 if($r.op -eq 'facts'){$out=Facts}
 else{
  if(-not $script:MutationLock -and $r.op -notin @('status','verify-runtime') -and -not($r.op -eq 'source' -and $r.source.op -eq 'read')){AcquireMutationLock}
  if($r.op -eq 'install'){$out=Install}
  else{
   $m=Owned
   switch($r.op){
    'status' {$out=Result $m}
    'verify-runtime' {$out=VerifyRuntime $m}
    'source' {$out=Source $m}
    'activate-source' {AssertStartup $m;StopOwned $m;StartOwned $m;$m.phase='running_unverified';SaveManifest $m;$out=Result $m}
    'start' {StartOwned $m;$m.phase='running_unverified';SaveManifest $m;$out=Result $m}
    'resume' {if(-not $m.core_path -or -not $m.task_sha256){Fail 'Partial installer outcome requires inspection; resume will not rerun an unknown installer'};StartOwned $m $false $true;$m.phase='running_unverified';SaveManifest $m;$out=Result $m}
    'restart' {AssertStartup $m;StopOwned $m;StartOwned $m;$m.phase='running_unverified';SaveManifest $m;$out=Result $m}
    'stop' {RestoreProxy $m;StopOwned $m;TaskRegister $m $false;$m.phase='stopped';SaveManifest $m;$out=Result $m}
    'remove' {RestoreProxy $m;StopOwned $m;AssertTask $m;Unregister-ScheduledTask -TaskName $m.task -Confirm:$false;$m.task_sha256='';$m.phase='removed_data_preserved';SaveManifest $m;$out=Result $m}
    'takeover' {$out=Takeover $m}
    'activate-gui' {$out=ActivateGUI $m}
    'ack' {$out=Ack $m}
    'rollback' {
     if($RequestPath -and (-not(Same $RequestPath (Join-Path $m.root 'rollback.json')) -or (HashBytes (ReadBytes $RequestPath)) -ne $m.rollback_request_sha256)){Fail 'Rollback request identity changed'}
     if($m.rollback_deadline -and [DateTime]::UtcNow -ge [DateTimeOffset]::Parse($m.rollback_deadline).UtcDateTime){RestoreProxy $m};$out=Result $m
    }
    'launch-core' {LaunchCore $m}
    'launch-gui' {LaunchGUI $m}
    default {Fail 'Unsupported Windows managed operation'}
   }
  }
 }
 }
 if($script:LaunchProcess){$script:LaunchProcess.WaitForExit();$code=$script:LaunchProcess.ExitCode;$script:LaunchProcess.Dispose();exit $code}
 [Console]::Out.WriteLine((JSON $out))
}catch{
 $op=if($r.op -in @('facts','install','status','verify-runtime','source','activate-source','start','resume','restart','stop','remove','takeover','activate-gui','ack','rollback','launch-core','launch-gui','prepare-transfer','verify-transfer','cleanup-transfer','dispatch-transfer')){$r.op}else{'request'}
 $stage=if($m.phase -in @('staging','installer_started','staged','running_unverified','proxy_activation_started','proxy_pending_verification','proxy_restore_started','proxy_restored','gui_activation_started','gui_pending_verification','running_verified','source_persisted','stopped','removed_data_preserved')){$m.phase}else{'request'}
 $kind=$_.Exception.GetType().FullName;if($kind -notmatch '^[A-Za-z0-9_.]+$'){$kind='Exception'}
 $line=[int]$_.InvocationInfo.ScriptLineNumber
 $cim=''
 if($_.Exception -is [Microsoft.Management.Infrastructure.CimException]){$cim='; cim_native='+[int]$_.Exception.NativeErrorCode+'; cim_status='+[uint32]$_.Exception.StatusCode+'; hresult='+[int]$_.Exception.HResult}
 $reason='Windows managed helper failed (operation='+$op+'; stage='+$stage+'; exception='+$kind+'; helper line='+$line+$cim+'). Check Windows path permissions and task prerequisites.'
 if($_.Exception.Message.StartsWith('LCWIN:')){$reason=$_.Exception.Message.Substring(6)}
 [Console]::Out.WriteLine((JSON @{error=$reason;status='unconfirmed'}))
 # Scheduled rollback retries on interruption/failure; SSH callers consume the same structured error.
 if($RequestPath){exit 1}
}finally{ReleaseMutationLock}
