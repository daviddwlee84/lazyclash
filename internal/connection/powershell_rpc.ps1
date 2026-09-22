param($RpcMetadata,[string]$RpcDirectory,$RpcClock)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$lcRpcValidated=$false
$lcRpcArmed=$false
function RpcNoReparse([string]$p) {
 while($p){if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'RPC reparse point'}};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}
}
function RpcOwned {
 RpcNoReparse $RpcDirectory
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $expected=Join-Path (Join-Path (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'lazyclash') 'rpc') $RpcMetadata.nonce
 if($RpcMetadata.nonce -notmatch '^[a-f0-9]{32}$' -or -not [string]::Equals([IO.Path]::GetFullPath($RpcDirectory),[IO.Path]::GetFullPath($expected),[StringComparison]::OrdinalIgnoreCase)){throw 'RPC directory identity'}
 $acl=Get-Acl -LiteralPath $RpcDirectory
 if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){throw 'RPC directory owner'}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.IdentityReference.Value -notin @($sid.Value,'S-1-5-18')){throw 'RPC directory ACL'}}
 $owner=Join-Path $RpcDirectory 'owner';RpcNoReparse $owner
 if((Get-Item -LiteralPath $owner).Length -gt 256 -or [IO.File]::ReadAllText($owner) -ne ('lazyclash-rpc-v1|'+$RpcMetadata.nonce+'|'+$sid.Value)){throw 'RPC owner marker'}
}
function RpcCleanup {
 RpcOwned
 foreach($f in @(Get-ChildItem -LiteralPath $RpcDirectory -Force)){if($f.Name -notin @('owner','helper.ps1','request.json') -or $f.PSIsContainer){throw 'RPC unexpected file'};RpcNoReparse $f.FullName}
 foreach($name in @('helper.ps1','request.json','owner')){$p=Join-Path $RpcDirectory $name;if(Test-Path -LiteralPath $p){[IO.File]::Delete($p)}}
 [IO.Directory]::Delete($RpcDirectory,$false)
}
try {
 RpcOwned
 $lcRpcValidated=$true
 if($RpcMetadata.input_size -lt 1 -or $RpcMetadata.input_size -gt 268435456 -or $RpcMetadata.input_sha256 -notmatch '^[a-f0-9]{64}$' -or $RpcMetadata.budget_ms -lt 1 -or $RpcMetadata.budget_ms -gt 360000){throw 'RPC bounds'}
 $path=Join-Path $RpcDirectory 'request.json';RpcNoReparse $path
 $stream=[IO.File]::Open($path,'Open','Read','Read')
 try {
  if($stream.Length -ne $RpcMetadata.input_size){throw 'RPC input size'}
  $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
  while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'RPC short read'};$offset+=$count}
 }finally{$stream.Dispose()}
 $hash=[Security.Cryptography.SHA256]::Create()
 try{$digest=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 if($digest -ne $RpcMetadata.input_sha256){throw 'RPC input hash'}
 Add-Type -TypeDefinition @'
using System;
using System.Threading;
public static class LazyclashRpcBudget {
 private static Timer timer;
 public static void Arm(int milliseconds) { timer = new Timer(delegate(object ignored) { Environment.Exit(124); }, null, milliseconds, Timeout.Infinite); }
 public static void Disarm() { if (timer != null) { timer.Dispose(); timer = null; } }
}
'@
 $remaining=[Math]::Max(1,([long]$RpcMetadata.budget_ms-$RpcClock.ElapsedMilliseconds))
 [LazyclashRpcBudget]::Arm([int]$remaining)
 $lcRpcArmed=$true
 $request=[Text.Encoding]::UTF8.GetString($bytes)
 $helper=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__LAZYCLASH_RPC_HELPER__'))
 & ([ScriptBlock]::Create($helper)) -RequestJson $request
}finally{
 if($lcRpcArmed){[LazyclashRpcBudget]::Disarm()}
 if($lcRpcValidated){try{RpcCleanup}catch{[Console]::Error.WriteLine('Private Windows RPC cleanup requires inspection')}}
}
