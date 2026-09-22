param([string]$Helper)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($Helper,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'helper AST failed'}
foreach($f in $ast.FindAll({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){Invoke-Expression $f.Extent.Text}
function Check($ok,$message){if(-not $ok){throw $message}}
function Reject($action,$message){try{& $action}catch{if($_.Exception.Message -like ('*'+$message+'*')){return};throw};throw ('Expected refusal: '+$message)}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('lc-transfer-guard-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$env:LOCALAPPDATA=$fixture;$script:SID='fixture-sid'
function Full($path){return [IO.Path]::GetFullPath($path.Replace('\','/'))}
function Same($a,$b){return [string]::Equals((Full $a),(Full $b),[StringComparison]::OrdinalIgnoreCase)}
function NoReparse($path){}
function SafeACL($path,$private=$true){}
function PrivateDir($path){[void][IO.Directory]::CreateDirectory($path)}
$script:facts=@{existing=$false;windows_state_digest='fresh'}
function Facts(){return @{facts=$script:facts}}
$script:ownedCalls=0;$script:ownerOkay=$true
function Owned(){$script:ownedCalls++;if(-not $script:ownerOkay){Fail 'fixture owner refused'};return @{}}
function AcquireMutationLock(){$script:MutationLock=$true}
function ReleaseMutationLock(){$script:MutationLock=$null}
$script:dispatches=0
function Source($m){$script:dispatches++;return @{status='fixture_source_complete'}}
function NewRequest([string]$operation='install'){
 $script:r=@{id='fixture';user_sid=$script:SID;owner_token=('b'*48);transfer_operation=$operation;transfer_id=([Guid]::NewGuid().ToString('N'));expected='fresh'}
 $script:r.root=ExpectedRoot
 $doc=@{host_os='windows';op=$operation;id=$r.id;user_sid=$r.user_sid;owner_token=$r.owner_token;root=$r.root;source=@{op='check'}}
 $script:payload=[Text.Encoding]::UTF8.GetBytes((JSON $doc))
 $r.transfer_sha256=HashBytes $script:payload;$r.transfer_size=$script:payload.Length
 return $doc
}
function UploadFixture(){[IO.File]::WriteAllBytes((Join-Path (TransferDirectory) 'payload.json'),$script:payload)}
try{
 [void](NewRequest)
 $candidate=TransferDirectory
 $script:facts.existing=$true;Reject {PrepareTransfer} 'pre-install facts changed';Check (-not(Test-Path -LiteralPath $candidate)) 'Stale install created transfer directory'
 $script:facts.existing=$false;$r.expected='stale';Reject {PrepareTransfer} 'pre-install facts changed';Check (-not(Test-Path -LiteralPath $candidate)) 'Changed preview created transfer directory'
 $r.expected='fresh';$prepared=PrepareTransfer;UploadFixture
 Check (Same $prepared.transfer_path (Join-Path $candidate 'payload.json')) 'Prepared path differs'
 Check ((VerifyTransfer).id -eq 'fixture') 'Valid private payload rejected'
 foreach($key in @('owner_token','transfer_sha256','transfer_size')){
  $old=$r[$key];$r[$key]=if($key -eq 'owner_token'){'c'*48}elseif($key -eq 'transfer_sha256'){'0'*64}else{[long]$old+1}
  Reject {VerifyTransfer} 'metadata changed';$r[$key]=$old
 }
 $r.transfer_path=Join-Path $candidate 'foreign.json';Reject {VerifyTransfer} 'payload path changed';$r.Remove('transfer_path')
 $bad=[byte[]]$script:payload.Clone();$bad[0]=32;[IO.File]::WriteAllBytes((Join-Path $candidate 'payload.json'),$bad)
 Reject {VerifyTransfer} 'size or SHA256';UploadFixture
 [IO.File]::WriteAllText((Join-Path $candidate 'unexpected.txt'),'fixture')
 Reject {CleanupTransfer} 'unexpected files';Check (Test-Path -LiteralPath (Join-Path $candidate 'payload.json')) 'Refused cleanup removed payload'
 Remove-Item -LiteralPath (Join-Path $candidate 'unexpected.txt');[void](CleanupTransfer);Check (-not(Test-Path -LiteralPath $candidate)) 'Exact cleanup left transfer directory'
 foreach($field in @('owner_token','op','root','transfer_id')){
  $doc=NewRequest;$doc[$field]=switch($field){'owner_token'{'c'*48};'op'{'dispatch-transfer'};'root'{Join-Path $fixture 'outside'};'transfer_id'{'d'*32}}
  $script:payload=[Text.Encoding]::UTF8.GetBytes((JSON $doc));$r.transfer_sha256=HashBytes $script:payload;$r.transfer_size=$script:payload.Length
  [void](PrepareTransfer);UploadFixture
  if($field -eq 'owner_token'){Reject {VerifyTransfer} 'owner identity differs'}else{Reject {VerifyTransfer} 'operation or root differs'}
  [void](CleanupTransfer)
 }
 [void](NewRequest 'source');$script:ownerOkay=$false;$candidate=TransferDirectory
 Reject {PrepareTransfer} 'fixture owner refused';Check (-not(Test-Path -LiteralPath $candidate)) 'Unowned source created transfer directory'
 $script:ownerOkay=$true;[void](PrepareTransfer);UploadFixture;Check ($script:ownedCalls -ge 2) 'Source preparation bypassed existing ownership'
 # Run the real dispatcher under mocked host identity/source execution.
 $main=@($ast.EndBlock.Statements|Where-Object {$_ -is [System.Management.Automation.Language.TryStatementAst]})[-1].Extent.Text
 $main=$main.Replace('$script:SID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',"`$script:SID='fixture-sid'")
 $entry=[ScriptBlock]::Create($main);$dispatch=$r.Clone();$dispatch.op='dispatch-transfer'
 $RequestJson=JSON $dispatch;$RequestPath=''
 $writer=New-Object IO.StringWriter;$oldOutput=[Console]::Out
 [Console]::SetOut($writer);try{& $entry}finally{[Console]::SetOut($oldOutput)}
 $first=$writer.ToString()|ConvertFrom-Json;$writer.Dispose()
 Check ($script:dispatches -eq 1 -and $first.status -eq 'fixture_source_complete') 'Private source was not dispatched once'
 $RequestJson=JSON $dispatch
 $writer=New-Object IO.StringWriter;[Console]::SetOut($writer);try{& $entry}finally{[Console]::SetOut($oldOutput)}
 $second=$writer.ToString()|ConvertFrom-Json;$writer.Dispose()
 Check ($script:dispatches -eq 1 -and $second.error -like '*already dispatched*') 'Private request was dispatched twice'
 $script:r=$dispatch;[void](CleanupTransfer)
 'PASS: fresh facts gate, existing source owner, exact metadata/path, actual payload hash, payload owner/root/op, nested-transfer refusal, safe cleanup, single dispatch'
}finally{Remove-Item -LiteralPath $fixture -Recurse -Force}
