package managedcore

import (
	"context"
	"encoding/json"
	"github.com/daviddwlee84/lazyclash/internal/connection"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This evaluates only the helper's function definitions with mocked Windows
// APIs. It never executes the operation dispatcher or touches registry/tasks.
func TestWindowsPowerShellSafetyRuntime(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed; Windows helper runtime checks require pwsh")
	}
	helper, err := filepath.Abs("windows_host.ps1")
	if err != nil {
		t.Fatal(err)
	}
	harness, err := filepath.Abs("testdata/windows_helper_safety.ps1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", harness, "-Helper", helper)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "PASS: AST") {
		t.Fatalf("PowerShell safety regression: %v\n%s", err, out)
	}
}

func TestWindowsUnrelatedProcessPaths(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell runtime is unavailable")
	}
	helper, err := filepath.Abs("windows_host.ps1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", "testdata/windows_process_paths.ps1", "-Helper", helper)
	if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "PASS: unrelated process paths") {
		t.Fatalf("process path safety: %v\n%s", err, output)
	}
}

func TestWindowsProcessExitDuringStop(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell runtime is unavailable")
	}
	helper, err := filepath.Abs("windows_host.ps1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", "testdata/windows_process_exit.ps1", "-Helper", helper)
	if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "PASS: CIM exit races") {
		t.Fatalf("process exit race: %v\n%s", err, output)
	}
}

func TestWindowsFactsRemoteReadOnlySmoke(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_BRIDGE_LIVE")
	if host == "" {
		t.Skip("set explicit Windows SSH alias for read-only facts smoke")
	}
	// Diagnostic output contains only exception class and our fixed source line,
	// never exception text, request data, registry values or credentials.
	script := strings.Replace(windowsHostScript, `[Console]::Out.WriteLine((JSON @{error=$reason;status='unconfirmed'}))`, `[Console]::Out.WriteLine((JSON @{error='facts diagnostic';status='unconfirmed';class=$_.Exception.GetType().FullName;line=$_.InvocationInfo.ScriptLineNumber;code=$_.InvocationInfo.Line.Trim()}))`, 1)
	request, _ := json.Marshal(windowsRequest{HostOS: "windows", Op: "facts", ID: "windows-laptop", Client: "verge", ControllerPort: 9097, MixedPort: 7897})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := connection.ExecutePowerShell(ctx, host, script, request, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil {
		t.Fatal("invalid facts response")
	}
	if _, bad := result["error"]; bad {
		t.Fatalf("fixed-helper facts diagnostic: class=%s line=%s code=%s", result["class"], result["line"], result["code"])
	}
	if len(result["facts"]) == 0 {
		t.Fatal("facts unavailable")
	}
}

func TestWindowsProxyEnvironmentReadOnly(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_BRIDGE_LIVE")
	if host == "" {
		t.Skip("set explicit Windows SSH alias for read-only proxy environment inspection")
	}
	script := `param([string]$RequestJson)
$ErrorActionPreference='Stop'
$items=@()
foreach($scope in @('User','Machine')){foreach($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')){
 $value=[Environment]::GetEnvironmentVariable($name,([EnvironmentVariableTarget]$scope))
 $item=@{scope=$scope;name=$name;configured=([bool]$value);old_cfw=$false}
 if($value){$parse=$value;if(-not $parse.Contains('://')){$parse='http://'+$parse};$uri=$null
  if([Uri]::TryCreate($parse,[UriKind]::Absolute,[ref]$uri)){$item.scheme=$uri.Scheme;$item.host=$uri.DnsSafeHost;$item.port=$uri.Port;$item.old_cfw=($uri.DnsSafeHost -in @('127.0.0.1','localhost','::1') -and $uri.Port -eq 7891)}else{$item.format='non-URL; value withheld'}
 }
 $items+=$item
}}
$winhttp=(& netsh.exe winhttp show proxy 2>$null|Out-String)
$result=@{environment=$items;winhttp=@{query_ok=($LASTEXITCODE -eq 0);direct=($winhttp -match 'Direct access|直接访问|直接存取');old_cfw=($winhttp -match '(127\.0\.0\.1|localhost|\[::1\]):7891')}}
[Console]::Out.WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := connection.ExecutePowerShell(ctx, host, script, []byte(`{}`), 8192)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("invalid proxy environment summary")
	}
	t.Log(strings.TrimSpace(string(raw)))
}

func TestWindowsInteropRemoteReadOnlySmoke(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_BRIDGE_LIVE")
	if host == "" {
		t.Skip("set explicit Windows SSH alias for read-only interop smoke")
	}
	phase := os.Getenv("LAZYCLASH_WINDOWS_SMOKE_PHASE")
	script := windowsHostScript[:strings.Index(windowsHostScript, "\ntry{\n $script:SID=")]
	switch phase {
	case "payload":
		script = "param([string]$RequestJson)\n#" + strings.Repeat("x", len(windowsHostScript)) + "\n[Console]::Out.WriteLine('{\"ok\":true}')"
	case "compile":
		script += "\nNetworkInterop;[Console]::Out.WriteLine('{\"ok\":true}')"
	case "flags":
		script += "\nNetworkInterop;$n=[Lazyclash.WindowsNetworkState]::ProxyFlags($false,0);[Console]::Out.WriteLine('{\"ok\":true}')"
	case "ras":
		script += "\n$n=RASCount;[Console]::Out.WriteLine('{\"ok\":true}')"
	default:
		t.Skip("select explicit payload/compile/flags/ras read-only phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := connection.ExecutePowerShell(ctx, host, script, []byte(`{}`), 1024)
	if err != nil {
		t.Fatalf("%s: %v", phase, err)
	}
	if !strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("%s did not complete", phase)
	}
}
