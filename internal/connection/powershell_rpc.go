package connection

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/hostpath"
)

//go:embed powershell_rpc.ps1
var powerShellRPCWrapper string

const rpcMaximumBudget = 360 * time.Second

// Only non-secret transport metadata is encoded into bootstrap arguments.
type powerShellRPCMetadata struct {
	Operation    string `json:"operation"`
	Nonce        string `json:"nonce"`
	HelperSHA256 string `json:"helper_sha256,omitempty"`
	HelperSize   int    `json:"helper_size,omitempty"`
	InputSHA256  string `json:"input_sha256,omitempty"`
	InputSize    int    `json:"input_size,omitempty"`
	BudgetMS     int64  `json:"budget_ms,omitempty"`
}

func rpcHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func executePowerShellRPC(ctx context.Context, host, script string, input []byte, limit int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcMaximumBudget)
	defer cancel()
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, errors.New("cannot create private Windows RPC identity")
	}
	m := powerShellRPCMetadata{Operation: "prepare", Nonce: hex.EncodeToString(nonceBytes)}
	wrapped := []byte(strings.Replace(powerShellRPCWrapper, "__LAZYCLASH_RPC_HELPER__", base64.StdEncoding.EncodeToString([]byte(script)), 1))
	m.HelperSHA256, m.HelperSize, m.InputSHA256, m.InputSize = rpcHash(wrapped), len(wrapped), rpcHash(input), len(input)
	spool, err := os.MkdirTemp("", "lazyclash-windows-rpc-")
	if err != nil {
		return nil, errors.New("cannot create private Windows RPC spool")
	}
	defer os.RemoveAll(spool)
	if err = os.Chmod(spool, 0700); err != nil {
		return nil, errors.New("cannot secure private Windows RPC spool")
	}
	for name, data := range map[string][]byte{"helper.ps1": wrapped, "request.json": input} {
		if err = os.WriteFile(filepath.Join(spool, name), data, 0600); err != nil {
			return nil, errors.New("cannot write private Windows RPC spool")
		}
	}
	prepared, err := runPowerShellRPCCommand(ctx, host, m, powerShellRPCPrepare, 8192)
	if err != nil {
		return nil, err
	}
	var result struct {
		Directory string `json:"directory"`
		Nonce     string `json:"nonce"`
	}
	if json.Unmarshal(prepared, &result) != nil || result.Nonce != m.Nonce || !validRPCDirectory(result.Directory, m.Nonce) {
		return nil, errors.New("Windows RPC preparation did not return its expected private directory")
	}
	dispatched := false
	defer func() {
		// Before dispatch, only temporary RPC files exist. Cleanup stays within
		// the caller's remaining budget; canceled/unknown results retain private
		// remote staging instead of extending the operation or retrying it.
		if !dispatched && ctx.Err() == nil {
			cleanCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			m.Operation = "cleanup"
			_, _ = runPowerShellRPCCommand(cleanCtx, host, m, powerShellRPCCleanup, 1024)
		}
	}()
	for _, name := range []string{"helper.ps1", "request.json"} {
		local, remote := filepath.Join(spool, name), hostpath.Join("windows", result.Directory, name)
		if host != "" {
			err = CopyPrivateFile(ctx, host, local, remote)
		} else {
			err = copyLocalRPCFile(local, remote)
		}
		if err != nil {
			return nil, err
		}
	}
	remaining := rpcMaximumBudget
	if deadline, ok := ctx.Deadline(); ok {
		remaining = time.Until(deadline)
	}
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	m.BudgetMS = remaining.Milliseconds()
	if m.BudgetMS < 1 {
		m.BudgetMS = 1
	}
	if m.BudgetMS > rpcMaximumBudget.Milliseconds() {
		m.BudgetMS = rpcMaximumBudget.Milliseconds()
	}
	m.Operation = "dispatch"
	dispatched = true
	return runPowerShellRPCCommand(ctx, host, m, powerShellRPCDispatch, limit)
}

func validRPCDirectory(path, nonce string) bool {
	if len(nonce) != 32 || !hostpath.IsAbs("windows", path) {
		return false
	}
	clean := hostpath.Clean("windows", path)
	if !strings.EqualFold(hostpath.Base("windows", clean), nonce) {
		return false
	}
	parent := hostpath.Dir("windows", clean)
	return strings.EqualFold(hostpath.Base("windows", parent), "rpc") && strings.EqualFold(hostpath.Base("windows", hostpath.Dir("windows", parent)), "lazyclash")
}

func copyLocalRPCFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return errors.New("cannot read private local RPC spool")
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create exact private local RPC destination")
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		return errors.New("private local RPC copy did not complete")
	}
	return nil
}

func runPowerShellRPCCommand(ctx context.Context, host string, m powerShellRPCMetadata, body string, limit int) ([]byte, error) {
	metadata, _ := json.Marshal(m)
	// The fixed bootstrap body varies only by nonce, hashes, sizes and timeout.
	// Helper source and request contents are never command-line data.
	code := "$lcRpcMeta=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(metadata) + "'))|ConvertFrom-Json);" + body
	argv := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(code)}
	remoteCommand := "powershell.exe " + strings.Join(argv, " ")
	if len(remoteCommand) > 8191 {
		return nil, errors.New("Windows RPC bootstrap exceeds the cmd.exe command-line limit")
	}
	var cmdArgs []string
	program := "powershell.exe"
	if host != "" {
		args, err := sshArgsContext(ctx, host)
		if err != nil {
			return nil, err
		}
		program = "ssh"
		cmdArgs = append(args, "-T", "--", host, remoteCommand)
	} else {
		cmdArgs = argv
	}
	cmd := commandContext(ctx, program, cmdArgs...)
	var output, diagnostic limitedBuffer
	output.limit = limit
	diagnostic.limit = 8192
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	cmd.WaitDelay = 2 * time.Second
	configureHelperProcess(cmd)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if output.Exceeded() || diagnostic.Exceeded() {
			return nil, ErrHelperOutputLimit
		}
		if host != "" && needsAuthentication(diagnostic.String()) {
			return nil, &AuthRequiredError{Host: host}
		}
		if transport := classifySSHTransport(err, diagnostic.String()); transport != nil {
			return nil, transport
		}
		return nil, fmt.Errorf("Windows RPC %s did not complete; inspect its private operation receipt and prerequisites", m.Operation)
	}
	if output.Exceeded() || diagnostic.Exceeded() {
		return nil, ErrHelperOutputLimit
	}
	return output.Bytes(), nil
}

const powerShellRPCPath = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false);if($lcRpcMeta.nonce -notmatch '^[a-f0-9]{32}$'){throw 'identity'};$lcRpcSID=[Security.Principal.WindowsIdentity]::GetCurrent().User;$lcRpcDir=Join-Path (Join-Path (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'lazyclash') 'rpc') $lcRpcMeta.nonce;$lcRpcOwner='lazyclash-rpc-v1|'+$lcRpcMeta.nonce+'|'+$lcRpcSID.Value;function NR($p){while($p){if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'reparse'}};$q=[IO.Path]::GetDirectoryName($p);if($q -eq $p){break};$p=$q}};`
const powerShellRPCPrepare = powerShellRPCPath + `try{NR $lcRpcDir;if(Test-Path -LiteralPath $lcRpcDir){throw 'exists'};$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetOwner($lcRpcSID);$acl.SetAccessRuleProtection($true,$false);foreach($sid in @($lcRpcSID,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))};[IO.Directory]::CreateDirectory($lcRpcDir,$acl)|Out-Null;NR $lcRpcDir;$file=[IO.File]::Open((Join-Path $lcRpcDir 'owner'),'CreateNew','Write','None');try{$bytes=[Text.Encoding]::UTF8.GetBytes($lcRpcOwner);$file.Write($bytes,0,$bytes.Length)}finally{$file.Dispose()};[Console]::Out.WriteLine((@{directory=$lcRpcDir;nonce=$lcRpcMeta.nonce}|ConvertTo-Json -Compress))}catch{[Console]::Error.WriteLine('Private Windows RPC preparation failed');exit 1}`
const powerShellRPCDispatch = powerShellRPCPath + `$lcRpcClock=[Diagnostics.Stopwatch]::StartNew();try{NR $lcRpcDir;$owner=Join-Path $lcRpcDir 'owner';NR $owner;if((Get-Item -LiteralPath $owner).Length -gt 256 -or [IO.File]::ReadAllText($owner) -ne $lcRpcOwner){throw 'owner'};$p=Join-Path $lcRpcDir 'helper.ps1';NR $p;if($lcRpcMeta.helper_size -lt 1 -or $lcRpcMeta.helper_size -gt 2097152){throw 'limit'};$f=[IO.File]::Open($p,'Open','Read','Read');try{if($f.Length -ne $lcRpcMeta.helper_size){throw 'size'};$b=New-Object byte[] ([int]$f.Length);$n=0;while($n -lt $b.Length){$r=$f.Read($b,$n,$b.Length-$n);if($r -le 0){throw 'short'};$n+=$r}}finally{$f.Dispose()};$h=[Security.Cryptography.SHA256]::Create();try{$sha=([BitConverter]::ToString($h.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($sha -ne $lcRpcMeta.helper_sha256){throw 'hash'};& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($b))) -RpcMetadata $lcRpcMeta -RpcDirectory $lcRpcDir -RpcClock $lcRpcClock}catch{[Console]::Error.WriteLine('Private Windows RPC dispatch failed');exit 1}`
const powerShellRPCCleanup = powerShellRPCPath + `try{NR $lcRpcDir;if(-not(Test-Path -LiteralPath $lcRpcDir)){exit 0};$p=Join-Path $lcRpcDir 'owner';NR $p;if([IO.File]::ReadAllText($p) -ne $lcRpcOwner){throw 'owner'};foreach($f in @(Get-ChildItem -LiteralPath $lcRpcDir -Force)){if($f.Name -notin @('owner','helper.ps1','request.json') -or $f.PSIsContainer){throw 'files'};NR $f.FullName};foreach($n in @('helper.ps1','request.json','owner')){$p=Join-Path $lcRpcDir $n;if(Test-Path -LiteralPath $p){[IO.File]::Delete($p)}};[IO.Directory]::Delete($lcRpcDir,$false)}catch{[Console]::Error.WriteLine('Private Windows RPC cleanup requires inspection');exit 1}`
