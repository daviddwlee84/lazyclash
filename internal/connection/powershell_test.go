package connection

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestFreshWindowsSSHUsesNewTransportAndPowerShell(t *testing.T) {
	cmd, err := freshWindowsSSHCommand(context.Background(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(cmd.Args, " ")
	for _, want := range []string{"ControlMaster=no", "ControlPath=none", "ControlPersist=no", "ClearAllForwardings=yes", "BatchMode=yes", "-- fixture powershell.exe", "-EncodedCommand"} {
		if !strings.Contains(args, want) {
			t.Fatal("missing fresh SSH guard", want)
		}
	}
	if strings.HasSuffix(args, " true") {
		t.Fatal("POSIX command used on Windows")
	}
	if _, err = freshWindowsSSHCommand(context.Background(), "bad;host"); err == nil {
		t.Fatal("unsafe alias accepted")
	}
}

func TestPowerShellRemoteRPCSmoke(t *testing.T) {
	host := os.Getenv("LAZYCLASH_WINDOWS_BRIDGE_LIVE")
	if host == "" {
		t.Skip("set explicit Windows SSH alias for private RPC smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := ExecutePowerShell(ctx, host, `param([string]$RequestJson); [Console]::Out.WriteLine('{"ok":true}')`, []byte(`{}`), 1024)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]bool
	if json.Unmarshal(out, &response) != nil || !response["ok"] {
		t.Fatal("unexpected read-only helper response")
	}
}

type rpcFixture struct {
	t              *testing.T
	phases         []string
	files          map[string][]byte
	spools         []string
	metadata       powerShellRPCMetadata
	failurePhase   string
	failure        muxReply
	wrongDirectory bool
	beforeDispatch func()
}

func decodedRPCMetadata(t *testing.T, command string) (powerShellRPCMetadata, string) {
	t.Helper()
	parts := strings.Split(command, "-EncodedCommand ")
	if len(parts) != 2 {
		t.Fatal("missing encoded RPC command")
	}
	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(data)%2 != 0 {
		t.Fatal("invalid encoded RPC")
	}
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	code := string(utf16.Decode(words))
	matches := regexp.MustCompile(`FromBase64String\('([A-Za-z0-9+/=]+)'\)`).FindStringSubmatch(code)
	if len(matches) != 2 {
		t.Fatal("missing bounded RPC metadata")
	}
	raw, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		t.Fatal(err)
	}
	var m powerShellRPCMetadata
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("invalid RPC metadata")
	}
	return m, code
}

func newRPCFixture(t *testing.T) *rpcFixture {
	t.Helper()
	f := &rpcFixture{t: t, files: map[string][]byte{}}
	clearMultiplexPolicies()
	old := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		reply := muxReply{}
		switch {
		case name == "ssh" && len(args) == 1 && args[0] == "-V":
			reply.Err = "OpenSSH_10.3p1, LibreSSL\n"
		case name == "ssh" && len(args) > 0 && args[0] == "-G":
			reply.Out = "controlmaster no\ncontrolpersist no\ncontrolpath none\n"
		case name == "scp":
			f.phases = append(f.phases, "upload")
			if len(args) < 3 || args[len(args)-3] != "--" {
				t.Fatal("unsafe RPC file copy")
			}
			local := args[len(args)-2]
			info, err := os.Stat(local)
			dir, dirErr := os.Stat(filepath.Dir(local))
			if err != nil || dirErr != nil || info.Mode().Perm() != 0600 || dir.Mode().Perm() != 0700 {
				t.Fatal("RPC spool is not private")
			}
			if !strings.HasPrefix(filepath.Base(filepath.Dir(local)), "lazyclash-windows-rpc-") {
				t.Fatal("unexpected RPC source")
			}
			data, err := os.ReadFile(local)
			if err != nil {
				t.Fatal(err)
			}
			f.files[filepath.Base(local)] = data
			f.spools = append(f.spools, local)
			if !strings.HasSuffix(args[len(args)-1], "/"+f.metadata.Nonce+"/"+filepath.Base(local)) {
				t.Fatal("RPC copy escaped prepared nonce")
			}
			if f.failurePhase == "upload" {
				reply = f.failure
			}
		case name == "ssh":
			command := args[len(args)-1]
			m, code := decodedRPCMetadata(t, command)
			f.metadata = m
			f.phases = append(f.phases, m.Operation)
			if len(command) > 8191 {
				t.Fatal("RPC command exceeds cmd.exe limit", len(command))
			}
			for _, secret := range []string{"credential-fixture", "helper-private-fixture", base64.StdEncoding.EncodeToString([]byte(`{"secret":"credential-fixture"}`))} {
				if strings.Contains(command, secret) || strings.Contains(code, secret) {
					t.Fatal("RPC command contains helper or request content")
				}
			}
			if strings.Contains(code, "Console]::In") || strings.Contains(code, "OpenStandardInput") {
				t.Fatal("production RPC reads stdin")
			}
			switch m.Operation {
			case "prepare":
				directory := "C:/Users/fixture/AppData/Local/lazyclash/rpc/" + m.Nonce
				if f.wrongDirectory {
					directory = "C:/Users/fixture/unowned"
				}
				raw, _ := json.Marshal(map[string]string{"directory": directory, "nonce": m.Nonce})
				reply.Out = string(raw)
			case "dispatch":
				if f.beforeDispatch != nil {
					f.beforeDispatch()
				}
				if rpcHash(f.files["helper.ps1"]) != m.HelperSHA256 || len(f.files["helper.ps1"]) != m.HelperSize || rpcHash(f.files["request.json"]) != m.InputSHA256 || len(f.files["request.json"]) != m.InputSize {
					t.Fatal("dispatcher lost exact file hashes/sizes")
				}
				if m.BudgetMS < 1 || m.BudgetMS > 360000 {
					t.Fatal("unbounded remote watchdog")
				}
				reply.Out = `{"status":"verified"}`
			case "cleanup":
			default:
				t.Fatal("unexpected RPC phase", m.Operation)
			}
			if f.failurePhase == m.Operation {
				reply = f.failure
			}
		default:
			t.Fatal("unexpected RPC subprocess", name)
		}
		raw, _ := json.Marshal(reply)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMuxReplyProcess")
		cmd.Env = append(os.Environ(), "LAZYCLASH_MUX_REPLY="+base64.StdEncoding.EncodeToString(raw), "GORACE=atexit_sleep_ms=0")
		return cmd
	}
	t.Cleanup(func() { commandContext = old; clearMultiplexPolicies() })
	return f
}

func TestExecutePowerShellRPCUsesPrivateFilesAndMetadataOnlyArguments(t *testing.T) {
	f := newRPCFixture(t)
	script := "param([string]$RequestJson); # helper-private-fixture"
	input := []byte(`{"secret":"credential-fixture"}`)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := ExecutePowerShell(ctx, "fixture-ssh", script, input, 1024)
	if err != nil || string(out) != `{"status":"verified"}` {
		t.Fatal("private RPC failed", err)
	}
	if !reflect.DeepEqual(f.phases, []string{"prepare", "upload", "upload", "dispatch"}) {
		t.Fatal("unexpected RPC ordering", f.phases)
	}
	if string(f.files["request.json"]) != string(input) || !strings.Contains(string(f.files["helper.ps1"]), base64.StdEncoding.EncodeToString([]byte(script))) {
		t.Fatal("private payload integrity changed")
	}
	if f.metadata.BudgetMS > 45000 {
		t.Fatal("caller budget was extended")
	}
	for _, path := range f.spools {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("local private RPC spool remained", err)
		}
	}
}

func TestPowerShellRPCRejectsDifferentPreparedDirectory(t *testing.T) {
	f := newRPCFixture(t)
	f.wrongDirectory = true
	_, err := ExecutePowerShell(context.Background(), "fixture-ssh", "param([string]$RequestJson)", []byte(`{}`), 128)
	if err == nil || len(f.phases) != 1 {
		t.Fatal("unowned prepared path accepted", err, f.phases)
	}
}

func TestPowerShellRPCFailuresAreClassifiedPrivateAndNeverRetried(t *testing.T) {
	cases := []struct {
		name, phase            string
		reply                  muxReply
		auth, transport, limit bool
	}{
		{"auth", "prepare", muxReply{Code: 255, Err: "PRIVATE: Permission denied (publickey)."}, true, false, false},
		{"route", "prepare", muxReply{Code: 255, Err: "ssh: connect to host PRIVATE port 22: No route to host"}, false, true, false},
		{"upload", "upload", muxReply{Code: 1, Err: "PRIVATE upload failure"}, false, false, false},
		{"dispatch", "dispatch", muxReply{Code: 1, Err: "PRIVATE helper exception"}, false, false, false},
		{"output-limit", "dispatch", muxReply{Out: strings.Repeat("PRIVATE", 4096)}, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRPCFixture(t)
			f.failurePhase, f.failure = tc.phase, tc.reply
			_, err := ExecutePowerShell(context.Background(), "fixture-ssh", "param([string]$RequestJson)", []byte(`{}`), 128)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("unsafe RPC failure", err)
			}
			var transport *SSHTransportError
			if IsAuthRequired(err) != tc.auth || errors.As(err, &transport) != tc.transport || errors.Is(err, ErrHelperOutputLimit) != tc.limit {
				t.Fatal("RPC error classification lost", err)
			}
			count := 0
			for _, phase := range f.phases {
				if phase == tc.phase {
					count++
				}
			}
			if count != 1 {
				t.Fatal("failed phase repeated", f.phases)
			}
			if tc.phase == "upload" && f.phases[len(f.phases)-1] != "cleanup" {
				t.Fatal("known pre-dispatch staging not cleaned")
			}
			if tc.phase == "dispatch" && f.phases[len(f.phases)-1] != "dispatch" {
				t.Fatal("unknown dispatch result was replayed or cleaned blindly")
			}
		})
	}
}

func TestPowerShellRPCCancellationBoundsLocalProcessAndRemoteBudget(t *testing.T) {
	f := newRPCFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f.failurePhase = "dispatch"
	f.failure = muxReply{Hold: true}
	f.beforeDispatch = func() { time.AfterFunc(75*time.Millisecond, cancel) }
	started := time.Now()
	_, err := ExecutePowerShell(ctx, "fixture-ssh", "param([string]$RequestJson)", []byte(`{}`), 128)
	if !errors.Is(err, context.Canceled) || time.Since(started) > 3*time.Second || f.metadata.BudgetMS > 2000 {
		t.Fatal("RPC local cancellation/budget failed", err, time.Since(started))
	}
	// This is a local mocked process test. Remote watchdog termination requires
	// the separate opt-in Windows test and is not inferred from cancellation.
}

func TestPowerShellRPCBoundsAndScripts(t *testing.T) {
	for _, script := range []string{powerShellRPCPrepare, powerShellRPCDispatch, powerShellRPCCleanup} {
		m := powerShellRPCMetadata{Operation: "dispatch", Nonce: strings.Repeat("a", 32), HelperSHA256: strings.Repeat("b", 64), HelperSize: 2 << 20, InputSHA256: strings.Repeat("c", 64), InputSize: 256 << 20, BudgetMS: 360000}
		raw, _ := json.Marshal(m)
		code := "$lcRpcMeta=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(raw) + "'))|ConvertFrom-Json);" + script
		command := "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encodedPowerShell(code)
		if len(command) > 8191 {
			t.Fatal("RPC bootstrap exceeds Windows cmd.exe bound", len(command))
		}
	}
	for _, guard := range []string{"AreAccessRulesProtected", "GetOwner", "S-1-5-18", "ReparsePoint", "helper.ps1", "request.json", "[IO.Directory]::Delete($RpcDirectory,$false)", "Environment.Exit(124)", "360000", "input_sha256"} {
		if !strings.Contains(powerShellRPCWrapper, guard) {
			t.Fatal("RPC ownership/lifetime guard missing", guard)
		}
	}
	if strings.Contains(powerShellRPCWrapper, "Remove-Item") || strings.Contains(powerShellRPCWrapper, "Kill(") {
		t.Fatal("RPC can recursively remove state or kill another process")
	}
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("pwsh unavailable for parser-only check")
	}
	payload, _ := json.Marshal([]string{powerShellRPCPrepare, powerShellRPCDispatch, powerShellRPCCleanup, powerShellRPCWrapper})
	parse := `$scripts=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:LC_RPC_PARSE))|ConvertFrom-Json;foreach($s in $scripts){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors);if($errors.Count){[Console]::Error.WriteLine(($errors|ForEach-Object {$_.Message}) -join ';');exit 1}}`
	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(parse))
	cmd.Env = append(os.Environ(), "LC_RPC_PARSE="+base64.StdEncoding.EncodeToString(payload))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("RPC PowerShell syntax: %s %v", out, err)
	}
}
