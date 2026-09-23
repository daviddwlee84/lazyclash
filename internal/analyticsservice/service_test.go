package analyticsservice

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestRunUsesSelectedHostJSONAndFixedHelper(t *testing.T) {
	r := Request{Action: "install", SSHHost: "my-server", Executable: "/opt/lazyclash", ConfigPath: "/home/user/config.json", StateDir: "/home/user/state"}
	called := false
	o := Options{Execute: func(_ context.Context, host, script string, input []byte, limit int) ([]byte, error) {
		called = true
		if host != r.SSHHost || script != hostScript || limit != 1<<20 {
			t.Fatal("unexpected execution contract")
		}
		var got Request
		if err := json.Unmarshal(input, &got); err != nil {
			t.Fatal(err)
		}
		if got.Executable != r.Executable || got.ConfigPath != r.ConfigPath || got.StateDir != r.StateDir || got.Apply || strings.Contains(string(input), r.SSHHost) {
			t.Fatal("request transport mismatch", string(input))
		}
		return []byte(`{"available":true,"preview":true,"digest":"reviewed","details":["session"]}`), nil
	}}
	result, err := Run(context.Background(), r, o)
	if err != nil || !called || !result.Preview || result.Digest != "reviewed" {
		t.Fatal(result, err)
	}
}

func TestRejectsUnreviewedMutationsAndRemoteLocalFallback(t *testing.T) {
	base := Request{Action: "install", SSHHost: "server", StateDir: "/state", ConfigPath: "/config"}
	called := false
	o := Options{Execute: func(context.Context, string, string, []byte, int) ([]byte, error) {
		called = true
		return nil, errors.New("must not execute")
	}}
	for _, mutate := range []func(*Request){
		func(r *Request) {}, // Remote executable must be explicitly host-local.
		func(r *Request) { r.Executable = "/binary"; r.Apply = true },
		func(r *Request) { r.Executable = "/binary"; r.Apply = true; r.Expect = "bad" },
		func(r *Request) { r.Executable = "/binary"; r.StateDir = "relative" },
		func(r *Request) { r.Executable = "/binary"; r.ConfigPath = "relative" },
		func(r *Request) { r.Action = "restart" },
		func(r *Request) { r.Action = "status"; r.Apply = true },
		func(r *Request) { r.Action = "stop"; r.Expect = strings.Repeat("0", 64) },
	} {
		r := base
		mutate(&r)
		if _, err := Run(context.Background(), r, o); err == nil {
			t.Fatal("expected rejection", r)
		}
	}
	base.Action, base.Apply, base.Expect = "stop", true, strings.Repeat("0", 64)
	o.ReadOnly = true
	if _, err := Run(context.Background(), base, o); err == nil || called {
		t.Fatal("read-only/unreviewed request reached host", err)
	}
}

func TestHelperErrorsAreReturned(t *testing.T) {
	r := Request{Action: "status", StateDir: "/state"}
	for _, raw := range []string{`{"error":"ownership drift"}`, `not json`} {
		o := Options{Execute: func(context.Context, string, string, []byte, int) ([]byte, error) { return []byte(raw), nil }}
		if _, err := Run(context.Background(), r, o); err == nil {
			t.Fatal("expected helper error")
		}
	}
}

// Execute the actual fixed helper against a temporary filesystem. All process
// calls, platform facts and home lookup are stubbed inside the isolated Python
// process, so this test cannot install or alter a real user service.
func TestHostLifecycleAndSafety(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("local POSIX host-helper fixture; native Windows adapter contracts are tested separately")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	cmd := exec.Command(python, "-c", hostScript+"\n"+hostFixture)
	// Suppress the helper's stdin entry point; this module name does not execute
	// __main__, and the fixture explicitly invokes its functions instead.
	cmd.Args = []string{python, "-c", "__name__ = 'analyticsservice_fixture'\n" + hostScript + "\n" + hostFixture}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("host lifecycle fixture: %v\n%s", err, out)
	}
	if string(out) != "fixture passed\n" {
		t.Fatalf("unexpected fixture output %q", out)
	}
}

const hostFixture = `
import tempfile
from unittest.mock import patch

def check(condition, message):
    if not condition:
        raise AssertionError(message)

def rejects(call, message):
    try:
        call()
    except (ValueError, OSError):
        return
    raise AssertionError(message)

for system in ('linux', 'darwin'):
    with tempfile.TemporaryDirectory() as temporary:
        base = pathlib.Path(os.path.realpath(temporary))
        home = base / 'home'
        home.mkdir(mode=0o700)
        state = home / 'state space $x %h'
        config = home / 'config space $x %h.json'
        exclusive(config, b'{"enabled":true}', 0o600)
        executable = home / 'source-lazyclash'
        binary = (b'\x7fELF\x02\x01' + b'\0'*12 + struct.pack('<H',62) + b'\0'*80) if system == 'linux' else (b'\xcf\xfa\xed\xfe' + struct.pack('<I',0x01000007) + b'\0'*80)
        exclusive(executable, binary, 0o700)
        live = {'loaded':False, 'running':False, 'enabled':False, 'linger':'yes', 'available':True, 'dropins':''}
        calls = []
        current = {}

        def fake_command(args, required=False):
            calls.append(args)
            if args == [str(executable), 'analytics', '--help']:
                return 'collect --analytics-config'
            if args[0] == 'loginctl':
                return live['linger'] + '\n'
            if args[0] == 'systemctl':
                check(args[1] == '--user', 'must never use system scope')
                op = args[3] if args[2] == '--no-pager' else args[2]
                if op == 'show-environment':
                    return '' if live['available'] else None
                if op == 'show':
                    c = current['c']
                    exists = c['unit'].exists()
                    token = c['owner'].read_text().strip() if exists else ''
                    return '\n'.join([
                        'LoadState=' + ('loaded' if exists else 'not-found'),
                        'ActiveState=' + ('active' if live['running'] else 'inactive'),
                        'UnitFileState=' + ('enabled' if live['enabled'] else 'disabled'),
                        'FragmentPath=' + (str(c['unit']) if exists else ''),
                        'DropInPaths=' + live['dropins'], 'NeedDaemonReload=no',
                        'Environment=' + (OWNER_ENV + '=' + token if exists else '')])
                if op == 'start': live['running'] = True
                elif op == 'stop': live['running'] = False
                elif op == 'enable': live['enabled'] = True
                elif op == 'disable': live['enabled'] = False
                elif op != 'daemon-reload': raise AssertionError(args)
                return ''
            if args[0] == 'launchctl':
                c = current['c']
                op = args[1]
                if op == 'print':
                    if args[2] == 'gui/' + str(os.getuid()):
                        return '' if live['available'] else None
                    if not live['loaded']: return None
                    return ('path = ' + str(c['unit']) + '\nprogram = ' + str(c['binary']) + '\n' + OWNER_ENV + ' => ' + c['owner'].read_text().strip() + '\nstate = ' + ('running' if live['running'] else 'waiting') + '\n')
                if op == 'bootstrap': live['loaded'],live['running'] = True,True
                elif op == 'kickstart': live['running'] = True
                elif op == 'bootout': live['loaded'],live['running'] = False,False
                else: raise AssertionError(args)
                return ''
            raise AssertionError(args)

        with patch.dict(globals(), {'platform_name':lambda:system, 'architecture':lambda:'amd64', 'command':fake_command}), patch('os.path.expanduser', return_value=str(home)), patch('os.geteuid', return_value=1000), patch('shutil.which', return_value='/fixture/tool'):
            request = {'action':'install', 'state_dir':str(state), 'config_path':str(config), 'executable':str(executable)}
            current['c'] = context(request)
            c = current['c']
            preview = main(request)
            check(preview['preview'] and not state.exists(), 'preview wrote managed state')
            check(len(preview['digest']) == 64 and not preview['owned'], 'preview contract')
            mutated = dict(request, apply=True, expect='0'*64)
            rejects(lambda:main(mutated), 'stale preview applied')
            check(not state.exists(), 'stale preview created state')
            installed = main(dict(request, apply=True, expect=preview['digest']))
            check(installed['owned'] and installed['installed'] and installed['changed'], 'install ownership missing')
            check(not installed['running'], 'install unexpectedly starts collection')
            check(c['binary'].read_bytes() == binary and stat.S_IMODE(c['binary'].stat().st_mode) == 0o700, 'private binary copy')
            check(stat.S_IMODE(c['manifest'].stat().st_mode) == 0o600 and stat.S_IMODE(c['owner'].stat().st_mode) == 0o600, 'private ownership')
            check(str(config) == installed['config_path'] and config.read_bytes() == b'{"enabled":true}', 'caller config must remain untouched')
            unit = c['unit'].read_bytes()
            if system == 'linux':
                check(b'%%h' in unit and b'$$x' in unit and b'StandardOutput=null' in unit, 'systemd quoting or bounded logging')
                live['linger'] = 'no'
                session = main({'action':'status','state_dir':str(state)})
                check(session['session_dependent'], 'linger warning missing')
                live['linger'] = 'yes'
            else:
                plist = plistlib.loads(unit)
                check(plist['ProgramArguments'] == [str(c['binary']),'analytics','--analytics-config',str(config),'--state-dir',str(state),'collect'], 'launch argument boundaries')
                check(plist['StandardErrorPath'] == '/dev/null' and installed['session_dependent'], 'launch session/logging')

            def action(name):
                r = {'action':name,'state_dir':str(state)}
                p = main(r)
                return main(dict(r,apply=True,expect=p['digest']))

            check(action('start')['running'], 'start failed')
            check(not action('start')['changed'], 'start should be idempotent')
            # Config changes are intentional and must not invalidate ownership.
            config.write_bytes(b'{"enabled":false}')
            check(not action('stop')['running'], 'stop after config edit failed')
            check(action('start')['running'], 'restart with edited config failed')
            # Unknown state survives removal; only hashes of owned artifacts are deleted.
            extra = c['root'] / 'keep-me'
            exclusive(extra,b'keep',0o600)
            data = state / 'analytics.sqlite'
            exclusive(data,b'fixture database',0o600)

            c['binary'].write_bytes(binary + b'drift')
            status = main({'action':'status','state_dir':str(state)})
            check(status['drifted'] and not status['owned'], 'binary drift not detected')
            p = main({'action':'remove','state_dir':str(state)})
            rejects(lambda:main({'action':'remove','state_dir':str(state),'apply':True,'expect':p['digest']}), 'drift removal succeeded')
            c['binary'].write_bytes(binary)
            if system == 'linux':
                live['dropins'] = '/some/override.conf'
                check(main({'action':'status','state_dir':str(state)})['drifted'], 'external drop-in not refused')
                live['dropins'] = ''
            removed = action('remove')
            check(removed['changed'] and not removed['installed'] and not removed['running'], 'remove failed')
            check(config.exists() and data.exists() and extra.exists(), 'remove deleted caller data')
            check(not c['binary'].exists() and not c['manifest'].exists() and not c['unit'].exists(), 'owned artifacts remain')
            check(not action('remove')['changed'], 'remove should be idempotent')
            check(all('sudo' not in a and not any(v in a for v in ('enable-linger','disable-linger')) for a in calls), 'privileged mutation')
            # Explicitly refuse symlinked config and insecure modes; no chmod repair.
            config.chmod(0o644)
            rejects(lambda:main(request), 'public config accepted')
            check(stat.S_IMODE(config.stat().st_mode) == 0o644, 'helper repaired source permissions')
            config.chmod(0o600)
            link = home/'linked.json'
            link.symlink_to(config)
            rejects(lambda:main(dict(request,config_path=str(link))), 'symlink config accepted')
            wrong = home/'wrong-binary'
            exclusive(wrong,b'not a host executable',0o700)
            rejects(lambda:main(dict(request,executable=str(wrong))), 'foreign binary accepted')
            live['available'] = False
            unavailable = main(request)
            check(not unavailable['available'], 'unavailable manager hidden')
            rejects(lambda:main(dict(request,apply=True,expect=unavailable['digest'])), 'unavailable manager applied')

print('fixture passed')
`
