#!/usr/bin/env python3
"""Verify reverse SSH CLI behavior with a real, disposable sshd and PTY.

Run after building bin/lazyclash: python3 scripts/reverse_pty_smoke.py
No configured host, real user SSH config, or system service is modified. Missing
local sshd/session capabilities skip by default; --require makes that a failure.
LAZYCLASH_TEST_WRAPPER_SHELL=/bin/dash checks the outer test shell explicitly.
"""
import argparse
import fcntl
import http.server
import json
import os
from pathlib import Path
import pty
import pwd
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin/lazyclash"
ALIAS = "lazyclash-reverse-fixture"


class Unavailable(Exception):
    pass


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def accepts(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.15):
            return True
    except OSError:
        return False


def eventually(predicate, label, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.04)
    raise AssertionError(label)


class Terminal:
    def __init__(self, args, env):
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
        self.raw = bytearray()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 130, 0, 0))

        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)

        # Catch SIGINT only in the test wrapper: dash otherwise exits with the
        # foreground child before we can observe its real status. A caught trap
        # resets in the exec'd child; an ignored signal would change CLI behavior.
        wrapper = ('trap ":" INT; "$@"; result=$?; trap - INT; '
                   'printf "\\n__LC_EXIT_%s__\\n" "$result"; '
                   'IFS= read -r reply; printf "__LC_ECHO_%s__\\n" "$reply"; exit "$result"')
        self.process = subprocess.Popen(
            [env.get("LAZYCLASH_TEST_WRAPPER_SHELL", "/bin/sh"), "-c", wrapper, "reverse-pty", *args], env=env,
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            preexec_fn=controlling_terminal, close_fds=True,
        )

    def read(self, seconds=0.08):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], max(0, deadline-time.monotonic()))
            if not ready:
                return
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return
            if not data:
                return
            self.raw.extend(data)
            if b"\x1b[6n" in data:
                os.write(self.master, b"\x1b[1;1R")

    def text(self):
        return self.raw.decode("utf-8", "replace").replace("\r", "")

    def send(self, text):
        os.write(self.master, text.encode() if isinstance(text, str) else text)
        self.read()

    def wait(self, predicate, label, timeout=15):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            self.read()
            if predicate(self.text()):
                return
            if self.process.poll() is not None:
                break
        raise AssertionError(label+"\n"+self.text())

    def finish(self, code):
        self.wait(lambda text: f"__LC_EXIT_{code}__" in text, f"expected exit {code}")
        assert termios.tcgetattr(self.slave) == self.original, "SSH did not restore terminal modes"
        self.send("terminal-restored\n")
        self.wait(lambda text: "__LC_ECHO_terminal-restored__" in text, "outer terminal input restored")
        self.process.wait(timeout=3)
        assert self.process.returncode == code

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        os.close(self.master)
        os.close(self.slave)


class Fixture:
    def __init__(self, root, gateway_ports="no"):
        self.root = root
        self.daemon = None
        self.http = None
        self.terminals = []
        self.requests = []
        self.user_socket = str(root / "user-master")
        self.ssh = shutil.which("ssh")
        self.sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").exists() else None)
        if not self.ssh or not self.sshd or not shutil.which("ssh-keygen"):
            raise Unavailable("OpenSSH client, daemon and key generator are required")
        self.log = (root / "sshd.log").open("w+")
        for name in ("host", "client"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root/name)], check=True, capture_output=True, timeout=10)
        self.port = free_port()
        self.trap_port = free_port()
        self.home = root / "remote-home"
        self.home.mkdir(mode=0o700)
        # Initial sshd shell startup also receives this private HOME/ZDOTDIR.
        # Default login mode intentionally reads our fixture rc; clean mode must
        # leave the prepared proxy environment in place.
        rc = 'export http_proxy=http://127.0.0.1:1\nexport LC_FIXTURE_RC=loaded\nPS1="fixture-login> "\n'
        (self.home / ".bash_profile").write_text(rc)
        (self.home / ".zprofile").write_text(rc)
        account = pwd.getpwuid(os.getuid()).pw_name
        server = f'''Port {self.port}
ListenAddress 127.0.0.1
HostKey {root / 'host'}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile {root / 'client.pub'}
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin yes
PermitUserRC no
AllowTcpForwarding yes
GatewayPorts {gateway_ports}
SetEnv HOME={self.home} ZDOTDIR={self.home} SHELL=/bin/bash
LogLevel ERROR
'''
        (root / "sshd_config").write_text(server)
        self.daemon = subprocess.Popen([self.sshd, "-D", "-e", "-f", str(root / "sshd_config")], stderr=self.log, stdout=subprocess.DEVNULL, start_new_session=True)
        try:
            eventually(lambda: accepts(self.port), "isolated sshd did not start", 3)
        except AssertionError:
            self.log.seek(0)
            raise Unavailable("isolated sshd cannot run for this account: "+self.log.read().strip())
        host_key = (root / "host.pub").read_text().strip()
        (root / "known_hosts").write_text(f"[127.0.0.1]:{self.port} {host_key}\n")
        client = f'''Host {ALIAS}
 HostName 127.0.0.1
 Port {self.port}
 User {account}
 IdentityFile {root / 'client'}
 IdentitiesOnly yes
 StrictHostKeyChecking yes
 UserKnownHostsFile {root / 'known_hosts'}
 LogLevel ERROR
 ControlMaster auto
 ControlPersist 60
 ControlPath {self.user_socket}
 LocalForward {self.trap_port} 127.0.0.1:9
'''
        self.client_file = root / "ssh_config"
        self.client_file.write_text(client)
        # Never read the real user's SSH config. Honor an explicit -F /dev/null
        # already supplied by the implementation for control-only operations.
        wrappers = root / "bin"
        wrappers.mkdir()
        wrapper = f'''#!{sys.executable}
import os,sys
args=sys.argv[1:]
if '-F' not in args: args=['-F',{str(self.client_file)!r},*args]
if '-O' in args and 'forward' in args: sys.stderr.write('fixture control diagnostic port 65535\\n')
os.execv({self.ssh!r},[{self.ssh!r},*args])
'''
        (wrappers / "ssh").write_text(wrapper)
        (wrappers / "ssh").chmod(0o755)
        self.env = {key: value for key, value in os.environ.items() if key not in ("LAZYCLASH_TARGET", "LAZYCLASH_CONFIG", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET", "LAZYCLASH_PROXY_SESSION", "LAZYCLASH_PROXY_ORIGIN", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")}
        self.env.update(HOME=str(root / "local-home"), ZDOTDIR=str(root / "local-home"), XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"), XDG_CACHE_HOME=str(root / "cache"), PATH=str(wrappers)+os.pathsep+os.environ["PATH"], TERM="xterm-256color", NO_COLOR="1")
        Path(self.env["HOME"]).mkdir()
        check = self.native(["-o", "ClearAllForwardings=yes", ALIAS, 'printf "%s|%s|%s" "$HOME" "$ZDOTDIR" "$SHELL"'])
        if check.returncode != 0:
            raise Unavailable("isolated sshd cannot authenticate this account: "+check.stderr.strip())
        expected = f"{self.home}|{self.home}|/bin/bash"
        if check.stdout != expected:
            raise Unavailable("sshd did not honor isolated shell environment: "+repr(check.stdout))
        # This pre-existing master must survive cleanup of every CLI-owned lease.
        check = self.native(["-M", "-N", "-f", "-o", "ClearAllForwardings=yes", ALIAS])
        if check.returncode != 0:
            raise Unavailable("isolated shared master failed: "+check.stderr.strip())
        owner = self
        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                owner.requests.append(self.path)
                self.send_response(204)
                self.end_headers()
            def log_message(self, *_):
                pass
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.settings = root / "settings.toml"
        self.settings.write_text(f'''default_target = "local"
[[targets]]
id = "local"
controller = "http://127.0.0.1:1"
probe_proxy = "http://127.0.0.1:{self.http.server_port}"
''')

    def native(self, args):
        return subprocess.run([self.ssh, "-F", str(self.client_file), "-o", "BatchMode=yes", *args], capture_output=True, text=True, timeout=10)

    def terminal(self, args):
        terminal = Terminal([str(BINARY), "--config", str(self.settings), "--target", "local", "proxy", *args], self.env)
        self.terminals.append(terminal)
        return terminal

    def shared_alive(self):
        result = self.native(["-S", self.user_socket, "-O", "check", ALIAS])
        assert result.returncode == 0 and "Master running" in result.stderr, "CLI closed the pre-existing fixture master"
        assert not accepts(self.trap_port), "private lease inherited an unrequested LocalForward"

    def close(self):
        for terminal in self.terminals:
            terminal.close()
        if hasattr(self, "client_file"):
            try:
                self.native(["-S", self.user_socket, "-O", "exit", ALIAS])
            except (OSError, subprocess.TimeoutExpired):
                pass
        if self.daemon is not None:
            try:
                os.killpg(self.daemon.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.daemon.wait(timeout=5)
        if self.http is not None:
            self.http.shutdown()
            self.http.server_close()
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="store_true", default=os.getenv("LAZYCLASH_REQUIRE_SSH_ISOLATION") == "1", help="fail if local isolated sshd capability is unavailable")
    args = parser.parse_args()
    if not BINARY.exists():
        raise SystemExit("build bin/lazyclash first")
    fixture = None
    # /tmp keeps private control paths well below Unix socket limits even on macOS.
    with tempfile.TemporaryDirectory(prefix="lc-rpty-", dir="/tmp") as scratch:
        try:
            fixture = Fixture.__new__(Fixture)
            fixture.__init__(Path(scratch))
            tokens = ["space value", "semi;literal", "$(printf not-run)", "quote'\"value", "-dash", ""]
            command = "import json,os,sys; print('__ARGV__'+json.dumps(sys.argv[1:])); print('__REMOTE_PROXY__'+os.environ['http_proxy'])"
            terminal = fixture.terminal(["ssh", ALIAS, "--", sys.executable, "-c", command, *tokens])
            terminal.wait(lambda text: "__LC_EXIT_0__" in text, "quoted command finished")
            found = re.search(r"__ARGV__(\[.*\])", terminal.text())
            assert found and json.loads(found.group(1)) == tokens, terminal.text()
            match = re.search(r"__REMOTE_PROXY__http://127\.0\.0\.1:(\d+)", terminal.text())
            assert match, terminal.text()
            port = int(match.group(1))
            terminal.finish(0)
            eventually(lambda: not accepts(port), "invocation forward survived command exit")
            fixture.shared_alive()

            counter = fixture.root / "command-count"
            command = "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_text(p.read_text()+'x' if p.exists() else 'x'); raise SystemExit(37)"
            terminal = fixture.terminal(["ssh", ALIAS, "--", sys.executable, "-c", command, str(counter)])
            terminal.finish(37)
            assert counter.read_text() == "x", "failed arbitrary command was replayed"
            fixture.shared_alive()

            terminal = fixture.terminal(["ssh", ALIAS])
            terminal.send("printf '__RC__%s|%s\\n' \"$http_proxy\" \"$LC_FIXTURE_RC\"\n")
            terminal.wait(lambda text: "__RC__http://127.0.0.1:1|loaded" in text, "default login rc precedence")
            terminal.send("exit 0\n")
            terminal.finish(0)
            fixture.shared_alive()

            terminal = fixture.terminal(["ssh", ALIAS, "--clean-shell"])
            terminal.send("printf '__CLEAN__%s|%s\\n' \"$http_proxy\" \"${LC_FIXTURE_RC-unset}\"\n")
            terminal.wait(lambda text: re.search(r"__CLEAN__http://127\.0\.0\.1:(\d+)\|unset", text), "clean shell preserves prepared proxy environment")
            clean_port = int(re.search(r"__CLEAN__http://127\.0\.0\.1:(\d+)\|unset", terminal.text()).group(1))
            before = len(fixture.requests)
            terminal.send("curl -sS -I --max-time 3 --noproxy '' -o /dev/null -w '__HTTP__%{http_code}\\n' http://fixture.invalid/reverse-pty\n")
            terminal.wait(lambda text: "__HTTP__204" in text, "remote request crosses reverse proxy")
            assert len(fixture.requests) > before
            terminal.send("exit 0\n")
            terminal.finish(0)
            eventually(lambda: not accepts(clean_port), "shell lease survived shell exit")
            fixture.shared_alive()

            shared_port = free_port()
            terminal = fixture.terminal(["tunnel", "share", ALIAS, "--remote-port", str(shared_port), "--json"])
            terminal.wait(lambda text: accepts(shared_port) and '"' in text, "foreground share is ready")
            assert terminal.process.poll() is None
            fixture.shared_alive()
            terminal.send(b"\x03")
            terminal.finish(130)
            eventually(lambda: not accepts(shared_port), "share forward survived Ctrl+C")
            fixture.shared_alive()
            with tempfile.TemporaryDirectory(prefix="lc-rpty-wild-", dir="/tmp") as wild_scratch:
                wildcard = None
                try:
                    wildcard = Fixture.__new__(Fixture)
                    wildcard.__init__(Path(wild_scratch), gateway_ports="yes")
                    sentinel = wildcard.root / "must-not-run"
                    terminal = wildcard.terminal(["ssh", ALIAS, "--", "/usr/bin/touch", str(sentinel)])
                    terminal.finish(1)
                    assert "not loopback-only" in terminal.text(), terminal.text()
                    assert not sentinel.exists(), "user command ran after unsafe bind was detected"
                    wildcard.shared_alive()
                finally:
                    if wildcard is not None and hasattr(wildcard, "log"):
                        wildcard.close()
            print("REVERSE PTY PASS: exact argv, control stderr separated, no replay, default rc/clean shell, remote proxy traffic, invocation/shell/share cleanup, wildcard rejection before command, borrowed master preserved, terminal restored")
        except Unavailable as error:
            if args.require:
                raise SystemExit(str(error))
            print("REVERSE PTY SKIP: "+str(error))
        finally:
            if fixture is not None and hasattr(fixture, "log"):
                fixture.close()


if __name__ == "__main__":
    main()
