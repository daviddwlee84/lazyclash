# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise native SSH authentication handoff using an isolated fake ssh.

Run: uv run scripts/auth_pty_smoke.py
Requires bin/lazyclash and bin/fakecore. All SSH commands, credentials, masters
and forwarded controllers belong to the fixture; no real SSH host is contacted.
"""

import getpass
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import termios
import time
from urllib.parse import urlsplit

from pty_smoke import ROOT, Terminal


PASSWORD = "fixture-passphrase-accepted"
WRONG_PASSWORD = "fixture-passphrase-rejected"


def fixture_event(root, event):
    # Record only operation names; never log command arguments or passwords.
    with (root / "events").open("a") as events:
        events.write(event + "\n")


def fixture_events(root):
    path = root / "events"
    return path.read_text().splitlines() if path.exists() else []


def forward_spec(spec):
    source_host, source_port, destination_host, destination_port = spec.split(":")
    assert source_host == destination_host == "127.0.0.1", "fixture only forwards loopback"
    assert int(destination_port) == int(os.environ["LAZYCLASH_AUTH_FIXTURE_PORT"])
    return int(source_port), int(destination_port)


def run_forward(root, spec):
    source_port, destination_port = forward_spec(spec)

    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(("127.0.0.1", destination_port), timeout=2) as remote:
                    remote.settimeout(None)
                    sockets = [self.request, remote]
                    while True:
                        ready, _, _ = select.select(sockets, [], [], 10)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            (remote if source is self.request else self.request).sendall(data)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with Server(("127.0.0.1", source_port), Relay) as server:
        (root / f"forward-{source_port}.ready").touch()
        server.serve_forever(poll_interval=0.05)


def stop_forward(root, port):
    pidfile = root / f"forward-{port}.pid"
    if pidfile.exists():
        try:
            os.kill(int(pidfile.read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass
        pidfile.unlink()
    (root / f"forward-{port}.ready").unlink(missing_ok=True)


def fake_ssh(args):
    root = Path(os.environ["LAZYCLASH_AUTH_FIXTURE"])
    if args[:1] == ["--fixture-forward"]:
        run_forward(root, args[1])
        return 0

    assert "--" in args and args[args.index("--") + 1] == "fixture-password-host", "unexpected SSH host"
    options = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "-o")
    if "-G" in args:
        fixture_event(root, "policy")
        if os.environ["LAZYCLASH_AUTH_FIXTURE_POLICY"] == "configured":
            print(f"controlpath {root / 'configured-control'}\ncontrolmaster auto\ncontrolpersist 300")
        else:
            print("controlpath none\ncontrolmaster no\ncontrolpersist no")
        return 0

    marker = root / "authenticated"
    if options.get("BatchMode") == "no":
        fixture_event(root, "auth-prompt")
        password = getpass.getpass("FAKE SSH password: ")
        if password != PASSWORD:
            fixture_event(root, "auth-failed")
            print("Permission denied (password).", file=sys.stderr)
            return 255
        marker.touch()
        fixture_event(root, "auth-ok")
        return 0

    if "-O" in args:
        operation = args[args.index("-O") + 1]
        if operation == "check":
            fixture_event(root, "master-check")
            return 0 if marker.exists() else 255
        if operation == "exit":
            fixture_event(root, "master-exit")
            marker.unlink(missing_ok=True)
            return 0
        spec = args[args.index("-L") + 1]
        source_port, _ = forward_spec(spec)
        if operation == "cancel":
            stop_forward(root, source_port)
            fixture_event(root, "forward-canceled")
            return 0
        assert operation == "forward", "unexpected master request"
        if not marker.exists():
            print("Control socket is not authenticated", file=sys.stderr)
            return 255
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--fixture-ssh", "--fixture-forward", spec],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        (root / f"forward-{source_port}.pid").write_text(str(process.pid))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if (root / f"forward-{source_port}.ready").exists():
                fixture_event(root, "forward-added")
                return 0
            if process.poll() is not None:
                break
            time.sleep(0.01)
        stop_forward(root, source_port)
        return 255

    assert options.get("BatchMode") == "yes", "background SSH must be noninteractive"
    fixture_event(root, "batch-rejected")
    print("Permission denied (publickey,password).", file=sys.stderr)
    return 255


def run_scenario(url, policy):
    terminal = None
    with tempfile.TemporaryDirectory(prefix="lazyclash-auth-pty-") as scratch:
        root = Path(scratch)
        executable = root / "bin" / "ssh"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " +
                              shlex.quote(str(Path(__file__).resolve())) + ' --fixture-ssh "$@"\n')
        executable.chmod(0o700)
        settings = root / "config.toml"
        settings.write_text(f'''default_target = "password"
[[targets]]
id = "password"
name = "Password Fixture"
controller = "{url}"
ssh_host = "fixture-password-host"
''')
        original_settings = settings.read_bytes()
        env = dict(os.environ)
        for name in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"):
            env.pop(name, None)
        env.update(HOME=scratch, XDG_CONFIG_HOME=scratch, TMPDIR=scratch, TERM="xterm-256color", NO_COLOR="1",
                   PATH=str(executable.parent) + os.pathsep + env.get("PATH", ""),
                   LAZYCLASH_AUTH_FIXTURE=scratch, LAZYCLASH_AUTH_FIXTURE_PORT=str(urlsplit(url).port),
                   LAZYCLASH_AUTH_FIXTURE_POLICY=policy)
        try:
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "SSH authentication required" in terminal.text() and
                          "[Enter Authenticate]" in terminal.text(), "explicit SSH authentication offer")
            assert "auth-prompt" not in fixture_events(root), "SSH prompted before user chose Authenticate"
            terminal.click_label("[Cancel]")
            terminal.wait(lambda: "A authenticate" in terminal.text() and
                          "[Enter Authenticate]" not in terminal.text(), "canceled offer leaves visible retry")
            terminal.send("?")
            terminal.wait(lambda: "help" in terminal.text().lower(), "dashboard remains usable after cancel")
            terminal.send("\x1b")
            assert "auth-prompt" not in fixture_events(root), "cancel started native authentication"

            terminal.send("A\r")
            terminal.wait(lambda: "FAKE SSH password:" in terminal.text(), "native terminal password prompt")
            if policy == "configured":
                terminal.send(WRONG_PASSWORD + "\n")
                terminal.wait(lambda: "SSH authentication failed or was canceled" in terminal.text(),
                              "native authentication failure returns to usable TUI")
                terminal.read(0.25)
                assert fixture_events(root).count("auth-prompt") == 1, "failed authentication repeated automatically"
                terminal.click_label("[Cancel]")
                terminal.click_label("Authenticate")
                terminal.click_label("[Enter Authenticate]")
                terminal.wait(lambda: fixture_events(root).count("auth-prompt") == 2 and
                              "FAKE SSH password:" in terminal.text(), "explicit mouse retry returns to native prompt")
            terminal.send(PASSWORD + "\n")
            terminal.wait(lambda: "Password Fixture [connected]" in terminal.text() and "Core RSS" in terminal.text(),
                          "authentication reconnects the same controller")
            terminal.click_label("2 Proxies")
            terminal.wait(lambda: "Groups" in terminal.text() and "Updated" in terminal.text(),
                          "mouse and keyboard restored after terminal handoff")
            assert settings.read_bytes() == original_settings, "authentication rewrote user preferences"
            assert PASSWORD.encode() not in terminal.raw and WRONG_PASSWORD.encode() not in terminal.raw, "password was echoed"
            assert not (termios.tcgetattr(terminal.slave)[0] & termios.IXON), "terminal flow control remained enabled"

            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean exit after authentication")
            restored = termios.tcgetattr(terminal.slave)
            for flag in (termios.ECHO, termios.ICANON):
                assert (restored[3] & flag) == (terminal.original[3] & flag), "terminal modes not restored"
            assert (restored[0] & termios.IXON) == (terminal.original[0] & termios.IXON), "flow control not restored"
            events = fixture_events(root)
            assert "forward-added" in events and "forward-canceled" in events, events
            if policy == "configured":
                assert "master-exit" not in events and (root / "authenticated").exists(), "application closed a shared master"
            else:
                assert "master-exit" in events and not (root / "authenticated").exists(), "private master was not cleaned up"
            terminal.send("auth-echo-restored\n")
            terminal.process.wait(timeout=5)
            assert terminal.process.returncode == 0, terminal.text()
        finally:
            if terminal:
                terminal.close()
            for pidfile in root.glob("forward-*.pid"):
                stop_forward(root, pidfile.stem.removeprefix("forward-"))


def main():
    process = subprocess.Popen([str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        url = process.stdout.readline().strip()
        assert url.startswith("http://127.0.0.1:"), url
        for policy in ("configured", "private"):
            run_scenario(url, policy)
        print("AUTH PTY PASS: typed auth offer, Cancel, native no-echo password, failure without repeat, keyboard/mouse retry, same-target reconnect, shared/private master ownership, terminal restoration")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture-ssh"]:
        raise SystemExit(fake_ssh(sys.argv[2:]))
    main()
