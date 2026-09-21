# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise Tailnet inventory and cancel-safe wizard handoffs in a real PTY.

Run: uv run scripts/pty_tailnet_smoke.py
Requires bin/lazyclash and bin/fakecore. SSH is replaced with a fixture that
never opens a connection; no real Tailscale state or user proxy settings change.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import termios

from pty_smoke import ROOT, Terminal


def main():
    core = subprocess.Popen([str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    terminal = None
    try:
        url = core.stdout.readline().strip()
        assert url.startswith("http://127.0.0.1:"), url
        with tempfile.TemporaryDirectory(prefix="lazyclash-tailnet-pty-") as scratch:
            base = Path(scratch)
            settings = base / "config.toml"
            settings.write_text(f'default_target = "client"\n[[targets]]\nid = "client"\ncontroller = "{url}"\n')
            inventory = base / "servers.toml"
            inventory.write_text('''version = 1
[[tailnet]]
id = "pi"
peer_id = "fixture-peer"
ssh_host = "fixture-tailnet-host"
hostname = "pi"
ips = ["100.72.1.1"]
os = "linux"
exit_status = "registered"
[[tailnet_proxies]]
id = "gateway"
node_id = "pi"
peer_id = "fixture-peer"
ssh_host = "fixture-tailnet-host"
name = "Gateway"
mode = "serve"
backend = "native"
egress = "direct"
port = 7898
local_port = 17898
status = "ready"
''')
            before = inventory.read_bytes()
            fakebin = base / "fixture-bin"
            fakebin.mkdir()
            ssh = fakebin / "ssh"
            ssh.write_text('#!/bin/sh\ncase "$*" in *" -G "*|"-G "*) printf "hostname fixture-tailnet-host\\ncontrolmaster false\\ncontrolpersist no\\n"; exit 0;; esac\nprintf "fixture peer offline\\n" >&2\nexit 255\n')
            ssh.chmod(0o700)
            env = dict(os.environ)
            for key in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"):
                env.pop(key, None)
            env.update(HOME=scratch, XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=str(base / "state"), LAZYCLASH_SERVERS_CONFIG=str(inventory), TERM="xterm-256color", NO_COLOR="1", PATH=str(fakebin) + os.pathsep + env["PATH"])
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "[1 Overview]" in terminal.text(), "dashboard startup")
            terminal.send(":Servers\r")
            terminal.wait(lambda: "Tailnet exit" in terminal.text() and "gateway" in terminal.text(), "saved Tailnet inventory")
            terminal.send("j")
            terminal.wait(lambda: "> gateway" in terminal.text(), "proxy row navigation")
            terminal.send("a")
            terminal.wait(lambda: "Manage Tailnet gateway" in terminal.text(), "proxy action handoff")
            terminal.send("\x1b")
            terminal.wait(lambda: "Servers / VPS" in terminal.text() and "> gateway" in terminal.text(), "cancel retains proxy selection")
            terminal.send("ggt")
            terminal.wait(lambda: "Tailnet setup" in terminal.text(), "Tailnet setup menu")
            terminal.send("\r")
            terminal.wait(lambda: "Register Tailnet device" in terminal.text(), "register-only form")
            terminal.send("jkhql/?")
            terminal.wait(lambda: "jkhql/?" in terminal.text(), "form owns shortcut keys")
            terminal.send(b"\x1b[200~q\nx\x1b[201~")
            assert terminal.process.poll() is None, "pasted text quit wizard"
            terminal.resize(36, 12)
            assert terminal.process.poll() is None, "narrow form crashed"
            terminal.resize(120, 32)
            terminal.send("\x1b")
            terminal.wait(lambda: "Servers / VPS" in terminal.text(), "register cancel restores inventory")
            terminal.send("p")
            terminal.wait(lambda: "Choose Tailnet device" in terminal.text(), "proxy device picker")
            terminal.send("\r")
            terminal.wait(lambda: "Tailnet proxy deploy" in terminal.text(), "proxy deployment form")
            terminal.send("\x1b")
            terminal.wait(lambda: "Servers / VPS" in terminal.text(), "proxy cancel restores inventory")
            assert inventory.read_bytes() == before, "cancel changed inventory"
            assert not list((base / "state").rglob("*.json")), "cancel created operation state"
            terminal.send("?")
            terminal.wait(lambda: "Tailscale" in terminal.text(), "Tailnet contextual help")
            terminal.send("\x1b")
            terminal.send("\x1b")
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean dashboard exit")
            restored = termios.tcgetattr(terminal.slave)
            for flag in (termios.ECHO, termios.ICANON):
                assert (restored[3] & flag) == (terminal.original[3] & flag), "terminal mode not restored"
            terminal.send("tailnet-echo-restored\n")
            terminal.process.wait(timeout=5)
            assert terminal.process.returncode == 0, terminal.text()
            print("PTY PASS: offline Tailnet inventory, stable selection, actions/setup/proxy handoffs, register-only form, text/paste ownership, narrow resize, canceled writes absent, contextual help, terminal restoration")
    finally:
        try:
            if terminal:
                terminal.close()
        finally:
            core.terminate()
            try:
                core.wait(timeout=3)
            except subprocess.TimeoutExpired:
                core.kill()
                core.wait()


if __name__ == "__main__":
    main()
