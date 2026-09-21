# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise server inventory and wizard handoffs in an isolated real PTY.

Run after building bin/lazyclash and bin/fakecore:
    uv run scripts/pty_servers_smoke.py
No provider CLI, real SSH host or cloud resource is contacted.
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
        with tempfile.TemporaryDirectory(prefix="lazyclash-servers-pty-") as scratch:
            base = Path(scratch)
            settings = base / "config.toml"
            settings.write_text(f'default_target = "client"\n[[targets]]\nid = "client"\ncontroller = "{url}"\n')
            inventory = base / "separate-inventory.toml"
            inventory.write_text('''version = 1
[[hosts]]
id = "first-host"
name = "First fixture"
provider = "ssh"
ssh_host = "unused-fixture-host"
public_host = "203.0.113.10"
status = "registered"
[[hosts]]
id = "second-host"
name = "Second fixture"
provider = "homelab"
ssh_host = "unused-fixture-two"
public_host = "203.0.113.11"
status = "registered"
''')
            before = inventory.read_bytes()
            env = dict(os.environ)
            for key in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"):
                env.pop(key, None)
            env.update(HOME=scratch, XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=str(base / "state"), LAZYCLASH_SERVERS_CONFIG=str(inventory), TERM="xterm-256color", NO_COLOR="1")
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "[1 Overview]" in terminal.text(), "dashboard startup")
            terminal.send(":Servers\r")
            terminal.wait(lambda: "Servers / VPS" in terminal.text() and "first-host" in terminal.text(), "offline server inventory")
            terminal.send("j")
            terminal.wait(lambda: "> second-host" in terminal.text(), "Vim row navigation")
            terminal.send("r")
            terminal.wait(lambda: "> second-host" in terminal.text() and "ready" in terminal.text().lower(), "refresh preserves identity")
            terminal.send("gg")
            terminal.wait(lambda: "> first-host" in terminal.text(), "gg navigation")
            terminal.resize(80, 24)
            terminal.click_label("[a Actions]")
            terminal.wait(lambda: "Manage first-host" in terminal.text(), "shared VPS action wizard")
            terminal.send("\x1b")
            terminal.wait(lambda: "Servers / VPS" in terminal.text() and "> first-host" in terminal.text(), "cancel returns to inventory")
            terminal.click_label("[n Deploy]")
            terminal.wait(lambda: "Deployment host" in terminal.text(), "deployment host picker")
            terminal.send("\r")
            terminal.wait(lambda: "Deploy proxy server" in terminal.text() and "Server ID" in terminal.text(), "prefilled deployment form")
            terminal.send("jkhql/?")
            terminal.wait(lambda: "jkhql/?" in terminal.text(), "typing owns action and quit keys")
            terminal.send(b"\x1b[200~q\nm\nu\x1b[201~")
            assert terminal.process.poll() is None, "paste quit the wizard"
            terminal.resize(36, 12)
            assert terminal.process.poll() is None, "narrow form crashed"
            terminal.resize(120, 32)
            terminal.send("\x1b")
            terminal.wait(lambda: "Servers / VPS" in terminal.text(), "cancel deployment restores inventory")
            assert inventory.read_bytes() == before, "canceled deployment modified inventory"
            assert not list((base / "state/lazyclash/servers").rglob("*.json")), "canceled form created server operation records"
            terminal.send("?")
            terminal.wait(lambda: "SSH" in terminal.text() and "separate" in terminal.text(), "contextual server help")
            terminal.send("\x1b")
            terminal.send("\x1b")
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean dashboard exit")
            restored = termios.tcgetattr(terminal.slave)
            for flag in (termios.ECHO, termios.ICANON):
                assert (restored[3] & flag) == (terminal.original[3] & flag), "terminal mode not restored"
            assert (restored[0] & termios.IXON) == (terminal.original[0] & termios.IXON), "flow control not restored"
            terminal.send("server-echo-restored\n")
            terminal.process.wait(timeout=5)
            assert terminal.process.returncode == 0, terminal.text()
            print("PTY PASS: independent server config, local inventory, j/gg navigation, identity-preserving refresh, mouse action/deploy buttons, shared CLI handoff/cancel/return, text/paste ownership, narrow resize, no canceled writes, help, shell echo/canonical/flow-control restoration")
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
