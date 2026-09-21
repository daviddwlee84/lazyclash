# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise the built dashboard in a real PTY against two isolated fake cores.

Run: uv run scripts/pty_smoke.py
Requires bin/lazyclash and bin/fakecore (build with go build -o ...).
No user proxy settings, SSH hosts or preferences are read or changed.
"""

import codecs
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time
import urllib.request

import pyte


ROOT = Path(__file__).resolve().parents[1]


def request(url, path):
    # Verification must not accidentally use the user's configured HTTP proxy.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url + path, timeout=2) as response:
        return json.load(response)


def saved_target_name(settings, env, target_id="first"):
    # Read through the public settings command instead of depending on the
    # TOML writer's choice of single/double quotes or whitespace.
    result = subprocess.run(
        [str(ROOT / "bin/lazyclash"), "--config", str(settings), "settings", "show", "--json"],
        env=env, capture_output=True, text=True, check=True, timeout=3,
    )
    targets = json.loads(result.stdout)["settings"]["targets"]
    return next(target.get("name", "") for target in targets if target["id"] == target_id)


class Terminal:
    def __init__(self, settings, env):
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
        self.raw = bytearray()
        self.screen = pyte.Screen(120, 32)
        self.stream = pyte.Stream(self.screen)
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))

        def child_terminal():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)

        self.process = subprocess.Popen(
            ["/bin/sh", "-c",
             '"$1" --config "$2"; result=$?; printf "\\n__LAZYCLASH_EXIT_%s__\\n" "$result"; '
             'IFS= read -r line; printf "__ECHO_%s__\\n" "$line"; exit "$result"',
             "pty-wrapper", str(ROOT / "bin/lazyclash"), str(settings)],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env=env, preexec_fn=child_terminal, close_fds=True,
        )

    def read(self, seconds=0.15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            try:
                data = os.read(self.master, 65536)
            except OSError:
                break
            if not data:
                break
            if b"\x1b[6n" in data:
                os.write(self.master, b"\x1b[1;1R")
            self.raw.extend(data)
            self.stream.feed(self.decoder.decode(data))

    def send(self, data):
        os.write(self.master, data.encode() if isinstance(data, str) else data)
        self.read()

    def mouse(self, x, y, button=0, release=True):
        self.send(f"\x1b[<{button};{x + 1};{y + 1}M")
        if release:
            self.send(f"\x1b[<{button};{x + 1};{y + 1}m")

    def click_label(self, label):
        for y, line in enumerate(self.screen.display):
            x = line.find(label)
            if x >= 0:
                self.mouse(x, y)
                return
        raise AssertionError(f"missing button {label}\n{self.text()}")

    def text(self):
        return "\n".join(line.rstrip() for line in self.screen.display)

    def wait(self, predicate, label, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.read(0.05)
            if predicate():
                return
            if self.process.poll() is not None:
                break
        raise AssertionError(f"{label}\n{self.text()}")

    def resize(self, width, height):
        self.screen.resize(lines=height, columns=width)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
        self.process.send_signal(signal.SIGWINCH)
        self.read(0.25)

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        os.close(self.master)
        os.close(self.slave)


def main():
    cores = []
    terminal = None
    try:
        for _ in range(2):
            process = subprocess.Popen([str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            cores.append(process)
        urls = [process.stdout.readline().strip() for process in cores]
        assert all(url.startswith("http://127.0.0.1:") for url in urls), urls
        with tempfile.TemporaryDirectory(prefix="lazyclash-pty-") as scratch:
            settings = Path(scratch) / "config.toml"
            settings.write_text(f'''default_target = "first"
[[targets]]
id = "first"
name = "Fixture One"
controller = "{urls[0]}"
[[targets.configs]]
id = "work"
path = "/fixture/work.yaml"
[[targets]]
id = "second"
name = "Fixture Two"
controller = "{urls[1]}"
''')
            env = dict(os.environ)
            for key in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"):
                env.pop(key, None)
            env.update(HOME=scratch, XDG_CONFIG_HOME=scratch, TERM="xterm-256color", NO_COLOR="1")
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "[1 Overview]" in terminal.text() and "Core RSS" in terminal.text(), "initial overview")
            terminal.wait(lambda: "1002h" in terminal.raw.decode("ascii", "ignore"), "SGR mouse capture enabled")
            terminal.wait(lambda: "LOCAL CONTROLLER" in terminal.text() and "[* Rule]" in terminal.text(), "visible controller and routing status")
            terminal.click_label("[Direct]")
            terminal.wait(lambda: request(urls[0], "/configs")["mode"] == "direct" and "[* Direct]" in terminal.text(), "explicit Direct mode and read-back")
            wide = terminal.text()
            terminal.resize(36, 12)
            terminal.wait(lambda: "[* Direct]" in terminal.text() and "TUN (core)" in terminal.text(), "narrow routing status stays visible")
            (ROOT / "bin/pty-smoke-overview-narrow.txt").write_text(terminal.text())
            terminal.resize(120, 32)
            terminal.click_label("[Global]")
            terminal.wait(lambda: request(urls[0], "/configs")["mode"] == "global" and "[* Global]" in terminal.text(), "explicit Global mode")
            terminal.click_label("[Rule]")
            terminal.wait(lambda: request(urls[0], "/configs")["mode"] == "rule" and "[* Rule]" in terminal.text(), "explicit Rule mode")
            terminal.send("M")
            terminal.wait(lambda: "1002l" in terminal.raw.decode("ascii", "ignore"), "mouse disabled for text selection")
            terminal.send("M")
            terminal.click_label("2 Proxies")
            terminal.wait(lambda: "Updated" in terminal.text() and "Groups" in terminal.text(), "mouse-selected proxy tab")

            # Text input and bracketed paste must not execute navigation/actions.
            terminal.send("/jkhql/?")
            assert terminal.process.poll() is None, "q typed into search quit the dashboard"
            assert "jkhql/?" in terminal.text(), terminal.text()
            terminal.send(b"\x1b[200~q\nm\nu\x1b[201~")
            assert request(urls[0], "/configs")["mode"] == "rule"
            terminal.send("\x1b")

            # Group/member search, Enter acceptance, explicit node selection.
            terminal.send("/Proxy\r")
            terminal.send("\x1b")
            terminal.send("\t")
            terminal.send("/東京\r")
            # A row click only selects; the explicit button applies the node.
            terminal.mouse(38, 4)
            assert request(urls[0], "/proxies")["proxies"]["🚀 Proxy"]["now"] != "🇯🇵 東京/01"
            terminal.click_label("[enter Choose]")
            terminal.wait(lambda: request(urls[0], "/proxies")["proxies"]["🚀 Proxy"]["now"] == "🇯🇵 東京/01", "node selection read-back")
            terminal.send("\x1b")
            terminal.send("m")
            terminal.wait(lambda: request(urls[0], "/configs")["mode"] == "global", "mode change")

            # Close-all is cancellable and only runs after confirmation.
            terminal.send("3")
            terminal.wait(lambda: "api.example.test" in terminal.text(), "connections view")
            terminal.send("X")
            terminal.wait(lambda: "Close all" in terminal.text(), "close-all review")
            terminal.send("\x1b")
            assert len(request(urls[0], "/connections")["connections"]) == 2
            terminal.send("X")
            terminal.click_label("[Confirm]")
            terminal.wait(lambda: not request(urls[0], "/connections")["connections"], "confirmed close-all")

            terminal.send("7")
            terminal.wait(lambda: "work" in terminal.text(), "registered configs")
            terminal.send("\r")
            terminal.wait(lambda: "/fixture/work.yaml" in terminal.text() and "Apply" in terminal.text(), "YAML review")
            terminal.send("y")
            terminal.wait(lambda: "appl" in terminal.text().lower() and "/fixture/work.yaml" in terminal.text(), "YAML receipt")

            # All remaining pages, streaming logs, narrow layout and help/back.
            terminal.send("4")
            terminal.wait(lambda: "example.test" in terminal.text(), "live logs")
            terminal.send(" ")
            assert "paused" in terminal.text(), terminal.text()
            terminal.send("5")
            terminal.wait(lambda: "DomainSuffix" in terminal.text(), "rules")
            terminal.send("6")
            terminal.wait(lambda: "providers" in terminal.text().lower() and "示範" in terminal.text(), "providers")
            terminal.resize(80, 24)
            terminal.send("2")
            terminal.wait(lambda: "Tab changes pane" in terminal.text(), "80x24 focused pane")
            terminal.send("?")
            terminal.wait(lambda: "help" in terminal.text().lower(), "help")
            terminal.send("\x1b")
            terminal.resize(36, 12)
            terminal.send("\t")
            assert terminal.process.poll() is None, "narrow resize crashed"
            terminal.resize(120, 32)

            # Target connectivity is read-only and does not save or select.
            before_settings = settings.read_bytes()
            terminal.send("t")
            terminal.click_label("[T Test]")
            terminal.wait(lambda: "Connectivity" in terminal.text(), "target connectivity test")
            terminal.click_label("[e Edit]")
            terminal.click_label("[Ctrl+T Test]")
            terminal.wait(lambda: "Connectivity" in terminal.text() and "connected" in terminal.text().lower(), "draft connectivity test")
            terminal.click_label("[Cancel]")
            assert settings.read_bytes() == before_settings, "draft test rewrote config"

            # Ctrl+S submits the current target field directly, including after
            # a draft connectivity test. Do not send Ctrl+Q: that would hide an
            # accidental terminal flow-control freeze instead of testing it.
            assert not (termios.tcgetattr(terminal.slave)[0] & termios.IXON), "TUI left XON/XOFF enabled"
            terminal.send("t")
            terminal.click_label("[e Edit]")
            terminal.click_label("Display name (optional)")
            terminal.send("\x15Fixture One Ctrl-S")
            terminal.send(b"\x14")
            terminal.wait(lambda: "Connectivity" in terminal.text() and "connected" in terminal.text().lower(), "mid-field draft test")
            terminal.send(b"\x13")
            terminal.wait(lambda: saved_target_name(settings, env) == "Fixture One Ctrl-S"
                          and "Fixture One Ctrl-S [connected]" in terminal.text()
                          and "Edit target" not in terminal.text()
                          and "Saving settings" not in terminal.text(), "raw Ctrl+S saves current display-name field")

            # Failed validation retains the form, focused input and saved file.
            # Correct it in place and submit again, without traversing 13 fields.
            terminal.send("t")
            terminal.click_label("[e Edit]")
            terminal.click_label("Controller URL")
            terminal.send("\x15http://")
            before_invalid_save = settings.read_bytes()
            terminal.send(b"\x13")
            terminal.wait(lambda: "missing a hostname" in terminal.text() and "Edit target" in terminal.text(), "Ctrl+S validation failure remains editable")
            assert settings.read_bytes() == before_invalid_save, "invalid Ctrl+S changed saved settings"
            terminal.send("\x15" + urls[0])
            terminal.send(b"\x13")
            terminal.wait(lambda: "Edit target" not in terminal.text()
                          and "Fixture One Ctrl-S [connected]" in terminal.text()
                          and "Saving settings" not in terminal.text(), "corrected field saves without flow-control freeze")

            # Keep later fixture-label assertions unchanged.
            terminal.send("t")
            terminal.click_label("[e Edit]")
            terminal.click_label("Display name (optional)")
            terminal.send("\x15Fixture One")
            terminal.send(b"\x13")
            terminal.wait(lambda: saved_target_name(settings, env) == "Fixture One"
                          and "Fixture One [connected]" in terminal.text()
                          and "Edit target" not in terminal.text()
                          and "Saving settings" not in terminal.text(), "Ctrl+S restores fixture name")

            # Switch targets; old target writes must never be repeated on new core.
            terminal.send("tj\r")
            terminal.wait(lambda: "Fixture Two [connected]" in terminal.text(), "second target handshake")
            assert request(urls[1], "/configs")["mode"] == "rule"
            assert len(request(urls[1], "/connections")["connections"]) == 2
            terminal.send("tk\r")
            terminal.wait(lambda: "Fixture One [connected]" in terminal.text(), "return to first target")
            assert request(urls[0], "/configs")["mode"] == "global"

            # Cross-target copy: picker, unchecked field, reviewed digest, cancel,
            # and explicit apply. No writes occur on row selection or preview.
            terminal.send(":Compare targets\r")
            terminal.wait(lambda: "choose source" in terminal.text(), "comparison source picker")
            terminal.send("\r")
            terminal.wait(lambda: "choose destination" in terminal.text(), "comparison destination picker")
            terminal.click_label("[Enter Choose]")
            terminal.wait(lambda: "runtime comparison" in terminal.text(), "runtime diff")
            assert request(urls[1], "/configs")["mode"] == "rule"
            terminal.send("j ")  # log-level first, mode second; Space checks mode.
            terminal.click_label("[p Preview]")
            terminal.wait(lambda: "Review copy" in terminal.text(), "copy preview")
            assert request(urls[1], "/configs")["mode"] == "rule"
            terminal.resize(36, 12)
            terminal.send("a")
            terminal.wait(lambda: "Apply reviewed change" in terminal.text(), "copy apply confirmation")
            terminal.send("\x1b")
            terminal.wait(lambda: "Review copy" in terminal.text(), "cancel returns to review")
            terminal.resize(120, 32)
            terminal.click_label("[a Apply]")
            terminal.click_label("[Confirm]")
            terminal.wait(lambda: request(urls[1], "/configs")["mode"] == "global", "copy destination readback")
            terminal.wait(lambda: "Copy" in terminal.text(), "copy receipt")
            terminal.send("\x1b")

            # Passive URL diagnostics: literal input and inspectable result.
            terminal.send(":Diagnose URL\r")
            terminal.wait(lambda: "Diagnose a URL" in terminal.text(), "URL form")
            terminal.send("https://api.example.test\r\r")
            terminal.send("\x15true\r\r")
            terminal.wait(lambda: "URL diagnosis" in terminal.text(), "passive topology", timeout=25)
            terminal.send("j\t\x1b[6~")
            terminal.resize(36, 12)
            assert terminal.process.poll() is None, "diagnosis resize crashed"
            terminal.resize(120, 32)
            terminal.send("\x1b")

            # pyte 0.8.2 truncates draw chunks at VS16/ZWJ; this is diagnostic
            # output, not a Unicode layout oracle. Go View tests check full
            # grapheme-bearing rows and terminal cell widths independently.
            (ROOT / "bin/pty-smoke-wide.txt").write_text(wide)
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean dashboard exit")
            restored = termios.tcgetattr(terminal.slave)
            for flag in (termios.ECHO, termios.ICANON):
                assert (restored[3] & flag) == (terminal.original[3] & flag), "terminal modes not restored"
            assert (restored[0] & termios.IXON) == (terminal.original[0] & termios.IXON), "terminal flow-control mode not restored"
            terminal.send("echo-restored\n")
            terminal.process.wait(timeout=5)
            assert terminal.process.returncode == 0, terminal.text()
            print("PTY PASS: overview startup, SGR mouse tabs/row/button/modal, mouse toggle, typing/paste, node/mode writes, confirmations, all pages, streams, resize, target/draft connectivity, raw Ctrl+S mid-field save/validation, target switching, reviewed cross-target copy, passive URL topology, terminal/flow-control restoration")
    finally:
        if terminal:
            terminal.close()
        for process in cores:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    main()
