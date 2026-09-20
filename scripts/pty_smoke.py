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


class Terminal:
    def __init__(self, settings, env):
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
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
            self.stream.feed(self.decoder.decode(data))

    def send(self, data):
        os.write(self.master, data.encode() if isinstance(data, str) else data)
        self.read()

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
            terminal.wait(lambda: "Updated" in terminal.text() and "Groups" in terminal.text(), "initial proxy view")
            wide = terminal.text()

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
            terminal.send("\r")
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
            terminal.send("Xy")
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

            # Switch targets; old target writes must never be repeated on new core.
            terminal.send("tj\r")
            terminal.wait(lambda: "Fixture Two [connected]" in terminal.text(), "second target handshake")
            assert request(urls[1], "/configs")["mode"] == "rule"
            assert len(request(urls[1], "/connections")["connections"]) == 2
            terminal.send("tk\r")
            terminal.wait(lambda: "Fixture One [connected]" in terminal.text(), "return to first target")
            assert request(urls[0], "/configs")["mode"] == "global"

            # pyte 0.8.2 truncates draw chunks at VS16/ZWJ; this is diagnostic
            # output, not a Unicode layout oracle. Go View tests check full
            # grapheme-bearing rows and terminal cell widths independently.
            (ROOT / "bin/pty-smoke-wide.txt").write_text(wide)
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean dashboard exit")
            restored = termios.tcgetattr(terminal.slave)
            for flag in (termios.ECHO, termios.ICANON):
                assert (restored[3] & flag) == (terminal.original[3] & flag), "terminal modes not restored"
            terminal.send("echo-restored\n")
            terminal.process.wait(timeout=5)
            assert terminal.process.returncode == 0, terminal.text()
            print("PTY PASS: startup, typing/paste, node/mode writes, confirmations, all pages, streams, resize, target switching, terminal restoration")
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
