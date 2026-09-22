# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Real terminal handoff + source wizard verification against isolated fixtures.

Requires bin/lazyclash and bin/fakecore. No production target, source, clipboard,
SSH host or proxy setting is touched. All write reviews are canceled; only an
intentional fixture credential export is submitted to terminal output.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import termios

from pty_smoke import ROOT, Terminal, request


def main():
    cores, terminal = [], None
    try:
        for _ in range(2):
            cores.append(subprocess.Popen([str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        urls = [core.stdout.readline().strip() for core in cores]
        with tempfile.TemporaryDirectory(prefix="lazyclash-tools-pty-") as scratch:
            root = Path(scratch)
            source = {
                "proxies": [
                    {"name": "🇹🇼 台北", "type": "trojan", "server": "example.test", "port": 443, "password": "fixture-export-secret"},
                    {"name": "🇯🇵 東京/01", "type": "trojan", "server": "example.test", "port": 443, "password": "fixture-other-secret"},
                ],
                "proxy-groups": [
                    {"name": "🚀 Proxy", "type": "select", "proxies": ["🇹🇼 台北", "🇯🇵 東京/01"]},
                    {"name": "♻️ Auto", "type": "url-test", "proxies": ["🇹🇼 台北", "🇯🇵 東京/01"], "url": "https://example.test/", "interval": 300},
                ],
                "rules": ["MATCH,🚀 Proxy"],
            }
            files = [root / "first.yaml", root / "second.yaml"]
            for path in files:
                path.write_text(json.dumps(source, ensure_ascii=False))
            snapshots = [path.read_bytes() for path in files]
            # Candidate validation now runs before preview. Match the fake
            # controller's version with a private parser fixture, while keeping
            # the real native OS sandbox and source-write boundaries exercised.
            validators = []
            for index, url in enumerate(urls):
                validator = root / f"fixture-validator-{index}"
                version = request(url, "/version")["version"]
                validator.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                                     "if '-v' in sys.argv: print('Mihomo Meta '+" + repr(version) + "+' fixture fixture')\n"
                                     "elif '-t' in sys.argv:\n document=json.load(sys.stdin)\n assert isinstance(document,dict) and isinstance(document.get('proxies'),list) and isinstance(document.get('proxy-groups'),list)\n"
                                     "else: sys.exit(1)\n")
                validator.chmod(0o700)
                validators.append(validator)
            settings = root / "settings.toml"
            sections = ['default_target = "first"']
            for index, target in enumerate(("first", "second")):
                sections.append(f'''[[targets]]
id = "{target}"
name = "Tools {target}"
controller = "{urls[index]}"
[[targets.configs]]
id = "main"
path = {json.dumps(str(files[index]))}
[targets.config_source]
kind = "native"
config_id = "main"
binary = {json.dumps(str(validators[index]))}
home = {json.dumps(scratch)}
''')
            settings.write_text("\n".join(sections))
            before_settings = settings.read_bytes()
            env = dict(os.environ)
            for name in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET", "LAZYCLASH_PROXY_SESSION"):
                env.pop(name, None)
            env.update(XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=str(root / "state"), XDG_DATA_HOME=str(root / "data"), TERM="xterm-256color", NO_COLOR="1")
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "Core RSS" in terminal.text(), "dashboard startup")
            terminal.send("2\t")
            terminal.wait(lambda: "Members" in terminal.text(), "node pane")
            # Select a stable fixture leaf even if Unicode sorting changes.
            terminal.send("/台北\r")
            terminal.send("e")
            terminal.wait(lambda: "Edit proxy" in terminal.text(), "dashboard releases input to source editor")
            terminal.send(b"\x1b[200~\n# qjkh/ stays in draft\x1b[201~")
            terminal.resize(38, 12)
            assert terminal.process.poll() is None, "wizard resize/typing quit dashboard"
            terminal.resize(120, 32)
            terminal.send("\x1b")
            terminal.wait(lambda: "canceled" in terminal.text() and "[2 Proxies]" in terminal.text(), "cancel restores dashboard")
            assert [path.read_bytes() for path in files] == snapshots

            terminal.send(":Edit current group\r")
            terminal.wait(lambda: "Group editor" in terminal.text(), "group editor choice")
            terminal.send("\r")
            terminal.wait(lambda: "Edit group" in terminal.text(), "common group fields")
            terminal.send("\x1b")
            terminal.wait(lambda: "canceled" in terminal.text() and "[2 Proxies]" in terminal.text(), "group cancel restores dashboard")
            assert [path.read_bytes() for path in files] == snapshots

            terminal.send(":Duplicate selected proxy\r")
            terminal.wait(lambda: "Duplicate proxy" in terminal.text(), "duplicate wizard")
            terminal.send("fixture duplicate qjkh")
            terminal.send(b"\x13")
            terminal.wait(lambda: "Apply persistent source change" in terminal.text(), "raw Ctrl+S opens review without XOFF freeze")
            terminal.send("\r")  # default focus is Cancel, never Apply.
            terminal.wait(lambda: "canceled" in terminal.text() and "[2 Proxies]" in terminal.text(), "default review cancel")
            assert [path.read_bytes() for path in files] == snapshots

            terminal.send(":Copy selected proxy\r")
            terminal.wait(lambda: "Copy destination" in terminal.text(), "nested destination picker")
            terminal.send("j\r")
            terminal.wait(lambda: "Copy source node" in terminal.text(), "destination draft")
            terminal.send(b"\x15fixture copied node\x13")
            terminal.wait(lambda: "Copy persistent node" in terminal.text(), "copy review")
            terminal.send("\x1b")
            terminal.wait(lambda: "canceled" in terminal.text() and "[2 Proxies]" in terminal.text(), "copy cancel restores dashboard")
            assert [path.read_bytes() for path in files] == snapshots

            terminal.send("y")
            terminal.wait(lambda: "Export " in terminal.text() and "Destination" in terminal.text(), "export wizard")
            terminal.send(b"\x13")
            terminal.wait(lambda: "Operation finished" in terminal.text(), "result remains visible until acknowledged")
            assert "fixture-export-secret" in terminal.text().replace("\n", ""), "intentional export disappeared before result pause\n" + terminal.text()
            terminal.send("\r")
            terminal.wait(lambda: "[2 Proxies]" in terminal.text(), "result acknowledgement resumes dashboard")
            assert settings.read_bytes() == before_settings
            assert [path.read_bytes() for path in files] == snapshots
            assert all(request(url, "/configs")["mode"] == "rule" for url in urls)
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean dashboard exit")
            current = termios.tcgetattr(terminal.slave)
            assert current == terminal.original, "terminal flags not restored"
            terminal.send("handoff-restored\n")
            terminal.wait(lambda: "__ECHO_handoff-restored__" in terminal.text(), "outer shell input restored")
            print("TOOLS PTY PASS: edit/paste/resize cancel, common group form cancel, duplicate Ctrl+S/default cancel, cross-target copy preview cancel, intentional export/result pause, source/settings unchanged, terminal restored")
    finally:
        try:
            if terminal is not None:
                if terminal.process.poll() is None:
                    try:
                        terminal.send("\r\x1bq\r")
                    except OSError:
                        pass  # the wrapper may have exited after the poll
                terminal.close()
        finally:
            for core in cores:
                core.terminate()
                core.wait(timeout=3)


if __name__ == "__main__":
    main()
