# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise opt-in analytics and dashboard handoff in a real isolated PTY.

Requires bin/lazyclash and bin/fakecore. No service is installed, no webhook is
configured and no real site is contacted. The diagnostic form is canceled.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import termios

from pty_smoke import ROOT, Terminal, request


def main():
    terminal = None
    controller = subprocess.Popen(
        [str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    try:
        url = controller.stdout.readline().strip()
        original_runtime = request(url, "/configs")
        with tempfile.TemporaryDirectory(prefix="lazyclash-analytics-pty-") as scratch:
            root = Path(scratch)
            settings = root / "settings.toml"
            settings.write_text(f'''default_target = "first"
[[targets]]
id = "first"
name = "Analytics fixture"
controller = "{url}"
''')
            settings.chmod(0o600)
            env = dict(os.environ)
            for name in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"):
                env.pop(name, None)
            env.update(XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=str(root / "state"),
                       XDG_DATA_HOME=str(root / "data"), TERM="xterm-256color", NO_COLOR="1")

            def cli(*args):
                result = subprocess.run(
                    [str(ROOT / "bin/lazyclash"), "--config", str(settings), *args],
                    env=env, capture_output=True, text=True, timeout=15,
                )
                assert result.returncode == 0, result.stderr
                return json.loads(result.stdout)

            preview = cli("--target", "first", "analytics", "setup", "--source", "desktop",
                          "--kind", "mihomo", "--json")
            assert not preview["saved"] and not (root / "lazyclash" / "analytics.toml").exists()
            cli("--target", "first", "analytics", "setup", "--source", "desktop",
                "--kind", "mihomo", "--enabled", "--poll-seconds", "1", "--yes", "--json")
            cli("analytics", "collect", "--duration", "1200ms", "--json")
            report = cli("analytics", "report", "--group-by", "domain", "--json")
            assert {row["key"] for row in report["rows"]} >= {"api.example.test", "static.example.test"}, report
            assert all(row["source_id"] == "desktop" and row["scope"] == "client" for row in report["rows"])
            config_bytes = (root / "lazyclash" / "analytics.toml").read_bytes()
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "Core RSS" in terminal.text(), "dashboard ready")
            terminal.send(":Historical analytics")
            terminal.wait(lambda: "Historical analytics: sources" in terminal.text(), "analytics palette action")
            terminal.send("\r")
            terminal.wait(lambda: "Historical analytics" in terminal.text() and "Stored observations ready" in terminal.text(), "analytics handoff")
            terminal.send("\r")
            terminal.wait(lambda: "analytics · domain" in terminal.text() and "api.example.test" in terminal.text(), "source to domain drill")
            terminal.send("/jkhql/?")
            terminal.wait(lambda: "jkhql/?" in terminal.text(), "filter owns shortcut letters")
            terminal.send("\x1b")
            terminal.wait(lambda: "api.example.test" in terminal.text(), "filter cancellation")
            terminal.send("?")
            terminal.wait(lambda: "no automatic rule changes" in terminal.text(), "analytics help")
            terminal.send("\x1b")
            terminal.send("d")
            terminal.wait(lambda: "Target ID:" in terminal.text(), "manual diagnosis target form")
            terminal.send("jkhql")
            terminal.wait(lambda: "jkhql" in terminal.text(), "target field owns q")
            terminal.send("\x1b")
            terminal.send("\t")
            terminal.resize(46, 16)
            terminal.wait(lambda: "Scope: client" in terminal.text(), "narrow detail pane")
            terminal.resize(120, 32)
            terminal.send("\t")
            terminal.send("w")
            terminal.wait(lambda: "domain · week" in terminal.text(), "weekly calendar window")
            terminal.send("w")
            terminal.wait(lambda: "domain · month" in terminal.text(), "monthly calendar window")
            terminal.send("r")
            terminal.wait(lambda: "Stored observations ready" in terminal.text(), "manual refresh")
            terminal.send("\x1b")
            terminal.wait(lambda: "analytics · source" in terminal.text(), "back to source")
            terminal.send("q")
            terminal.wait(lambda: "Core RSS" in terminal.text(), "return to dashboard")
            assert (root / "lazyclash" / "analytics.toml").read_bytes() == config_bytes
            assert request(url, "/configs") == original_runtime, "analytics changed core settings"
            status = cli("analytics", "status", "--json")
            assert status["collector"]["state"] == "stopped", status
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean exit")
            assert termios.tcgetattr(terminal.slave) == terminal.original, "terminal state not restored"
            terminal.send("analytics-restored\n")
            terminal.wait(lambda: "__ECHO_analytics-restored__" in terminal.text(), "outer reader restored")
            print("ANALYTICS PTY PASS: preview/opt-in, persistent source/domain reports, dashboard handoff, filter ownership, manual diagnosis cancellation, resize, day/week/month, back/refresh, no core writes, terminal restored")
    finally:
        if terminal is not None:
            terminal.close()
        controller.terminate()
        controller.wait(timeout=3)


if __name__ == "__main__":
    main()
