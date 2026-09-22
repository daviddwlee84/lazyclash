# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Saved-checks dashboard workflow against a disposable controller and proxy.

Requires bin/lazyclash and bin/fakecore. The only HTTP check destination is an
in-process fake data proxy; production settings, controllers and sites are not
read or changed.
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import termios
import threading

from pty_smoke import ROOT, Terminal, request


class Proxy(http.server.BaseHTTPRequestHandler):
    requests = []

    def do_HEAD(self):
        self.requests.append(self.path)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_):
        pass


def saved_checks(settings, env):
    result = subprocess.run(
        [str(ROOT / "bin/lazyclash"), "--config", str(settings), "--target", "first",
         "diagnostics", "checks", "list", "--json"],
        env=env, capture_output=True, text=True, check=True, timeout=3,
    )
    return json.loads(result.stdout)["checks"]


def main():
    terminal, controller = None, None
    proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        controller = subprocess.Popen([str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        url = controller.stdout.readline().strip()
        original_runtime = request(url, "/configs")
        with tempfile.TemporaryDirectory(prefix="lazyclash-checks-pty-") as scratch:
            root = Path(scratch)
            settings = root / "settings.toml"
            settings.write_text(f'''# keep checks fixture comment
default_target = "first"
[[targets]]
id = "first"
name = "Saved checks fixture"
controller = "{url}"
probe_proxy = "http://127.0.0.1:{proxy.server_port}"
future_field = "keep"
''')
            before = settings.read_bytes()
            env = dict(os.environ)
            for name in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET", "LAZYCLASH_PROXY_SESSION"):
                env.pop(name, None)
            env.update(XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=str(root / "state"), XDG_DATA_HOME=str(root / "data"), TERM="xterm-256color", NO_COLOR="1")
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "Saved connectivity checks" in terminal.text(), "visible Overview checks button")
            terminal.click_label("Saved connectivity checks")
            terminal.wait(lambda: "Review saved checks" in terminal.text(), "shared checks menu")
            terminal.send("\x1b")
            terminal.wait(lambda: "canceled" in terminal.text() and "Core RSS" in terminal.text(), "menu cancellation returns dashboard")
            assert settings.read_bytes() == before and not Proxy.requests

            terminal.send("C")
            terminal.wait(lambda: "Review saved checks" in terminal.text(), "checks shortcut")
            terminal.send("j\r")
            terminal.wait(lambda: "Add saved connectivity check" in terminal.text(), "add check form")
            terminal.send("discarded draft")
            terminal.send("\x1b")
            terminal.wait(lambda: "canceled" in terminal.text() and "Core RSS" in terminal.text(), "draft cancellation")
            assert settings.read_bytes() == before and not Proxy.requests

            terminal.send("C")
            terminal.wait(lambda: "Review saved checks" in terminal.text(), "open add menu")
            terminal.send("j\r")
            terminal.wait(lambda: "Add saved connectivity check" in terminal.text(), "reopen add form")
            terminal.send("fixture-web\tFixture website\thttp://check.invalid/\x13")
            terminal.wait(lambda: "Operation finished" in terminal.text(), "saved definition result pause")
            checks = saved_checks(settings, env)
            assert len(checks) == 1 and checks[0]["id"] == "fixture-web" and checks[0]["url"] == "http://check.invalid/"
            assert not Proxy.requests, "saving a definition ran an HTTP check"
            terminal.send("\r")
            terminal.wait(lambda: "Core RSS" in terminal.text(), "saved settings reload")

            terminal.send("C")
            terminal.wait(lambda: "Run all saved checks" in terminal.text(), "saved checks run choices")
            terminal.send("j\r")
            terminal.wait(lambda: "Operation finished" in terminal.text() and "1/1 passed" in terminal.text(), "manual run-all result", timeout=15)
            result = terminal.text()
            assert "transport reachable" in result and "HTTP 204 (matched)" in result, result
            assert "Rule / chain: unknown" in result and "Authentication / application access: not tested" in result, result
            assert Proxy.requests == ["http://check.invalid/"], Proxy.requests
            assert request(url, "/configs") == original_runtime, "checks changed runtime configuration"
            terminal.send("\r")
            terminal.wait(lambda: "Core RSS" in terminal.text(), "run result returns dashboard")

            terminal.send("C")
            terminal.wait(lambda: "Review saved checks" in terminal.text(), "remove menu")
            terminal.send("jjjjj\r")
            terminal.wait(lambda: "Choose saved check" in terminal.text(), "remove selection")
            terminal.send("\r")
            terminal.wait(lambda: "Remove saved connectivity check" in terminal.text(), "remove review")
            terminal.send("\r")  # The review defaults to Cancel.
            terminal.wait(lambda: "canceled" in terminal.text() and "Core RSS" in terminal.text(), "removal cancel")
            assert len(saved_checks(settings, env)) == 1

            terminal.send("C")
            terminal.wait(lambda: "Review saved checks" in terminal.text(), "reopen remove menu")
            terminal.send("jjjjj\r")
            terminal.wait(lambda: "Choose saved check" in terminal.text(), "reopen remove selection")
            terminal.send("\r")
            terminal.wait(lambda: "Remove saved connectivity check" in terminal.text(), "reopen remove review")
            terminal.send("\t\r")
            terminal.wait(lambda: "Operation finished" in terminal.text(), "removal result pause")
            assert saved_checks(settings, env) == []
            assert 'future_field = "keep"' in settings.read_text() and "# keep checks fixture comment" in settings.read_text()
            assert Proxy.requests == ["http://check.invalid/"] and request(url, "/configs") == original_runtime
            terminal.send("\r")
            terminal.wait(lambda: "Core RSS" in terminal.text(), "remove result returns dashboard")
            terminal.send("q")
            terminal.wait(lambda: "__LAZYCLASH_EXIT_0__" in terminal.text(), "clean dashboard exit")
            assert termios.tcgetattr(terminal.slave) == terminal.original, "terminal flags were not restored"
            terminal.send("checks-restored\n")
            terminal.wait(lambda: "__ECHO_checks-restored__" in terminal.text(), "outer terminal reader restored")
            print("CHECKS PTY PASS: visible button, shared menu, draft cancellation, save without probe, explicit Run all, transport/status/auth/routing distinction, removal review/cancel/apply, settings preservation, runtime unchanged, terminal restored")
    finally:
        if terminal is not None:
            terminal.close()
        if controller is not None:
            controller.terminate()
            controller.wait(timeout=3)
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
