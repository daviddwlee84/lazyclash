# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Real PTY rule observation, reviewed batch apply, and guarded discovery.

Run: uv run scripts/rule_discovery_pty_smoke.py
Builds bin/lazyclash and uses only a loopback fixture and disposable Verge files.
No real controller, user settings, DNS probes, or proxy service is used.
"""

import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import termios
import threading
from urllib.parse import unquote, urlsplit

from pty_smoke import ROOT, Terminal


class Controller(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.lock = threading.Lock()
        self.selection = "Proxy"
        self.writes = []
        self.stop_streams = threading.Event()
        self.emitted = 0

    def proxies(self):
        with self.lock:
            selected = self.selection
        return {
            "DIRECT": {"name": "DIRECT", "type": "Direct", "alive": True},
            "Proxy": {"name": "Proxy", "type": "Socks5", "alive": True},
            "Final": {"name": "Final", "type": "Selector", "all": ["Proxy", "DIRECT"], "now": selected},
        }


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def response(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path in ("/logs", "/traffic", "/memory"):
            return self.stream(path)
        if path == "/version":
            return self.response({"version": "v1.19.29", "meta": True})
        if path == "/configs":
            return self.response({"mode": "rule", "mixed-port": 7890, "allow-lan": False, "log-level": "info", "tun": {"enable": False}})
        if path == "/proxies":
            return self.response({"proxies": self.server.proxies()})
        if path.startswith("/proxies/"):
            proxy = self.server.proxies().get(path.removeprefix("/proxies/"))
            return self.response(proxy or {}, 200 if proxy else 404)
        if path == "/rules":
            return self.response({"rules": [{"type": "Match", "payload": "", "proxy": "Final"}]})
        if path == "/connections":
            return self.response({"connections": [], "uploadTotal": 1024, "downloadTotal": 4096, "memory": 1048576})
        if path in ("/providers/rules", "/providers/proxies"):
            return self.response({"providers": {}})
        return self.response({"message": "fixture endpoint unavailable"}, 404)

    def do_PUT(self):
        path = unquote(urlsplit(self.path).path)
        value = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        with self.server.lock:
            self.server.writes.append((path, value))
            if path == "/proxies/Final" and value.get("name") in ("DIRECT", "Proxy"):
                self.server.selection = value["name"]
            else:
                return self.response({"message": "unexpected fixture mutation"}, 400)
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def stream(self, path):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            while not self.server.stop_streams.is_set():
                if path == "/traffic":
                    records = [{"up": 10, "down": 40}]
                elif path == "/memory":
                    records = [{"inuse": 1048576}]
                else:
                    selected = self.server.proxies()["Final"]["now"]
                    records = [
                        {"type": "warning", "payload": "[TCP] dial Final (match Match/) 127.0.0.1:4001(curl) --> alpha.example.test:443 error: i/o timeout"},
                        {"type": "warning", "payload": "[TCP] dial Final (match Match/) 127.0.0.1:4002(browser) --> beta.example.test:443 error: connection refused"},
                        {"type": "info", "payload": f"[TCP] 127.0.0.1:4003(browser) --> healthy.example.test:443 match Match using Final[{selected}]"},
                    ]
                    with self.server.lock:
                        self.server.emitted += len(records)
                for record in records:
                    self.wfile.write(json.dumps(record).encode() + b"\n")
                self.wfile.flush()
                self.server.stop_streams.wait(0.2)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def fixture(root, url):
    home = root / "verge"
    (home / "profiles").mkdir(parents=True)
    manifest = home / "profiles.yaml"
    manifest.write_text(
        "current: chosen\nitems:\n"
        "- uid: chosen\n  type: remote\n  file: base.yaml\n  option: {rules: owned-rules}\n"
        "- {uid: owned-rules, type: rules, file: owned.yaml}\n"
    )
    (home / "profiles/base.yaml").write_text("rules:\n- MATCH,Final\n")
    companion = home / "profiles/owned.yaml"
    companion.write_text("# disposable rule discovery fixture\nprepend: []\nappend: []\ndelete: []\n")
    settings = root / "config.toml"
    settings.write_text(
        'default_target = "fixture"\n[[targets]]\nid = "fixture"\nname = "Rule Discovery Fixture"\n'
        f'controller = "{url}"\n[targets.rule_source]\nkind = "verge"\nversion = "2.5.2"\n'
        f'data_dir = {json.dumps(str(home))}\nprofile_uid = "chosen"\n'
    )
    env = dict(os.environ)
    for name in tuple(env):
        if name.startswith("LAZYCLASH_") or name in ("CLASH_CONTROLLER", "CLASH_SECRET") or name.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            env.pop(name, None)
    env.update(HOME=str(root), XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"), TERM="xterm-256color", NO_COLOR="1")
    return settings, companion, manifest, env


def finish(terminal):
    terminal.send("q")
    terminal.wait(lambda: b"__LAZYCLASH_EXIT_0__" in terminal.raw, "clean dashboard exit", timeout=15)
    assert termios.tcgetattr(terminal.slave) == terminal.original, "terminal attributes not restored"
    terminal.send("rule-discovery-restored\n")
    terminal.wait(lambda: b"__ECHO_rule-discovery-restored__" in terminal.raw, "shell echo restored")
    assert terminal.process.wait(timeout=3) == 0


def main():
    build_env = dict(os.environ)
    homebrew_go = Path("/opt/homebrew/opt/go/libexec")
    if homebrew_go.is_dir():
        build_env["GOROOT"] = str(homebrew_go)
    subprocess.run(["go", "build", "-o", "bin/lazyclash", "./cmd/lazyclash"], cwd=ROOT, env=build_env, check=True, timeout=120)
    controller = Controller()
    thread = threading.Thread(target=controller.serve_forever, daemon=True)
    thread.start()
    terminal = None
    try:
        with tempfile.TemporaryDirectory(prefix="lazyclash-rule-discovery-pty-") as scratch:
            root = Path(scratch)
            settings, companion, manifest, env = fixture(root, f"http://127.0.0.1:{controller.server_port}")
            before = companion.read_bytes()
            fixed = {settings: settings.read_bytes(), manifest: manifest.read_bytes(), manifest.parent / "profiles/base.yaml": (manifest.parent / "profiles/base.yaml").read_bytes()}
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "Core RSS" in terminal.text(), "dashboard ready", timeout=15)
            terminal.send("4")
            terminal.wait(lambda: "alpha.example.test" in terminal.text() and "beta.example.test" in terminal.text(), "normal live logs")
            terminal.send("R")
            terminal.wait(lambda: "Review observed connection logs" in terminal.text() and "alpha.example.test" in terminal.text(), "recent observations review")
            terminal.send("/qj")
            terminal.send(b"\x1b[200~k/y\x1b[201~")
            terminal.wait(lambda: "qjk/y" in terminal.text(), "filter and paste own shortcut letters")
            assert terminal.process.poll() is None and controller.writes == []
            terminal.send("\x1b")
            terminal.send("v")
            terminal.wait(lambda: "observed MATCH connections" in terminal.text() and "healthy.example.test" in terminal.text(), "optional successful MATCH view")
            terminal.send("vv")
            terminal.wait(lambda: "View: anomalies" in terminal.text(), "anomaly view restored")
            terminal.send(" j pProxy\r")
            terminal.wait(lambda: "DOMAIN,beta.example.test,Proxy" in terminal.text(), "batch policy applied to marked rows")
            terminal.send("a")
            terminal.wait(lambda: "Batch: ready" in terminal.text() and "y Apply reviewed batch" in terminal.text(), "validated batch preview", timeout=20)
            assert companion.read_bytes() == before and controller.writes == [], "preview mutated owner or controller"
            terminal.send("\r")
            terminal.wait(lambda: "View: anomalies" in terminal.text(), "Enter canceled preview")
            assert companion.read_bytes() == before
            terminal.send("a")
            terminal.wait(lambda: "y Apply reviewed batch" in terminal.text(), "second batch preview", timeout=20)
            terminal.send("yy")
            terminal.wait(lambda: "Receipt:" in terminal.text() and "persisted_pending_owner_reload" in terminal.text(), "reviewed apply saved Verge companion", timeout=20)
            applied = companion.read_text()
            assert applied.count("DOMAIN,alpha.example.test,Proxy") == 1, applied
            assert applied.count("DOMAIN,beta.example.test,Proxy") == 1, applied
            receipts = list((root / "state/lazyclash/rule-receipts").glob("*/receipt.json"))
            assert len(receipts) == 1, f"batch was applied more than once: {receipts}"
            assert controller.writes == [], "Verge apply mutated runtime"
            terminal.send("\rq")
            terminal.wait(lambda: "Rule Discovery Fixture" in terminal.text() and "Review observed" not in terminal.text(), "back to dashboard")

            terminal.send("D")
            terminal.wait(lambda: "Temporarily observe fallback via DIRECT" in terminal.text(), "discovery duration form")
            terminal.send("\x01\x1530s\r\r")
            terminal.wait(lambda: "Start DIRECT discovery" in terminal.text() and "Proxy → DIRECT" in terminal.text(), "fallback change confirmation", timeout=15)
            assert controller.writes == [], "confirmation wrote before apply"
            terminal.send("y")
            terminal.wait(lambda: controller.selection == "DIRECT" and "DIRECT discovery running" in terminal.text(), "guarded DIRECT collection", timeout=20)
            terminal.read(0.7)
            terminal.send("D")
            terminal.wait(lambda: "Review observed connection logs" in terminal.text(), "stop restored then opened review", timeout=20)
            assert controller.selection == "Proxy", "review appeared before restoring original selection"
            assert controller.writes == [("/proxies/Final", {"name": "DIRECT"}), ("/proxies/Final", {"name": "Proxy"})], controller.writes
            sessions = [json.loads(p.read_text()) for p in (root / "state/lazyclash/rule-discovery").glob("*.json")]
            saved = [s for s in sessions if s["mode"] == "fallback_direct"]
            assert len(saved) == 1 and saved[0]["status"] == "completed" and saved[0]["observed"] > 0, saved
            assert saved[0]["previous_selection"] == "Proxy" and saved[0]["fallback_policy"] == "Final"
            terminal.resize(40, 12)
            terminal.send("\tjj")
            terminal.wait(lambda: "Candidate:" in terminal.text() or "Observed evidence" in terminal.text(), "narrow detail pane")
            terminal.resize(120, 32)
            terminal.send("q")
            terminal.wait(lambda: "Review observed" not in terminal.text(), "review back to dashboard")
            assert all(path.read_bytes() == content for path, content in fixed.items()), "settings/base/manifest changed"
            finish(terminal)
            print("RULE DISCOVERY PTY PASS: normal logs → R review, text/paste ownership, MATCH view, multi-select policy, preview cancel, one reviewed batch/Verge pending reload, D start/stop with verified restoration before review, durable evidence, narrow resize, terminal/echo restored")
    finally:
        if terminal:
            # Help a failed assertion leave the wrapper's terminal reader
            # normally before falling back to Terminal's process cleanup.
            if terminal.process.poll() is None:
                terminal.send("\x03")
                terminal.read(0.3)
                terminal.send("cleanup\n")
                terminal.read(0.3)
            terminal.close()
        controller.stop_streams.set()
        controller.shutdown()
        controller.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    main()
