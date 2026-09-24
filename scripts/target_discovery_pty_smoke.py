# /// script
# requires-python = ">=3.11"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise targets add --ssh using real PTYs and injected discovery fixtures.

Run: uv run scripts/target_discovery_pty_smoke.py

Builds the CLI's Go test helper in a temporary directory. Discovery and native
authentication are deterministic local fixtures; no SSH or controller is opened.
All settings, HOME and XDG paths are disposable. No production test switches exist.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import termios
import tomllib

import pty_smoke
from pty_smoke import Terminal


ROOT = Path(__file__).resolve().parents[1]
HELPER = "^TestTargetDiscoveryPTYHelper$"
SECRETS = ("fixture-private-secret", "fixture-private-secret-two", "fixture-local-reference-value")
INITIAL = b"# Disposable target discovery fixture.\n"


class Case:
    def __init__(self, root, binary, name, scenario):
        self.root = root / name
        self.root.mkdir()
        self.binary = binary
        self.settings = self.root / "config.toml"
        self.settings.write_bytes(INITIAL)
        self.log = self.root / "events.log"
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("LAZYCLASH_", "CLASH_"))
        }
        self.env.update(
            HOME=str(self.root), XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_STATE_HOME=str(self.root / "state"), XDG_CACHE_HOME=str(self.root / "cache"),
            XDG_DATA_HOME=str(self.root / "data"),
            TERM="xterm-256color", NO_COLOR="1",
            FIXTURE_CONTROLLER_SECRET="fixture-local-reference-value",
            LAZYCLASH_TARGET_DISCOVERY_PTY_HELPER="1",
            LAZYCLASH_TARGET_DISCOVERY_SCENARIO=scenario,
            LAZYCLASH_TARGET_DISCOVERY_LOG=str(self.log),
        )

    def unchanged(self):
        assert self.settings.read_bytes() == INITIAL, "registration wrote before Save"

    def events(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def private(self, output):
        if isinstance(output, (bytes, bytearray)):
            output = output.decode("utf-8", "replace")
        settings = self.settings.read_text()
        assert all(secret not in output and secret not in settings for secret in SECRETS), "discovered secret exposed"
        assert not any(line.startswith("UNEXPECTED_OPEN") for line in self.events()), "registration opened a controller"

    def saved(self, target_id, controller, source=None):
        cfg = tomllib.loads(self.settings.read_text())
        assert cfg["default_target"] == target_id, cfg
        assert len(cfg["targets"]) == 1, cfg
        target = cfg["targets"][0]
        assert target["id"] == target_id, target
        assert target["controller"] == controller, target
        assert target["ssh_host"] == "fixture-host", target
        assert target.get("source_config", "") == (source or ""), target
        for field in ("secret", "transient", "transport_override", "auth_required", "rule_source", "config_source", "service", "managed_core_id"):
            assert not target.get(field), f"discovery granted or persisted {field}"
        if source:
            assert target["configs"][0]["path"] == source, target
        else:
            assert not target.get("configs"), target
        return target

    @contextmanager
    def terminal(self, args):
        shim = self.root / "shim"
        (shim / "bin").mkdir(parents=True)
        wrapper = shim / "bin/lazyclash"
        wrapper.write_text(
            "#!/bin/sh\nexec " + shlex.quote(str(self.binary))
            + " -test.run=" + shlex.quote(HELPER) + ' -- "$@" '
            + shlex.join(args) + "\n"
        )
        wrapper.chmod(0o700)
        original_root = pty_smoke.ROOT
        terminal = None
        try:
            pty_smoke.ROOT = shim
            terminal = Terminal(self.settings, self.env)
            yield terminal
        finally:
            pty_smoke.ROOT = original_root
            if terminal:
                try:
                    self.private(terminal.raw)
                finally:
                    terminal.close()

    def run_pipe(self, args):
        result = subprocess.run(
            [str(self.binary), "-test.run=" + HELPER, "--", "--config", str(self.settings), *args],
            input="", capture_output=True, text=True, env=self.env, timeout=10,
        )
        self.private(result.stdout + result.stderr)
        assert "\x1b" not in result.stdout + result.stderr, "non-TTY emitted terminal controls"
        return result


def review(terminal, endpoint="19090"):
    terminal.wait(
        lambda: "Review target registration" in terminal.text() and endpoint in terminal.text(),
        "registration review", timeout=10,
    )


def finished(terminal, status=0):
    marker = f"__LAZYCLASH_EXIT_{status}__".encode()
    terminal.wait(lambda: marker in terminal.raw, f"exit {status}", timeout=10)
    assert termios.tcgetattr(terminal.slave) == terminal.original, "termios not restored"
    terminal.send("restored\n")
    terminal.wait(lambda: b"__ECHO_restored__" in terminal.raw, "shell echo restored")
    assert terminal.process.wait(timeout=3) == status, "wrapper exit status"


def main():
    with tempfile.TemporaryDirectory(prefix="lazyclash-target-discovery-pty-") as scratch:
        root = Path(scratch)
        binary = root / "cli.test"
        subprocess.run(["go", "test", "-c", "-o", str(binary), "./internal/cli"], cwd=ROOT, check=True, timeout=120)

        case = Case(root, binary, "single", "single")
        with case.terminal(["targets", "add", "--ssh", "fixture-host", "--secret-env", "FIXTURE_CONTROLLER_SECRET"]) as terminal:
            review(terminal)
            case.unchanged()
            terminal.send("\x13")
            finished(terminal)
            target = case.saved("core-fixture1", "http://127.0.0.1:19090", "/fixture/one.yaml")
            assert target["secret_env"] == "FIXTURE_CONTROLLER_SECRET", target
            assert case.events() == ["discover fixture-host"], case.events()

        case = Case(root, binary, "multiple", "multiple")
        with case.terminal(["targets", "add", "multi", "--ssh", "fixture-host"]) as terminal:
            terminal.wait(lambda: "Choose discovered controller" in terminal.text() and "19091" in terminal.text(), "candidate picker")
            case.unchanged()
            terminal.send("j\r")
            review(terminal, "19091")
            terminal.send("\t\x01\x0bRetained jkhql/? draft")
            terminal.send("\x1b")
            terminal.wait(lambda: "draft retained" in terminal.text(), "Back retains draft")
            case.unchanged()
            terminal.send("\r")
            review(terminal, "19091")
            assert "Retained jkhql/? draft" in terminal.text(), terminal.text()
            terminal.resize(36, 12)
            terminal.resize(120, 32)
            review(terminal, "19091")
            terminal.send("\x13")
            finished(terminal)
            target = case.saved("multi", "http://127.0.0.1:19091", "/fixture/two.yaml")
            assert target["name"] == "Retained jkhql/? draft", target

        case = Case(root, binary, "manual", "zero")
        with case.terminal(["targets", "add", "manual", "--ssh", "fixture-host"]) as terminal:
            terminal.wait(lambda: "Enter controller manually" in terminal.text(), "empty discovery recovery")
            terminal.send("\x1b[B\r")
            terminal.wait(lambda: "Review target registration" in terminal.text(), "manual registration")
            case.unchanged()
            terminal.send("\t\thttp://127.0.0.1:19094\x13")
            finished(terminal)
            case.saved("manual", "http://127.0.0.1:19094")

        for name, scenario, screen, cancel in (
            ("cancel-review", "single", "Review target registration", "\x03"),
            ("cancel-empty", "zero", "Enter controller manually", "\x1b"),
            ("cancel-picker", "multiple", "Choose discovered controller", "\x1b"),
        ):
            case = Case(root, binary, name, scenario)
            with case.terminal(["targets", "add", name, "--ssh", "fixture-host"]) as terminal:
                terminal.wait(lambda: screen in terminal.text(), screen)
                terminal.send(cancel)
                finished(terminal, 130)
                case.unchanged()

        for scenario in ("zero-retry", "auth", "auth-failed"):
            case = Case(root, binary, scenario, scenario)
            with case.terminal(["targets", "add", scenario, "--ssh", "fixture-host"]) as terminal:
                if scenario != "auth":
                    terminal.wait(lambda: "Retry discovery" in terminal.text(), "retry recovery")
                    case.unchanged()
                    terminal.send("\r")
                review(terminal)
                case.unchanged()
                terminal.send("\x03")
                finished(terminal, 130)
                case.unchanged()
                expected = ["discover fixture-host", "discover fixture-host"]
                if scenario.startswith("auth"):
                    expected.insert(1, "authenticate fixture-host")
                    result = b"failed" if scenario == "auth-failed" else b"completed"
                    assert b"Fixture SSH authentication " + result in terminal.raw, "native authentication not visible"
                assert case.events() == expected, case.events()

        case = Case(root, binary, "control", "control")
        with case.terminal(["targets", "add", "control", "--ssh", "fixture-host"]) as terminal:
            review(terminal)
            case.unchanged()
            terminal.send("\x13")
            finished(terminal)
            target = case.saved("control", "http://127.0.0.1:19090", "/fixture/one.yaml")
            assert b"\x1b]52;" not in terminal.raw and b"\x1b[31m" not in terminal.raw, "candidate injected terminal controls"
            assert "\x1b" not in target["name"] and "\a" not in target["name"], "candidate persisted controls"

        for name, extra in (("non-tty", []), ("json", ["--json"])):
            case = Case(root, binary, name, "auth")
            result = case.run_pipe([*extra, "targets", "add", name, "--ssh", "fixture-host"])
            assert result.returncode == 2 and "--controller" in result.stderr, result.stderr
            case.unchanged()
            assert case.events() == [], "noninteractive registration invoked discovery/authentication"

        case = Case(root, binary, "json-tty", "auth")
        with case.terminal(["--json", "targets", "add", "json-tty", "--ssh", "fixture-host"]) as terminal:
            finished(terminal, 2)
            case.unchanged()
            assert case.events() == [], "JSON terminal registration invoked discovery/authentication"
            assert b"Review target registration" not in terminal.raw, "JSON terminal opened wizard"

        case = Case(root, binary, "invalid-host", "single")
        result = case.run_pipe(["targets", "add", "invalid", "--ssh", "fixture-host\x1b]52;c;PRIVATE_CLIPBOARD\a"])
        assert result.returncode == 2, result.stderr
        case.unchanged()
        assert case.events() == [], "invalid host invoked discovery"

        case = Case(root, binary, "complete-non-tty", "auth")
        secret = case.root / "local-secret"
        secret.write_text("fixture-local-reference-value")
        result = case.run_pipe(["targets", "add", "complete", "--ssh", "fixture-host", "--controller", "http://127.0.0.1:19095", "--secret-file", str(secret)])
        assert result.returncode == 0, result.stderr
        target = case.saved("complete", "http://127.0.0.1:19095")
        assert target["secret_file"] == str(secret), target
        assert case.events() == [], "complete registration invoked discovery/authentication"

    print("PASS: zero/single/multiple discovery, explicit Save, retained Back, cancel, retry, native auth handoff, resize, private credentials, no write grants, non-TTY/JSON and terminal restoration")


if __name__ == "__main__":
    main()
