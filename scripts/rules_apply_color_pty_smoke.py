"""Check rules apply semantic colors on real stdout PTYs with stdin redirected.

Run: python3 scripts/rules_apply_color_pty_smoke.py

Builds a disposable Go test helper which renders production CLI writers with
fixed reports. No settings, remote hosts, credentials, or controllers are used.
"""

import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import tempfile
import termios
import time


ROOT = Path(__file__).resolve().parents[1]
SGR = re.compile(rb"\x1b\[[0-9;]*m")


def capture(binary, scenario, flags=(), environment=None, terminal=True, width=120):
    env = os.environ.copy()
    for key in ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "FORCE_COLOR"):
        env.pop(key, None)
    env.update(TERM="xterm-256color", LAZYCLASH_RULES_COLOR_PTY_HELPER="1",
               LAZYCLASH_RULES_COLOR_SCENARIO=scenario)
    env.update(environment or {})
    argv = [str(binary), "-test.run=^TestRulesApplyColorPTYHelper$", "--", *flags]
    if not terminal:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=10)
        assert result.returncode == 0, result.stderr
        assert not result.stderr, result.stderr
        return result.stdout
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, width, 0, 0))
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave,
                             env=env, close_fds=True)
    os.close(slave)
    raw = bytearray()
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if not ready:
                if child.poll() is not None:
                    break
                continue
            try:
                data = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            raw.extend(data)
        assert child.wait(timeout=max(0.1, deadline - time.monotonic())) == 0, raw
    finally:
        os.close(master)
        if child.poll() is None:
            child.kill()
            child.wait()
    return bytes(raw).replace(b"\r\n", b"\n")


def styled(raw, text, color):
    # Lip Gloss combines bold/foreground parameters in a single SGR sequence.
    return re.search(rb"\x1b\[(?:[0-9]+;)*" + str(color).encode() +
                     rb"(?:;[0-9]+)*m" + re.escape(text.encode()), raw) is not None


def main():
    with tempfile.TemporaryDirectory(prefix="lazyclash-color-pty-") as scratch:
        binary = Path(scratch) / "cli.test"
        subprocess.run(["go", "test", "-c", "-o", str(binary), "./internal/cli"],
                       cwd=ROOT, check=True)
        ready = capture(binary, "ready")
        assert styled(ready, "Rule: ", 36), ready
        assert styled(ready, "ready", 32), ready
        assert styled(ready, "+ [0] DOMAIN-SUFFIX,api.enterprise.githubcopilot.com,DIRECT", 32), ready
        assert styled(ready, "  warning [runtime_policy_drift]", 33), ready
        assert b"\x1b[2mDigest:" in ready, ready
        plain = SGR.sub(b"", ready)
        assert b"Operation checks:" in plain and b"Existing health" in plain and b"Next:" in plain

        blocked = capture(binary, "blocked")
        assert styled(blocked, "blocked", 31), blocked
        assert styled(blocked, "  error [selector_conflict]", 31), blocked
        for scenario, status, color in (
            ("completed", "applied_verified", 32),
            ("pending", "persisted_pending_owner_reload", 33),
            ("unknown", "write_result_unknown", 33),
            ("unavailable", "skipped_unavailable", 33),
        ):
            raw = capture(binary, scenario)
            assert styled(raw, status, color), raw
            if scenario != "unavailable":
                assert b"receipt-fixture" in raw and b"/fixture/config.yaml" in raw, raw
        assert b"\x1b[2mskipped_existing" in capture(binary, "skipped")

        for flags, env, terminal in (
            (("--color", "never"), {}, True),
            ((), {"NO_COLOR": "1"}, True),
            ((), {"TERM": "dumb"}, True),
            ((), {}, False),
        ):
            raw = capture(binary, "ready", flags, env, terminal)
            assert b"\x1b" not in raw and raw == plain, raw
        always = capture(binary, "ready", ("--color", "always"), {"NO_COLOR": "1", "TERM": "dumb"}, False)
        assert styled(always, "ready", 32) and SGR.sub(b"", always) == plain
        for terminal in (True, False):
            raw = capture(binary, "ready", ("--json", "--color", "always"), terminal=terminal)
            assert b"\x1b" not in raw and json.loads(raw)["status"] == "ready", raw
        sanitized = capture(binary, "sanitized")
        assert b"\x1b]" not in sanitized and b"PRIVATE_CLIPBOARD" not in sanitized
        assert b"Remote diagnostic" in sanitized
        narrow = capture(binary, "ready", width=40)
        assert SGR.sub(b"", narrow) == plain
    print("rules apply color PTY smoke passed: semantic colors, plain/JSON modes, environment precedence, sanitized text, narrow terminal; stdin redirected throughout")


if __name__ == "__main__":
    main()
