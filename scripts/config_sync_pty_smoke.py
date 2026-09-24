# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise configuration sync against disposable Verge owners in a real PTY.

Run:
  go build -o bin/lazyclash ./cmd/lazyclash
  go build -o bin/fakecore ./tools/fakecore
  uv run scripts/config_sync_pty_smoke.py

No real target, subscription, provider, or application configuration is used.
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import termios

import pty_smoke
from pty_smoke import Terminal


ROOT = Path(__file__).resolve().parents[1]


def make_owner(root, name, source):
    home = root / name
    (home / "profiles").mkdir(parents=True)
    (home / "profiles.yaml").write_text(
        "current: chosen\nitems:\n"
        "- uid: chosen\n  type: remote\n  file: base.yaml\n"
        "  option: {rules: r, proxies: p, groups: g, merge: m}\n"
        "- {uid: r, type: rules, file: rules.yaml}\n"
        "- {uid: p, type: proxies, file: proxies.yaml}\n"
        "- {uid: g, type: groups, file: groups.yaml}\n"
        "- {uid: m, type: merge, file: merge.yaml}\n"
    )
    for kind in ("rules", "proxies", "groups"):
        (home / "profiles" / f"{kind}.yaml").write_text("prepend: []\nappend: []\ndelete: []\n")
    (home / "profiles/merge.yaml").write_text("{}\n")
    if source:
        document = (
            "proxies:\n"
            "- {name: Shared, type: trojan, server: shared.example, port: 443, password: SECRET_SOURCE_SYNC}\n"
            "- {name: CopyMe, type: http, server: copy.example, port: 8080, username: user, password: SECRET_COPY_SYNC}\n"
            "proxy-groups:\n- {name: Route, type: select, proxies: [Shared]}\n"
            "rules:\n- MATCH,DIRECT\n"
        )
    else:
        document = (
            "proxies:\n"
            "- {name: Shared, type: trojan, server: shared.example, port: 443, password: SECRET_DEST_SYNC}\n"
            "- {name: Local, type: socks5, server: local.example, port: 1080}\n"
            "proxy-groups:\n- {name: Route, type: select, proxies: [Local]}\n"
            "rules:\n- MATCH,DIRECT\n"
        )
    (home / "profiles/base.yaml").write_text(document)
    return home


def main():
    core = subprocess.Popen(
        [str(ROOT / "bin/fakecore")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    terminal = None
    original_root = pty_smoke.ROOT
    try:
        url = core.stdout.readline().strip()
        assert url.startswith("http://127.0.0.1:"), url
        with tempfile.TemporaryDirectory(prefix="lazyclash-sync-pty-") as scratch:
            root = Path(scratch)
            owners = {name: make_owner(root, name, name == "src") for name in ("src", "d1", "d2")}
            originals = {path: path.read_bytes() for home in owners.values() for path in home.rglob("*.yaml")}
            settings = root / "config.toml"
            settings.write_text(
                'default_target = "src"\n'
                + "".join(
                    f'[[targets]]\nid = "{name}"\ncontroller = "{url}"\n'
                    f'[targets.config_source]\nkind = "verge"\nversion = "2.5.2"\n'
                    f'data_dir = "{home}"\nprofile_uid = "chosen"\n'
                    for name, home in owners.items()
                )
            )
            before_settings = settings.read_bytes()
            # Keep the common terminal wrapper and its shell-restoration probe,
            # while invoking the standalone shared selector rather than the dashboard.
            shim = root / "shim"
            (shim / "bin").mkdir(parents=True)
            wrapper = shim / "bin/lazyclash"
            wrapper.write_text(
                "#!/bin/sh\nexec " + shlex.quote(str(ROOT / "bin/lazyclash"))
                + ' "$@" configs sync src --all --interactive\n'
            )
            wrapper.chmod(0o700)
            pty_smoke.ROOT = shim
            env = dict(os.environ)
            for name in ("LAZYCLASH_CONFIG", "LAZYCLASH_TARGET", "LAZYCLASH_CONTROLLER", "CLASH_CONTROLLER", "CLASH_SECRET"):
                env.pop(name, None)
            env.update(HOME=scratch, XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=scratch, TERM="xterm-256color", NO_COLOR="1")
            terminal = Terminal(settings, env)
            terminal.wait(lambda: "Destination 1/2: d1" in terminal.text() and "Shared" in terminal.text(), "initial catalog", timeout=15)
            assert "d1: 0" in terminal.text() and "d2: 0" in terminal.text(), "preselected objects"

            terminal.send("/Route\r ")
            terminal.send("l")
            terminal.wait(lambda: "Destination 2/2: d2" in terminal.text() and "CopyMe" in terminal.text(), "second target", timeout=15)
            assert "d1: 1" in terminal.text() and "d2: 0" in terminal.text(), terminal.text()
            terminal.send("/CopyMe\r g")
            terminal.wait(lambda: "Attach selected proxy" in terminal.text(), "group picker")
            terminal.send(" \rp")

            terminal.wait(lambda: "Resolve dependency collisions" in terminal.text(), "dependency review", timeout=20)
            assert "unresolved" in terminal.text(), terminal.text()
            terminal.send("\r")
            assert "Reuse the destination definition" in terminal.text(), terminal.text()
            assert "Replace with the source definition" in terminal.text(), terminal.text()
            terminal.send("j\rp")
            terminal.wait(lambda: "Review selected changes" in terminal.text(), "review", timeout=20)
            assert "Apply unavailable" not in terminal.text(), terminal.text()
            assert all(path.read_bytes() == data for path, data in originals.items()), "preview changed source"

            terminal.send("\r")
            terminal.wait(lambda: "Destination 2/2: d2" in terminal.text(), "default Back")
            assert "d1: 1" in terminal.text() and "d2: 1" in terminal.text(), terminal.text()
            terminal.resize(36, 12)
            terminal.send("\tjj")
            terminal.resize(120, 32)
            terminal.send("p")
            terminal.wait(lambda: "Review selected changes" in terminal.text(), "review again", timeout=20)
            terminal.send("\t\r")
            terminal.wait(lambda: "Configuration sync · complete" in terminal.text(), "apply results", timeout=25)
            assert "Receipt:" in terminal.text(), terminal.text()

            assert "Shared" in (owners["d1"] / "profiles/groups.yaml").read_text(), "group replacement missing"
            assert "CopyMe" in (owners["d2"] / "profiles/proxies.yaml").read_text(), "added proxy missing"
            assert "CopyMe" in (owners["d2"] / "profiles/groups.yaml").read_text(), "attachment missing"
            assert all(
                path.read_bytes() == data for path, data in originals.items()
                if path.is_relative_to(owners["src"]) or path.name in ("profiles.yaml", "base.yaml")
            ), "source/base/index changed"
            assert settings.read_bytes() == before_settings, "settings changed"
            output = terminal.raw.decode("utf-8", "replace")
            assert all(secret not in output for secret in ("SECRET_SOURCE_SYNC", "SECRET_DEST_SYNC", "SECRET_COPY_SYNC")), "secret exposed"

            terminal.send("\r")
            terminal.wait(lambda: b"__LAZYCLASH_EXIT_0__" in terminal.raw, "exit")
            assert termios.tcgetattr(terminal.slave) == terminal.original, "termios not restored"
            terminal.send("restored\n")
            terminal.wait(lambda: b"__ECHO_restored__" in terminal.raw, "echo restored")
            print("PASS: independent selections, masked diff, dependency reuse, group attachment, default Back, resize, isolated batch apply and terminal restoration")
    finally:
        pty_smoke.ROOT = original_root
        if terminal:
            terminal.close()
        core.terminate()
        core.wait(timeout=3)


if __name__ == "__main__":
    main()
