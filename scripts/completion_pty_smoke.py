"""Verify generated and installed completion through an actual isolated zsh PTY.

Requires bin/lazyclash and zsh. No user shell rc, SSH host, credentials or
controller is used. Commands under completion are inspected but never executed.
"""

import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import time


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "bin/lazyclash"


def main():
    zsh = "/bin/zsh" if Path("/bin/zsh").exists() else shutil.which("zsh")
    if not zsh:
        raise SystemExit("zsh is required for completion PTY verification")
    with tempfile.TemporaryDirectory(prefix="lazyclash-completion-pty-") as scratch:
        directory = Path(scratch)
        executable_dir = directory / "bin"
        executable_dir.mkdir()
        (executable_dir / "lazyclash").symlink_to(BINARY)
        settings = directory / "config.toml"
        settings.write_text('''[[targets]]
id = "alpha"
controller = "http://127.0.0.1:1"
secret_env = "MUST_NOT_RESOLVE_COMPLETION_SECRET"
[[targets.configs]]
id = "work"
path = "/remote/work.yaml"
[[targets]]
id = "beta"
controller = "http://127.0.0.1:2"
''')
        env = {
            "PATH": str(executable_dir) + os.pathsep + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": scratch,
            "ZDOTDIR": scratch,
            "XDG_DATA_HOME": str(directory / "data"),
            "XDG_CONFIG_HOME": scratch,
            "LAZYCLASH_CONFIG": str(settings),
            "TERM": "xterm-256color",
            "LC_ALL": "C",
        }

        def cli(*args):
            return subprocess.check_output([str(BINARY), *args], env=env, text=True, timeout=10)

        raw = cli("completion", "zsh")
        assert raw.startswith("#compdef lazyclash"), raw[:200]
        assert "__complete" in raw, "generated bridge does not query current binary"
        # The application's printed activation snippet must handle both spaces
        # and apostrophes. Use it verbatim in the isolated shell startup file.
        completion_dir = directory / "completion path's space"
        installed = json.loads(cli("completion", "install", "zsh", "--dir", str(completion_dir), "--json"))
        status = json.loads(cli("completion", "status", "zsh", "--dir", str(completion_dir), "--json"))
        assert installed["state"] == status["state"] == "current"
        assert status["activation"].startswith("unknown"), status
        (directory / ".zshrc").write_text(installed["setup"] + '''
unsetopt BEEP
PROMPT='__LAZYCLASH_COMPLETION_READY__> '
zstyle ':completion:*' menu no
bindkey '^I' expand-or-complete
function lazyclash_capture_buffer() {
  print -r -- "__BUFFER__${BUFFER}__END__"
  BUFFER=''
  CURSOR=0
  zle reset-prompt
}
zle -N lazyclash_capture_buffer
bindkey '^X^G' lazyclash_capture_buffer
''')
        pid, master = pty.fork()
        if pid == 0:
            os.execve(zsh, [zsh, "-d", "-i"], env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
        child_status = None
        output = bytearray()

        def poll():
            nonlocal child_status
            if child_status is None:
                child, status = os.waitpid(pid, os.WNOHANG)
                if child:
                    child_status = os.waitstatus_to_exitcode(status)
            return child_status

        def wait_for(marker, timeout=8):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output.extend(data)
                if marker.encode() in output:
                    return
                if poll() is not None:
                    break
            raise AssertionError(f"missing {marker!r}\n{output.decode('utf-8', 'replace')}")

        try:
            wait_for("__LAZYCLASH_COMPLETION_READY__>")
            for typed, completed in (
                ("lazyclash --target alp", "lazyclash --target alpha "),
                ("lazyclash mode ru", "lazyclash mode rule "),
                ("lazyclash configs apply wo", "lazyclash configs apply work "),
                ("lazyclash diagnostics u", "lazyclash diagnostics url "),
            ):
                output.clear()
                os.write(master, typed.encode() + b"\t\x18\x07")
                wait_for("__BUFFER__" + completed + "__END__")
            os.write(master, b"\x15exit\r")
            deadline = time.monotonic() + 5
            while poll() is None and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.05)
                if ready:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        pass
            assert poll() == 0, output.decode("utf-8", "replace")
            print("zsh PTY completion passed: generated/install/status, target, mode, saved config and new command")
        finally:
            if poll() is None:
                os.killpg(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(master)


if __name__ == "__main__":
    main()
