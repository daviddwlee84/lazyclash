# /// script
# requires-python = ">=3.10"
# dependencies = ["pyte==0.8.2"]
# ///
"""Exercise Azure/AWS wizard selection and reviewed Lightsail cancellation.

Run after building bin/lazyclash:
    uv run scripts/pty_cloud_vps_smoke.py
Only disposable local files and a strict mock cloud CLI are used.
"""

import codecs
import fcntl
import json
import os
from pathlib import Path
import pty
import struct
import subprocess
import sys
import tempfile
import termios

import pyte

from pty_smoke import ROOT, Terminal


class CloudTerminal(Terminal):
    def __init__(self, settings, env, args):
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
             '"$@"; result=$?; printf "\\n__LAZYCLASH_EXIT_%s__\\n" "$result"; '
             'IFS= read -r line; printf "__ECHO_%s__\\n" "$line"; exit "$result"',
             "cloud-pty-wrapper", str(ROOT / "bin/lazyclash"), "--config", str(settings), *args],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env=env, preexec_fn=child_terminal, close_fds=True,
        )

    def finish_cancel(self):
        self.wait(lambda: "__LAZYCLASH_EXIT_130__" in self.text(), "cancellation exit")
        restored = termios.tcgetattr(self.slave)
        for flag in (termios.ECHO, termios.ICANON):
            assert (restored[3] & flag) == (self.original[3] & flag), "terminal mode not restored"
        assert (restored[0] & termios.IXON) == (self.original[0] & termios.IXON), "flow control not restored"
        self.send("cloud-echo-restored\n")
        self.process.wait(timeout=5)
        assert self.process.returncode == 130, self.text()


MOCK_AWS = r'''
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with Path(os.environ["MOCK_CLOUD_CALLS"]).open("a") as calls:
    calls.write(json.dumps(args) + "\n")
def has(*words):
    return any(args[i:i+len(words)] == list(words) for i in range(len(args)))
if has("sts", "get-caller-identity"):
    value = {"Account":"123456789012", "Arn":"arn:aws:iam::123456789012:user/fixture", "UserId":"fixture"}
elif has("lightsail", "get-regions"):
    value = {"regions":[{"name":"us-east-1", "displayName":"Fixture region", "availabilityZones":[{"zoneName":"us-east-1a", "state":"available"}]}]}
elif has("lightsail", "get-bundles"):
    value = {"bundles":[{"bundleId":"small_3_0", "name":"Small", "instanceType":"t3.micro", "price":7, "cpuCount":2, "ramSizeInGb":1, "diskSizeInGb":40, "transferPerMonthInGb":2048, "isActive":True, "supportedPlatforms":["LINUX_UNIX"], "supportedAppCategories":["LfR"], "power":500, "publicIpv4AddressCount":1}]}
elif has("lightsail", "get-blueprints"):
    value = {"blueprints":[{"blueprintId":"ubuntu_24_04", "name":"Ubuntu", "group":"ubuntu", "version":"24.04", "versionCode":"1", "platform":"LINUX_UNIX", "type":"os", "isActive":True, "minPower":0}]}
else:
    raise SystemExit("mock forbids unknown or mutating cloud command: " + json.dumps(args))
print(json.dumps(value))
'''


def main():
    terminal = None
    try:
        with tempfile.TemporaryDirectory(prefix="lazyclash-cloud-pty-") as scratch:
            base = Path(scratch)
            settings = base / "config.toml"
            settings.write_text("")
            inventory = base / "servers.toml"
            inventory.write_text("version = 1\n")
            before = inventory.read_bytes()
            key = base / "fixture.pub"
            key.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFB0eUZhY2xlUGJHdXZYaXV5SlVBM0VLR2doZEM2Sm1ScVg1WGM fixture\n")
            mock_bin = base / "mock-bin"
            mock_bin.mkdir()
            for name in ("aws", "az"):
                path = mock_bin / name
                path.write_text(f"#!{sys.executable}\n" + MOCK_AWS)
                path.chmod(0o755)
            calls = base / "cloud-calls.jsonl"
            env = dict(os.environ)
            for name in list(env):
                if name.startswith(("AWS_", "AZURE_", "LAZYCLASH_")) or name in ("CLASH_CONTROLLER", "CLASH_SECRET"):
                    env.pop(name, None)
            env.update(HOME=scratch, XDG_CONFIG_HOME=scratch, XDG_STATE_HOME=str(base / "state"),
                       LAZYCLASH_SERVERS_CONFIG=str(inventory), TERM="xterm-256color", NO_COLOR="1",
                       PATH=str(mock_bin) + os.pathsep + env.get("PATH", ""), MOCK_CLOUD_CALLS=str(calls))

            for provider in ("azure", "aws-lightsail", "aws-ec2"):
                terminal = CloudTerminal(settings, env, ["vps", "create"])
                terminal.wait(lambda: "VPS provider" in terminal.text(), "provider picker")
                terminal.send("/" + provider + "\r\r")
                terminal.wait(lambda: "Create " + provider + " VPS" in terminal.text(), "selected cloud form")
                terminal.send("jkhql/?")
                terminal.wait(lambda: "jkhql/?" in terminal.text(), "input owns navigation and quit keys")
                terminal.resize(36, 12)
                assert terminal.process.poll() is None, "narrow cloud form crashed"
                terminal.resize(120, 32)
                terminal.send("\x1b")
                terminal.finish_cancel()
                terminal.close()
                terminal = None
            assert not calls.exists(), "canceled provider selection contacted a cloud API"

            args = ["vps", "create", "fixture-lightsail", "--provider", "aws-lightsail", "--profile", "fixture",
                    "--region", "us-east-1", "--plan", "small_3_0", "--image", "ubuntu_24_04",
                    "--architecture", "amd64", "--availability-zone", "us-east-1a", "--ssh-key", str(key), "--interactive"]
            terminal = CloudTerminal(settings, env, args)
            terminal.wait(lambda: "Create aws-lightsail VPS" in terminal.text(), "prefilled Lightsail form")
            terminal.send("\x13")
            terminal.wait(lambda: "Review new cloud VM" in terminal.text(), "cost and account preview", timeout=15)
            assert calls.exists(), "review did not consult the provider fixture"
            terminal.send("\r")
            terminal.finish_cancel()
            terminal.close()
            terminal = None
            assert inventory.read_bytes() == before, "canceled cloud review modified inventory"
            assert not list((base / "state").rglob("*.json")), "canceled review created operation journals"
            recorded = [json.loads(line) for line in calls.read_text().splitlines()]
            assert recorded and all(not any(word.startswith(("create-", "allocate-", "attach-", "delete-")) for word in call) for call in recorded)
            print("PTY PASS: Azure/Lightsail/EC2 picker, prefilled cloud form, text ownership, narrow resize, Ctrl+S review, strict read-only mock calls, default-cancel review, unchanged inventory/state, terminal restoration")
    finally:
        if terminal:
            terminal.close()


if __name__ == "__main__":
    main()
