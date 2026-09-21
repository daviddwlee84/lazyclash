import hashlib
import io
import json
import subprocess
from unittest import mock
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

import release


class FakeRemote:
    def __init__(self, files=None, draft=True, exists=True):
        self.files = files or {}
        self.draft = draft
        self.exists = exists
        self.uploaded = []
        self.published = False

    def release(self, tag):
        if not self.exists:
            return None
        return {"draft": self.draft, "prerelease": False, "assets": [{"name": name} for name in self.files]}

    def create(self, tag):
        self.exists = True

    def asset_digest(self, tag, name):
        return hashlib.sha256(self.files[name]).hexdigest()

    def upload(self, tag, path):
        assert path.name not in self.files
        self.files[path.name] = path.read_bytes()
        self.uploaded.append(path.name)

    def publish(self, tag):
        self.draft = False
        self.published = True


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def assets(self):
        paths = {}
        for name in ("one.tar.gz", "two.tar.gz", "checksums.txt"):
            paths[name] = self.root / name
            paths[name].write_bytes(name.encode())
        return paths

    def test_resume_draft_and_idempotent_public_release(self):
        assets = self.assets()
        remote = FakeRemote({"one.tar.gz": assets["one.tar.gz"].read_bytes()})
        release.publish_complete(remote, "v0.1.0", assets)
        self.assertTrue(remote.published)
        self.assertEqual(set(remote.uploaded), {"two.tar.gz", "checksums.txt"})
        remote.published = False
        remote.uploaded.clear()
        release.publish_complete(remote, "v0.1.0", assets)
        self.assertFalse(remote.published)
        self.assertEqual(remote.uploaded, [])

    def test_different_existing_bytes_are_never_overwritten(self):
        remote = FakeRemote({"one.tar.gz": b"different"})
        with self.assertRaisesRegex(ValueError, "refusing to replace"):
            release.publish_complete(remote, "v0.1.0", self.assets())
        self.assertEqual(remote.uploaded, [])
        self.assertFalse(remote.published)

    def test_incomplete_public_release_is_not_mutated(self):
        remote = FakeRemote({"one.tar.gz": b"one.tar.gz"}, draft=False)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            release.publish_complete(remote, "v0.1.0", self.assets())
        self.assertEqual(remote.uploaded, [])

    def fixture_dist(self):
        rows = []
        for os_name, arch in release.TARGETS:
            name = f"example_0.1.0_{os_name}_{arch}.tar.gz"
            if os_name == "linux":
                binary = bytearray(20)
                binary[:6] = b"\x7fELF\x02\x01"
                struct.pack_into("<H", binary, 18, {"amd64": 62, "arm64": 183}[arch])
            else:
                binary = bytearray(b"\xcf\xfa\xed\xfe" + b"\0" * 4)
                struct.pack_into("<I", binary, 4, {"amd64": 0x01000007, "arm64": 0x0100000C}[arch])
            with tarfile.open(self.root / name, "w:gz") as archive:
                for path, data in {"example": bytes(binary), "LICENSE": b"MIT", "completions/example.bash": b"bash", "completions/example.zsh": b"zsh"}.items():
                    info = tarfile.TarInfo(path)
                    info.size = len(data)
                    info.mode = 0o755 if path == "example" else 0o644
                    archive.addfile(info, io.BytesIO(data))
            rows.append(f"{release.digest(self.root / name)}  {name}")
        (self.root / "checksums.txt").write_text("\n".join(rows) + "\n")

    def test_archive_contract_and_checksum_failure(self):
        self.fixture_dist()
        self.assertEqual(len(release.verify_dist(self.root, "example", "example", "0.1.0")), 5)
        (self.root / "example_0.1.0_linux_amd64.tar.gz").write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release.verify_dist(self.root, "example", "example", "0.1.0")

    def test_missing_platform_is_rejected(self):
        self.fixture_dist()
        lines = (self.root / "checksums.txt").read_text().splitlines()
        (self.root / "checksums.txt").write_text("\n".join(lines[:-1]) + "\n")
        with self.assertRaisesRegex(ValueError, "exactly the four"):
            release.verify_dist(self.root, "example", "example", "0.1.0")


class GitHubAPITests(unittest.TestCase):
    def lookup(self, pages):
        missing = subprocess.CompletedProcess([], 1, "", "gh: Not Found (HTTP 404)")
        with mock.patch("release.subprocess.run", return_value=missing), mock.patch(
            "release.subprocess.check_output", return_value=json.dumps(pages)
        ) as request:
            result = release.GitHub("example/tool").release("v0.1.0")
            request.assert_called_once_with(
                ["gh", "api", "--paginate", "--slurp", "repos/example/tool/releases?per_page=100"], text=True)
            return result

    def test_tag_endpoint_404_finds_draft_on_later_page(self):
        draft = {"id": 392759439, "tag_name": "v0.1.0", "draft": True, "prerelease": False, "assets": []}
        self.assertEqual(self.lookup([[{"id": 1, "tag_name": "v0.0.9"}], [draft]]), draft)

    def test_absent_tag_after_full_listing(self):
        self.assertIsNone(self.lookup([[]]))

    def test_ambiguous_draft_listing_is_not_selected_or_recreated(self):
        with self.assertRaisesRegex(RuntimeError, "multiple releases"):
            self.lookup([[{"id": 1, "tag_name": "v0.1.0"}], [{"id": 2, "tag_name": "v0.1.0"}]])

    def test_published_tag_lookup_does_not_enumerate(self):
        public = {"tag_name": "v0.1.0", "draft": False, "prerelease": False, "assets": []}
        result = subprocess.CompletedProcess([], 0, json.dumps(public), "")
        with mock.patch("release.subprocess.run", return_value=result), mock.patch("release.subprocess.check_output") as pages:
            self.assertEqual(release.GitHub("example/tool").release("v0.1.0"), public)
            pages.assert_not_called()

    def test_non_404_error_is_not_absence(self):
        result = subprocess.CompletedProcess([], 1, "", "gh: Forbidden (HTTP 403)")
        with mock.patch("release.subprocess.run", return_value=result), mock.patch("release.subprocess.check_output") as pages:
            with self.assertRaisesRegex(RuntimeError, "cannot inspect"):
                release.GitHub("example/tool").release("v0.1.0")
            pages.assert_not_called()


if __name__ == "__main__":
    unittest.main()
