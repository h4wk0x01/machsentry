from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import machsentry_setup as setup


class SetupTests(unittest.TestCase):
    def test_corrupt_cached_download_is_refused_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive.zip"
            path.write_bytes(b"changed")
            asset = {"url": "https://example.invalid/archive.zip", "sha256": hashlib.sha256(b"expected").hexdigest()}
            with mock.patch.object(setup.urllib.request, "urlopen") as fetch:
                with self.assertRaisesRegex(RuntimeError, "mismatch"):
                    setup.download(asset, Path(directory))
                fetch.assert_not_called()

    def test_zip_traversal_and_symbolic_links_are_refused(self):
        for name, symlink in [("../outside", False), ("/absolute", False), ("C:/drive", False), ("link", True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "archive.zip"
                with zipfile.ZipFile(archive, "w") as output:
                    member = zipfile.ZipInfo(name)
                    if symlink:
                        member.external_attr = (stat.S_IFLNK | 0o777) << 16
                    output.writestr(member, b"outside")
                destination = Path(directory) / "runtime"
                destination.mkdir()
                with self.assertRaises(RuntimeError):
                    setup.extract_archive(archive, destination)
                self.assertFalse((Path(directory) / "outside").exists())
        with self.assertRaises(RuntimeError):
            setup.member_path(Path.cwd(), "dir\\escape")

    def test_tar_link_outside_installation_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "archive.tgz"
            with tarfile.open(archive, "w:gz") as output:
                member = tarfile.TarInfo("link")
                member.type = tarfile.SYMTYPE
                member.linkname = "../outside"
                output.addfile(member)
            destination = Path(directory) / "runtime"
            destination.mkdir()
            with self.assertRaises(tarfile.FilterError):
                setup.extract_archive(archive, destination)

    def test_install_is_idempotent_and_preserves_existing_unowned_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory)
            downloads = tools / "downloads"
            downloads.mkdir()
            archive = downloads / "archive.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("runtime/LICENSE", "license retained")
            asset = {"url": "https://example.invalid/archive.zip", "sha256": setup.digest_file(archive, "sha256")}
            installed = setup.install_asset(asset, "owned", tools)
            marker_time = (installed / ".machsentry-asset.json").stat().st_mtime_ns
            self.assertEqual(setup.install_asset(asset, "owned", tools), installed)
            self.assertEqual((installed / ".machsentry-asset.json").stat().st_mtime_ns, marker_time)
            self.assertEqual((installed / "runtime/LICENSE").read_text(), "license retained")
            existing = tools / "unowned"
            existing.mkdir()
            with self.assertRaisesRegex(RuntimeError, "not owned"):
                setup.install_asset(asset, "unowned", tools)
            self.assertTrue(existing.exists())

    def test_configuration_backup_only_when_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "runtime.json"
            setup.write_json_backed_up(target, {"version": 1})
            stamp = target.stat().st_mtime_ns
            setup.write_json_backed_up(target, {"version": 1})
            self.assertEqual(target.stat().st_mtime_ns, stamp)
            self.assertEqual(list(target.parent.glob("*.bak")), [])
            setup.write_json_backed_up(target, {"version": 2})
            backups = list(target.parent.glob("*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(json.loads(backups[0].read_text()), {"version": 1})

    def test_launcher_preserves_caller_environment_and_sets_only_missing_defaults(self):
        config = {"executables": {"node": str(Path("node") / "node")}, "environment": {"JAVA_HOME": "bundled-jdk", "GHIDRA_INSTALL_DIR": "bundled-ghidra", "REA_ANALYSIS_PROVIDER": "ghidra"}}
        with mock.patch.dict(os.environ, {"JAVA_HOME": "chosen-jdk", "GHIDRA_HEADLESS_MAXMEM": "768M"}, clear=True):
            environment = setup.runtime_environment(config)
            self.assertEqual(environment["JAVA_HOME"], "chosen-jdk")
            self.assertEqual(environment["GHIDRA_HEADLESS_MAXMEM"], "768M")
            self.assertEqual(environment["GHIDRA_INSTALL_DIR"], "bundled-ghidra")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(setup.runtime_environment(config)["GHIDRA_HEADLESS_MAXMEM"], "512M")


if __name__ == "__main__":
    unittest.main()
