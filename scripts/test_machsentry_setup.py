from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import machsentry_setup as setup

CPYTHON_312 = (3, 12, 3, "final", 0)


def project_config(platform: str) -> dict:
    return {"host": {"platform": platform, "arch": "x64"}, "executables": {"node": "node", "npm_cli": "npm-cli.js"}, "environment": {"JAVA_HOME": "jdk"}}


class SetupTests(unittest.TestCase):
    def test_failed_doctor_preserves_the_provider_failure_reason(self):
        config = project_config("win32")
        report = {"healthy": False, "scope_checks": [{"name": "ghidra", "ok": False, "detail": "JDK version is unsupported"}]}
        def run(command, **kwargs):
            if "doctor" in command:
                return subprocess.CompletedProcess(command, 1, json.dumps(report), "")
            return subprocess.CompletedProcess(command, 0, "", "")
        with mock.patch.object(setup.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "JDK version is unsupported"):
                setup.install_project(config)

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
        for platform in ("win32", "darwin"):
            config = {"host": {"platform": platform, "arch": "x64"}, "executables": {"node": str(Path("node") / "node")}, "environment": {"JAVA_HOME": "bundled-jdk", "GHIDRA_INSTALL_DIR": "bundled-ghidra", "REA_ANALYSIS_PROVIDER": "ghidra"}}
            with self.subTest(platform=platform):
                with mock.patch.dict(os.environ, {"JAVA_HOME": "chosen-jdk", "GHIDRA_HEADLESS_MAXMEM": "768M"}, clear=True):
                    environment = setup.runtime_environment(config)
                    self.assertEqual(environment["JAVA_HOME"], "chosen-jdk")
                    self.assertEqual(environment["GHIDRA_HEADLESS_MAXMEM"], "768M")
                    self.assertEqual(environment["GHIDRA_INSTALL_DIR"], "bundled-ghidra")
                with mock.patch.dict(os.environ, {}, clear=True):
                    self.assertEqual(setup.runtime_environment(config)["GHIDRA_HEADLESS_MAXMEM"], "512M")

    def test_linux_runtime_environment_ignores_ambient_java_and_ghidra(self):
        config = {"host": {"platform": "linux", "arch": "x64"}, "executables": {"node": str(Path("node") / "node")}, "environment": {"JAVA_HOME": "bundled-jdk", "GHIDRA_INSTALL_DIR": "bundled-ghidra", "REA_ANALYSIS_PROVIDER": "ghidra"}}
        ambient = {"JAVA_HOME": "runner-jdk", "GHIDRA_INSTALL_DIR": "other-ghidra", "GHIDRA_HEADLESS_MAXMEM": "1536M", "REA_ANALYSIS_PROVIDER": "chosen-provider"}
        with mock.patch.dict(os.environ, ambient, clear=True):
            environment = setup.runtime_environment(config)
        self.assertEqual(environment["JAVA_HOME"], "bundled-jdk")
        self.assertEqual(environment["GHIDRA_INSTALL_DIR"], "bundled-ghidra")
        self.assertEqual(environment["GHIDRA_HEADLESS_MAXMEM"], "1536M")
        self.assertEqual(environment["REA_ANALYSIS_PROVIDER"], "chosen-provider")
        self.assertIn(str(Path("bundled-jdk") / "bin"), environment["PATH"].split(os.pathsep))
        self.assertNotIn(str(Path("runner-jdk") / "bin"), environment["PATH"].split(os.pathsep))

    def test_host_key_accepts_linux_x64_and_refuses_other_linux_architectures(self):
        with mock.patch.object(setup.sys, "platform", "linux"):
            with mock.patch.object(setup.platform, "machine", return_value="x86_64"):
                self.assertEqual(setup.host_key(), "linux-x64")
            with mock.patch.object(setup.platform, "machine", return_value="aarch64"):
                with self.assertRaisesRegex(RuntimeError, "does not support linux-arm64"):
                    setup.host_key()
        with mock.patch.object(setup.sys, "platform", "win32"), mock.patch.object(setup.platform, "machine", return_value="AMD64"):
            self.assertEqual(setup.host_key(), "win32-x64")

    def test_runtime_lock_pins_every_supported_host(self):
        lock = json.loads(setup.LOCK_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(lock["platforms"]), set(setup.SUPPORTED_HOSTS))
        for host, selected in lock["platforms"].items():
            with self.subTest(host=host):
                for name in ("jdk", "node"):
                    self.assertTrue(selected[name]["url"].startswith("https://"))
                    self.assertRegex(selected[name]["sha256"], r"^[0-9a-f]{64}$")
                self.assertIsInstance(selected["jdk"]["size"], int)
                self.assertTrue(selected["decompiler_platform"])
        linux = lock["platforms"]["linux-x64"]
        jdk = lock["versions"]["jdk"].replace("+", "_")
        self.assertTrue(linux["jdk"]["url"].endswith(f"/OpenJDK21U-jdk_x64_linux_hotspot_{jdk}.tar.gz"))
        self.assertTrue(linux["node"]["url"].endswith(f"/node-v{lock['versions']['node']}-linux-x64.tar.gz"))
        self.assertIsInstance(linux["node"]["size"], int)
        self.assertEqual(linux["decompiler_platform"], "linux_x86_64")

    def test_java_home_resolves_from_each_jdk_layout(self):
        layouts = {"win32-x64": "jdk-21/bin/java.exe", "darwin-arm64": "jdk-21/Contents/Home/bin/java", "linux-x64": "jdk-21/bin/java"}
        for host, executable in layouts.items():
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / executable).parent.mkdir(parents=True)
                (root / executable).write_bytes(b"")
                (root / ".machsentry-asset.json").write_text("{}")
                java = setup.unique_file(root, setup.java_pattern(host))
                self.assertEqual(java.parent.parent, (root / executable).parent.parent)
        self.assertEqual(setup.java_pattern("darwin-x64"), "*/Contents/Home/bin/java")

    def test_linux_preflight_requires_a_procps_listing_of_this_process(self):
        listing = f"    1     0     1     0 Ss   /sbin/init\n{os.getpid():>5}     1 {os.getpid():>5}  1000 S+   python3 scripts/machsentry_setup.py\n"
        cases = [
            (None, None, "procps"),
            ("/usr/bin/ps", subprocess.CompletedProcess([], 0, "    1     0     1     0 Ss   /sbin/init\n", ""), "must list this process"),
            ("/usr/bin/ps", subprocess.CompletedProcess([], 1, "", "ps: unknown option"), "procps"),
            ("/usr/bin/ps", subprocess.CompletedProcess([], 0, listing, ""), None),
        ]
        for executable, result, error in cases:
            with self.subTest(executable=executable, error=error):
                with mock.patch.object(setup.sys, "version_info", CPYTHON_312), mock.patch.object(setup.shutil, "which", return_value=executable), mock.patch.object(setup.subprocess, "run", return_value=result) as run:
                    if error is None:
                        setup.linux_preflight()
                        self.assertEqual(run.call_args.args[0], ["/usr/bin/ps", "-axo", "pid=,ppid=,pgid=,uid=,stat=,command="])
                    else:
                        with self.assertRaisesRegex(RuntimeError, error):
                            setup.linux_preflight()

    def test_linux_preflight_refuses_a_python_the_wheel_lock_does_not_cover(self):
        with mock.patch.object(setup.sys, "version_info", (3, 13, 1, "final", 0)), mock.patch.object(setup.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "CPython 3.12"):
                setup.linux_preflight()
            run.assert_not_called()

    def test_linux_preflight_runs_before_any_download_unless_runtimes_only(self):
        lock = json.loads(setup.LOCK_PATH.read_text(encoding="utf-8"))
        with mock.patch.object(setup, "host_key", return_value="linux-x64"), mock.patch.object(setup, "setup_lock", return_value=contextlib.nullcontext()), contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(setup, "linux_preflight", side_effect=RuntimeError("procps missing")), mock.patch.object(setup, "install_runtimes") as install:
                with mock.patch.object(sys, "argv", ["machsentry_setup.py"]), self.assertRaisesRegex(RuntimeError, "procps missing"):
                    setup.main()
                install.assert_not_called()
            with mock.patch.object(setup, "linux_preflight") as preflight, mock.patch.object(setup, "install_runtimes") as install:
                with mock.patch.object(sys, "argv", ["machsentry_setup.py", "--runtimes-only"]):
                    self.assertEqual(setup.main(), 0)
                preflight.assert_not_called()
                install.assert_called_once_with(lock, "linux-x64")

    def test_linux_project_install_uses_only_hashed_requirements(self):
        healthy = json.dumps({"healthy": True, "scope_checks": []})
        for platform in ("linux", "win32"):
            commands = []
            def run(command, **kwargs):
                commands.append(command)
                return subprocess.CompletedProcess(command, 0, healthy if "doctor" in command else "", "")
            with self.subTest(platform=platform), mock.patch.object(setup.subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                setup.install_project(project_config(platform))
                pip = [command[3:] for command in commands if command[1:3] == ["-m", "pip"]]
                if platform == "linux":
                    self.assertEqual(pip, [
                        ["install", "--require-hashes", "--only-binary=:all:", "--no-deps", "-r", str(setup.PYTHON_LINUX_LOCK)],
                        ["install", "--no-deps", "--no-build-isolation", "-e", str(setup.ROOT / "macos_static")],
                        ["check"],
                    ])
                else:
                    self.assertEqual(pip, [["install", "-e", str(setup.ROOT / "macos_static")]])

    def test_python_linux_lock_hashes_every_pinned_dependency(self):
        lines = [line for line in setup.PYTHON_LINUX_LOCK.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
        pins = {}
        for line in lines:
            match = re.fullmatch(r"([a-z0-9][a-z0-9-]*)==(\S+) --hash=sha256:[0-9a-f]{64}", line)
            self.assertIsNotNone(match, line)
            self.assertNotIn(match[1], pins)
            pins[match[1]] = match[2]
        project = tomllib.loads((setup.ROOT / "macos_static/pyproject.toml").read_text(encoding="utf-8"))
        for dependency in project["project"]["dependencies"]:
            name, version = dependency.split("==")
            self.assertEqual(pins.get(name.lower()), version, dependency)
        self.assertEqual(project["build-system"]["requires"], ["setuptools>=77"])
        self.assertGreaterEqual(int(pins["setuptools"].split(".")[0]), 77)


if __name__ == "__main__":
    unittest.main()
