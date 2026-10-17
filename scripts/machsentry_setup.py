#!/usr/bin/env python3
"""Explicit, project-local setup; archives and their original licenses stay in .tools."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / ".tools"
LOCK_PATH = Path(__file__).with_name("machsentry-runtime.lock.json")


def host_key() -> str:
    architecture = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    if sys.platform == "darwin" and architecture == "x64":
        probe = subprocess.run(["/usr/sbin/sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip() == "1":
            raise RuntimeError("Run setup with a native arm64 Python, outside Rosetta.")
    key = f"{sys.platform}-{architecture}"
    if key not in {"win32-x64", "darwin-x64", "darwin-arm64"}:
        raise RuntimeError(f"Managed setup does not support {key}; configure REA runtimes manually.")
    return key


def digest_file(path: Path, algorithm: str) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def validate_archive(path: Path, asset: dict) -> None:
    algorithm = "sha256" if "sha256" in asset else "sha512"
    if "size" in asset and path.stat().st_size != asset["size"]:
        raise RuntimeError(f"Archive size mismatch: {path.name}")
    if digest_file(path, algorithm) != asset[algorithm]:
        raise RuntimeError(f"Archive {algorithm} mismatch: {path.name}; refusing to install.")


def download(asset: dict, downloads: Path) -> Path:
    if urllib.parse.urlsplit(asset["url"]).scheme != "https":
        raise RuntimeError("Only HTTPS runtime archives are accepted.")
    downloads.mkdir(parents=True, exist_ok=True)
    target = downloads / Path(urllib.parse.urlsplit(asset["url"]).path).name
    if target.exists():
        validate_archive(target, asset)
        return target
    print(f"Downloading {target.name}", flush=True)
    temporary = target.with_name(target.name + f".{uuid.uuid4().hex}.part")
    try:
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "MachSentry-local-setup"})
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("xb") as stream:
            if urllib.parse.urlsplit(response.url).scheme != "https":
                raise RuntimeError("Runtime download redirected away from HTTPS.")
            shutil.copyfileobj(response, stream, 1024 * 1024)
        validate_archive(temporary, asset)
        temporary.replace(target)
        return target
    finally:
        temporary.unlink(missing_ok=True)


def member_path(destination: Path, name: str) -> Path:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
        raise RuntimeError(f"Unsafe archive member: {name}")
    target = destination.joinpath(*path.parts)
    if not target.resolve().is_relative_to(destination.resolve()):
        raise RuntimeError(f"Archive member escapes destination: {name}")
    return target


def extract_archive(archive: Path, destination: Path) -> None:
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as source:
            for member in source.infolist():
                target = member_path(destination, member.filename)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"ZIP symbolic link is not supported: {member.filename}")
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
                if os.name != "nt" and mode:
                    target.chmod((mode & 0o755) | 0o600)
    else:
        with tarfile.open(archive) as source:
            for member in source.getmembers():
                member_path(destination, member.name)
            source.extractall(destination, filter="data")


def asset_stamp(asset: dict) -> dict:
    return {key: asset[key] for key in ("url", "sha256", "sha512") if key in asset}


def install_asset(asset: dict, name: str, tools: Path = TOOLS) -> Path:
    destination = tools / name
    marker = destination / ".machsentry-asset.json"
    if destination.exists():
        if not marker.is_file() or json.loads(marker.read_text()) != asset_stamp(asset):
            raise RuntimeError(f"Existing runtime is not owned by this lock: {destination}")
        return destination
    archive = download(asset, tools / "downloads")
    stage = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=tools))
    try:
        extract_archive(archive, stage)
        (stage / marker.name).write_text(json.dumps(asset_stamp(asset), indent=2) + "\n", encoding="utf-8")
        stage.rename(destination)
    finally:
        if stage.exists() and stage.resolve().is_relative_to(tools.resolve()):
            shutil.rmtree(stage)
    return destination


def unique_file(root: Path, pattern: str) -> Path:
    paths = [path for path in root.glob(pattern) if path.is_file()]
    if len(paths) != 1:
        raise RuntimeError(f"Expected exactly one {pattern} in {root}; found {len(paths)}.")
    return paths[0]


def native_decompiler(ghidra: Path, host: str, folder: str) -> None:
    filename = "decompile.exe" if host.startswith("win32") else "decompile"
    feature = ghidra / "Ghidra/Features/Decompiler"
    installed = feature / "os" / folder / filename
    built = feature / "build/os" / folder / filename
    if installed.is_file() or built.is_file():
        return
    if not host.startswith("darwin"):
        raise RuntimeError(f"The release lacks its native decompiler: {installed}")
    missing = [command for command in ("make", "clang++", "bison") if not shutil.which(command)]
    xcode = subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True, text=True)
    if missing or xcode.returncode != 0:
        raise RuntimeError("Ghidra's macOS decompiler needs existing Apple Command Line Tools (make, clang++, bison). Install them with xcode-select --install, then rerun setup.")
    architecture = "arm64" if host.endswith("arm64") else "x86_64"
    source = feature / "src/decompile/cpp"
    subprocess.run(["make", "ghidra_opt", f"ARCH_TYPE=-arch {architecture}", f"OSDIR={folder}", "ADDITIONAL_FLAGS=-w"], cwd=source, check=True)
    installed.parent.mkdir(parents=True, exist_ok=True)
    with (source / "ghidra_opt").open("rb") as stream, installed.open("xb") as output:
        shutil.copyfileobj(stream, output)
    installed.chmod(0o755)


def write_json_backed_up(path: Path, value: dict) -> None:
    text = json.dumps(value, indent=2) + "\n"
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + f".{uuid.uuid4().hex}.bak"))
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


@contextlib.contextmanager
def setup_lock(tools: Path):
    tools.mkdir(parents=True, exist_ok=True)
    with (tools / ".setup.lock").open("a+b") as stream:
        stream.seek(0)
        stream.write(b"\0")
        stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def runtime_environment(config: dict) -> dict:
    environment = dict(os.environ)
    for key, value in config["environment"].items():
        environment.setdefault(key, value)
    environment.setdefault("GHIDRA_HEADLESS_MAXMEM", "512M")
    environment["PATH"] = os.pathsep.join([str(TOOLS / "bin"), str(Path(config["executables"]["node"]).parent), str(Path(environment["JAVA_HOME"]) / "bin"), environment.get("PATH", "")])
    return environment


def write_npm_launcher(config: dict) -> None:
    directory = TOOLS / "bin"
    directory.mkdir(exist_ok=True)
    node = config["executables"]["node"]
    npm = config["executables"]["npm_cli"]
    if os.name == "nt":
        target = directory / "npm.cmd"
        relative_node = os.path.relpath(node, directory)
        relative_npm = os.path.relpath(npm, directory)
        content = f'@echo off\n"%~dp0{relative_node}" "%~dp0{relative_npm}" %*\n'
    else:
        target = directory / "npm"
        content = f'#!/bin/sh\nexec {shlex.quote(node)} {shlex.quote(npm)} "$@"\n'
    if target.exists() and target.read_text() == content:
        return
    if target.exists():
        shutil.copy2(target, target.with_name(target.name + f".{uuid.uuid4().hex}.bak"))
    target.write_text(content, encoding="utf-8", newline="\n")
    if os.name != "nt":
        target.chmod(0o755)


def install_windows_addon(lock: dict) -> None:
    asset = lock["windows_addon"]
    artifact = ROOT / "native/windows/build/rea-windows-x64.node"
    manifest = artifact.with_name("manifest.json")
    if artifact.is_file() and manifest.is_file() and digest_file(artifact, "sha256") == asset["addon_sha256"]:
        return
    package = install_asset(asset, "rea-native-package-6.5.0") / "package/native/windows/build"
    if digest_file(package / artifact.name, "sha256") != asset["addon_sha256"]:
        raise RuntimeError("Published REA Windows addon differs from the pinned artifact.")
    artifact.parent.mkdir(parents=True, exist_ok=True)
    for target in (artifact, manifest):
        source = package / target.name
        if target.exists():
            if target.read_bytes() == source.read_bytes():
                continue
            raise RuntimeError(f"Preserving existing native build: {target}; verify it or build REA from source.")
        with source.open("rb") as stream, target.open("xb") as output:
            shutil.copyfileobj(stream, output)


def install_runtimes(lock: dict, host: str) -> dict:
    selected = lock["platforms"][host]
    ghidra_root = install_asset(lock["ghidra"], "ghidra-" + lock["versions"]["ghidra"])
    jdk_root = install_asset(selected["jdk"], f"jdk-{host}-" + lock["versions"]["jdk"].replace("+", "-"))
    node_root = install_asset(selected["node"], f"node-{host}-" + lock["versions"]["node"])
    npm_root = install_asset(lock["npm"], "npm-" + lock["versions"]["npm"])
    ghidra = unique_file(ghidra_root, "*/Ghidra/application.properties").parent.parent
    java = unique_file(jdk_root, "*/bin/java.exe" if host.startswith("win32") else "*/Contents/Home/bin/java")
    node = unique_file(node_root, "*/node.exe" if host.startswith("win32") else "*/bin/node")
    npm = unique_file(npm_root, "package/bin/npm-cli.js")
    native_decompiler(ghidra, host, selected["decompiler_platform"])
    config = {
        "schema_version": 1,
        "host": dict(zip(("platform", "arch"), host.split("-", 1))),
        "executables": {"node": str(node), "npm_cli": str(npm)},
        "environment": {"GHIDRA_INSTALL_DIR": str(ghidra), "JAVA_HOME": str(java.parent.parent), "REA_ANALYSIS_PROVIDER": "ghidra"},
        "versions": lock["versions"],
    }
    write_npm_launcher(config)
    write_json_backed_up(TOOLS / "runtime.json", config)
    return config


def install_project(config: dict) -> None:
    environment = runtime_environment(config)
    node = config["executables"]["node"]
    npm = config["executables"]["npm_cli"]
    subprocess.run([node, npm, "ci"], cwd=ROOT, env=environment, check=True)
    subprocess.run([node, npm, "run", "build:cached"], cwd=ROOT, env=environment, check=True)
    venv = ROOT / ".venv-unpack"
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python.is_file():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    subprocess.run([str(python), "-m", "pip", "install", "-e", str(ROOT / "macos_static")], cwd=ROOT, check=True)
    diagnosis = subprocess.run([node, str(ROOT / "scripts/rea.mjs"), "doctor", "--provider", "ghidra", "--json"], cwd=ROOT, env=environment, capture_output=True, text=True, encoding="utf-8")
    try:
        report = json.loads(diagnosis.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"REA doctor returned no valid JSON (exit {diagnosis.returncode}): {diagnosis.stderr.strip()}") from error
    if diagnosis.returncode != 0 or report.get("healthy") is not True:
        failures = [check for check in report.get("scope_checks", []) if check.get("ok") is not True]
        raise RuntimeError("REA Ghidra readiness failed: " + json.dumps(failures or report))
    print("REA doctor: selected Ghidra provider is ready.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print selected pinned downloads and steps without writes.")
    parser.add_argument("--runtimes-only", action="store_true", help="Install runtimes without npm, Python package or REA build.")
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        raise RuntimeError("Python 3.12 or newer is required.")
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    host = host_key()
    print(f"MachSentry setup for {host}; all runtimes stay under {TOOLS}.", flush=True)
    print("Ghidra/JDK/Node/npm archives retain their bundled licenses. No global settings or security controls are changed.", flush=True)
    if args.dry_run:
        print(json.dumps({"versions": lock["versions"], "ghidra": lock["ghidra"], "npm": lock["npm"], "platform": lock["platforms"][host], "build_project": not args.runtimes_only}, indent=2))
        return 0
    with setup_lock(TOOLS):
        config = install_runtimes(lock, host)
        if not args.runtimes_only:
            if host == "win32-x64":
                install_windows_addon(lock)
            install_project(config)
    print(f"Runtime configuration: {TOOLS / 'runtime.json'}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Setup failed: {error}", file=sys.stderr)
        raise SystemExit(1)
