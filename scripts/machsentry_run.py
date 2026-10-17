#!/usr/bin/env python3
"""Run MachSentry or the official REA CLI with the project-local runtimes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from machsentry_setup import ROOT, TOOLS, host_key, runtime_environment


def main() -> int:
    manifest = TOOLS / "runtime.json"
    if not manifest.is_file():
        raise RuntimeError("Run python scripts/machsentry_setup.py first.")
    config = json.loads(manifest.read_text(encoding="utf-8"))
    host = config.get("host", {})
    if config.get("schema_version") != 1 or f"{host.get('platform')}-{host.get('arch')}" != host_key():
        raise RuntimeError("Runtime configuration belongs to another host; rerun setup on this machine.")
    arguments = sys.argv[1:]
    if arguments[:1] == ["rea"]:
        command = [config["executables"]["node"], str(ROOT / "scripts/rea.mjs"), *arguments[1:]]
    else:
        python = ROOT / ".venv-unpack" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        command = [str(python), "-m", "machsentry", *arguments]
    return subprocess.call(command, env=runtime_environment(config))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"MachSentry launch failed: {error}", file=sys.stderr)
        raise SystemExit(1)
