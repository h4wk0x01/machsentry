"""Local CLI and JSON worker boundary. The output directory must be new."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

from . import __version__
from .metrics import peak_memory_bytes
from .render import function_assembly, markdown
from .service import analyze
from .source import AnalysisError, Limits, load_source, read_regular


def _write(path: Path, text: str):
    with path.open('x', encoding='utf-8', newline='\n') as output:
        output.write(text)


def publish(report: dict, data: bytes, output: Path) -> dict:
    try:
        output.mkdir(parents=True, exist_ok=False)
        assembly, truncated = function_assembly(data, report)
        report['coverage']['assembly_export'] = {"truncated": truncated, "max_bytes": 2 * 1024 * 1024}
        exports = {'functions.asm.txt': assembly}
        if report['yara']['rule'] is not None:
            filename = 'candidate-rejected.yar.txt' if report['yara']['status'] in ('rejected', 'related_samples_missed') else 'detection.yar'
            exports[filename] = report['yara']['rule']
        for index, script in enumerate(report['scripts']):
            exports[f'script-{index:03d}.txt'] = script['content']
        for filename, text in exports.items():
            _write(output / filename, text)
        # Report is the completion record and is written after evidence exports.
        report['exports'] = {name: {"sha256": sha256(text.encode()).hexdigest(), "size_bytes": len(text.encode())}
                             for name, text in exports.items()}
        _write(output / 'report.md', markdown(report))
        _write(output / '.report.json.pending', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        (output / '.report.json.pending').rename(output / 'report.json')
        return {"report": str((output / 'report.json').absolute()),
                "markdown": str((output / 'report.md').absolute()), "directory": str(output.absolute())}
    except OSError as error:
        raise AnalysisError('output_error', f'{error}; incomplete outputs, if any, retained at {output}') from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='facemessenger', description='Offline static Mach-O malware triage')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('analyze')
    command.add_argument('path', type=Path)
    command.add_argument('--member', help='Exact ZIP member; decoded in memory, never extracted')
    command.add_argument('--zip-password', help='Password for the explicitly selected ZIP member')
    command.add_argument('--output', type=Path, required=True, help='New output directory (no overwrites)')
    command.add_argument('--benign-file', type=Path, action='append', default=[], help='Explicit negative-corpus file; repeatable')
    command.add_argument('--related-file', type=Path, action='append', default=[], help='Explicit related positive specimen; repeatable, never executed')
    command.add_argument('--yara-mode', choices=('auto', 'hybrid', 'strings', 'opcodes'), default='auto',
                         help='auto uses hybrid strings+instructions when sufficient; explicit modes never silently fall back')
    command.add_argument('--json', action='store_true', help='Return the complete Result/report envelope on stdout')
    args = parser.parse_args(argv)
    started, cpu_started = time.perf_counter(), time.process_time()
    try:
        if args.output.exists():
            raise AnalysisError('output_exists', 'Output directory already exists; select a new run directory')
        limits = Limits()
        if len(args.benign_file) + len(args.related_file) > 128:
            raise AnalysisError('resource_limit', 'Validation corpora exceed 128 explicit files')
        negatives, related, retained = [], [], 0
        for paths, destination in ((args.benign_file, negatives), (args.related_file, related)):
            for path in paths:
                blob = read_regular(path, min(limits.max_file_bytes, 64 * 1024 * 1024 - retained))
                destination.append((str(path.absolute()), blob))
                retained += len(blob)
        source = load_source(args.path, limits, args.member, args.zip_password)
        report = analyze(source, limits, negatives, args.yara_mode, related)
        report['metrics'].update({"worker_elapsed_before_publication_seconds": round(time.perf_counter() - started, 6),
            "worker_cpu_before_publication_seconds": round(time.process_time() - cpu_started, 6),
            "process_family_peak_memory_bytes": peak_memory_bytes(), "child_processes": 0,
            "runtime_llm_tokens": 0, "unmeasured": ["agent development tokens", "Python interpreter startup", "publication cost"]})
        outputs = publish(report, source.data, args.output)
        value = report if args.json else {"artifact": report['artifact'], "risk": report['risk'],
            "function_count": len(report['functions']), "script_count": len(report['scripts']),
            "yara_status": report['yara']['status'], "metrics": report['metrics']}
        print(json.dumps({"ok": True, "value": value, "outputs": outputs}, ensure_ascii=True))
        return 0
    except AnalysisError as error:
        print(json.dumps({"ok": False, "error": error.as_dict()}, ensure_ascii=True))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"ok": False, "error": {"code": "cancelled", "message": "Interrupted; any partial output remains owned by this run"}}))
        return 130
    except Exception as error:
        # Native parser/library exceptions are failures, never clean verdicts.
        print(json.dumps({"ok": False, "error": {"code": "analysis_failed", "message": str(error)}}, ensure_ascii=True))
        return 3
