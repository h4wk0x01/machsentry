"""Local CLI and JSON worker boundary. The output directory must be new."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

from . import __version__
from .analyst_view import analyst_view
from .detection import rule_export_name
from .html_report import html_report
from .metrics import peak_memory_bytes
from .report_schema import SCHEMA
from .render import function_assembly, markdown
from .rea_client import ReaOptions
from .service import analyze
from .source import AnalysisError, Limits, load_source, read_regular


def _write(path: Path, text: str):
    with path.open('x', encoding='utf-8', newline='\n') as output:
        output.write(text)


def publish(report: dict, data: bytes, output: Path, brand: str = 'machsentry') -> dict:
    try:
        output.mkdir(parents=True, exist_ok=False)
        assembly, truncated = function_assembly(data, report)
        report['coverage']['assembly_export'] = {"truncated": truncated, "max_bytes": 2 * 1024 * 1024}
        exports = {'functions.asm.txt': assembly}
        for index, function in enumerate(report['functions']):
            if function.get('pseudocode'):
                exports[f'function-{index:03d}-{function["architecture"]}.pseudo.c.txt'] = function['pseudocode']
        evidence = {record['evidence_id']: record for record in report.get('rea', {}).get('records', [])}
        for index, bundle in enumerate(report.get('rea', {}).get('evidence_bundles', [])):
            complete = {key: value for key, value in bundle.items() if key != 'record_ids'}
            complete['records'] = [evidence[identifier] for identifier in bundle['record_ids']]
            exports[f'rea-evidence-{index:03d}.json'] = json.dumps(complete, ensure_ascii=False, indent=2) + '\n'
        filename = rule_export_name(report['yara'], report['analysis_status'])
        if filename is not None:
            exports[filename] = report['yara']['rule']
        for index, script in enumerate(report['scripts']):
            exports[f'script-{index:03d}.txt'] = script['content']
        view = analyst_view(report)
        exports['report.html'] = html_report(view, brand)
        exports['report-view.json'] = json.dumps(view, ensure_ascii=False, indent=2) + '\n'
        exports['report-view.schema.json'] = json.dumps(SCHEMA, ensure_ascii=False, indent=2) + '\n'
        report['presentation'] = {'schema_version': '1.0', 'html': 'report.html', 'data': 'report-view.json',
                                  'schema': 'report-view.schema.json'}
        for filename, text in exports.items():
            _write(output / filename, text)
        # Report is the completion record and is written after evidence exports.
        report['exports'] = {name: {"sha256": sha256(text.encode()).hexdigest(), "size_bytes": len(text.encode())}
                             for name, text in exports.items()}
        _write(output / 'report.md', markdown(report))
        _write(output / '.report.json.pending', json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        (output / '.report.json.pending').rename(output / 'report.json')
        return {"report": str((output / 'report.json').absolute()),
                "html": str((output / 'report.html').absolute()),
                "view": str((output / 'report-view.json').absolute()),
                "markdown": str((output / 'report.md').absolute()), "directory": str(output.absolute())}
    except OSError as error:
        raise AnalysisError('output_error', f'{error}; incomplete outputs, if any, retained at {output}') from error


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='machsentry', description='Static Mach-O malware reports using REA/Ghidra MCP')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('analyze')
    command.add_argument('path', type=Path)
    command.add_argument('--member', help='Exact ZIP member; staged in an owned temporary file for static REA import')
    command.add_argument('--zip-password', help='Password for the explicitly selected ZIP member')
    command.add_argument('--output', type=Path, required=True, help='New output directory (no overwrites)')
    command.add_argument('--benign-file', type=Path, action='append', default=[], help='Explicit negative-corpus file; repeatable')
    command.add_argument('--related-file', type=Path, action='append', default=[], help='Explicit related positive specimen; repeatable, never executed')
    command.add_argument('--yara-mode', choices=('auto', 'hybrid', 'strings', 'opcodes'), default='auto',
                         help='auto uses hybrid strings+instructions when sufficient; explicit modes never silently fall back')
    command.add_argument('--json', action='store_true', help='Return the complete Result/report envelope on stdout')
    command.add_argument('--rea-root', type=Path, help='Built REA checkout (default: this repository)')
    command.add_argument('--rea-node', help='Explicit Node executable for the REA MCP server')
    command.add_argument('--architecture', choices=('x86_64', 'arm64', 'x86', 'arm'), help='Analyze only this exact REA-reported slice')
    command.add_argument('--max-functions', type=int, default=64, help='Per-slice decompiler work budget; omitted functions stay unknown')
    command.add_argument('--rea-timeout', type=float, default=900, help='Seconds per REA request including initial Ghidra import')
    command.add_argument('--report-brand', choices=('machsentry', 'unpacked'), default='machsentry',
                         help='Product name in the HTML report header, title and footer; the analysis is unchanged')
    args = parser.parse_args(argv)
    started, cpu_started = time.perf_counter(), time.process_time()
    try:
        if args.output.exists():
            raise AnalysisError('output_exists', 'Output directory already exists; select a new run directory')
        if args.max_functions < 1 or args.rea_timeout <= 0:
            raise AnalysisError('invalid_input', '--max-functions and --rea-timeout must be positive')
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
        report = analyze(source, limits, negatives, args.yara_mode, related,
                         ReaOptions(root=args.rea_root, node=args.rea_node, architecture=args.architecture,
                                    request_timeout_seconds=args.rea_timeout, max_decompiled_functions=args.max_functions))
        report['metrics'].update({"worker_elapsed_before_publication_seconds": round(time.perf_counter() - started, 6),
            "worker_cpu_before_publication_seconds": round(time.process_time() - cpu_started, 6),
            "python_peak_memory_bytes": peak_memory_bytes(),
            "runtime_llm_tokens": 0})
        outputs = publish(report, source.data, args.output, args.report_brand)
        if report['analysis_status'] == 'failed':
            print(json.dumps({'ok': False, 'error': report.get('error', {'code': 'rea_analysis_failed',
                'message': 'REA/Ghidra analysis or owned cleanup failed; retained evidence is in the report'}),
                'outputs': outputs, **({'partial_report': report} if args.json else {})}, ensure_ascii=True))
            return 2
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
