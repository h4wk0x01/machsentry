#!/usr/bin/env python3
"""Real REA CLI decompilation of encoded, inert Mach-O fixtures; never runs them."""

import argparse
from hashlib import sha256
import json
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def verify_report_pipeline(output: Path, environment: dict, architectures: list[str]) -> dict:
    """Import and decompile inert pointer-return functions containing test literals."""
    spec = importlib.util.spec_from_file_location('machsentry_verification_fixtures', ROOT / 'macos_static/tests/fixtures.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Fixture source is unavailable in this checkout')
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    source = (output / 'inert-behavior-universal.macho').resolve()
    source.write_bytes(fixtures.universal_fixture())
    negatives = []
    for architecture in ('x86_64', 'arm64'):
        path = (output / f'negative-{architecture}.macho').resolve()
        path.write_bytes(fixture(architecture))
        negatives.append(path)
    before = {str(path): sha256(path.read_bytes()).hexdigest() for path in [source, *negatives]}
    destination = (output / 'mcp-report').resolve()
    command = [sys.executable, str(ROOT / 'scripts/machsentry_run.py'), 'analyze', str(source), '--output', str(destination)]
    if len(architectures) == 1:
        command.extend(['--architecture', architectures[0]])
    for negative in negatives:
        command.extend(['--benign-file', str(negative)])
    started = time.perf_counter()
    run = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, encoding='utf-8', timeout=1800)
    (output / 'mcp-report.stdout.json').write_text(run.stdout, encoding='utf-8')
    (output / 'mcp-report.stderr.txt').write_text(run.stderr, encoding='utf-8')
    envelope = json.loads(run.stdout) if run.stdout.strip() else {}
    report_path = destination / 'report.json'
    report = json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else {}
    selected = [item for item in report.get('slices', []) if item.get('status') == 'analyzed']
    functions = report.get('functions', [])
    evidence = {item['evidence_id']: item for item in report.get('rea', {}).get('records', [])}
    validation = report.get('yara', {}).get('validation') or {}
    verified = (run.returncode == 0 and envelope.get('ok') is True and report.get('schema_version') == '2.0'
                and {item['architecture'] for item in selected} == set(architectures)
                and len(functions) == 4 * len(architectures)
                and report.get('risk', {}).get('verdict') == 'high_risk_indicators'
                and report.get('risk', {}).get('maliciousness') == 'unconfirmed'
                and all(item.get('pseudocode') and evidence.get(item.get('rea_evidence_id'), {}).get('provider', {}).get('id') == 'ghidra'
                        for item in functions)
                and report.get('rea', {}).get('closure_confirmed') is True
                and not report.get('rea', {}).get('errors')
                and all(item['confirmed'] for item in report.get('rea', {}).get('staging_cleanup', []))
                and validation.get('compiled') is True and validation.get('sample_matched') is True
                and validation.get('negative_count') == 2 and validation.get('negative_matches') == 0
                and report.get('yara', {}).get('effective_mode') == 'hybrid')
    yara_check = {}
    if verified:
        python = ROOT / '.venv-unpack' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        script = ('import json,sys,yara; rules=yara.compile(filepath=sys.argv[1]); '
                  'print(json.dumps({"positive":bool(rules.match(filepath=sys.argv[2])), '
                  '"negatives":[bool(rules.match(filepath=p)) for p in sys.argv[3:]]}))')
        checked = subprocess.run([str(python), '-c', script, str(destination / 'detection.yar'), str(source), *map(str, negatives)],
                                 cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=30)
        (output / 'yara-check.stdout.json').write_text(checked.stdout, encoding='utf-8')
        (output / 'yara-check.stderr.txt').write_text(checked.stderr, encoding='utf-8')
        yara_check = json.loads(checked.stdout) if checked.returncode == 0 else {}
        verified = checked.returncode == 0 and yara_check == {'positive': True, 'negatives': [False, False]}
    unchanged = all(sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in before.items())
    return {'workflow': 'MachSentry via real REA MCP / Ghidra', 'exit_code': run.returncode,
            'elapsed_seconds': round(time.perf_counter() - started, 3), 'source_hashes': before,
            'sources_unchanged': unchanged, 'analyzed_architectures': [item['architecture'] for item in selected],
            'function_count': len(functions), 'pseudocode_count': sum(bool(item.get('pseudocode')) for item in functions),
            'evidence_count': len(evidence), 'independent_yara_check': yara_check,
            'verified': verified and unchanged,
            'scope': 'Inert synthetic test data intentionally exercises heuristics; this is not a malware classification or a false-positive-rate measurement',
            'unmeasured': ['process-family CPU and peak memory', 'agent tokens']}


def fixture(architecture: str) -> bytes:
    base, offset, symoff = 0x100000000, 512, 1024
    code = bytes.fromhex('b8 2a 00 00 00 c3' if architecture == 'x86_64' else '40 05 80 52 c0 03 5f d6')
    cpu, subtype = (0x01000007, 3) if architecture == 'x86_64' else (0x0100000c, 0)
    name = b'\0_machsentry_fixture\0'
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', base + offset,
                          len(code), offset, 2, 0, 0, 0x80000400, 0, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 152, b'__TEXT', base, 4096, 0, 4096, 7, 5, 1, 0) + section
    symtab = struct.pack('<6I', 2, 24, symoff, 1, symoff + 16, len(name))
    main = struct.pack('<IIQQ', 0x80000028, 24, offset, 0)
    commands = segment + symtab + main
    header = struct.pack('<8I', 0xfeedfacf, cpu, subtype, 2, 3, len(commands), 0, 0)
    data = bytearray(4096)
    data[:len(header + commands)] = header + commands
    data[offset:offset + len(code)] = code
    data[symoff:symoff + 16] = struct.pack('<IBBHQ', 1, 0xf, 1, 0, base + offset)
    data[symoff + 16:symoff + 16 + len(name)] = name
    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='New directory for retained fixtures and Evidence')
    parser.add_argument('--architecture', choices=['x86_64', 'arm64'], action='append')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    environment = dict(os.environ)
    environment.setdefault('REA_GHIDRA_STARTUP_TIMEOUT_MS', '900000')
    for architecture in args.architecture or ['x86_64', 'arm64']:
        path = (args.output / f'inert-{architecture}.macho').resolve()
        path.write_bytes(fixture(architecture))
        before = sha256(path.read_bytes()).hexdigest()
        started = time.perf_counter()
        run = subprocess.run([sys.executable, str(ROOT / 'scripts/machsentry_run.py'), 'rea',
                              'decompile', str(path), '0x100000200', '--provider', 'ghidra', '--format', 'json'],
                             cwd=ROOT, env=environment, capture_output=True, text=True, encoding='utf-8', timeout=1100)
        (args.output / f'{architecture}.stdout.json').write_text(run.stdout, encoding='utf-8')
        (args.output / f'{architecture}.stderr.txt').write_text(run.stderr, encoding='utf-8')
        result = {'architecture': architecture, 'sha256': before,
                  'source_unchanged': before == sha256(path.read_bytes()).hexdigest(),
                  'exit_code': run.returncode, 'elapsed_seconds': round(time.perf_counter() - started, 3)}
        evidence = json.loads(run.stdout) if run.returncode == 0 else {}
        pseudocode = evidence.get('normalized_result')
        result['decompilation_verified'] = (
            evidence.get('operation') == 'procedure_pseudo_code'
            and evidence.get('provider', {}).get('id') == 'ghidra'
            and evidence.get('subject', {}).get('architecture') == architecture
            and evidence.get('subject', {}).get('digest', {}).get('sha256') == before
            and isinstance(pseudocode, str)
            and ('return 0x2a;' in pseudocode or 'return 42;' in pseudocode)
        )
        result['evidence_id'] = evidence.get('evidence_id')
        result['provider'] = evidence.get('provider')
        result['unmeasured'] = ['process-family CPU and peak memory', 'agent tokens']
        results.append(result)
        (args.output / 'verification.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result), flush=True)
        if run.returncode != 0 or not result['source_unchanged'] or not result['decompilation_verified']:
            raise RuntimeError(f'Real REA {architecture} verification failed; inspect retained output')
    pipeline = verify_report_pipeline(args.output, environment, list(dict.fromkeys(args.architecture or ['x86_64', 'arm64'])))
    results.append(pipeline)
    (args.output / 'verification.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(pipeline), flush=True)
    if not pipeline['verified']:
        raise RuntimeError('Real REA MCP report verification failed; inspect retained output')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
