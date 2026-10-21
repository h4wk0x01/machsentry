#!/usr/bin/env python3
"""Verify real REA/Ghidra clipboard evidence links using inert Mach-O data."""

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def verify(report: dict, architectures: list[str]) -> dict:
    records = {row['evidence_id']: row for row in report['rea']['records']}
    slices = {row['index']: row for row in report['slices'] if row.get('status') == 'analyzed'}
    assert {row['architecture'] for row in slices.values()} == set(architectures)
    functions = report['functions']
    assert len(functions) == 4 * len(architectures)
    links, api_stub_links = [], []
    for index, info in slices.items():
        observed = {row['address']: row for row in functions if row['slice'] == index}
        assert set(observed) == {'0x100000200', '0x100000240', '0x100000280', '0x1000002c0'}
        for function in observed.values():
            dossier = records[function['rea_evidence_id']]
            assert function['pseudocode'] and function['classification'] == 'review_context'
            assert dossier['provider']['id'] == 'ghidra' and dossier['operation'] == 'analyze_function'
            assert dossier['subject']['digest']['sha256'] == info['sha256']
            assert dossier['subject']['architecture'] == info['architecture']
            assert dossier['normalized_result']['procedure']['address'] == function['address']
        findings = {row['category']: row for row in report['findings'] if row['slice'] == index}
        for category in ('clipboard_access', 'dynamic_api_resolution'):
            finding = findings[category]
            assert finding['weight'] == 0
            assert set(finding['function_addresses']) == {'0x100000200', '0x100000240'}
        caller = observed['0x1000002c0']
        assert 'sensitive_api_caller' in caller['selection_reasons']
        assert observed['0x100000280']['names'] == ['_dlsym']
        assert 'return 0;' in observed['0x100000280']['pseudocode']
        assert not observed['0x100000280']['direct_calls']
        assert any(row['address'] == '0x100000280' and row['classification']['external'] is False
                   for row in caller['direct_calls'])
        callers = [row for row in records.values() if row['operation'] == 'procedure_callers'
                   and row['subject']['digest']['sha256'] == info['sha256']
                   and row['parameters']['procedure'] == '0x100000280'
                   and '0x1000002c0' in row['normalized_result']]
        assert callers, f"REA procedure_callers Evidence missing for {info['architecture']}"
        api_stub_links.append({'architecture': info['architecture'], 'local_stub_address': '0x100000280',
                               'caller_address': caller['address'], 'caller_evidence_id': caller['rea_evidence_id'],
                               'procedure_callers_evidence_id': callers[0]['evidence_id']})
        for address, expected_edges in [('0x100000200', 1), ('0x100000240', 2)]:
            function = observed[address]
            assert function['pseudocode'] and 'indicator_reference' in function['selection_reasons']
            paths = [ref for ref in function['references']
                     if len(ref.get('reference_path', [])) == expected_edges
                     and ref['target_address'] == '0x100000400']
            assert paths, f"REA did not retain the {expected_edges}-edge clipboard reference for {info['architecture']}:{address}"
            reference = paths[0]
            string = next(row for row in report['evidence'] if row['id'] == reference['evidence_id'])
            assert all(text in string['text'] for text in ('NSPasteboard', 'generalPasteboard', '_dlopen', '_dlsym'))
            path = reference['reference_path']
            assert path[-1]['target_address'] == string['address']
            if expected_edges == 2:
                assert path[0]['target_address'] == path[1]['source_address'] == '0x100000380'
            for edge in path:
                evidence = records[edge['xref_evidence_id']]
                assert evidence['provider']['id'] == 'ghidra' and evidence['operation'] == 'xrefs'
                assert edge['source_address'] in evidence['normalized_result']
                assert evidence['subject']['digest']['sha256'] == info['sha256']
            links.append({'architecture': info['architecture'], 'function_address': address,
                          'function_evidence_id': function['rea_evidence_id'],
                          'string_evidence_id': string['id'], 'reference_path': path})
    assert report['risk']['value'] == 0 and report['risk']['verdict'] == 'inconclusive'
    assert report['yara']['status'] == 'not_generated'
    assert report['rea']['closure_confirmed'] is True and not report['rea']['errors']
    assert report['rea']['staging_cleanup'] and all(row['confirmed'] for row in report['rea']['staging_cleanup'])
    assert report['metrics']['runtime_llm_tokens'] == 0
    return {'links': links, 'function_count': len(functions), 'score': 0,
            'synthetic_api_stub_links': api_stub_links,
            'yara_status': report['yara']['status'], 'closure_confirmed': True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='New output directory')
    parser.add_argument('--architecture', choices=['x86_64', 'arm64'], action='append')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    architectures = list(dict.fromkeys(args.architecture or ['x86_64', 'arm64']))
    spec = importlib.util.spec_from_file_location('machsentry_clipboard_fixtures', ROOT / 'macos_static/tests/fixtures.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Fixture source is unavailable')
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    source = (args.output / 'inert-clipboard-universal.macho').resolve()
    source.write_bytes(fixtures.clipboard_reference_universal_fixture())
    digest = sha256(source.read_bytes()).hexdigest()
    destination = (args.output / 'mcp-report').resolve()
    command = [sys.executable, str(ROOT / 'scripts/machsentry_run.py'), 'analyze', str(source), '--output', str(destination)]
    if len(architectures) == 1:
        command.extend(['--architecture', architectures[0]])
    environment = dict(os.environ)
    environment.setdefault('REA_GHIDRA_STARTUP_TIMEOUT_MS', '900000')
    started = time.perf_counter()
    run = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True,
                         text=True, encoding='utf-8', timeout=1800)
    (args.output / 'mcp.stdout.json').write_text(run.stdout, encoding='utf-8')
    (args.output / 'mcp.stderr.txt').write_text(run.stderr, encoding='utf-8')
    result = {'exit_code': run.returncode, 'sha256': digest,
              'source_unchanged': sha256(source.read_bytes()).hexdigest() == digest,
              'elapsed_seconds': round(time.perf_counter() - started, 3), 'verified': False,
              'scope': 'Inert functions return data pointers or call a fixture-local zero-return stub named _dlsym. No external API, imports, syscalls, target execution, IOC or AI stage.'}
    try:
        assert run.returncode == 0 and json.loads(run.stdout).get('ok') is True
        report = json.loads((destination / 'report.json').read_text(encoding='utf-8'))
        assert report['artifact']['sha256'] == digest and result['source_unchanged']
        result.update(verify(report, architectures))
        python = ROOT / '.venv-unpack' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        script = ('import json,sys; from pathlib import Path; from jsonschema import Draft202012Validator; '
                  'p=Path(sys.argv[1]); schema=json.loads((p/"report-view.schema.json").read_text(encoding="utf-8")); '
                  'Draft202012Validator.check_schema(schema); '
                  'Draft202012Validator(schema).validate(json.loads((p/"report-view.json").read_text(encoding="utf-8")))')
        subprocess.run([str(python), '-c', script, str(destination)], check=True, cwd=ROOT, timeout=30)
        result.update({'verified': True, 'dashboard_schema_valid': True})
    finally:
        (args.output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
