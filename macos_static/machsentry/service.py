"""Report, score and detection composition over retained REA/Ghidra Evidence."""

from dataclasses import asdict
from datetime import datetime, timezone
from importlib.metadata import version
import time

import anyio

from . import __version__
from .behavior import RULESET_VERSION, SIGNATURE_CATEGORIES, risk_score, scripts_and_iocs
from .detection import generate_rule
from .opcodes import build_opcode_patterns
from .rea_client import ReaOptions
from .rea_workflow import collect
from .source import AnalysisError, Limits, Source


def analyze(source: Source, limits: Limits = Limits(), negatives: list[tuple[str, bytes]] | None = None,
            yara_mode: str = 'auto', related: list[tuple[str, bytes]] | None = None,
            rea_options: ReaOptions = ReaOptions()) -> dict:
    started, cpu = time.perf_counter(), time.process_time()
    if len(source.data) > limits.max_file_bytes:
        raise AnalysisError('resource_limit', 'Source exceeds analysis admission budget')
    facts = anyio.run(collect, source, limits, rea_options)
    strings, findings, functions = facts['strings'], facts['findings'], facts['functions']
    scripts, iocs = scripts_and_iocs(strings)
    signature_findings = {finding['id']: SIGNATURE_CATEGORIES.index(finding['category'])
                          for finding in findings if finding['category'] in SIGNATURE_CATEGORIES}
    signature_functions = sorted([function for function in functions if function['opcode_bytes_verified']
                                  and any(identifier in signature_findings for identifier in function['finding_ids'])],
                                 key=lambda function: min(signature_findings[identifier] for identifier in function['finding_ids']
                                                          if identifier in signature_findings))
    opcodes = build_opcode_patterns(source.data, signature_functions) if yara_mode != 'strings' else None
    yara = generate_rule(source.data, source.sha256, findings, strings, negatives or [], opcodes, yara_mode, related)
    analyzed = sum(item.get('status') == 'analyzed' for item in facts['slices'])
    cleanup_failed = not facts['rea']['closure_confirmed'] or any(not item['confirmed'] for item in facts['rea']['staging_cleanup'])
    status = 'failed' if not analyzed or cleanup_failed else 'partial'
    risk = risk_score(findings, True)
    risk['assessment_available'] = analyzed > 0
    if not analyzed:
        risk['value'] = None
        risk['maliciousness'] = 'not_assessed'
        risk['explanation'] = 'REA/Ghidra did not complete a selected slice; the score is unknown'
    limits_text = [
        'Static REA/Ghidra analysis only: sample and extracted scripts were never executed; no IOC was contacted',
        'Pseudocode is decompiler output, not original source and not guaranteed compilable or semantically complete',
        'Configured behavior indicators select functions; unselected code, constructed strings, unpacking and runtime behavior remain unknown',
        'Provider references associate code with indicators; neither static reachability nor malicious intent proves execution',
        'Score is a heuristic, not a calibrated probability; missing findings never establish benignity',
        'Addresses are unslid per-architecture virtual addresses; report file offsets refer to admitted uncompressed source bytes',
        'Capstone is used only to mask operands in REA-attributed, byte-verified function ranges for YARA',
        'No guarantee of zero YARA false positives or family coverage; actual tested corpora are recorded',
    ]
    for record in facts['rea']['records']:
        limits_text.extend(record.get('limitations', []))
    report = {
        'schema_version': '2.1', 'engine': {'name': 'machsentry', 'version': __version__,
            'analysis_engine': 'REA', 'provider': 'ghidra', 'ruleset_version': RULESET_VERSION,
            'mcp_sdk': version('mcp'), 'capstone': version('capstone'), 'yara_python': version('yara-python')},
        'created_at': datetime.now(timezone.utc).isoformat(), 'mode': 'static_offline',
        'artifact': source.identity(), 'analysis_status': status, 'risk': risk,
        'behavior_summary': [{'category': category, 'title': next(f['title'] for f in findings if f['category'] == category),
                              'finding_ids': [f['id'] for f in findings if f['category'] == category]}
                             for category in dict.fromkeys(f['category'] for f in findings)],
        'slices': facts['slices'], 'findings': findings, 'functions': functions, 'scripts': scripts,
        'ioc_candidates': iocs, 'evidence': strings, 'rea': facts['rea'], 'yara': yara,
        'coverage': {'slices': facts['coverage'], 'decompilation': 'REA analyze_function / Ghidra decompiler',
                     'runtime': 'not_performed', 'network': 'not_performed',
                     'analyzed_slice_count': analyzed, 'requested_architecture': rea_options.architecture},
        'limits': {**asdict(limits), 'max_decompiled_functions': rea_options.max_decompiled_functions,
                   'rea_request_timeout_seconds': rea_options.request_timeout_seconds},
        'limitations': list(dict.fromkeys(limits_text)),
        'metrics': {'analysis_elapsed_seconds': round(time.perf_counter() - started, 6),
                    'python_cpu_seconds': round(time.process_time() - cpu, 6),
                    'process_family_cpu_seconds': None, 'process_family_peak_memory_bytes': None,
                    'agent_tokens': None, 'runtime_llm_tokens': 0,
                    'unmeasured': ['REA/JVM process-family CPU and peak memory', 'agent development tokens'],
                    'cache': 'one fresh REA session per slice; provider results reused within session'},
    }
    if 'error' in facts:
        report['error'] = facts['error']
    if cleanup_failed:
        report['cleanup_error'] = 'Owned resource cleanup was not confirmed; see rea.cleanup and rea.staging_cleanup'
    return report
