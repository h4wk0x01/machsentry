"""Shared one-shot workflow; no subprocesses, sockets, target execution or billing."""

from dataclasses import asdict
from datetime import datetime, timezone
from importlib.metadata import version
import time

from . import __version__
from .behavior import RULESET_VERSION, SIGNATURE_CATEGORIES, attribute_functions, find_behaviors, risk_score, scripts_and_iocs
from .detection import generate_rule
from .evidence import correlate, extract_strings
from .macho import parse_images
from .opcodes import build_opcode_patterns
from .source import AnalysisError, Limits, Source


def analyze(source: Source, limits: Limits = Limits(), negatives: list[tuple[str, bytes]] | None = None,
            yara_mode: str = 'auto', related: list[tuple[str, bytes]] | None = None) -> dict:
    start = time.perf_counter()
    cpu = time.process_time()
    if len(source.data) > limits.max_file_bytes:
        raise AnalysisError('resource_limit', 'Source exceeds parser admission budget')
    images = parse_images(source.data, limits)
    strings, string_coverage = extract_strings(source.data, images, limits)
    disassembly = [{"slice": image.index, **correlate(source.data, image, strings, limits)} for image in images]
    findings = find_behaviors(strings, [image.index for image in images])
    functions = attribute_functions(images, findings, strings)
    scripts, iocs = scripts_and_iocs(strings)
    score = risk_score(findings, True)
    signature_findings = {f['id']: SIGNATURE_CATEGORIES.index(f['category']) for f in findings if f['category'] in SIGNATURE_CATEGORIES}
    signature_functions = sorted([f for f in functions if any(fid in signature_findings for fid in f['finding_ids'])],
        key=lambda f: min(signature_findings[fid] for fid in f['finding_ids'] if fid in signature_findings))
    opcodes = build_opcode_patterns(source.data, signature_functions) if yara_mode != 'strings' else None
    yara = generate_rule(source.data, source.sha256, findings, strings, negatives or [], opcodes, yara_mode, related)
    known_limits = [
        "Static analysis only: the sample and extracted scripts were never executed; no IOC was contacted",
        "Automated triage and function reference analysis are not complete reverse engineering or decompilation",
        "No emulation, unpacking, decryption, Objective-C dispatch recovery or full interprocedural data flow",
        "ASCII and ASCII-range UTF-16LE strings in file-backed noncode sections only; encoded/constructed strings remain unknown",
        "No persistence finding does not prove absence; no clean verdict or calibrated probability is produced",
        "Addresses are unslid virtual addresses per slice; file offsets refer to the selected uncompressed member",
        "Signature presence is structural only; cryptographic validity and notarization were not checked",
    ]
    for image in images:
        known_limits.extend(f"slice {image.index}: {item}" for item in image.limitations)
    report = {
        "schema_version": "1.0", "engine": {"name": "machsentry", "version": __version__,
            "ruleset_version": RULESET_VERSION, "lief": version('lief'), "capstone": version('capstone'),
            "yara_python": version('yara-python')},
        "created_at": datetime.now(timezone.utc).isoformat(), "mode": "static_offline",
        "artifact": source.identity(), "analysis_status": "partial", "risk": score,
        "behavior_summary": [{"category": category, "title": next(f['title'] for f in findings if f['category'] == category),
            "finding_ids": [f['id'] for f in findings if f['category'] == category]}
            for category in dict.fromkeys(f['category'] for f in findings)],
        "slices": [{"index": image.index, "architecture": image.architecture, "file_offset": image.offset,
                    "size_bytes": image.size, **image.metadata} for image in images],
        "findings": findings, "functions": functions, "scripts": scripts, "ioc_candidates": iocs,
        "evidence": strings, "yara": yara,
        "coverage": {"strings": string_coverage, "disassembly": disassembly,
                     "behavior_rules": "listed heuristic categories only", "decompilation": "not_performed",
                     "runtime": "not_performed", "network": "not_performed"},
        "limits": asdict(limits), "limitations": known_limits,
        "metrics": {"analysis_elapsed_seconds": round(time.perf_counter() - start, 6),
                    "analysis_cpu_seconds": round(time.process_time() - cpu, 6),
                    "process_family_peak_memory_bytes": None, "agent_tokens": None,
                    "unmeasured": ["process family peak memory", "agent tokens"], "cache": "none"},
    }
    return report
