"""Generate conservative static signatures and report actual validation scope."""

from hashlib import sha256
import json
import yara

from . import __version__
from .behavior import SIGNATURE_CATEGORIES


def rule_export_name(yara_result: dict, analysis_status: str) -> str | None:
    if yara_result['rule'] is None:
        return None
    if analysis_status != 'failed' and yara_result['status'] in ('validated_candidate', 'positive_only'):
        return 'detection.yar'
    return 'candidate-rejected.yar.txt'


def generate_rule(data: bytes, digest: str, findings: list[dict], strings: list[dict], negatives: list[tuple[str, bytes]],
                  opcode_analysis: dict | None = None, mode: str = 'auto', related: list[tuple[str, bytes]] | None = None) -> dict:
    if mode not in ('auto', 'strings', 'hybrid', 'opcodes'):
        raise ValueError('Unknown YARA mode')
    lookup = {r['id']: r for r in strings}
    # These categories must be present together in one slice and linked to code.
    priorities = SIGNATURE_CATEGORIES
    by_slice: dict[int, dict[str, dict]] = {}
    for finding in findings:
        if finding['function_addresses'] and finding['category'] in priorities:
            by_slice.setdefault(finding['slice'], {})[finding['category']] = finding
    available = max(by_slice.values(), key=len, default={})
    base = {"engine": f"yara-python/{yara.__version__}", "kind": "static_behavior_indicator_conjunction", "requested_mode": mode,
            "false_positive_guarantee": False, "production_ready": False,
            "selection": {"strings": [], "opcodes": [], "condition": None},
            "limitations": ["YARA observes file bytes, not executed behavior",
                            "Zero matches in a finite negative corpus does not establish zero false positives",
                            "Signature is sample-derived; family coverage is unverified",
                            "Opcode wildcards model decoded variable operands; they do not establish stability across compiler builds"]}
    if len(available) < 3 and mode in ('auto', 'strings', 'hybrid'):
        return {**base, "status": "not_generated", "reason": "Insufficient independent code-linked indicators",
                "rule": None, "validation": None}
    chosen = []
    for category in priorities:
        if category not in available:
            continue
        candidates = []
        for span in available[category].get('indicator_spans', []):
            record = lookup[span['evidence_id']]
            if record.get('yara_eligible') is False:
                continue
            position, length = span['character_offset'], span['character_length']
            # Keep context around the actual semantic anchor, never an unrelated prefix.
            if len(record['text']) <= 160:
                start, end = 0, len(record['text'])
            else:
                start, end = max(0, position - 32), min(len(record['text']), position + length + 64)
            literal = record['text'][start:end]
            if len(literal) >= 12:
                candidates.append({"category": category, "evidence_id": record['id'], "literal": literal,
                                   "encoding": record['encoding'], "character_offset": start,
                                   "anchor_offset": position, "anchor_length": length, "priority": span['priority']})
        candidates.sort(key=lambda item: (item['priority'], -len(item['literal']), item['character_offset']))
        used = {item['literal'] for item in chosen}
        candidate = next((item for item in candidates if item['literal'] not in used), None)
        if candidate is not None:
            chosen.append(candidate)
    if len(chosen) < 3 and mode in ('auto', 'strings', 'hybrid'):
        return {**base, "status": "not_generated", "reason": "Insufficient specific literals",
                "rule": None, "validation": None}
    # Require multiple independent code windows within one source slice.
    opcode_groups = {}
    for pattern in (opcode_analysis or {}).get('patterns', []):
        group = opcode_groups.setdefault(pattern['slice'], [])
        if not any(p['hex_pattern'] == pattern['hex_pattern'] or p['function_address'] == pattern['function_address'] for p in group):
            group.append(pattern)
    opcode_groups = {sid: patterns for sid, patterns in opcode_groups.items()
                     if len({p['function_address'] for p in patterns}) >= 2
                     and len({p['hex_pattern'] for p in patterns}) >= 2}
    effective = ('hybrid' if opcode_groups else 'strings') if mode == 'auto' else mode
    if effective in ('hybrid', 'opcodes') and not opcode_groups:
        return {**base, "status": "not_generated", "effective_mode": effective,
                "reason": "At least two sufficiently specific instruction windows from distinct functions in one slice are required",
                "rule": None, "validation": None, "opcode_analysis": opcode_analysis}
    base['effective_mode'] = effective
    declarations, opcode_conditions = [], []
    selected_strings, selected_opcodes, groups = [], [], []
    for number, indicator in enumerate(chosen if effective != 'opcodes' else []):
        selected_strings.append({**indicator, "symbol": f"$b{number}",
                                 "finding_id": available[indicator['category']]['id']})
        # JSON escaping matches YARA for retained ASCII text, CR/LF/tab and quotes.
        declarations.append(f"        $b{number} = {json.dumps(indicator['literal'], ensure_ascii=True)} "
                            + ('wide' if indicator['encoding'] == 'utf-16le' else 'ascii'))
    if effective in ('hybrid', 'opcodes'):
        for slice_number, patterns in sorted(opcode_groups.items()):
            symbols = []
            for number, pattern in enumerate(patterns):
                symbol = f"$op_s{slice_number}_{number}"
                symbols.append(symbol)
                selected_opcodes.append({"symbol": symbol, "pattern_id": pattern['id']})
                declarations.append(f"        $op_s{slice_number}_{number} = {{ {pattern['hex_pattern']} }}")
            groups.append({"slice": slice_number, "minimum_matches": 2, "symbols": symbols})
            opcode_conditions.append(f"2 of ($op_s{slice_number}_*)")
    condition = 'all of ($b*)' if effective != 'opcodes' else ''
    if opcode_conditions:
        condition += (' and ' if condition else '') + '(' + ' or '.join(opcode_conditions) + ')'
    base['selection'] = {"strings": selected_strings, "opcodes": selected_opcodes,
                         "condition": {"mach_o_required": True, "all_strings_required": effective != 'opcodes',
                                       "opcode_groups_any": groups}}
    rule = '\n'.join([
        f"rule machsentry_{effective}_{digest[:16]}", "{", "    meta:",
        '        description = "Mach-O matching the selected static indicators"',
        f'        sample_sha256 = "{digest}"', f'        generator = "machsentry {__version__}"',
        '        validation = "sample positive; negative corpus recorded in report.json"',
        "    strings:", *declarations, "    condition:",
        "        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or",
        "         uint32(0) == 0xcffaedfe or uint32(0) == 0xcefaedfe or",
        "         uint32(0) == 0xbebafeca or uint32(0) == 0xbfbafeca or",
        "         uint32(0) == 0xcafebabe or uint32(0) == 0xcafebabf) and",
        '        ' + condition, "}", ""])
    compiled = yara.compile(source=rule, error_on_warning=True)
    positive = bool(compiled.match(data=data, timeout=10))
    related_results = [{"name": name, "sha256": sha256(blob).hexdigest(), "bytes": len(blob),
                        "matched": bool(compiled.match(data=blob, timeout=10))} for name, blob in (related or [])]
    tested = []
    for name, blob in negatives:
        matches = compiled.match(data=blob, timeout=10)
        tested.append({"name": name, "sha256": sha256(blob).hexdigest(), "bytes": len(blob), "matched": bool(matches)})
    false_matches = sum(item['matched'] for item in tested)
    status = ('validated_candidate' if tested else 'positive_only') if positive and not false_matches else 'rejected'
    if status != 'rejected' and any(not row['matched'] for row in related_results):
        status = 'related_samples_missed'
    return {**base, "status": status,
            "rule": rule, "indicators": chosen if effective != 'opcodes' else [], "opcode_analysis": opcode_analysis,
            "validation": {"compiled": True, "sample_matched": positive, "negative_count": len(tested),
                           "negative_matches": false_matches, "negatives": tested,
                           "related_samples": related_results,
                           "related_labels": "caller-selected related specimens; family membership not authenticated",
                           "negative_labels": "caller-supplied; benignness not independently authenticated"}}
