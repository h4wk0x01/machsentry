"""Selects the AI input from MachSentry's report.json within a byte budget (contract section 8).

The document carries the site-verified sample identity, the engine's assessment and coverage,
findings with their evidence ids, the string evidence they reference (each <= 300 chars),
functions with pseudocode chosen by finding relevance (each <= 4,000 chars), the YARA result
with its rule text (<= 2,000 chars), script excerpts (<= 1,500 chars) and IOC candidates. Worker
paths from report.json are never copied. Items are added in priority order while the serialized
UTF-8 size fits the budget. Coverage separates provider inventory, retained observations and AI
selection. Up to 24 additional, uncitable string observations give bounded inventory context.

Citable ids are the linked strings sent and the finding ids: report-view.json resolves findings and
the evidence they reference. Function entries use their verified architecture/address identity.
Script and IOC entries point to
those ids (`evidence_id` when their string was sent, `finding_ids`) and carry no citable id of
their own.
"""

from dataclasses import dataclass
import json

SCHEMA = 'unpacked-analysis-ai-input/3'
STRING_CHARS = 300
PSEUDOCODE_CHARS = 4000
SCRIPT_CHARS = 1500
IOC_CHARS = 300
YARA_RULE_CHARS = 2000
FIRST_PASS_STRINGS = 3
CONTEXT_STRINGS = 24
CALLEES_PER_FUNCTION = 16
# Selection hints route retained observations to the analyst. They carry no score or category.
_CONTEXT_HINTS = ('pasteboard', 'clipboard', 'pbpaste', 'pbcopy', 'stringfortype', 'setstring:',
                  'changecount', 'http://', 'https://', 'curl ', 'launchagent', 'keychain',
                  '_dlopen', '_dlsym', '_proc_pidpath', '_popen', '_fgets', '_fputs', '_usleep',
                  'password', 'authorization', 'base64',
                  'osascript', 'wallet', 'bech32', 'taproot', 'p2pkh', 'base58')
_CONTEXT_LABELS = frozenset({'eth', 'sui', 'btc', 'doge', 'sol'})
# Retrieval hints choose verbatim code windows. They assign no behavior or score.
_CODE_HINTS = (
    ('clipboard', ('pasteboard', 'pbpaste', 'pbcopy', 'clipboard', 'stringfortype', 'setstring:')),
    ('dynamic_api', ('dlopen', 'dlsym', 'objc_getclass', 'sel_registername')),
    ('process', ('popen', 'posix_spawn', 'execve', 'nstask', 'system(')),
    ('network', ('nsurlsession', 'curl', 'send(', 'sendto(', 'connect(', 'http://', 'https://')),
    ('transformation', ('base64', 'cccrypt', 'btc_', 'strstr(', 'strcmp(')),
    ('environment', ('proc_pidpath', 'ptrace', 'sysctl', 'dyld_image_count', 'mach_absolute_time')),
)
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
# Engine values the AI must explain in words instead of copying. The YARA mode stays out: its values
# (strings, opcodes, auto) are ordinary analyst words.
_ENUM_PATHS = (('assessment', 'verdict'), ('assessment', 'maliciousness'), ('assessment', 'analysis_status'),
               ('yara', 'status'), ('coverage', 'runtime'), ('coverage', 'network'))
# English engine values without an underscore that read as a leak in Portuguese text.
ENGINE_WORDS = frozenset({'partial', 'suspicious', 'inconclusive', 'unconfirmed', 'analyzed', 'rejected', 'failed',
                          'skipped'})


def dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def size_of(value) -> int:
    return len(dumps(value).encode())


def _clip(text, limit: int) -> tuple[str, bool]:
    text = text if isinstance(text, str) else ''
    return (text, False) if len(text) <= limit else (text[:limit], True)


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _total(rows, key):
    values = [_count(row.get(key)) for row in rows]
    return sum(values) if values and all(value is not None for value in values) else None


def _code_context(source):
    """Head, tail and relevant exact windows share the existing per-function character cap."""
    if not isinstance(source, str):
        return {'pseudocode': None, 'pseudocode_truncated': False,
                'pseudocode_character_count': None, 'pseudocode_excerpts': []}
    if len(source) <= PSEUDOCODE_CHARS:
        return {'pseudocode': source, 'pseudocode_truncated': False,
                'pseudocode_character_count': len(source), 'pseudocode_excerpts': []}
    head = PSEUDOCODE_CHARS // 4
    remaining = PSEUDOCODE_CHARS - head
    retained, excerpts = [(0, head)], []

    def add(start, end, reason):
        nonlocal remaining
        pending = [(max(head, start), min(len(source), end))]
        for lo, hi in retained:
            pieces = []
            for a, b in pending:
                if a < min(b, lo):
                    pieces.append((a, min(b, lo)))
                if max(a, hi) < b:
                    pieces.append((max(a, hi), b))
            pending = pieces
        for start, end in pending:
            end = min(end, start + remaining)
            if start < end:
                excerpts.append({'start_character': start, 'end_character': end,
                                 'text': source[start:end], 'selection_reason': reason})
                retained.append((start, end))
                remaining -= end - start

    # Preserve the function's ending as well as code around review signals.
    add(len(source) - head, len(source), 'function_end')
    lower = source.translate(_ASCII_LOWER)
    for category, hints in _CODE_HINTS:
        positions = sorted({position for hint in hints if (position := lower.find(hint, head)) >= 0})
        for position in positions:
            if remaining <= 0:
                break
            if any(lo <= position < hi for lo, hi in retained):
                continue
            start = max(head, position - head // 5)
            add(start, start + head, category)
    if remaining > 0:
        add(len(source) - head - remaining, len(source) - head, 'function_end_context')
    return {'pseudocode': source[:head], 'pseudocode_truncated': True,
            'pseudocode_character_count': len(source),
            'pseudocode_excerpts': sorted(excerpts, key=lambda entry: entry['start_character'])}


def _call_context(function):
    unresolved = function.get('unresolved_calls')
    unresolved_count = len(unresolved) if isinstance(unresolved, list) else None
    calls = function.get('direct_calls')
    if not isinstance(calls, list):
        return {'callees': [], 'callees_omitted': None, 'unresolved_call_count': unresolved_count}
    calls = [call for call in calls if isinstance(call, dict)
             and isinstance(call.get('address'), str) and isinstance(call.get('name'), str)]
    hints = tuple(hint.removesuffix('(') for _, group in _CODE_HINTS for hint in group)
    ranked = sorted(enumerate(calls), key=lambda pair: (
        not any(hint in pair[1]['name'].translate(_ASCII_LOWER) for hint in hints), pair[0]))
    selected = []
    for _, call in ranked[:CALLEES_PER_FUNCTION]:
        name, truncated = _clip(call['name'], 120)
        selected.append({'address': call['address'], 'name': name, 'name_truncated': truncated})
    return {'callees': selected, 'callees_omitted': max(0, len(calls) - len(selected)),
            'unresolved_call_count': unresolved_count}


def _context_candidates(evidence, linked):
    """Diverse hints and inventory-wide samples over unique, nonblank unlinked observations."""
    unlinked = [(ordinal, item) for ordinal, item in enumerate(evidence)
                if isinstance(item, dict) and item.get('id') not in linked and isinstance(item.get('text'), str)]
    # Preserve the first source ordinal and exact text. Filtering affects AI selection only.
    seen, eligible = set(), []
    for ordinal, item in unlinked:
        text = item['text']
        if text.strip() and text not in seen:
            seen.add(text)
            eligible.append((ordinal, item, text.lower()))
    hinted, chosen = [], set()
    # A separate pass per hint keeps repeated financial labels from occupying every slot before APIs.
    for hint in _CONTEXT_HINTS:
        candidate = next(((ordinal, item) for ordinal, item, text in eligible
                          if ordinal not in chosen and hint in text), None)
        if candidate is not None:
            hinted.append(candidate)
            chosen.add(candidate[0])
        if len(hinted) == CONTEXT_STRINGS // 2:
            break
    for ordinal, item, text in eligible:
        if len(hinted) == CONTEXT_STRINGS // 2:
            break
        if ordinal not in chosen and text.strip().strip('"\'') in _CONTEXT_LABELS:
            hinted.append((ordinal, item))
            chosen.add(ordinal)
    remaining = [(ordinal, item) for ordinal, item, _ in eligible if ordinal not in chosen]
    slots = min(CONTEXT_STRINGS - len(hinted), len(remaining))
    spread = [remaining[index * (len(remaining) - 1) // max(1, slots - 1)] for index in range(slots)]
    # Keep both inventory ends before interior samples if the byte budget cuts this list.
    if len(spread) > 2:
        spread = [spread[0], spread[-1], *spread[1:-1]]
    return hinted + spread, len(unlinked), len(eligible)


@dataclass(frozen=True)
class Selection:
    text: str
    evidence_ids: frozenset
    finding_ids: frozenset


def internal_terms(document: dict) -> frozenset:
    """Keys and engine values of the AI input that must not reach the analyst as raw words.

    Keys are fixed worker names everywhere, so every snake_case key counts. Values come from the
    engine (verdicts, statuses, categories) or from the sample (strings, names, pseudocode); only the
    engine ones are read, and only when they have an underscore or are in ENGINE_WORDS.
    """
    terms, values = set(), []

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if '_' in key:
                    terms.add(key)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)
    values += [_dict(document.get(section)).get(key) for section, key in _ENUM_PATHS]
    values += [item.get('status') for item in _list(_dict(document.get('coverage')).get('slices')) if isinstance(item, dict)]
    values += [item.get('category') for item in _list(document.get('findings')) if isinstance(item, dict)]
    values += [item.get('classification') for item in _list(document.get('ioc_candidates')) if isinstance(item, dict)]
    terms.update(value for value in values
                 if isinstance(value, str) and value and ('_' in value or value in ENGINE_WORDS))
    return frozenset(terms)


def function_keys(report: dict) -> frozenset:
    """Every (architecture, address) the engine reported; AI references must use one of them."""
    return frozenset((function.get('architecture'), function.get('address'))
                     for function in _list(report.get('functions')) if isinstance(function, dict))


def select(report: dict, sample: dict, locale: str, budget: int) -> Selection | None:
    """Returns None when even the core (identity, assessment, coverage, findings) exceeds the budget."""
    architectures = {item.get('index'): item.get('architecture') for item in _list(report.get('slices'))
                     if isinstance(item, dict)}
    risk, coverage, yara = _dict(report.get('risk')), _dict(report.get('coverage')), _dict(report.get('yara'))
    slices = {item.get('slice'): item for item in _list(coverage.get('slices')) if isinstance(item, dict)}
    findings = sorted((item for item in _list(report.get('findings')) if isinstance(item, dict)),
                      key=lambda item: (-(item.get('weight') or 0), str(item.get('id'))))
    raw_evidence = _list(report.get('evidence'))
    evidence = [item for item in raw_evidence if isinstance(item, dict)]
    functions = [item for item in _list(report.get('functions')) if isinstance(item, dict)]
    coverage_rows = [item for item in _list(coverage.get('slices')) if isinstance(item, dict)]
    linked = {identifier for finding in findings for identifier in _list(finding.get('evidence_ids'))
              if isinstance(identifier, str)}
    context, unlinked_count, context_eligible = _context_candidates(raw_evidence, linked)
    weights = {item.get('id'): item.get('weight') or 0 for item in findings}
    finding_entries = [{
        'id': item.get('id'), 'category': item.get('category'), 'slice': item.get('slice'),
        'architecture': architectures.get(item.get('slice')), 'title': _clip(item.get('title'), STRING_CHARS)[0],
        'weight': item.get('weight'), 'confidence': item.get('confidence'), 'evidence_ids': [],
        'function_addresses': [address for address in _list(item.get('function_addresses'))[:32]
                               if isinstance(address, str)],
    } for item in findings]
    document = {
        'schema': SCHEMA,
        'locale': locale,
        'sample': {key: sample.get(key) for key in ('name', 'sha256', 'size', 'architectures')},
        'assessment': {'score': risk.get('value'), 'maximum': 100, 'verdict': risk.get('verdict'),
                       'maliciousness': risk.get('maliciousness'), 'method': risk.get('method'),
                       'analysis_status': report.get('analysis_status'),
                       'contributions': _dict(risk.get('contributions'))},
        'coverage': {
            'analyzed_slices': coverage.get('analyzed_slice_count'), 'runtime': 'not_performed',
            'network': 'not_performed',
            'strings': {'provider_total': _total(coverage_rows, 'string_inventory_count'),
                        'retained': len(evidence), 'citable_selected': len(evidence),
                        'context_selected': len(context), 'unlinked_retained': unlinked_count,
                        'context_eligible': context_eligible},
            'functions': {'provider_total': _total(coverage_rows, 'procedure_inventory_count'),
                          'not_selected': _total(coverage_rows, 'functions_not_selected'),
                          'attempted': _total(coverage_rows, 'functions_attempted'),
                          'inspection_failures': _total(coverage_rows, 'function_inspection_failures'),
                          'candidates': _total(coverage_rows, 'candidate_functions'),
                          'inspected': _total(coverage_rows, 'functions_inspected'),
                          'omitted': _total(coverage_rows, 'functions_omitted'),
                          'retained': len(functions), 'selected': len(functions)},
            'slices': [{'slice': item.get('index'), 'architecture': item.get('architecture'),
                        'status': item.get('status'),
                        'strings_provider_total': _count(slices.get(item.get('index'), {}).get('string_inventory_count')),
                        'strings_retained': _count(slices.get(item.get('index'), {}).get('strings_retained')),
                        'functions_candidates': _count(slices.get(item.get('index'), {}).get('candidate_functions')),
                        'functions_provider_total': _count(slices.get(item.get('index'), {}).get('procedure_inventory_count')),
                        'functions_not_selected': _count(slices.get(item.get('index'), {}).get('functions_not_selected')),
                        'functions_attempted': _count(slices.get(item.get('index'), {}).get('functions_attempted')),
                        'function_inspection_failures': _count(slices.get(item.get('index'), {}).get('function_inspection_failures')),
                        'functions_inspected': slices.get(item.get('index'), {}).get('functions_inspected'),
                        'functions_omitted': slices.get(item.get('index'), {}).get('functions_omitted'),
                        'strings_complete': slices.get(item.get('index'), {}).get('strings_complete_over_provider_inventory'),
                        'reference_budget_exhausted': slices.get(item.get('index'), {}).get('reference_budget_exhausted')}
                       for item in _list(report.get('slices')) if isinstance(item, dict)],
        },
        'yara': {'status': yara.get('status'), 'mode': yara.get('effective_mode') or yara.get('requested_mode'),
                 'reason': _clip(yara.get('reason'), STRING_CHARS)[0] or None,
                 'sample_matched': _dict(yara.get('validation')).get('sample_matched'),
                 'clean_files_tested': _dict(yara.get('validation')).get('negative_count'),
                 'clean_files_matched': _dict(yara.get('validation')).get('negative_matches'),
                 'rule': None, 'rule_truncated': False},
        'findings': finding_entries,
        'strings': [], 'context_strings': [], 'functions': [], 'scripts': [], 'ioc_candidates': [],
        'omitted': {'strings': 0, 'context_strings': context_eligible, 'functions': 0, 'scripts': 0, 'ioc_candidates': 0},
    }
    # The omitted counters grow after the fit checks; the margin keeps the final text in budget.
    limit = budget - 24
    if size_of(document) > limit:
        return None
    strings = {item.get('id'): item for item in evidence}
    included = set()

    def fits() -> bool:
        return size_of(document) <= limit

    def add_string(identifier) -> bool:
        if identifier in included or identifier not in strings:
            return identifier in included
        item = strings[identifier]
        text, truncated = _clip(item.get('text'), STRING_CHARS)
        document['strings'].append({'id': identifier, 'slice': item.get('slice'), 'address': item.get('address'),
                                    'text': text, 'text_truncated': truncated})
        owners = [entry for entry, finding in zip(finding_entries, findings)
                  if identifier in _list(finding.get('evidence_ids'))]
        for entry in owners:
            entry['evidence_ids'].append(identifier)
        if fits():
            included.add(identifier)
            return True
        document['strings'].pop()
        for entry in owners:
            entry['evidence_ids'].pop()
        return False

    def add(section: str, entry: dict) -> bool:
        document[section].append(entry)
        if fits():
            return True
        document[section].pop()
        document['omitted'][section] += 1
        return False

    def links(evidence_id) -> dict:
        """Script and IOC references to citable ids; every string sent is final by now."""
        if not isinstance(evidence_id, str):
            return {'evidence_id': None, 'finding_ids': []}
        return {'evidence_id': evidence_id if evidence_id in included else None,
                'finding_ids': [entry['id'] for entry, finding in zip(finding_entries, findings)
                                if isinstance(entry['id'], str) and evidence_id in _list(finding.get('evidence_ids'))]}

    contextual = set()

    def add_context(ordinal, item):
        if ordinal in contextual:
            return
        text, truncated = _clip(item['text'], STRING_CHARS)
        entry = {'inventory_ordinal': ordinal, 'slice': item.get('slice'),
                 'architecture': architectures.get(item.get('slice')), 'address': item.get('address'),
                 'text': text, 'text_truncated': truncated}
        document['context_strings'].append(entry)
        if fits():
            contextual.add(ordinal)
        else:
            document['context_strings'].pop()

    referenced = [[identifier for identifier in _list(finding.get('evidence_ids')) if isinstance(identifier, str)]
                  for finding in findings]
    for identifiers in referenced:
        for identifier in identifiers[:FIRST_PASS_STRINGS]:
            add_string(identifier)
    # When no heuristic owns a string, keep a small context seed ahead of baseline code.
    if not linked:
        for ordinal, item in context[:FIRST_PASS_STRINGS]:
            add_context(ordinal, item)
    ranked = sorted(enumerate(functions), key=lambda pair: (
        -sum(weights.get(identifier, 0) or 0 for identifier in _list(pair[1].get('finding_ids'))),
        -len(_list(pair[1].get('finding_ids'))), pair[0]))
    for _, function in ranked:
        add('functions', {'architecture': function.get('architecture'), 'slice': function.get('slice'),
                          'address': function.get('address'),
                          'names': [_clip(name, 120)[0] for name in _list(function.get('names'))[:5]],
                          'finding_ids': [identifier for identifier in _list(function.get('finding_ids'))
                                          if identifier in weights],
                          **_code_context(function.get('pseudocode')), **_call_context(function)})
    for identifiers in referenced:
        for identifier in identifiers[FIRST_PASS_STRINGS:]:
            add_string(identifier)
    if isinstance(yara.get('rule'), str) and yara['rule']:
        rule, truncated = _clip(yara['rule'], YARA_RULE_CHARS)
        document['yara'].update(rule=rule, rule_truncated=truncated)
        if not fits():
            document['yara'].update(rule=None, rule_truncated=False)
    document['omitted']['strings'] = len({identifier for identifiers in referenced for identifier in identifiers
                                          if identifier in strings} - included)
    for script in _list(report.get('scripts')):
        if isinstance(script, dict):
            content, truncated = _clip(script.get('content'), SCRIPT_CHARS)
            add('scripts', {**links(script.get('evidence_id')), 'slice': script.get('slice'),
                            'address': script.get('address'), 'content': content, 'content_truncated': truncated})
    for candidate in _list(report.get('ioc_candidates')):
        if isinstance(candidate, dict):
            add('ioc_candidates', {'kind': candidate.get('kind'), 'value': _clip(candidate.get('value'), IOC_CHARS)[0],
                                   **links(candidate.get('evidence_id')),
                                   'classification': 'unverified_candidate', 'contacted': False})
    # Context follows citable observations and code. Its ordinals identify the retained inventory,
    # while the citation allowlists remain limited to strings linked to published findings.
    for ordinal, item in context:
        add_context(ordinal, item)
    document['coverage']['strings'].update(citable_selected=len(document['strings']),
                                            context_selected=len(document['context_strings']))
    document['omitted']['context_strings'] = context_eligible - len(document['context_strings'])
    document['coverage']['functions']['selected'] = len(document['functions'])
    text = dumps(document)
    if len(text.encode()) > budget:
        return None
    return Selection(text, frozenset(included),
                     frozenset(entry['id'] for entry in finding_entries if isinstance(entry['id'], str)))
