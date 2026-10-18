"""Selects the AI input from MachSentry's report.json within a byte budget (contract section 8).

The document carries the site-verified sample identity, the engine's assessment and coverage,
findings with their evidence ids, the string evidence they reference (each <= 300 chars),
functions with pseudocode chosen by finding relevance (each <= 4,000 chars), script excerpts
(<= 1,500 chars), IOC candidates and the YARA status. Worker paths from report.json are never
copied. Items are added in priority order while the serialized UTF-8 size fits the budget.

Citable ids are the strings sent and the finding ids: report-view.json resolves only findings and
the evidence they reference, so the site can check nothing else. Script and IOC entries point to
those ids (`evidence_id` when their string was sent, `finding_ids`) and carry no citable id of
their own.
"""

from dataclasses import dataclass
import json

SCHEMA = 'unpacked-analysis-ai-input/1'
STRING_CHARS = 300
PSEUDOCODE_CHARS = 4000
SCRIPT_CHARS = 1500
IOC_CHARS = 300
FIRST_PASS_STRINGS = 3


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


@dataclass(frozen=True)
class Selection:
    text: str
    evidence_ids: frozenset
    finding_ids: frozenset


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
            'slices': [{'slice': item.get('index'), 'architecture': item.get('architecture'),
                        'status': item.get('status'),
                        'functions_inspected': slices.get(item.get('index'), {}).get('functions_inspected'),
                        'functions_omitted': slices.get(item.get('index'), {}).get('functions_omitted'),
                        'strings_complete': slices.get(item.get('index'), {}).get('strings_complete_over_provider_inventory'),
                        'reference_budget_exhausted': slices.get(item.get('index'), {}).get('reference_budget_exhausted')}
                       for item in _list(report.get('slices')) if isinstance(item, dict)],
        },
        'yara': {'status': yara.get('status'), 'mode': yara.get('effective_mode') or yara.get('requested_mode')},
        'findings': finding_entries,
        'strings': [], 'functions': [], 'scripts': [], 'ioc_candidates': [],
        'omitted': {'strings': 0, 'functions': 0, 'scripts': 0, 'ioc_candidates': 0},
    }
    # The omitted counters grow after the fit checks; the margin keeps the final text in budget.
    limit = budget - 24
    if size_of(document) > limit:
        return None
    strings = {item.get('id'): item for item in _list(report.get('evidence')) if isinstance(item, dict)}
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

    referenced = [[identifier for identifier in _list(finding.get('evidence_ids')) if isinstance(identifier, str)]
                  for finding in findings]
    for identifiers in referenced:
        for identifier in identifiers[:FIRST_PASS_STRINGS]:
            add_string(identifier)
    functions = [item for item in _list(report.get('functions')) if isinstance(item, dict)]
    ranked = sorted(enumerate(functions), key=lambda pair: (
        -sum(weights.get(identifier, 0) or 0 for identifier in _list(pair[1].get('finding_ids'))),
        -len(_list(pair[1].get('finding_ids'))), pair[0]))
    for _, function in ranked:
        pseudocode, truncated = (_clip(function['pseudocode'], PSEUDOCODE_CHARS)
                                 if isinstance(function.get('pseudocode'), str) else (None, False))
        add('functions', {'architecture': function.get('architecture'), 'slice': function.get('slice'),
                          'address': function.get('address'),
                          'names': [_clip(name, 120)[0] for name in _list(function.get('names'))[:5]],
                          'finding_ids': [identifier for identifier in _list(function.get('finding_ids'))
                                          if identifier in weights],
                          'pseudocode': pseudocode, 'pseudocode_truncated': truncated})
    for identifiers in referenced:
        for identifier in identifiers[FIRST_PASS_STRINGS:]:
            add_string(identifier)
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
    text = dumps(document)
    if len(text.encode()) > budget:
        return None
    return Selection(text, frozenset(included),
                     frozenset(entry['id'] for entry in finding_entries if isinstance(entry['id'], str)))
