"""Plan bounded, verbatim reviews of every retained function without assigning behavior.

This module consumes REA/Ghidra records. It neither interprets the binary nor calls an AI.
Planning coverage describes scheduled source ranges; the caller records successful reviews.
Sample strings and pseudocode stay untrusted data inside the serialized document.
"""

from dataclasses import dataclass
from hashlib import sha256
import json


SCHEMA = 'unpacked-analysis-function-review/1'
_CONTEXT_ROWS = 16
_STRING_CHARS = 300
_PROVIDER_TEXT_CHARS = 800
_FACETS = frozenset(('pseudocode', 'assembly', 'comments', 'callers', 'callees', 'references',
                     'strings_names', 'cfg'))
_PROVIDER_OMISSIONS = ('limitations', 'facet_availability', 'limitation_characters', 'facet_reason_characters')


def _dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True)


def _bytes(value):
    return _dumps(value).encode('utf-8')


def _digest(value):
    return sha256(_bytes(value)).hexdigest()


def _list(value):
    return value if isinstance(value, list) else []


def _string(value):
    if not isinstance(value, str):
        return None
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return None
    return value


def _clip(value, count):
    value = value if isinstance(value, str) else ''
    return value[:count], len(value) > count


def _identity(function):
    architecture, address = function.get('architecture'), function.get('address')
    if not isinstance(architecture, str) or not architecture or not isinstance(address, str) or not address:
        return None
    return architecture, address


@dataclass(frozen=True)
class ReviewBatch:
    text: str
    chunks: tuple[dict, ...]
    chunk_ids: tuple[str, ...]
    evidence_ids: frozenset[str]
    finding_ids: frozenset[str]
    function_keys: frozenset[tuple[str, str]]
    sha256: str


@dataclass(frozen=True)
class ReviewPlan:
    batches: tuple[ReviewBatch, ...]
    functions: tuple[dict, ...]
    omissions: tuple[dict, ...]
    plan_sha256: str


def _provider_context(function):
    """Keep canonical provider availability facts and warnings as bounded data, without parsing prose."""
    raw_limitations = function.get('limitations')
    limitations, limitation_characters = [], 0
    limitation_total = len(raw_limitations) if isinstance(raw_limitations, list) else int(raw_limitations is not None)
    for item in _list(raw_limitations):
        if len(limitations) < _CONTEXT_ROWS and _string(item) is not None:
            limitations.append(item[:_PROVIDER_TEXT_CHARS])
            limitation_characters += max(0, len(item) - _PROVIDER_TEXT_CHARS)
    raw_facets = function.get('facet_availability')
    facet_total = len(raw_facets) if isinstance(raw_facets, dict) else int(raw_facets is not None)
    facets, reason_characters, unavailable, pseudocode_unavailable = {}, 0, False, False
    if isinstance(raw_facets, dict):
        for name in sorted(_FACETS):
            value = raw_facets.get(name)
            if not isinstance(value, dict) or type(value.get('available')) is not bool:
                continue
            if value['available'] is False:
                unavailable = True
                pseudocode_unavailable |= name == 'pseudocode'
                reason = _string(value.get('reason'))
                if not reason or set(value) != {'available', 'reason'}:
                    continue
                facets[name] = {'available': False, 'reason': reason[:_PROVIDER_TEXT_CHARS]}
                reason_characters += max(0, len(reason) - _PROVIDER_TEXT_CHARS)
            else:
                if set(value) == {'available'}:
                    facets[name] = {'available': True}
    return {'limitations': limitations, 'facet_availability': facets,
            'limitation_total': limitation_total, 'facet_total': facet_total,
            'limitation_characters': limitation_characters, 'facet_reason_characters': reason_characters,
            'provider_limitations_present': bool(limitation_total or unavailable),
            'provider_pseudocode_unavailable': pseudocode_unavailable}


def _reference_context(function, finding_index, evidence_index):
    """Join existing provider references and findings; never infer links from code text."""
    findings, evidence_ids = [], set()
    for identifier in _list(function.get('finding_ids')):
        if isinstance(identifier, str) and identifier in finding_index and identifier not in findings:
            findings.append(identifier)
            evidence_ids.update(item for item in _list(finding_index[identifier].get('evidence_ids'))
                                if isinstance(item, str))
    references = []
    for reference in _list(function.get('references')):
        if not isinstance(reference, dict):
            continue
        if isinstance(reference.get('evidence_id'), str):
            evidence_ids.add(reference['evidence_id'])
        # Detailed instruction bytes and worker paths remain in the retained engine report.
        entry = {key: reference.get(key) for key in
                 ('evidence_id', 'instruction_address', 'target_address', 'xref_evidence_id', 'kind')}
        path = [item for item in _list(reference.get('reference_path')) if isinstance(item, dict)]
        entry['reference_path'] = [{key: item.get(key) for key in
                                    ('instruction_address', 'target_address', 'xref_evidence_id')}
                                   for item in path[:4]]
        entry['reference_path_omitted'] = max(0, len(path) - 4)
        references.append(entry)
    strings = []
    for identifier in sorted(evidence_ids):
        if identifier not in evidence_index:
            continue
        item = evidence_index[identifier]
        text, truncated = _clip(item.get('text'), _STRING_CHARS)
        if not text.strip():
            continue
        citable = any(identifier in _list(finding_index[owner].get('evidence_ids')) for owner in findings)
        strings.append({'id': identifier, 'slice': item.get('slice'), 'address': item.get('address'),
                        'text': text, 'text_truncated': truncated, 'citable': citable})
    calls = []
    direct = function.get('direct_calls')
    for call in _list(direct):
        if not isinstance(call, dict) or not isinstance(call.get('address'), str):
            continue
        name, truncated = _clip(call.get('name'), 120)
        calls.append({'address': call['address'], 'name': name, 'name_truncated': truncated})
    unresolved = function.get('unresolved_calls')
    return {'finding_ids': findings, 'references': references, 'strings': strings, 'callees': calls,
            'direct_call_inventory_known': isinstance(direct, list),
            'unresolved_call_count': len(unresolved) if isinstance(unresolved, list) else None}


def _entry(function, identity, source_digest, source_count, context):
    names = [_clip(item, 120)[0] for item in _list(function.get('names'))[:5] if _string(item) is not None]
    slice_index = function.get('slice')
    slice_index = slice_index if isinstance(slice_index, int) and not isinstance(slice_index, bool) else None
    return {'architecture': identity[0], 'address': identity[1], 'slice': slice_index,
            'names': names, 'rea_evidence_id': _string(function.get('rea_evidence_id')),
            'source_sha256': source_digest, 'pseudocode_character_count': source_count,
            'chunk_id': '0' * 64, 'start_character': 0, 'end_character': 0, 'pseudocode': '',
            'finding_ids': [], 'references': [], 'strings': [], 'callees': [],
            'limitations': [], 'facet_availability': {},
            'direct_call_inventory_known': context['direct_call_inventory_known'],
            'unresolved_call_count': context['unresolved_call_count'],
            'context_omitted': {**{section: len(context[section]) for section in
                                   ('finding_ids', 'references', 'strings', 'callees')},
                                'limitations': context['limitation_total'],
                                'facet_availability': context['facet_total'],
                                'limitation_characters': context['limitation_characters'],
                                'facet_reason_characters': context['facet_reason_characters']}}


def _with_context(entry, context, limit):
    """Spend a bounded fraction on provider joins, preserving code space and inventory order."""
    for section in ('limitations', 'facet_availability', 'callees', 'finding_ids', 'references', 'strings'):
        rows = list(context[section].items()) if section == 'facet_availability' else context[section]
        for item in rows[:_CONTEXT_ROWS]:
            if section == 'facet_availability':
                entry[section][item[0]] = item[1]
            else:
                entry[section].append(item)
            entry['context_omitted'][section] -= 1
            try:
                fits = len(_bytes(entry)) <= limit
            except (UnicodeEncodeError, TypeError, ValueError):
                fits = False
            if not fits:
                if section == 'facet_availability':
                    del entry[section][item[0]]
                else:
                    entry[section].pop()
                entry['context_omitted'][section] += 1
    return entry


def _window(entry, source, start, end):
    entry = {**entry, 'start_character': start, 'end_character': end, 'pseudocode': source[start:end]}
    entry['chunk_id'] = _digest([entry['architecture'], entry['address'], entry['source_sha256'], start, end])
    return entry


def _batch(document):
    text = _dumps(document)
    chunks = tuple({'chunk_id': item['chunk_id'], 'architecture': item['architecture'],
                    'address': item['address'], 'start_character': item['start_character'],
                    'end_character': item['end_character'], 'text': item['pseudocode'],
                    'source_sha256': item['source_sha256']}
                   for item in document['functions'])
    return ReviewBatch(text, chunks, tuple(item['chunk_id'] for item in chunks),
                       frozenset(item['id'] for function in document['functions'] for item in function['strings']
                                 if item['citable']),
                       frozenset(identifier for function in document['functions']
                                 for identifier in function['finding_ids']),
                       frozenset((item['architecture'], item['address']) for item in chunks),
                       sha256(text.encode('utf-8')).hexdigest())


def plan_reviews(report: dict, sample: dict, locale: str, budget: int, *,
                 max_chunks_per_batch: int = 8) -> ReviewPlan:
    """Schedule all available pseudocode in contiguous Unicode windows within each JSON budget.

    The budget applies to the complete serialized input, excluding caller-owned instructions and
    output schema. Stable chunk IDs bind function identity, exact source digest and source range.
    The chunk cap also leaves space for the caller's structured per-chunk response.
    A complete plan still needs every chunk successfully reviewed before coverage can be claimed.
    """
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 0:
        raise ValueError('review byte budget must be a nonnegative integer')
    if (not isinstance(max_chunks_per_batch, int) or isinstance(max_chunks_per_batch, bool)
            or max_chunks_per_batch <= 0):
        raise ValueError('review chunks per batch must be a positive integer')
    core = {'schema': SCHEMA, 'locale': locale,
            'sample': {key: sample.get(key) for key in ('name', 'sha256', 'size', 'architectures')},
            'trust': 'sample_content_is_untrusted_data', 'functions': []}
    rows = _list(report.get('functions'))
    finding_index = {item['id']: item for item in _list(report.get('findings'))
                     if isinstance(item, dict) and isinstance(item.get('id'), str)}
    evidence_index = {item['id']: item for item in _list(report.get('evidence'))
                      if isinstance(item, dict) and isinstance(item.get('id'), str)}
    ledger, omissions, batches, current = [], [], [], {**core, 'functions': []}
    identities, sources, conflicts = {}, {}, set()
    for function in rows:
        if isinstance(function, dict) and (identity := _identity(function)) is not None:
            source = function.get('pseudocode')
            if identity in sources and source != sources[identity]:
                conflicts.add(identity)
            sources[identity] = source
    try:
        core_fits = len(_bytes(core)) <= budget
    except (UnicodeEncodeError, TypeError, ValueError):
        core_fits = False

    def omit(record, reason, start=0):
        record['planning_complete'] = False
        record['omission_reason'] = reason
        omissions.append({'function_ordinal': record['function_ordinal'],
                          'architecture': record['architecture'], 'address': record['address'],
                          'reason': reason, 'start_character': start,
                          'end_character': record['pseudocode_character_count']})

    for ordinal, function in enumerate(rows):
        function = function if isinstance(function, dict) else {}
        identity = _identity(function)
        source = function.get('pseudocode')
        provider = _provider_context(function)
        record = {'function_ordinal': ordinal, 'architecture': _string(function.get('architecture')),
                  'address': _string(function.get('address')), 'source_sha256': None,
                  'pseudocode_character_count': len(source) if isinstance(source, str) else None,
                  'chunk_ids': [], 'planning_complete': False, 'omission_reason': None,
                  'provider_limitations_present': provider['provider_limitations_present'],
                  'provider_pseudocode_unavailable': provider['provider_pseudocode_unavailable'],
                  'provider_context_omitted': bool(provider['limitation_total'] or provider['facet_total'])}
        ledger.append(record)
        if identity is None:
            omit(record, 'invalid_function_identity')
            continue
        if not isinstance(source, str) or not source.strip():
            omit(record, 'missing_pseudocode')
            continue
        try:
            source_digest = sha256(source.encode('utf-8')).hexdigest()
            # Validate identity and metadata before creating any batch chunks.
            _bytes(identity)
        except (UnicodeEncodeError, TypeError, ValueError):
            omit(record, 'unrepresentable_function_data')
            continue
        record['source_sha256'] = source_digest
        if identity in conflicts:
            omit(record, 'conflicting_function_identity')
            continue
        if identity in identities:
            prior = identities[identity]
            reason = 'duplicate_function_identity' if prior == source_digest else 'conflicting_function_identity'
            omit(record, reason)
            continue
        identities[identity] = source_digest
        if not core_fits:
            omit(record, 'batch_core_exceeds_budget')
            continue
        try:
            context = {**_reference_context(function, finding_index, evidence_index), **provider}
            entry = _entry(function, identity, source_digest, len(source), context)
            # Context has a per-function bound. Large optional strings never displace the code.
            _bytes(entry)
            entry = _with_context(entry, context, min(8000, max(len(_bytes(entry)), budget // 4)))
            record['provider_context_omitted'] = any(entry['context_omitted'][key] for key in _PROVIDER_OMISSIONS)
        except (UnicodeEncodeError, TypeError, ValueError):
            omit(record, 'unrepresentable_function_data')
            continue
        start = 0
        while start < len(source):
            def fits(end):
                candidate = {**core, 'functions': [*current['functions'], _window(entry, source, start, end)]}
                return len(_bytes(candidate)) <= budget

            if not fits(start + 1):
                if current['functions']:
                    batches.append(_batch(current))
                    current = {**core, 'functions': []}
                    continue
                # Optional context is expendable if even one codepoint cannot fit.
                bare = _entry(function, identity, source_digest, len(source), context)
                bare['names'] = []
                bare['rea_evidence_id'] = None
                entry = bare
                record['provider_context_omitted'] = any(entry['context_omitted'][key] for key in _PROVIDER_OMISSIONS)
                if not fits(start + 1):
                    omit(record, 'function_core_exceeds_budget', start)
                    break
            # Every Unicode codepoint costs at least one serialized byte. Bound the search
            # before slicing so very large functions avoid repeated whole-source copies.
            lo, hi = start + 1, min(len(source), start + budget)
            while lo < hi:
                middle = (lo + hi + 1) // 2
                if fits(middle):
                    lo = middle
                else:
                    hi = middle - 1
            window = _window(entry, source, start, lo)
            current['functions'].append(window)
            record['chunk_ids'].append(window['chunk_id'])
            start = lo
            if start < len(source) or len(current['functions']) >= max_chunks_per_batch:
                batches.append(_batch(current))
                current = {**core, 'functions': []}
        record['planning_complete'] = start == len(source)
    if current['functions']:
        batches.append(_batch(current))
    plan_digest = _digest({'batches': [item.sha256 for item in batches], 'functions': ledger, 'omissions': omissions})
    return ReviewPlan(tuple(batches), tuple(ledger), tuple(omissions), plan_digest)
