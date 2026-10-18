"""Output contract of the AI stage (`unpacked-analysis-ai-output/1`, contract section 8).

`OUTPUT_SCHEMA` is sent as the Responses API strict `text.format`. Strict mode requires every
property and `additionalProperties: false`; string length caps are not schema keywords there, so
`validate` enforces them together with evidence-id and (architecture, address) references.

The site re-checks the output and drops what fails without telling anyone, so these rules match
its validateAi: lengths in UTF-16 code units (JavaScript string length) and 200 for technique
names and function titles. A stricter worker only costs a correction call.
"""

import re

FORMAT_NAME = 'unpacked_analysis_ai_output_v1'
TECHNIQUE_ID = re.compile(r'^T\d{4}(\.\d{3})?$')
SUMMARY_CHARS = 1500
TEXT_CHARS = 800
NAME_CHARS = 200
LIMITS = {'behaviors': 12, 'techniques': 12, 'functions': 32, 'gaps': 12, 'next_steps': 12}
EVIDENCE_PER_CLAIM = 16
FUNCTIONS_PER_BEHAVIOR = 8
MAX_ERRORS = 32


def _object(properties: dict) -> dict:
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def _array(items: dict, maximum: int) -> dict:
    return {'type': 'array', 'items': items, 'maxItems': maximum}


_TEXT = {'type': 'string'}
_EVIDENCE = _array(_TEXT, EVIDENCE_PER_CLAIM)
_FUNCTION_REF = _object({'architecture': _TEXT, 'address': _TEXT})

OUTPUT_SCHEMA = _object({
    'summary': _TEXT,
    'behaviors': _array(_object({
        'title': _TEXT, 'explanation': _TEXT, 'confidence': {'type': 'string', 'enum': ['low', 'medium', 'high']},
        'evidence_ids': _EVIDENCE, 'functions': _array(_FUNCTION_REF, FUNCTIONS_PER_BEHAVIOR)}), LIMITS['behaviors']),
    'techniques': _array(_object({
        'id': {'type': 'string', 'pattern': TECHNIQUE_ID.pattern}, 'name': _TEXT, 'rationale': _TEXT,
        'evidence_ids': _EVIDENCE}), LIMITS['techniques']),
    'functions': _array(_object({
        'architecture': _TEXT, 'address': _TEXT, 'title': _TEXT, 'explanation': _TEXT,
        'evidence_ids': _EVIDENCE}), LIMITS['functions']),
    'gaps': _array(_TEXT, LIMITS['gaps']),
    'next_steps': _array(_TEXT, LIMITS['next_steps']),
})


def text_format() -> dict:
    return {'type': 'json_schema', 'name': FORMAT_NAME, 'schema': OUTPUT_SCHEMA, 'strict': True}


def validate(output, evidence_ids, finding_ids, function_keys) -> list[str]:
    """Returns the problems found, capped; an empty list means the output may be published."""
    errors: list[str] = []
    allowed = set(evidence_ids) | set(finding_ids)

    def error(path: str, problem: str):
        if len(errors) < MAX_ERRORS:
            errors.append(f'{path}: {problem}')

    def shape(value, path: str, keys: tuple) -> bool:
        if not isinstance(value, dict):
            error(path, 'must be an object')
            return False
        if set(value) != set(keys):
            error(path, f'must have exactly the keys {", ".join(keys)}')
            return False
        return True

    def text(value, path: str, limit: int = TEXT_CHARS):
        if not isinstance(value, str) or not value.strip():
            error(path, 'must be a non-empty string')
        elif len(value.encode('utf-16-le', 'surrogatepass')) // 2 > limit:
            error(path, f'exceeds {limit} characters')

    def items(value, path: str, limit: int) -> list:
        if not isinstance(value, list):
            error(path, 'must be an array')
            return []
        if len(value) > limit:
            error(path, f'has more than {limit} items')
        return value[:limit]

    def evidence(value, path: str):
        entries = items(value, path, EVIDENCE_PER_CLAIM)
        if isinstance(value, list) and not value:
            error(path, 'needs at least one evidence id')
        for index, identifier in enumerate(entries):
            if not isinstance(identifier, str) or identifier not in allowed:
                error(f'{path}[{index}]', 'unknown evidence id')

    def function(architecture, address, path: str):
        if not isinstance(architecture, str) or not isinstance(address, str) or (architecture, address) not in function_keys:
            error(path, 'unknown function (architecture, address)')

    if not shape(output, '$', tuple(OUTPUT_SCHEMA['properties'])):
        return errors
    text(output['summary'], 'summary', SUMMARY_CHARS)
    for index, behavior in enumerate(items(output['behaviors'], 'behaviors', LIMITS['behaviors'])):
        path = f'behaviors[{index}]'
        if shape(behavior, path, ('title', 'explanation', 'confidence', 'evidence_ids', 'functions')):
            text(behavior['title'], f'{path}.title')
            text(behavior['explanation'], f'{path}.explanation')
            if behavior['confidence'] not in ('low', 'medium', 'high'):
                error(f'{path}.confidence', 'must be low, medium or high')
            evidence(behavior['evidence_ids'], f'{path}.evidence_ids')
            for position, reference in enumerate(items(behavior['functions'], f'{path}.functions', FUNCTIONS_PER_BEHAVIOR)):
                if shape(reference, f'{path}.functions[{position}]', ('architecture', 'address')):
                    function(reference['architecture'], reference['address'], f'{path}.functions[{position}]')
    for index, technique in enumerate(items(output['techniques'], 'techniques', LIMITS['techniques'])):
        path = f'techniques[{index}]'
        if shape(technique, path, ('id', 'name', 'rationale', 'evidence_ids')):
            if not isinstance(technique['id'], str) or not TECHNIQUE_ID.match(technique['id']):
                error(f'{path}.id', 'must match T0000 or T0000.000')
            text(technique['name'], f'{path}.name', NAME_CHARS)
            text(technique['rationale'], f'{path}.rationale')
            evidence(technique['evidence_ids'], f'{path}.evidence_ids')
    for index, entry in enumerate(items(output['functions'], 'functions', LIMITS['functions'])):
        path = f'functions[{index}]'
        if shape(entry, path, ('architecture', 'address', 'title', 'explanation', 'evidence_ids')):
            function(entry['architecture'], entry['address'], path)
            text(entry['title'], f'{path}.title', NAME_CHARS)
            text(entry['explanation'], f'{path}.explanation')
            evidence(entry['evidence_ids'], f'{path}.evidence_ids')
    for key in ('gaps', 'next_steps'):
        for index, value in enumerate(items(output[key], key, LIMITS[key])):
            text(value, f'{key}[{index}]')
    return errors
