"""Public dashboard contract; backend Evidence remains in the analysis report."""

from jsonschema import Draft202012Validator

from .analyst_view import SECTIONS


def obj(**properties):
    return {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False}


def array(items):
    return {'type': 'array', 'items': items}


TEXT = {'type': 'string'}
OPTIONAL_TEXT = {'type': ['string', 'null']}
COUNT = {'type': 'integer', 'minimum': 0}
OPTIONAL_COUNT = {'type': ['integer', 'null'], 'minimum': 0}
OPTIONAL_BOOL = {'type': ['boolean', 'null']}
TEXTS = array(TEXT)
CORPUS = array(obj(name=TEXT, sha256={'type': 'string', 'pattern': '^[a-f0-9]{64}$'}, matched={'type': 'boolean'}))
CONDITION = obj(mach_o_required={'const': True}, all_strings_required={'type': 'boolean'},
                opcode_groups_any=array(obj(slice=COUNT, minimum_matches={'const': 2}, symbols=TEXTS)))

SCHEMA = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    'title': 'MachSentry analyst report v1.0',
    **obj(
        schema_version={'const': '1.0'}, section_order={'const': [key for key, _ in SECTIONS]}, created_at=TEXT,
        sample=obj(name=TEXT, archive_member=OPTIONAL_TEXT, sha256={'type': 'string', 'pattern': '^[a-f0-9]{64}$'},
                   container_sha256={'type': ['string', 'null'], 'pattern': '^[a-f0-9]{64}$'}, size_bytes=COUNT,
                   format={'enum': ['Mach-O', None]}, architectures=TEXTS),
        assessment=obj(score={'type': ['integer', 'null'], 'minimum': 0, 'maximum': 100}, maximum={'const': 100},
                       verdict={'enum': ['high_risk_indicators', 'suspicious', 'inconclusive']},
                       maliciousness={'enum': ['unconfirmed', 'not_assessed']}, status={'enum': ['partial', 'failed']},
                       summary=TEXT, factors=array(obj(title=TEXT, points=COUNT))),
        behaviors=array(obj(id=TEXT, title=TEXT, interpretation=TEXT, architecture=OPTIONAL_TEXT, slice=COUNT,
                            confidence={'enum': ['medium', 'high', 'low', 'unknown']}, functions=TEXTS,
                            evidence=array(obj(id=TEXT, text=TEXT, address=OPTIONAL_TEXT, file_offset=OPTIONAL_COUNT)))),
        functions=array(obj(architecture=TEXT, slice=COUNT, address=TEXT, names=TEXTS, behaviors=TEXTS)),
        scripts=array(obj(content=TEXT, architecture=OPTIONAL_TEXT, address=OPTIONAL_TEXT,
                          file_offset=OPTIONAL_COUNT, behaviors=TEXTS)),
        network=array(obj(kind=TEXT, value=TEXT, file_offset=OPTIONAL_COUNT, architecture=OPTIONAL_TEXT)),
        detection=obj(status={'enum': ['not_generated', 'rejected', 'related_samples_missed', 'positive_only', 'validated_candidate']},
                      mode={'enum': ['auto', 'hybrid', 'strings', 'opcodes']}, reason=TEXT, rule=OPTIONAL_TEXT,
                      download={'enum': ['detection.yar', None]},
                      condition={'anyOf': [CONDITION, {'type': 'null'}]},
                      criteria=array(obj(symbol=TEXT, kind={'enum': ['string', 'opcodes']}, value=TEXT,
                                         encoding=OPTIONAL_TEXT, architecture=OPTIONAL_TEXT, slice=COUNT,
                                         function_address=OPTIONAL_TEXT, file_offset=OPTIONAL_COUNT, meaning=TEXT,
                                         behaviors=TEXTS, selection_reason=TEXT, evidence_ids=TEXTS,
                                         fixed_bytes=OPTIONAL_COUNT, length=OPTIONAL_COUNT,
                                         wildcards=array(obj(kind=TEXT, address=TEXT, meaning=TEXT, mask=TEXT)))),
                      validation=obj(compiled=OPTIONAL_BOOL, sample_matched=OPTIONAL_BOOL, negatives=CORPUS, related=CORPUS),
                      limitations=TEXTS),
        coverage=obj(analyzed_slices=COUNT, publication_failed={'type': 'boolean'},
                     slices=array(obj(slice=COUNT, architecture=TEXT, status=TEXT, functions_inspected=OPTIONAL_COUNT,
                                      functions_omitted=OPTIONAL_COUNT, strings_complete=OPTIONAL_BOOL,
                                      reference_limit_reached=OPTIONAL_BOOL)), limitations=TEXTS),
    ),
}

VALIDATOR = Draft202012Validator(SCHEMA)


def validate_view(view):
    VALIDATOR.validate(view)
