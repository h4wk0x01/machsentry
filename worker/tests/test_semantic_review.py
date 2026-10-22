"""Semantic orchestration contracts with scripted responses, not model-accuracy measurements.

Every pseudocode body is inert test text. No sample, API or network request is executed.
The responses deliberately state configured conclusions; tests check citations, coverage and spend.
"""

from copy import deepcopy
from dataclasses import replace
import json
import time
import unittest

import worker_support as support
from machsentry_worker import ai
from machsentry_worker.ai_stage import AiStage
from machsentry_worker.job import parse_claim
from machsentry_worker.review_batches import plan_reviews
from machsentry_worker.semantic_review import validate_batch
from machsentry_worker.site_api import SiteError


BENIGN = 'no_malicious_behavior_observed'


def code_report(codes, *, provider_count=None):
    functions = [{'architecture': 'arm64', 'slice': 0, 'address': hex(0x100000100 + index * 32),
                  'names': [f'synthetic_{index}'], 'pseudocode': code, 'finding_ids': [], 'references': [],
                  'direct_calls': [], 'unresolved_calls': [], 'rea_evidence_id': f'rea:synthetic:{index}'}
                 for index, code in enumerate(codes)]
    return {'analysis_status': 'partial', 'functions': functions, 'findings': [], 'evidence': [],
            'slices': [{'index': 0, 'architecture': 'arm64', 'status': 'analyzed'}],
            'coverage': {'analyzed_slice_count': 1, 'slices': [{
                'slice': 0, 'procedure_inventory_count': len(functions) if provider_count is None else provider_count,
                'functions_inspected': len(functions), 'functions_omitted': 0}]},
            'risk': {'value': 0, 'verdict': 'inconclusive', 'maliciousness': 'unconfirmed',
                     'method': 'synthetic-test-only', 'contributions': {}},
            'yara': {'status': 'not_generated'}, 'scripts': [], 'ioc_candidates': []}


def plain_output():
    return {'summary': 'The reviewed code is described by its cited operations.', 'behaviors': [],
            'techniques': [], 'functions': [], 'gaps': [], 'next_steps': []}


def batch_value(document, *, verdict='inconclusive', quote=None, gaps=(), counter=()):
    rows = []
    for item in document['functions']:
        proof = quote if quote is not None else item['pseudocode'][:100]
        rows.append({'chunk_id': item['chunk_id'], 'source_sha256': item['source_sha256'],
                     'verdict': verdict, 'summary': 'Synthetic configured code interpretation.',
                     'evidence': [{'quote': proof, 'statement': 'This is the exact operation reviewed.'}],
                     'counter_evidence': list(counter), 'gaps': list(gaps)})
    return {'chunks': rows}


class MemoryLedger:
    def __init__(self):
        self.reservations, self.settlements = [], []
        self.deny = {}
        self.fail_settlement_at = None

    def ai_reserve(self, job_id, attempt, lease, index, input_tokens, output_tokens, model, version):
        self.reservations.append({'index': index, 'input_tokens': input_tokens, 'output_tokens': output_tokens,
                                  'model': model, 'version': version})
        if index in self.deny:
            return {'granted': False, 'reason': self.deny[index]}
        return {'granted': True, 'callId': f'synthetic_call_{index}'}

    def ai_settle(self, job_id, attempt, lease, call_id, outcome, **kwargs):
        self.settlements.append({'call_id': call_id, 'outcome': outcome, **kwargs})
        if len(self.settlements) - 1 == self.fail_settlement_at:
            raise SiteError('synthetic_settlement_failure')
        return {'costMicros': 123}


class ScriptedModel:
    def __init__(self, *, batch_verdict='inconclusive', final_verdict='inconclusive', quote=None,
                 gaps=(), counter=(), mutate=None, output_tokens=100, override=None):
        self.batch_verdict, self.final_verdict = batch_verdict, final_verdict
        self.quote, self.gaps, self.counter = quote, gaps, counter
        self.mutate, self.output_tokens, self.override = mutate, output_tokens, override
        self.requests = []

    def __call__(self, key, body, **kwargs):
        index = len(self.requests)
        self.requests.append(deepcopy(body))
        document = json.loads(body['input'])
        synthesis = document['schema'] == 'unpacked-code-review-synthesis-input/1'
        if synthesis:
            proofs = [{'chunk_id': item['chunk_id'], **proof} for item in document['verified_reviews']
                      for proof in item['evidence']][:24]
            value = {**plain_output(), 'classification': {
                'verdict': self.final_verdict, 'confidence': 'medium',
                'rationale': 'Configured synthesis for a scripted contract test.', 'evidence': proofs,
                'counter_evidence': list(self.counter), 'gaps': []}}
        else:
            value = batch_value(document, verdict=self.batch_verdict, quote=self.quote,
                                gaps=self.gaps, counter=self.counter)
        if self.mutate:
            self.mutate(value, document, synthesis, index)
        if self.override:
            overridden = self.override(value, document, synthesis, index)
            if overridden is not None:
                return overridden
        return ai.CallResult('succeeded', usage={'inputTokens': 800, 'cachedInputTokens': 50,
                                                'outputTokens': self.output_tokens},
                             request_id=f'req_synthetic_{index}', status='completed',
                             text=json.dumps(value, ensure_ascii=False))


class SemanticReviewTests(unittest.TestCase):
    def setUp(self):
        base = parse_claim(support.raw_claim(locale='en-US'))
        self.claim = replace(base, ai={**base.ai, 'promptVersion': 'unpacked-analysis-ai-v5',
                                     'maxCalls': 12, 'maxOutputTokensPerJob': 16000})
        self.site = MemoryLedger()

    def run_stage(self, report, model=None, *, cancelled=lambda: False):
        model = model or ScriptedModel()
        stage = AiStage(self.site, support.API_KEY, support.MODEL, call=model)
        return stage.run(self.claim, report, time.monotonic() + 900, cancelled), model

    def test_diverse_scripted_effects_keep_exact_source_citations_and_zero_heuristic_score(self):
        scenarios = [
            ('legitimate clipboard', 'if (userPressedCopy) pasteboard_set(selectedText);', BENIGN,
             'userPressedCopy', ('The user requested copying the selected text.',)),
            ('clipboard substitution', 'if (matches_wallet(copied)) pasteboard_set(attacker_wallet);', 'malicious',
             'pasteboard_set(attacker_wallet)', ()),
            ('credential exfiltration', 'secret = read_keychain(); post(remote, secret);', 'malicious',
             'post(remote, secret)', ()),
            ('miner', 'for (;;) { work = pool_job(); nonce = hash_work(work); submit_share(nonce); }', 'malicious',
             'submit_share(nonce)', ()),
            ('ransomware', 'for (file in documents) { encrypt(file, key); unlink_original(file); }', 'malicious',
             'unlink_original(file)', ()),
            ('API name only', 'const char *help = "NSPasteboard bitcoin dlopen encrypt"; return help;', 'inconclusive',
             'return help', ()),
        ]
        for name, code, verdict, quote, counter in scenarios:
            with self.subTest(name=name):
                self.site = MemoryLedger()
                report = code_report([code])
                original = deepcopy(report)
                result, model = self.run_stage(report, ScriptedModel(batch_verdict=verdict,
                    final_verdict=verdict, quote=quote, counter=counter))
                self.assertEqual(result.status, 'completed')
                self.assertEqual(result.review['verdict'], verdict)
                self.assertTrue(result.review['synthesis_validated'])
                self.assertEqual(result.review['evidence'][0]['text'], quote)
                self.assertEqual(report, original)
                self.assertEqual(report['risk']['value'], 0)
                self.assertEqual(len(model.requests), 2)

    def test_each_chunk_and_settled_call_is_counted_and_no_input_exceeds_reservation(self):
        result, model = self.run_stage(code_report(['return 0;'] * 17))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(len(model.requests), 6)
        self.assertEqual(result.review['coverage']['reviewed_chunks'], 17)
        self.assertEqual(result.review['coverage']['reviewed_functions'], 17)
        self.assertTrue(result.review['coverage']['all_inventory_code_reviewed'])
        self.assertEqual(len(result.calls), len(self.site.settlements))
        self.assertEqual(result.cost_micros, 6 * 123)
        self.assertEqual(result.output_tokens, 600)
        for reserve, body in zip(self.site.reservations, model.requests):
            self.assertLessEqual(reserve['input_tokens'], self.claim.ai['maxInputTokensPerCall'])
            schema_size = len(json.dumps(body['text']['format'], ensure_ascii=False, separators=(',', ':')).encode())
            self.assertEqual(reserve['input_tokens'], len(body['instructions'].encode())
                             + len(body['input'].encode()) + schema_size + 256)
            self.assertLessEqual(reserve['output_tokens'], 6000)
            self.assertEqual(body['reasoning'], {'effort': 'medium'})
            self.assertFalse(body['store'])
            self.assertNotIn('tools', body)

    def test_full_legitimate_review_can_get_negative_with_counter_evidence(self):
        result, _ = self.run_stage(code_report(['if (userPressedCopy) pasteboard_set(selected);']),
                                  ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN,
                                                counter=('A user action supplies the selected text.',)))
        self.assertEqual((result.status, result.review['verdict']), ('completed', BENIGN))
        self.assertTrue(result.review['counter_evidence'])

    def test_inconclusive_chunks_cannot_be_erased_by_negative_synthesis(self):
        result, _ = self.run_stage(code_report(['indirect_unknown();']),
                                  ScriptedModel(batch_verdict='inconclusive', final_verdict=BENIGN))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.review['verdict'], 'inconclusive')
        self.assertTrue(result.review['synthesis_validated'])
        self.assertTrue(result.review['gaps'])

    def test_negative_requires_complete_provider_inventory_and_available_pseudocode(self):
        for report in (code_report(['return 0;'], provider_count=4), code_report(['return 0;', None])):
            with self.subTest(report=report):
                result, _ = self.run_stage(report, ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN))
                self.assertEqual(result.status, 'completed')
                self.assertEqual(result.review['verdict'], 'inconclusive')
                self.assertTrue(result.review['synthesis_validated'])
                self.assertTrue(result.review['gaps'])

    def test_negative_requires_no_material_gaps_or_positive_chunk(self):
        for verdict, gaps in ((BENIGN, ('The branch target requires its missing caller.',)), ('suspicious', ())):
            with self.subTest(verdict=verdict):
                result, _ = self.run_stage(code_report(['conditional_send();']),
                                          ScriptedModel(batch_verdict=verdict, final_verdict=BENIGN, gaps=gaps))
                self.assertEqual(result.review['verdict'], 'inconclusive')
                self.assertTrue(result.review['synthesis_validated'])
                self.assertTrue(result.review['gaps'])

    def test_max_calls_leaves_one_for_synthesis_and_preserves_partial_coverage(self):
        # Keep the verified-review inventory small enough for synthesis so this test
        # reaches the call ceiling rather than independently hitting the input ceiling.
        def concise(value, document, synthesis, index):
            if not synthesis:
                for item in value['chunks']:
                    item['summary'] = 'Code reviewed.'
                    item['evidence'] = []
        result, model = self.run_stage(code_report(['return 0;'] * 96), ScriptedModel(mutate=concise))
        self.assertEqual(len(model.requests), 12)
        self.assertEqual(result.review['coverage']['stopped_reason'], 'max_calls')
        self.assertEqual(result.review['coverage']['reviewed_functions'], 44)
        self.assertFalse(result.review['coverage']['all_captured_code_reviewed'])
        self.assertEqual(result.review['verdict'], 'inconclusive')

    def test_output_budget_reserves_synthesis_without_exceeding_16k(self):
        result, model = self.run_stage(code_report(['return 0;'] * 32), ScriptedModel(output_tokens=4000))
        self.assertEqual(len(model.requests), 4)
        self.assertEqual(result.output_tokens, 16000)
        self.assertEqual(result.review['coverage']['stopped_reason'], 'token_limit')
        self.assertEqual(result.review['coverage']['reviewed_functions'], 12)
        self.assertFalse(result.review['coverage']['all_inventory_code_reviewed'])

    def test_synthesis_input_overflow_preserves_reviewed_facts_without_extra_call(self):
        # The synthesis schema/instructions and verified identities leave less space than
        # the batch review format. A lower grant makes even the compact synthesis impossible.
        self.claim = replace(self.claim, ai={**self.claim.ai, 'maxInputTokensPerCall': 8000})
        result, model = self.run_stage(code_report(['return 0;'] * 9))
        self.assertGreater(len(model.requests), 0)
        self.assertTrue(all(json.loads(body['input'])['schema'] == 'unpacked-analysis-function-review/1'
                            for body in model.requests))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(result.review['coverage']['reviewed_functions'], 9)
        self.assertEqual(result.review['coverage']['stopped_reason'], 'synthesis_input_budget')
        self.assertFalse(result.review['synthesis_validated'])
        self.assertIsNone(result.output)

    def test_partial_call_budget_prevents_negative_claim(self):
        self.claim = replace(self.claim, ai={**self.claim.ai, 'maxCalls': 2})
        result, model = self.run_stage(code_report(['return 0;'] * 9),
                                      ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN))
        self.assertEqual(len(model.requests), 2)
        self.assertEqual(result.review['verdict'], 'inconclusive')
        self.assertTrue(result.review['synthesis_validated'])
        self.assertEqual(result.review['coverage']['reviewed_functions'], 4)

    def test_reservation_denial_never_calls_model(self):
        self.site.deny[0] = 'daily_budget'
        result, model = self.run_stage(code_report(['return 0;']))
        self.assertEqual(result.status, 'skipped_budget')
        self.assertEqual(model.requests, [])
        self.assertEqual(self.site.settlements, [])

    def test_cancelled_before_reservation_has_no_paid_effect(self):
        result, model = self.run_stage(code_report(['return 0;']), cancelled=lambda: True)
        self.assertNotEqual(result.status, 'completed')
        self.assertEqual(result.error_code, 'cancelled')
        self.assertEqual(model.requests, [])
        self.assertEqual(self.site.reservations, [])

    def test_too_little_input_budget_keeps_code_unreviewed(self):
        self.claim = replace(self.claim, ai={**self.claim.ai, 'maxInputTokensPerCall': 1000})
        result, model = self.run_stage(code_report(['return 0;']))
        self.assertNotEqual(result.status, 'completed')
        self.assertEqual(model.requests, [])
        self.assertEqual(result.review['coverage']['reviewed_functions'], 0)
        self.assertFalse(result.review['coverage']['all_inventory_code_reviewed'])

    def test_usage_unknown_stops_without_retry_or_synthesis(self):
        def override(*args):
            return ai.CallResult('usage_unknown', error_code='synthetic_timeout')
        result, model = self.run_stage(code_report(['return 0;'] * 9), ScriptedModel(override=override))
        self.assertEqual(result.status, 'usage_unknown')
        self.assertEqual(len(model.requests), 1)
        self.assertEqual(result.review['coverage']['reviewed_chunks'], 0)
        self.assertEqual(self.site.settlements[0]['outcome'], 'usage_unknown')

    def test_settlement_failure_stops_even_with_valid_model_output(self):
        self.site.fail_settlement_at = 0
        result, model = self.run_stage(code_report(['return 0;'] * 9))
        self.assertEqual(result.status, 'usage_unknown')
        self.assertEqual(len(model.requests), 1)
        self.assertEqual(result.review['coverage']['reviewed_chunks'], 0)
        self.assertEqual(result.cost_micros, 0)

    def test_synthesis_usage_unknown_preserves_coverage_but_no_published_output(self):
        def override(value, document, synthesis, index):
            return ai.CallResult('usage_unknown', error_code='synthetic_timeout') if synthesis else None
        result, model = self.run_stage(code_report(['return 0;']), ScriptedModel(override=override))
        self.assertEqual((result.status, len(model.requests)), ('usage_unknown', 2))
        self.assertEqual(result.review['coverage']['reviewed_chunks'], 1)
        self.assertFalse(result.review['synthesis_validated'])
        self.assertIsNone(result.output)

    def test_refusal_is_invalid_output_and_never_a_budget_skip(self):
        def override(*args):
            return ai.CallResult('succeeded', usage={'inputTokens': 100, 'cachedInputTokens': 0, 'outputTokens': 20},
                                 request_id='req_refusal', status='completed', refusal='Synthetic refusal')
        result, model = self.run_stage(code_report(['return 0;']), ScriptedModel(override=override))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(len(model.requests), 1)
        self.assertFalse(result.review['synthesis_validated'])

    def test_malformed_batch_json_is_invalid_and_never_a_budget_skip(self):
        def override(*args):
            return ai.CallResult('succeeded', usage={'inputTokens': 100, 'cachedInputTokens': 0, 'outputTokens': 20},
                                 status='completed', text='{broken')
        result, model = self.run_stage(code_report(['return 0;']), ScriptedModel(override=override))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(result.error_code, 'invalid_batch')
        self.assertEqual(len(model.requests), 1)

    def test_incomplete_provider_response_never_counts_as_reviewed(self):
        def override(value, document, synthesis, index):
            return ai.CallResult('succeeded', usage={'inputTokens': 100, 'cachedInputTokens': 0, 'outputTokens': 100},
                                 status='incomplete', incomplete_reason='max_output_tokens', text=json.dumps(value))
        result, model = self.run_stage(code_report(['return 0;']), ScriptedModel(override=override))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(result.review['coverage']['reviewed_chunks'], 0)
        self.assertEqual(len(model.requests), 1)

    def test_malformed_unicode_model_text_is_rejected_before_synthesis_serialization(self):
        def mutate(value, document, synthesis, index):
            if not synthesis:
                value['chunks'][0]['summary'] = '\ud800'
        result, model = self.run_stage(code_report(['return 0;']), ScriptedModel(mutate=mutate))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(result.review['coverage']['reviewed_chunks'], 0)
        self.assertEqual(len(model.requests), 1)

    def test_malformed_unicode_in_legacy_synthesis_field_is_rejected_before_publication(self):
        def mutate(value, document, synthesis, index):
            if synthesis:
                value['summary'] = '\ud800'
        result, model = self.run_stage(code_report(['return 0;']), ScriptedModel(mutate=mutate))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(result.error_code, 'invalid_synthesis')
        self.assertEqual(len(model.requests), 2)
        self.assertIsNone(result.output)

    def test_invalid_batch_never_counts_partial_chunks(self):
        changes = {
            'missing': lambda value: value['chunks'].pop(),
            'duplicate': lambda value: value['chunks'].__setitem__(1, deepcopy(value['chunks'][0])),
            'digest': lambda value: value['chunks'][0].__setitem__('source_sha256', 'b' * 64),
            'unknown': lambda value: value['chunks'][0].__setitem__('chunk_id', 'unknown'),
            'quote': lambda value: value['chunks'][0]['evidence'][0].__setitem__('quote', 'not in source'),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                def mutate(value, document, synthesis, index):
                    if not synthesis:
                        change(value)
                result, model = self.run_stage(code_report(['return 0;', 'return 1;']),
                                              ScriptedModel(mutate=mutate))
                self.assertEqual(result.status, 'invalid')
                self.assertEqual(result.review['coverage']['reviewed_chunks'], 0)
                self.assertEqual(len(model.requests), 1)

    def test_unicode_quote_offsets_refer_to_exact_original_characters(self):
        code = '/* 😀İe\u0301 */\nconst char *texto = "ação"; return texto;'
        quote = '"ação"; return texto'
        result, _ = self.run_stage(code_report([code]), ScriptedModel(quote=quote))
        self.assertEqual(result.status, 'completed')
        proof = result.review['evidence'][0]
        self.assertEqual(proof['start_character'], code.index(quote))
        self.assertEqual(code[proof['start_character']:proof['end_character']], quote)

    def test_synthesis_must_use_a_reviewed_chunk_and_literal_source(self):
        for mutation in ('quote', 'chunk'):
            with self.subTest(mutation=mutation):
                def mutate(value, document, synthesis, index):
                    if synthesis:
                        proof = value['classification']['evidence'][0]
                        proof['quote' if mutation == 'quote' else 'chunk_id'] = 'fabricated'
                result, _ = self.run_stage(code_report(['return 0;']), ScriptedModel(mutate=mutate))
                self.assertEqual(result.status, 'invalid')
                self.assertEqual(result.error_code, 'invalid_synthesis')
                self.assertIsNone(result.output)

    def test_synthesis_can_choose_another_literal_quote_from_supplied_reviewed_code(self):
        code = '/* 😀 */ prepare();\nsend(secret);'
        def mutate(value, document, synthesis, index):
            if synthesis:
                value['classification']['evidence'][0]['quote'] = 'send(secret);'
        result, _ = self.run_stage(code_report([code]), ScriptedModel(quote='prepare();', mutate=mutate))
        self.assertEqual(result.status, 'completed')
        proof = result.review['evidence'][0]
        self.assertEqual(proof['text'], 'send(secret);')
        self.assertEqual(proof['start_character'], code.index('send(secret);'))
        self.assertEqual(code[proof['start_character']:proof['end_character']], proof['text'])

    def test_synthesis_cannot_cite_unsupplied_context_even_inside_a_reviewed_chunk(self):
        code = 'return 0;\n' + ('a' * 6500) + 'HIDDEN_MIDDLE_LITERAL' + ('b' * 6500)
        def mutate(value, document, synthesis, index):
            if synthesis:
                self.assertNotIn('HIDDEN_MIDDLE_LITERAL', json.dumps(document['engine_context']))
                value['classification']['evidence'][0]['quote'] = 'HIDDEN_MIDDLE_LITERAL'
        result, _ = self.run_stage(code_report([code]), ScriptedModel(quote='return 0;', mutate=mutate))
        self.assertEqual(result.error_code, 'invalid_synthesis')
        self.assertFalse(result.review['synthesis_validated'])

    def test_positive_batch_requires_a_source_quote(self):
        def mutate(value, document, synthesis, index):
            if not synthesis:
                value['chunks'][0]['evidence'] = []
        result, model = self.run_stage(code_report(['do_something();']),
                                      ScriptedModel(batch_verdict='malicious', mutate=mutate))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(len(model.requests), 1)

    def test_batch_validator_rejects_long_or_structurally_malformed_proofs(self):
        report = code_report(['a' * 600])
        batch = plan_reviews(report, self.claim.sample, 'en-US', 30000).batches[0]
        value = batch_value(json.loads(batch.text))
        for proof in ({'quote': 'a' * 401, 'statement': 'x'}, {'quote': 'a', 'statement': 'x' * 801},
                      {'quote': 1, 'statement': 'x'}, {'quote': 'a', 'statement': 'x', 'extra': 1}):
            with self.subTest(proof=proof):
                changed = deepcopy(value)
                changed['chunks'][0]['evidence'] = [proof]
                self.assertIsNone(validate_batch(changed, batch))

    def test_no_decompiled_code_creates_no_fictitious_review_or_paid_call(self):
        result, model = self.run_stage(code_report([None]))
        self.assertNotEqual(result.status, 'completed')
        self.assertEqual(model.requests, [])
        self.assertEqual(result.review['coverage']['reviewed_functions'], 0)
        self.assertFalse(result.review['coverage']['all_inventory_code_reviewed'])

    def test_no_findings_constrains_legacy_facets_and_keeps_code_classification(self):
        result, model = self.run_stage(code_report(['void f(){ copy_user_selection(); }']),
                                       ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN))
        self.assertEqual(result.status, 'completed')
        schema = model.requests[-1]['text']['format']['schema']['properties']
        self.assertEqual(schema['behaviors']['maxItems'], 0)
        self.assertEqual(schema['techniques']['maxItems'], 0)
        self.assertEqual(schema['functions']['items']['properties']['evidence_ids']['maxItems'], 0)
        self.assertEqual(schema['functions']['maxItems'], 0)
        self.assertEqual(schema['behaviors']['items']['properties']['evidence_ids']['minItems'], 1)
        self.assertEqual(result.review['verdict'], BENIGN)

    def test_twenty_four_function_notes_are_retained_without_duplicate_synthesis_annotations(self):
        self.claim = replace(self.claim, ai={**self.claim.ai, 'maxOutputTokensFirstCall': 6000})
        result, model = self.run_stage(code_report(['return 0;'] * 24),
            ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.review['coverage']['reviewed_functions'], 24)
        self.assertTrue(result.review['coverage']['all_inventory_code_reviewed'])
        self.assertTrue(all(item['summary'] for item in result.review['functions']))
        self.assertEqual(result.output['functions'], [])
        self.assertEqual(model.requests[-1]['text']['format']['schema']['properties']['functions']['maxItems'], 0)
        self.assertEqual(model.requests[-1]['max_output_tokens'], 6000)

    def test_synthesis_rejects_duplicate_function_annotations_outside_v5_schema(self):
        def mutate(value, document, synthesis, index):
            if synthesis:
                value['functions'] = [{'architecture': 'arm64', 'address': '0x100000100',
                    'title': 'Repeated note', 'explanation': 'Already retained.', 'evidence_ids': []}]
        result, _ = self.run_stage(code_report(['return 0;']), ScriptedModel(mutate=mutate))
        self.assertEqual(result.review['coverage']['stopped_reason'], 'invalid_synthesis')
        self.assertFalse(result.review['synthesis_validated'])

    def test_synthesis_reduces_rejected_reservation_without_repeating_a_paid_call(self):
        self.claim = replace(self.claim, ai={**self.claim.ai, 'maxOutputTokensFirstCall': 6000})
        reserve = self.site.ai_reserve
        def bounded(*args):
            result = reserve(*args)
            return {'granted': False, 'reason': 'job_budget'} if args[3] == 6 and args[5] > 4000 else result
        self.site.ai_reserve = bounded
        result, model = self.run_stage(code_report(['return 0;'] * 24),
            ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN))
        self.assertEqual(result.status, 'completed')
        self.assertTrue(result.review['synthesis_validated'])
        self.assertEqual(len(model.requests), 7)
        self.assertEqual(len(self.site.settlements), 7)
        self.assertEqual([r['output_tokens'] for r in self.site.reservations[-2:]], [6000, 4000])
        self.assertEqual([r['index'] for r in self.site.reservations[-2:]], [6, 6])
        self.assertEqual(model.requests[-1]['max_output_tokens'], 4000)

    def test_synthesis_still_blocked_at_minimum_reservation_spends_no_extra_call(self):
        self.site.deny[1] = 'job_budget'
        result, model = self.run_stage(code_report(['return 0;']),
            ScriptedModel(batch_verdict=BENIGN, final_verdict=BENIGN))
        self.assertEqual(result.review['coverage']['stopped_reason'], 'job_budget')
        self.assertFalse(result.review['synthesis_validated'])
        self.assertEqual(len(model.requests), 1)
        self.assertEqual(len(self.site.settlements), 1)
        self.assertLessEqual(len(self.site.reservations), 4)

    def test_global_budget_denial_does_not_negotiate_or_send_synthesis(self):
        self.site.deny[1] = 'daily_budget'
        result, model = self.run_stage(code_report(['return 0;']))
        self.assertEqual(result.review['coverage']['stopped_reason'], 'daily_budget')
        self.assertEqual(len(self.site.reservations), 2)
        self.assertEqual(len(model.requests), 1)

    def test_legacy_v4_remains_single_call_low_reasoning_without_semantic_review(self):
        self.claim = replace(self.claim, ai={**self.claim.ai, 'promptVersion': 'unpacked-analysis-ai-v4',
                                           'maxCalls': 2, 'maxOutputTokensPerJob': 8000})
        calls = []
        def legacy(key, body, **kwargs):
            calls.append(body)
            return ai.CallResult('succeeded', usage={'inputTokens': 100, 'cachedInputTokens': 0, 'outputTokens': 100},
                                 request_id='req_legacy', status='completed', text=json.dumps(support.valid_output()))
        stage = AiStage(self.site, support.API_KEY, support.MODEL, call=legacy)
        result = stage.run(self.claim, support.report(), time.monotonic() + 600)
        self.assertEqual(result.status, 'completed')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['reasoning'], {'effort': 'low'})
        self.assertIsNone(result.review)


if __name__ == '__main__':
    unittest.main()
