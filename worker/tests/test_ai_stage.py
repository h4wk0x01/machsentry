"""AI stage against a local fake of the Responses API and the site: grants, settlements, at most
two calls, and no repeated call after an uncertain outcome."""

import json
import time
import unittest

import worker_support as support
from machsentry_worker import ai
from machsentry_worker.ai_stage import AiStage
from machsentry_worker.job import parse_claim
from machsentry_worker.site_api import SiteApi


class AiStageTests(unittest.TestCase):
    def setUp(self):
        self.site = support.FakeSite()
        self.addCleanup(self.site.close)
        self.site.respond('/jobs/:id/ai/reserve', lambda body: (200, {'granted': True, 'callId': f'call_{body["callIndex"]}'}))
        self.site.respond('/jobs/:id/ai/settle', lambda body: (200, {'costMicros': 1000 + len(body['outcome'])}))
        self.api = SiteApi(self.site.url, support.TOKEN, timeout=5, sleep=lambda _: None)
        self.claim = parse_claim(support.raw_claim())
        self.report = support.report()

    def stage(self, openai: support.FakeOpenAI, timeout: float = 5) -> AiStage:
        def call(key, body, **kwargs):
            return ai.call(key, body, **{**kwargs, 'url': openai.endpoint, 'timeout': min(kwargs['timeout'], timeout)})
        return AiStage(self.api, support.API_KEY, support.MODEL, call=call)

    def run_stage(self, *script, timeout: float = 5):
        openai = support.FakeOpenAI(*script)
        self.addCleanup(openai.close)
        result = self.stage(openai, timeout).run(self.claim, self.report, time.monotonic() + 600)
        return result, openai

    def test_reservation_denied_means_no_call(self):
        self.site.respond('/jobs/:id/ai/reserve', (200, {'granted': False, 'reason': 'daily_budget'}))
        result, openai = self.run_stage()
        self.assertEqual(result.status, 'skipped_budget')
        self.assertEqual(openai.requests, [])
        self.assertEqual(self.site.calls('/jobs/:id/ai/settle'), [])

    def test_valid_output_completes_after_one_settled_call(self):
        result, openai = self.run_stage(('json', 200, support.response_body(json.dumps(support.valid_output()))))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.output['techniques'][0]['id'], 'T1056.002')
        self.assertEqual(len(openai.requests), 1)
        request = openai.requests[0]
        body = request['body']
        self.assertEqual(set(body), {'model', 'instructions', 'input', 'text', 'max_output_tokens', 'store', 'reasoning'})
        self.assertEqual((body['model'], body['store'], body['reasoning'], body['max_output_tokens']),
                         (support.MODEL, False, {'effort': 'low'}, 6000))
        self.assertEqual(body['text']['format']['type'], 'json_schema')
        self.assertTrue(body['text']['format']['strict'])
        self.assertNotIn('tools', body)
        self.assertEqual(request['headers']['Authorization'], 'Bearer test-openai-key-not-a-secret')
        self.assertEqual(request['headers']['X-Client-Request-Id'], 'call_0')
        reserve = self.site.calls('/jobs/:id/ai/reserve')[0]
        schema_bytes = len(json.dumps(body['text']['format'], ensure_ascii=False, separators=(',', ':')).encode())
        self.assertEqual(reserve['inputTokens'], len(body['instructions'].encode()) + len(body['input'].encode())
                         + schema_bytes + 256)
        self.assertLessEqual(reserve['inputTokens'], 40000)
        settle = self.site.calls('/jobs/:id/ai/settle')
        self.assertEqual(settle, [{'attempt': 1, 'leaseToken': 'lease-token-test', 'callId': 'call_0',
                                   'outcome': 'succeeded', 'requestId': 'req_test_123',
                                   'usage': {'inputTokens': 1200, 'cachedInputTokens': 200, 'outputTokens': 300}}])
        self.assertEqual((result.input_tokens, result.cached_input_tokens, result.output_tokens), (1200, 200, 300))
        self.assertEqual(result.cost_micros, 1009)
        self.assertEqual(result.assessment()['calls'][0]['costMicros'], 1009)

    def test_invalid_output_gets_one_correction_then_stays_invalid(self):
        bad = support.valid_output()
        bad['behaviors'][0]['evidence_ids'] = ['s9:str:404']
        result, openai = self.run_stage(('json', 200, support.response_body(json.dumps(bad))),
                                        ('json', 200, support.response_body(json.dumps(bad), output_tokens=500)))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(len(openai.requests), 2)
        second = openai.requests[1]['body']
        self.assertEqual(second['max_output_tokens'], 8000 - 300)
        correction = json.loads(second['input'])
        self.assertIn('behaviors[0].evidence_ids[0]: unknown evidence id', correction['correction']['errors'])
        self.assertEqual(json.loads(correction['correction']['previous_output']), bad)
        self.assertEqual([body['callIndex'] for body in self.site.calls('/jobs/:id/ai/reserve')], [0, 1])
        self.assertEqual(len(self.site.calls('/jobs/:id/ai/settle')), 2)
        self.assertTrue(result.validation_errors)
        self.assertIsNone(result.assessment()['output'])

    def test_unlinked_script_or_ioc_citation_goes_through_the_correction_call(self):
        # The site resolves only findings and their evidence: citing an unlinked script or IOC
        # string is a validation error here, never a silent drop after publication.
        self.report = support.unlinked_script_and_ioc(support.report())
        bad = support.valid_output()
        bad['behaviors'][0]['evidence_ids'] = ['s0:credential_prompt', support.UNLINKED_SCRIPT]
        bad['techniques'][0]['evidence_ids'] = [support.UNLINKED_IOC]
        result, openai = self.run_stage(('json', 200, support.response_body(json.dumps(bad))),
                                        ('json', 200, support.response_body(json.dumps(support.valid_output()))))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(len(openai.requests), 2)
        errors = json.loads(openai.requests[1]['body']['input'])['correction']['errors']
        self.assertEqual(errors, ['behaviors[0].evidence_ids[1]: unknown evidence id',
                                  'techniques[0].evidence_ids[0]: unknown evidence id'])
        instructions = openai.requests[0]['body']['instructions']
        self.assertIn('strings[].id or findings[].id, nothing else', instructions)

    def test_correction_can_complete(self):
        bad = support.valid_output()
        bad['functions'][0]['address'] = '0xdeadbeef'
        result, _ = self.run_stage(('json', 200, support.response_body(json.dumps(bad))),
                                   ('json', 200, support.response_body(json.dumps(support.valid_output()))))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(result.validation_errors, [])

    def test_timeout_is_usage_unknown_and_never_repeated(self):
        result, openai = self.run_stage(('sleep', 2.0), timeout=0.5)
        self.assertEqual(result.status, 'usage_unknown')
        self.assertEqual(len(openai.requests), 1)
        settle = self.site.calls('/jobs/:id/ai/settle')
        self.assertEqual(len(settle), 1)
        self.assertEqual((settle[0]['outcome'], settle[0]['errorCode']), ('usage_unknown', 'timeout'))
        self.assertEqual(len(self.site.calls('/jobs/:id/ai/reserve')), 1)

    def test_http_500_is_failed_not_billed(self):
        result, openai = self.run_stage(('json', 500, {'error': {'code': 'server_error', 'message': 'x'}}))
        self.assertEqual(result.status, 'failed')
        self.assertEqual(len(openai.requests), 1)
        settle = self.site.calls('/jobs/:id/ai/settle')[0]
        self.assertEqual((settle['outcome'], settle['errorCode'], settle['requestId']),
                         ('failed_not_billed', 'server_error', 'req_test_123'))
        self.assertNotIn('usage', settle)

    def test_refusal(self):
        result, openai = self.run_stage(('json', 200, support.response_body(refusal='I cannot help with that.')))
        self.assertEqual((result.status, result.error_code), ('failed', 'refusal'))
        self.assertEqual(len(openai.requests), 1)
        self.assertEqual(self.site.calls('/jobs/:id/ai/settle')[0]['outcome'], 'succeeded')

    def test_failed_response_status_gets_no_correction(self):
        body = support.response_body(None, status='failed')
        body['error'] = {'code': 'server_error', 'message': 'x'}
        result, openai = self.run_stage(('json', 200, body))
        self.assertEqual((result.status, result.error_code), ('failed', 'server_error'))
        self.assertEqual(len(openai.requests), 1)

    def test_incomplete_response_is_corrected_with_the_remaining_budget(self):
        result, openai = self.run_stage(
            ('json', 200, support.response_body('{"summary": "cut', status='incomplete', incomplete='max_output_tokens',
                                                output_tokens=6000)),
            ('json', 200, support.response_body(json.dumps(support.valid_output()))))
        self.assertEqual(result.status, 'completed')
        self.assertEqual(openai.requests[1]['body']['max_output_tokens'], 2000)

    def test_connection_lost_after_sending(self):
        result, openai = self.run_stage(('drop',))
        self.assertEqual(result.status, 'usage_unknown')
        self.assertEqual(len(openai.requests), 1)

    def test_nothing_runs_for_failed_engine_or_missing_key(self):
        openai = support.FakeOpenAI()
        self.addCleanup(openai.close)
        failed = AiStage(self.api, support.API_KEY, support.MODEL).run(self.claim, support.report(status='failed'),
                                                                       time.monotonic() + 600)
        self.assertEqual(failed.status, 'not_requested')
        missing = AiStage(self.api, None, support.MODEL).run(self.claim, self.report, time.monotonic() + 600)
        self.assertEqual((missing.status, missing.error_code), ('failed', 'api_key_missing'))
        mismatch = AiStage(self.api, support.API_KEY, 'gpt-other').run(self.claim, self.report, time.monotonic() + 600)
        self.assertEqual(mismatch.error_code, 'model_mismatch')
        late = AiStage(self.api, support.API_KEY, support.MODEL).run(self.claim, self.report, time.monotonic() + 10)
        self.assertEqual(late.error_code, 'no_time')
        self.assertEqual(self.site.requests, [])
        self.assertEqual(openai.requests, [])

    def test_settle_failure_stops_further_calls(self):
        self.site.respond('/jobs/:id/ai/settle', (503, None))
        bad = support.valid_output()
        bad['gaps'] = ['']
        self.api = SiteApi(self.site.url, support.TOKEN, timeout=5, attempts=2, sleep=lambda _: None)
        result, openai = self.run_stage(('json', 200, support.response_body(json.dumps(bad))))
        self.assertEqual(result.status, 'invalid')
        self.assertEqual(len(openai.requests), 1)


if __name__ == '__main__':
    unittest.main()
