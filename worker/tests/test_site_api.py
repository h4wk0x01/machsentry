"""Worker API client: request shapes, bearer token, bounded retries and typed errors."""

import unittest

import worker_support as support
from machsentry_worker import USER_AGENT
from machsentry_worker.site_api import LeaseLost, SiteApi, SiteError, SiteUnavailable, Unauthorized


class SiteApiTests(unittest.TestCase):
    def setUp(self):
        self.site = support.FakeSite()
        self.addCleanup(self.site.close)
        self.sleeps = []
        self.api = SiteApi(self.site.url, support.TOKEN, timeout=5, sleep=self.sleeps.append)

    def test_headers_and_body_shape(self):
        self.site.respond('/jobs/:id/heartbeat', (200, {'cancel': False, 'deadlineAt': '2026-10-18T12:20:00Z'}))
        self.assertEqual(self.api.heartbeat('job_1', 1, 'lease', 'static_analysis'),
                         {'cancel': False, 'deadlineAt': '2026-10-18T12:20:00Z'})
        request = self.site.requests[0]
        self.assertEqual(request['headers']['Authorization'], 'Bearer test-worker-token-not-a-secret')
        self.assertEqual(request['headers']['User-Agent'], USER_AGENT)
        self.assertEqual(request['headers']['Content-Type'], 'application/json')
        self.assertEqual(request['body'], {'attempt': 1, 'leaseToken': 'lease', 'phase': 'static_analysis'})

    def test_every_route_uses_contract_field_names(self):
        for route in ('/worker/boot', '/worker/ready', '/worker/claim', '/worker/idle', '/worker/stopping',
                      '/jobs/:id/ai/reserve', '/jobs/:id/ai/settle', '/jobs/:id/artifacts', '/jobs/:id/complete',
                      '/jobs/:id/fail'):
            self.site.respond(route, (200, {'ok': True}))
        self.api.boot('i-1', 'boot', 'sha256:' + 'a' * 64, 'abc1234',
                      [{'jobId': 'j', 'attempt': 1, 'cleanupConfirmed': True, 'reason': 'worker_restart'}])
        self.api.ready('run', 'i-1', {'image': True}, {'worker': '0.1.0'})
        self.api.claim('run', 'i-1')
        self.api.idle('run', 'i-1')
        self.api.stopping('run', 'watchdog')
        self.api.ai_reserve('j', 1, 'l', 0, 1000, 6000, 'model', 'prompt')
        self.api.ai_settle('j', 1, 'l', 'call', 'succeeded', usage={'inputTokens': 1, 'cachedInputTokens': 0,
                                                                     'outputTokens': 2}, request_id='req')
        self.api.ai_settle('j', 1, 'l', 'call', 'usage_unknown', error_code='timeout')
        self.api.artifacts('j', 1, 'l', [{'name': 'service-result.json', 'size': 1, 'sha256': 'a' * 64}])
        self.api.complete('j', 1, 'l', 'partial', 'completed', [], {'elapsedSeconds': 1}, {'containerRemoved': True})
        self.api.fail('j', 1, 'l', 'oom', False, {'containerRemoved': True})
        bodies = {route: self.site.calls(route) for route in set(self.site.routes_called())}
        self.assertEqual(set(bodies['/worker/boot'][0]), {'instanceId', 'bootId', 'image', 'release', 'terminatedAttempts'})
        self.assertEqual(set(bodies['/worker/ready'][0]), {'runId', 'instanceId', 'checks', 'versions'})
        self.assertEqual(bodies['/worker/claim'][0], {'runId': 'run', 'instanceId': 'i-1'})
        self.assertEqual(bodies['/worker/idle'][0], {'runId': 'run', 'instanceId': 'i-1'})
        self.assertEqual(bodies['/worker/stopping'][0], {'runId': 'run', 'reason': 'watchdog'})
        self.assertEqual(bodies['/jobs/:id/ai/reserve'][0], {
            'attempt': 1, 'leaseToken': 'l', 'callIndex': 0, 'inputTokens': 1000, 'maxOutputTokens': 6000,
            'model': 'model', 'promptVersion': 'prompt'})
        self.assertEqual(set(bodies['/jobs/:id/ai/settle'][0]),
                         {'attempt', 'leaseToken', 'callId', 'outcome', 'usage', 'requestId'})
        self.assertEqual(set(bodies['/jobs/:id/ai/settle'][1]), {'attempt', 'leaseToken', 'callId', 'outcome', 'errorCode'})
        self.assertEqual(set(bodies['/jobs/:id/artifacts'][0]), {'attempt', 'leaseToken', 'artifacts'})
        self.assertEqual(set(bodies['/jobs/:id/complete'][0]), {
            'attempt', 'leaseToken', 'engineStatus', 'aiStatus', 'artifacts', 'metrics', 'cleanup'})
        self.assertEqual(set(bodies['/jobs/:id/fail'][0]), {'attempt', 'leaseToken', 'code', 'retryable', 'cleanup'})

    def test_idempotent_calls_retry_transient_failures(self):
        self.site.respond('/jobs/:id/complete', (503, {'error': 'maintenance'}), 'drop', (429, None), (200, {'id': 'j'}))
        self.assertEqual(self.api.complete('j', 1, 'l', 'partial', 'completed', [], {}, {}), {'id': 'j'})
        self.assertEqual(len(self.site.calls('/jobs/:id/complete')), 4)
        self.assertEqual(self.sleeps, [1.0, 2.0, 4.0])

    def test_retries_are_bounded(self):
        self.site.respond('/jobs/:id/settle', (502, None))
        self.site.respond('/jobs/:id/ai/settle', (502, None))
        with self.assertRaises(SiteUnavailable):
            self.api.ai_settle('j', 1, 'l', 'c', 'succeeded')
        self.assertEqual(len(self.site.calls('/jobs/:id/ai/settle')), 4)

    def test_claim_reserve_and_idle_are_sent_once(self):
        for route in ('/worker/claim', '/jobs/:id/ai/reserve', '/worker/idle'):
            self.site.respond(route, (503, None))
        for call in (lambda: self.api.claim('r', 'i'), lambda: self.api.idle('r', 'i'),
                     lambda: self.api.ai_reserve('j', 1, 'l', 0, 1, 1, 'm', 'p')):
            with self.assertRaises(SiteUnavailable):
                call()
        self.assertEqual(self.site.routes_called(), ['/worker/claim', '/worker/idle', '/jobs/:id/ai/reserve'])

    def test_typed_errors(self):
        self.site.respond('/jobs/:id/heartbeat', (409, {'error': 'lease_lost'}))
        with self.assertRaises(LeaseLost):
            self.api.heartbeat('j', 1, 'l', 'ai_review')
        self.site.respond('/worker/claim', (401, {'error': 'unauthorized'}))
        with self.assertRaises(Unauthorized):
            self.api.claim('r', 'i')
        self.site.respond('/jobs/:id/cancel', (409, {'error': 'already_finished'}))
        self.site.respond('/jobs/:id/fail', (409, {'error': 'already_finished'}))
        with self.assertRaises(SiteError) as caught:
            self.api.fail('j', 1, 'l', 'oom', False, {})
        self.assertEqual(caught.exception.code, 'already_finished')
        self.assertNotIsInstance(caught.exception, LeaseLost)

    def test_redirects_are_not_followed(self):
        def redirect(handler, _):
            handler.send_response(307)
            handler.send_header('Location', 'http://127.0.0.1:9/elsewhere')
            handler.send_header('Content-Length', '0')
            handler.end_headers()
        self.site.dispatch = redirect
        with self.assertRaises(SiteError) as caught:
            self.api.stopping('r', 'x')
        self.assertEqual(caught.exception.code, 'http_307')

    def test_oversized_request_is_refused_locally(self):
        with self.assertRaises(SiteError) as caught:
            self.api.fail('j', 1, 'l', 'internal', False, {'blob': 'x' * 70_000})
        self.assertEqual(caught.exception.code, 'request_too_large')
        self.assertEqual(self.site.requests, [])


if __name__ == '__main__':
    unittest.main()
