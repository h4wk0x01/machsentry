"""Supervisor flows against the fake site, docker CLI and host: completion, cancel, lease loss,
failures, boot reconcile, readiness, idle stop race and unreachable site."""

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import time
import unittest

import worker_support as support
from machsentry_worker import ai
from machsentry_worker.ai_stage import AiStage
from machsentry_worker.config import ConfigError, HostConfig, Release
from machsentry_worker.docker_runner import DockerRunner
from machsentry_worker.site_api import SiteApi
from machsentry_worker.state import State
from machsentry_worker.supervisor import Supervisor

IMAGE_ID = 'sha256:' + 'c' * 64
CLEAN = {'containerRemoved': True, 'workdirRemoved': True, 'sampleDeleted': True}


class Harness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = HostConfig(region='us-east-2', state_dir=root / 'state', release_file=root / 'release.json',
                                 heartbeat_file=root / 'run' / 'heartbeat')
        self.site = support.FakeSite()
        self.addCleanup(self.site.close)
        self.site.sample = support.sample_bytes()
        self.site.respond('/jobs/:id/heartbeat', (200, {'cancel': False, 'deadlineAt': '2030-01-01T00:00:00Z'}))
        self.site.respond('/jobs/:id/ai/reserve', lambda body: (200, {'granted': True, 'callId': f'call_{body["callIndex"]}'}))
        self.site.respond('/jobs/:id/ai/settle', (200, {'costMicros': 2500}))
        self.site.respond('/jobs/:id/artifacts', self.site.upload_grant)
        self.site.respond('/jobs/:id/complete', (200, {'id': 'job_1', 'status': 'completed'}))
        self.site.respond('/jobs/:id/fail', (200, {'id': 'job_1', 'status': 'failed'}))
        self.api = SiteApi(self.site.url, support.TOKEN, timeout=5, sleep=lambda _: None)
        self.openai = support.FakeOpenAI(('json', 200, support.response_body(json.dumps(support.valid_output()))))
        self.addCleanup(self.openai.close)
        self.docker = support.FakeDockerCli(on_run=support.engine_writer(), image_id=IMAGE_ID)
        self.ops = support.FakeOps()
        self.powered_off = []

    def supervisor(self, **overrides) -> Supervisor:
        endpoint = self.openai.endpoint
        stage = AiStage(self.api, support.API_KEY, support.MODEL,
                        call=lambda key, body, **kwargs: ai.call(key, body, **{**kwargs, 'url': endpoint}))
        options = dict(site=self.api, cli=self.docker, runner=DockerRunner(self.docker, sleep=lambda _: time.sleep(0.01)),
                       ops=self.ops, state=State(self.config.state_file), ai_stage=stage, config=self.config,
                       release=Release('abc1234', IMAGE_ID), instance_id='i-0test', boot_id='boot1234abcd',
                       poweroff=lambda: self.powered_off.append(True), poll_seconds=0.01, heartbeat_seconds=0.05)
        options.update(overrides)
        supervisor = Supervisor(**options)
        supervisor.run_id = 'run_1'
        return supervisor

    def claim(self, **kwargs) -> dict:
        return support.raw_claim(self.site.url + '/sealed/job_1/sample', **kwargs)

    def jobs_empty(self) -> bool:
        return not any(self.config.jobs_dir.iterdir()) if self.config.jobs_dir.exists() else True


class JobTests(Harness):
    def test_job_runs_to_completion(self):
        observed = {}

        def reserve(body):
            # The static stage is over: sample, container and loop image must already be gone.
            observed['jobs_empty'] = self.jobs_empty()
            observed['containers'] = dict(self.docker.containers)
            return 200, {'granted': True, 'callId': 'call_0'}
        self.site.respond('/jobs/:id/ai/reserve', reserve)
        supervisor = self.supervisor()
        ai_run = supervisor.ai_stage.run

        def bounded_ai(claim, report, deadline, cancelled):
            self.assertGreater(deadline - supervisor.clock(), claim.limits['aiSeconds'] - 1)
            self.assertLessEqual(deadline - supervisor.clock(), claim.limits['aiSeconds'])
            return ai_run(claim, report, deadline, cancelled)

        supervisor.ai_stage.run = bounded_ai
        self.assertTrue(supervisor.process(self.claim()))
        self.assertEqual(observed, {'jobs_empty': True, 'containers': {}})
        routes = [route for route in self.site.routes_called() if route != '/jobs/:id/heartbeat']
        self.assertEqual(routes[:4], ['GET sample', '/jobs/:id/ai/reserve', '/jobs/:id/ai/settle', '/jobs/:id/artifacts'])
        self.assertEqual(routes[-1], '/jobs/:id/complete')
        phases = [body['phase'] for body in self.site.calls('/jobs/:id/heartbeat')]
        self.assertEqual(phases[0], 'static_analysis')
        self.assertLess(phases.index('ai_review'), phases.index('publishing'))
        complete = self.site.calls('/jobs/:id/complete')[0]
        self.assertEqual((complete['engineStatus'], complete['aiStatus'], complete['cleanup']), ('partial', 'completed', CLEAN))
        self.assertEqual(complete['attempt'], 1)
        self.assertEqual(complete['leaseToken'], 'lease-token-test')
        self.assertEqual({item['name'] for item in complete['artifacts']},
                         {'service-result.json', 'report-view.json', 'report.html', 'functions.json', 'report.json',
                          'detection.yar', 'ai-assessment.json'})
        self.assertEqual(set(complete['metrics']), {'elapsedSeconds', 'staticSeconds', 'aiSeconds', 'cpuSeconds',
                                                    'peakMemoryBytes', 'diskBytes', 'inputTokens', 'cachedInputTokens',
                                                    'outputTokens', 'aiCostMicros'})
        self.assertEqual((complete['metrics']['aiCostMicros'], complete['metrics']['diskBytes']), (2500, 123456))
        service = json.loads(self.site.objects['service-result.json']['data'])
        self.assertEqual((service['jobId'], service['image'], service['release'], service['cleanup']),
                         ('job_1', IMAGE_ID, 'abc1234', CLEAN))
        assessment = json.loads(self.site.objects['ai-assessment.json']['data'])
        self.assertEqual((assessment['status'], assessment['calls'][0]['callId']), ('completed', 'call_0'))
        run = next(entry for entry in self.docker.log if entry[0] == 'run')
        self.assertEqual(run, ('run', 'machsentry-job_1-1'))
        self.assertTrue(self.jobs_empty())
        self.assertFalse((self.config.state_dir / 'results' / 'job_1-1').exists())
        self.assertIsNone(State(self.config.state_file).active)
        logs = support.LOGS.getvalue()
        for secret in ('test-worker-token', 'test-openai-key', 'TEST DATA ONLY', '/sealed/', 'lease-token-test'):
            self.assertNotIn(secret, logs)

    def test_cancel_during_static_stage(self):
        self.docker.exit_after = None
        self.site.respond('/jobs/:id/heartbeat', (200, {'cancel': True, 'deadlineAt': '2030-01-01T00:00:00Z'}))
        self.assertTrue(self.supervisor().process(self.claim()))
        fail = self.site.calls('/jobs/:id/fail')
        self.assertEqual(len(fail), 1)
        self.assertEqual((fail[0]['code'], fail[0]['retryable'], fail[0]['cleanup']), ('cancelled', False, CLEAN))
        self.assertEqual(self.site.calls('/jobs/:id/ai/reserve'), [])
        self.assertEqual(self.site.calls('/jobs/:id/complete'), [])
        self.assertNotIn('kill', [entry[0] for entry in self.docker.log])
        self.assertTrue(self.jobs_empty())

    def test_lease_lost_stops_work_and_cleans_up(self):
        self.docker.exit_after = None
        self.site.respond('/jobs/:id/heartbeat', (409, {'error': 'lease_lost'}))
        self.site.respond('/jobs/:id/fail', (409, {'error': 'lease_lost'}))
        self.assertTrue(self.supervisor().process(self.claim()))
        self.assertEqual(self.site.calls('/jobs/:id/ai/reserve'), [])
        self.assertEqual(self.site.calls('/jobs/:id/fail')[0]['code'], 'worker_lost')
        self.assertTrue(self.jobs_empty())
        self.assertEqual(self.docker.containers, {})
        state = State(self.config.state_file)
        self.assertIsNone(state.active)
        self.assertEqual(state.terminated, [{'jobId': 'job_1', 'attempt': 1, 'cleanupConfirmed': True,
                                             'reason': 'lease_lost'}])

    def test_lease_lost_during_ai_stage(self):
        self.site.respond('/jobs/:id/ai/reserve', (409, {'error': 'lease_lost'}))
        self.site.respond('/jobs/:id/fail', (409, {'error': 'lease_lost'}))
        self.supervisor().process(self.claim())
        self.assertEqual(self.openai.requests, [])
        self.assertEqual(self.site.calls('/jobs/:id/complete'), [])
        self.assertEqual(State(self.config.state_file).terminated[0]['reason'], 'lease_lost')

    def test_oom_without_report_fails_with_oom(self):
        self.docker.on_run, self.docker.exit_code, self.docker.oom = None, 137, True
        self.supervisor().process(self.claim())
        fail = self.site.calls('/jobs/:id/fail')[0]
        self.assertEqual((fail['code'], fail['retryable'], fail['cleanup']), ('oom', False, CLEAN))
        self.assertEqual([item['name'] for item in fail['artifacts']], ['service-result.json'])
        service = json.loads(self.site.objects['service-result.json']['data'])
        self.assertEqual((service['exitCode'], service['engineStatus'], service['aiStatus']), (137, None, 'not_requested'))

    def test_engine_failed_report_completes_without_ai(self):
        self.docker.on_run, self.docker.exit_code = support.engine_writer(support.report(status='failed')), 2
        self.supervisor().process(self.claim())
        complete = self.site.calls('/jobs/:id/complete')[0]
        self.assertEqual((complete['engineStatus'], complete['aiStatus']), ('failed', 'not_requested'))
        self.assertEqual(self.openai.requests, [])

    def test_report_for_other_bytes_is_rejected(self):
        self.docker.on_run = support.engine_writer(support.report(sha='d' * 64))
        self.supervisor().process(self.claim())
        self.assertEqual(self.site.calls('/jobs/:id/fail')[0]['code'], 'analysis_failed')

    def test_digest_mismatch_never_starts_a_container(self):
        raw = self.claim()
        raw['sample']['sha256'] = sha256(b'other').hexdigest()
        self.supervisor().process(raw)
        fail = self.site.calls('/jobs/:id/fail')[0]
        self.assertEqual((fail['code'], fail['retryable']), ('digest_mismatch', False))
        self.assertNotIn('run', [entry[0] for entry in self.docker.log])
        self.assertTrue(self.jobs_empty())

    def test_invalid_format_and_docker_start_failure(self):
        self.site.sample = support.thin_header(cpu=12)
        self.supervisor().process(self.claim(data=self.site.sample))
        self.assertEqual(self.site.calls('/jobs/:id/fail')[-1]['code'], 'architecture')
        self.site.sample = support.sample_bytes()
        self.docker.run_error = 125
        self.supervisor().process(self.claim())
        fail = self.site.calls('/jobs/:id/fail')[-1]
        self.assertEqual((fail['code'], fail['retryable']), ('engine_unavailable', True))

    def test_malformed_claim_is_failed_without_work(self):
        raw = self.claim()
        raw['limits'] = {}
        self.assertTrue(self.supervisor().process(raw))
        self.assertEqual(self.site.calls('/jobs/:id/fail')[0]['code'], 'internal')
        self.assertEqual(self.docker.log, [])

    def test_shutdown_requeues_as_worker_lost(self):
        self.docker.exit_after = None
        supervisor = self.supervisor()
        original = supervisor.runner.run_static

        def run_static(*args, **kwargs):
            supervisor.stop_event.set()
            return original(*args, **kwargs)
        supervisor.runner.run_static = run_static
        supervisor.process(self.claim())
        fail = self.site.calls('/jobs/:id/fail')[0]
        self.assertEqual((fail['code'], fail['retryable']), ('worker_lost', True))

    def test_unremovable_container_stops_the_host(self):
        self.docker.remove = lambda name: False
        self.assertFalse(self.supervisor().process(self.claim()))
        complete = self.site.calls('/jobs/:id/complete')[0]
        self.assertFalse(complete['cleanup']['containerRemoved'])


class LoopTests(Harness):
    def fake_time(self, supervisor: Supervisor) -> support.FakeClock:
        clock = support.FakeClock()
        supervisor.clock = supervisor.runner.clock = supervisor.ai_stage.clock = clock
        supervisor.wait = clock.sleep
        return clock

    def test_idle_stop_race_keeps_polling_on_stop_false(self):
        self.site.respond('/worker/claim', (200, {'job': None, 'reason': 'empty', 'workerIdleSeconds': 60}))
        self.site.respond('/worker/idle', (200, {'stop': False}), (200, {'stop': True}))
        supervisor = self.supervisor(poll_seconds=10)
        self.fake_time(supervisor)
        self.assertEqual(supervisor.serve(), 'idle')
        routes = self.site.routes_called()
        self.assertEqual(routes.count('/worker/idle'), 2)
        first, second = [index for index, route in enumerate(routes) if route == '/worker/idle']
        self.assertGreaterEqual(routes[first:second].count('/worker/claim'), 6)
        self.assertTrue(self.config.heartbeat_file.exists())

    def test_queue_then_idle_default_wait(self):
        self.site.respond('/worker/claim', (200, {'job': self.claim()}), (200, {'job': None, 'reason': 'empty'}))
        self.site.respond('/worker/idle', (200, {'stop': True}))
        supervisor = self.supervisor(poll_seconds=10)
        clock = self.fake_time(supervisor)
        start = clock()
        self.assertEqual(supervisor.serve(), 'idle')
        self.assertEqual(len(self.site.calls('/jobs/:id/complete')), 1)
        self.assertGreaterEqual(clock() - start, 300)

    def test_unreachable_site_while_idle_powers_off(self):
        self.site.respond('/worker/claim', (503, None))
        self.site.respond('/worker/idle', (503, None))
        supervisor = self.supervisor(poll_seconds=10)
        clock = self.fake_time(supervisor)
        self.assertEqual(supervisor.serve(), 'unreachable')
        self.assertGreaterEqual(clock() - 1000, 600)

    def test_drain_mode_never_claims(self):
        self.site.respond('/worker/boot', (200, {'runId': 'run_9', 'mode': 'drain'}))
        self.site.respond('/worker/ready', (200, {'ok': True}))
        self.site.respond('/worker/stopping', (200, {'ok': True}))
        supervisor = self.supervisor(poll_seconds=10)
        self.fake_time(supervisor)
        self.assertEqual(supervisor.run(), 'drain')
        self.assertNotIn('/worker/claim', self.site.routes_called())
        self.assertEqual(self.site.calls('/worker/stopping'), [{'runId': 'run_9', 'reason': 'drain'}])
        self.assertEqual(self.powered_off, [True])

    def test_drain_written_while_running_ends_claims_after_the_current_job(self):
        modes = ['active', 'drain']
        self.site.respond('/worker/claim', (200, {'job': self.claim()}), (200, {'job': self.claim(job_id='job_2')}))
        supervisor = self.supervisor(poll_seconds=10, read_mode=lambda: modes.pop(0) if len(modes) > 1 else modes[0])
        self.fake_time(supervisor)
        self.assertEqual(supervisor.serve(), 'drain')
        self.assertEqual(self.site.routes_called().count('/worker/claim'), 1)
        self.assertEqual(len(self.site.calls('/jobs/:id/complete')), 1)
        self.assertNotIn('/worker/idle', self.site.routes_called())

    def test_resume_is_read_and_an_unreadable_mode_keeps_the_last_one(self):
        reads =[ConfigError('parameter_unavailable', 'worker/mode'), 'active']

        def read_mode():
            value = reads.pop(0) if len(reads) > 1 else reads[0]
            if isinstance(value, Exception):
                raise value
            return value
        self.site.respond('/worker/claim', (200, {'job': None, 'reason': 'empty', 'workerIdleSeconds': 60}))
        self.site.respond('/worker/idle', (200, {'stop': True}))
        supervisor = self.supervisor(poll_seconds=10, mode='drain', read_mode=read_mode)
        self.fake_time(supervisor)
        routes_before = len(self.site.routes_called())
        self.assertEqual(supervisor.serve(), 'idle')
        routes = self.site.routes_called()[routes_before:]
        self.assertEqual(routes[-1], '/worker/idle')
        self.assertIn('/worker/claim', routes)
        self.assertEqual(supervisor.mode, 'active')
        self.assertIn('"event": "mode_unavailable"', support.LOGS.getvalue())


class BootTests(Harness):
    def test_boot_reconcile_reports_terminated_attempts(self):
        state = State(self.config.state_file)
        state.finish({'jobId': 'job_lost', 'attempt': 2, 'cleanupConfirmed': True, 'reason': 'lease_lost'})
        state.begin('job_old', 1, 'machsentry-job_old-1', time.time() + 60, time.time())
        leftover = self.config.jobs_dir / 'job_old-1' / 'input'
        leftover.mkdir(parents=True)
        (leftover / 'sample.macho').write_bytes(b'inert')
        self.docker.leftovers = [{'id': 'machsentry-job_old-1', 'name': 'machsentry-job_old-1', 'created': time.time(),
                                  'jobId': 'job_old', 'attempt': 1}]
        self.site.respond('/worker/boot', (200, {'runId': 'run_2', 'mode': 'active'}))
        supervisor = self.supervisor()
        self.assertEqual(supervisor.boot(), 'ok')
        boot = self.site.calls('/worker/boot')[0]
        self.assertEqual((boot['instanceId'], boot['bootId'], boot['image'], boot['release']),
                         ('i-0test', 'boot1234abcd', IMAGE_ID, 'abc1234'))
        self.assertCountEqual(boot['terminatedAttempts'], [
            {'jobId': 'job_lost', 'attempt': 2, 'cleanupConfirmed': True, 'reason': 'lease_lost'},
            {'jobId': 'job_old', 'attempt': 1, 'cleanupConfirmed': True, 'reason': 'worker_restart'}])
        self.assertIn(('rm', 'machsentry-job_old-1'), self.docker.log)
        self.assertTrue(self.jobs_empty())
        saved = State(self.config.state_file)
        self.assertEqual((saved.data['runId'], saved.active, saved.terminated), ('run_2', None, []))

    def test_unconfirmed_cleanup_is_reported_and_blocks_readiness(self):
        (self.config.jobs_dir / 'job_x-1' / 'work').mkdir(parents=True)
        self.ops.mounted.add(str(self.config.jobs_dir / 'job_x-1' / 'work'))
        self.ops.fail_unmount = True
        self.site.respond('/worker/boot', (200, {'runId': 'run_3', 'mode': 'active'}))
        self.site.respond('/worker/stopping', (200, {'ok': True}))
        supervisor = self.supervisor()
        self.assertEqual(supervisor.run(), 'host_unclean')
        boot = self.site.calls('/worker/boot')[0]
        self.assertEqual(boot['terminatedAttempts'], [{'jobId': 'job_x', 'attempt': 1, 'cleanupConfirmed': False,
                                                        'reason': 'worker_restart'}])
        self.assertNotIn('/worker/ready', self.site.routes_called())
        self.assertEqual(self.site.calls('/worker/stopping')[0]['reason'], 'host_unclean')

    def test_readiness_checks_image_and_doctor(self):
        self.site.respond('/worker/ready', (200, {'ok': True}))
        supervisor = self.supervisor()
        self.assertTrue(supervisor.readiness())
        ready = self.site.calls('/worker/ready')[0]
        self.assertEqual(ready['checks'], {'hostClean': True, 'image': True, 'doctor': True})
        self.assertEqual((ready['versions']['image'], ready['versions']['release']), (IMAGE_ID, 'abc1234'))
        self.assertIn(('call', 'run', 'machsentry-doctor-boot1234'), self.docker.log)
        self.docker.image = 'sha256:' + 'e' * 64
        self.assertFalse(self.supervisor().readiness())
        self.docker.image, self.docker.doctor_stdout = IMAGE_ID, '{"healthy": false}'
        self.assertFalse(self.supervisor().readiness())
        self.assertEqual(len(self.site.calls('/worker/ready')), 1)

    def test_sigterm_exits_without_power_off(self):
        self.site.respond('/worker/boot', (200, {'runId': 'run_4', 'mode': 'active'}))
        self.site.respond('/worker/ready', (200, {'ok': True}))
        supervisor = self.supervisor()
        supervisor.stop_event.set()
        self.assertEqual(supervisor.run(), 'stopped')
        self.assertEqual(self.powered_off, [])
        self.assertNotIn('/worker/stopping', self.site.routes_called())

    def test_unauthorized_boot_powers_off(self):
        self.site.respond('/worker/boot', (401, {'error': 'unauthorized'}))
        supervisor = self.supervisor()
        self.assertEqual(supervisor.run(), 'unauthorized')
        self.assertEqual(self.powered_off, [True])
        self.assertNotIn('/worker/stopping', self.site.routes_called())


if __name__ == '__main__':
    unittest.main()
