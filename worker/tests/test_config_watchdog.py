"""Host config and SSM parameters, structured log redaction, state.json, and watchdog decisions."""

import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import worker_support as support
from machsentry_worker import logs
from machsentry_worker.config import (ConfigError, HostConfig, load_host_config, load_parameters, load_release,
                                     read_mode)
from machsentry_worker.job import ClaimInvalid, parse_claim
from machsentry_worker.state import State
from machsentry_worker.watchdog import (CONTAINER_GRACE_SECONDS, HEARTBEAT_STALE_SECONDS, MAX_UPTIME_SECONDS, decide,
                                        run_once)


class FakeSsm:
    def __init__(self, values):
        self.values, self.calls = values, []

    def get_parameter(self, Name, WithDecryption):
        self.calls.append((Name, WithDecryption))
        if Name not in self.values:
            error = Exception('not found')
            error.response = {'Error': {'Code': 'ParameterNotFound'}}
            raise error
        return {'Parameter': {'Value': self.values[Name]}}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_host_config_defaults_and_validation(self):
        path = self.root / 'config.json'
        path.write_text(json.dumps({'region': 'us-east-2'}))
        config = load_host_config(path)
        self.assertEqual((config.ssm_prefix, config.image), ('/unpacked/analysis', 'machsentry-analyzer:current'))
        self.assertEqual(config.state_file, Path('/var/lib/machsentry-worker/state.json'))
        self.assertEqual(config.heartbeat_file, Path('/run/machsentry-worker/heartbeat'))
        for bad in ({'region': 'Ohio'}, {'region': 'us-east-2', 'stateDir': 'relative'},
                    {'region': 'us-east-2', 'ssmPrefix': 'no-slash'}, {'region': 'us-east-2', 'stateDir': '/var/../etc'}):
            path.write_text(json.dumps(bad))
            with self.assertRaises(ConfigError):
                load_host_config(path)

    def test_release_file(self):
        path = self.root / 'release.json'
        path.write_text(json.dumps({'commit': 'abc1234', 'image_id': 'sha256:' + 'f' * 64, 's3Key': 'x'}))
        release = load_release(path)
        self.assertEqual((release.commit, release.image_id), ('abc1234', 'sha256:' + 'f' * 64))
        path.write_text(json.dumps({'commit': 'abc1234', 'image_id': 'machsentry-analyzer:current'}))
        with self.assertRaises(ConfigError):
            load_release(path)

    def test_parameters_are_decrypted_and_kept_in_memory(self):
        prefix = '/unpacked/analysis'
        ssm = FakeSsm({f'{prefix}/worker/token': 'tok-123', f'{prefix}/worker/site-url': 'https://www.unpackedlab.com/',
                       f'{prefix}/worker/mode': 'active', f'{prefix}/openai/model': support.MODEL})
        parameters = load_parameters(HostConfig(region='us-east-2'), ssm)
        self.assertTrue(all(decrypt for _, decrypt in ssm.calls))
        self.assertEqual(parameters.site_url, 'https://www.unpackedlab.com')
        self.assertIsNone(parameters.openai_api_key)
        self.assertEqual(parameters.token.reveal(), 'tok-123')
        self.assertNotIn('tok-123', repr(parameters))
        ssm.values[f'{prefix}/worker/site-url'] = 'http://www.unpackedlab.com'
        with self.assertRaises(ConfigError):
            load_parameters(HostConfig(region='us-east-2'), ssm)
        del ssm.values[f'{prefix}/worker/token']
        with self.assertRaises(ConfigError) as caught:
            load_parameters(HostConfig(region='us-east-2'), ssm)
        self.assertEqual(caught.exception.code, 'parameter_unavailable')

    def test_mode_is_read_on_its_own(self):
        prefix = '/unpacked/analysis'
        ssm = FakeSsm({f'{prefix}/worker/mode': ' drain\n'})
        self.assertEqual(read_mode(HostConfig(region='us-east-2'), ssm), 'drain')
        self.assertEqual(ssm.calls, [(f'{prefix}/worker/mode', True)])
        ssm.values[f'{prefix}/worker/mode'] = 'paused'
        with self.assertRaises(ConfigError) as caught:
            read_mode(HostConfig(region='us-east-2'), ssm)
        self.assertEqual(caught.exception.code, 'parameter_invalid')

    def test_claim_limits_are_clamped(self):
        raw = support.raw_claim()
        raw['limits'] = {key: 10 ** 12 for key in raw['limits']}
        for key in ('maxCalls', 'maxInputTokensPerCall', 'maxOutputTokensFirstCall', 'maxOutputTokensPerJob'):
            raw['ai'][key] = 10 ** 12
        claim = parse_claim(raw)
        self.assertEqual(claim.limits, {'staticSeconds': 1200, 'aiSeconds': 540, 'finalizeSeconds': 120,
                                       'maxFunctions': 128, 'memoryBytes': 3 * 1024 ** 3,
                                       'pids': 256, 'diskBytes': 4 * 1024 ** 3})
        self.assertEqual({key: claim.ai[key] for key in
                          ('maxCalls', 'maxInputTokensPerCall', 'maxOutputTokensFirstCall', 'maxOutputTokensPerJob')},
                         {'maxCalls': 12, 'maxInputTokensPerCall': 40_000,
                          'maxOutputTokensFirstCall': 6_000, 'maxOutputTokensPerJob': 16_000})
        raw['id'] = '../escape'
        with self.assertRaises(ClaimInvalid):
            parse_claim(raw)

    def test_claim_preserves_site_v4_and_v5_grants_below_worker_ceilings(self):
        for version, static, ai_seconds, functions, calls, first_output, total_output in (
                ('v4', 900, 180, 64, 2, 6000, 8000),
                ('v5', 1200, 540, 128, 12, 4000, 16000)):
            with self.subTest(version=version):
                raw = support.raw_claim()
                raw['limits'].update(staticSeconds=static, aiSeconds=ai_seconds, maxFunctions=functions)
                raw['ai'].update(promptVersion=f'unpacked-analysis-ai-{version}', maxCalls=calls,
                                 maxOutputTokensFirstCall=first_output, maxOutputTokensPerJob=total_output)
                claim = parse_claim(raw)
                self.assertEqual(claim.limits, raw['limits'])
                self.assertEqual(claim.ai, raw['ai'])


class LogTests(unittest.TestCase):
    def test_only_identifiers_reach_the_log(self):
        stream = io.StringIO()
        logs.set_stream(stream)
        try:
            logs.log('job_failed', 'warning', jobId='job_1', code='oom', prompt='secret prompt text',
                     reason='https://evil.example/x', attempt=1)
        finally:
            logs.set_stream(support.LOGS)
        record = json.loads(stream.getvalue())
        self.assertEqual(record['code'], 'oom')
        self.assertEqual(record['reason'], '[redacted]')
        self.assertNotIn('prompt', record)


class StateTests(unittest.TestCase):
    def test_atomic_round_trip_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            state = State(path)
            state.set_run('run_1')
            state.begin('job_1', 1, 'machsentry-job_1-1', 2000.0, 1000.0)
            self.assertEqual(State(path).active['container'], 'machsentry-job_1-1')
            state.finish({'jobId': 'job_1', 'attempt': 1, 'cleanupConfirmed': True, 'reason': 'lease_lost'})
            state.acknowledged([{'jobId': 'job_1', 'attempt': 1}])
            self.assertEqual((State(path).active, State(path).terminated), (None, []))
            path.write_text('{broken')
            self.assertEqual(State(path).data['terminated'], [])


class WatchdogTests(unittest.TestCase):
    NOW = 1_800_000_000.0

    def test_uptime_limit(self):
        self.assertIsNone(decide(self.NOW, MAX_UPTIME_SECONDS - 1, self.NOW, None, []).poweroff)
        self.assertEqual(decide(self.NOW, MAX_UPTIME_SECONDS + 1, self.NOW, None, []).poweroff, 'max_session')

    def test_heartbeat_staleness(self):
        self.assertIsNone(decide(self.NOW, 3000, self.NOW - HEARTBEAT_STALE_SECONDS + 5, None, []).poweroff)
        self.assertEqual(decide(self.NOW, 3000, self.NOW - HEARTBEAT_STALE_SECONDS - 5, None, []).poweroff,
                         'supervisor_stale')
        self.assertIsNone(decide(self.NOW, 120, None, None, []).poweroff)
        self.assertEqual(decide(self.NOW, HEARTBEAT_STALE_SECONDS + 1, None, None, []).poweroff, 'supervisor_silent')

    def test_containers_past_deadline(self):
        active = {'jobId': 'job_1', 'attempt': 1, 'deadlineEpoch': self.NOW - 60}
        recorded = {'id': 'c1', 'jobId': 'job_1', 'attempt': 1, 'created': self.NOW - 3000}
        self.assertEqual(decide(self.NOW, 100, self.NOW, active, [recorded]).remove, [])
        active['deadlineEpoch'] = self.NOW - CONTAINER_GRACE_SECONDS - 1
        self.assertEqual(decide(self.NOW, 100, self.NOW, active, [recorded]).remove, [recorded])
        stranger = {'id': 'c2', 'jobId': 'job_9', 'attempt': 3, 'created': self.NOW - 23 * 60}
        doctor = {'id': 'c3', 'jobId': None, 'attempt': None, 'created': self.NOW - 60}
        self.assertEqual(decide(self.NOW, 100, self.NOW, None, [stranger, doctor]).remove, [stranger])

    def test_run_once_acts_and_notifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = HostConfig(region='us-east-2', state_dir=root, heartbeat_file=root / 'heartbeat')
            config.heartbeat_file.write_text('')
            stale = time.time() - HEARTBEAT_STALE_SECONDS - 30
            os.utime(config.heartbeat_file, (stale, stale))
            state = State(config.state_file)
            state.set_run('run_7')
            state.begin('job_1', 2, 'machsentry-job_1-2', time.time() - 600, time.time() - 1500)
            docker = support.FakeDockerCli(labeled=[{'id': 'machsentry-job_1-2', 'jobId': 'job_1', 'attempt': 2,
                                                     'created': time.time() - 1500}])
            notified, powered = [], []
            decision = run_once(config, docker, now=time.time(), uptime=4000,
                                notify=lambda cfg, run_id, reason: notified.append((run_id, reason)),
                                poweroff=lambda: powered.append(True))
            self.assertEqual(decision.poweroff, 'supervisor_stale')
            self.assertIn(('rm', 'machsentry-job_1-2'), docker.log)
            self.assertEqual((notified, powered), ([('run_7', 'supervisor_stale')], [True]))


if __name__ == '__main__':
    unittest.main()
