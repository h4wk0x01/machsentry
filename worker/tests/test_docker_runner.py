"""Container isolation flags, deadline handling, OOM mapping and cgroup sampling."""

from pathlib import Path
import tempfile
import unittest

import worker_support as support
from machsentry_worker.docker_runner import (CgroupProbe, DockerCli, DockerRunner, StaticOutcome, analysis_command,
                                             doctor_command, envelope_code)
from machsentry_worker.supervisor import failure_code


class CommandTests(unittest.TestCase):
    def test_analysis_command_has_the_contract_flags(self):
        argv = analysis_command('machsentry-job_1-2', 'job_1', 2, 'sha256:' + 'a' * 64,
                                Path('/var/lib/machsentry-worker/jobs/job_1-2/input/sample.macho'),
                                Path('/var/lib/machsentry-worker/jobs/job_1-2/work'), 64)
        self.assertEqual(argv[:4], ['run', '--detach', '--name', 'machsentry-job_1-2'])
        joined = ' '.join(argv)
        for flags in ('--network none', '--read-only', '--init', '--user 10001:10001', '--cap-drop ALL',
                      '--security-opt no-new-privileges', '--pids-limit 256', '--memory 3g', '--memory-swap 3g',
                      '--cpus 2', '--tmpfs /tmp:rw,nosuid,nodev,size=64m', '--label machsentry.job=job_1',
                      '--label machsentry.attempt=2'):
            self.assertIn(flags, joined)
        self.assertIn('type=bind,source=/var/lib/machsentry-worker/jobs/job_1-2/input/sample.macho,'
                      'target=/input/sample.macho,readonly', argv)
        self.assertIn('type=bind,source=/var/lib/machsentry-worker/jobs/job_1-2/work,target=/work', argv)
        environment = [argv[i + 1] for i, item in enumerate(argv) if item == '--env']
        self.assertEqual(environment, ['HOME=/work/home', 'TMPDIR=/work/tmp', 'GHIDRA_HEADLESS_MAXMEM=1536M',
                                       'REA_GHIDRA_STARTUP_TIMEOUT_MS=780000', 'PYTHONDONTWRITEBYTECODE=1',
                                       'LANG=C.UTF-8'])
        self.assertEqual(argv[argv.index('sha256:' + 'a' * 64):], [
            'sha256:' + 'a' * 64, 'python', '-m', 'machsentry', 'analyze', '/input/sample.macho', '--output',
            '/work/out/report', '--rea-root', '/opt/machsentry', '--max-functions', '64', '--rea-timeout', '840', '--report-brand', 'unpacked'])
        self.assertNotIn('docker.sock', joined)
        self.assertFalse(any(item.startswith(('AWS', 'OPENAI')) for item in environment))

    def test_doctor_runs_in_the_same_isolation(self):
        argv = doctor_command('machsentry-doctor-1', 'sha256:' + 'b' * 64)
        joined = ' '.join(argv)
        self.assertIn('--network none --read-only --init --user 10001:10001 --cap-drop ALL', joined)
        self.assertNotIn('--mount', argv)
        self.assertTrue(joined.endswith('node scripts/rea.mjs doctor --provider ghidra --json'))

    def test_cli_environment_is_minimal(self):
        seen = {}

        def run(argv, **kwargs):
            seen.update(kwargs)

            class Completed:
                returncode, stdout, stderr = 0, b'', b''
            return Completed()
        DockerCli(run=run).call(['ps'])
        self.assertEqual(set(seen['env']), {'PATH', 'LANG'})


class StaticRunTests(unittest.TestCase):
    def runner(self, docker, clock):
        return DockerRunner(docker, clock=clock, sleep=clock.sleep)

    def test_deadline_sends_sigint_then_waits_grace_then_removes(self):
        clock = support.FakeClock()
        docker = support.FakeDockerCli(exit_after=None)
        outcome = self.runner(docker, clock).run_static('machsentry-j-1', ['run', '--name', 'machsentry-j-1'],
                                                        deadline=clock() + 10)
        self.assertTrue(outcome.timed_out)
        self.assertTrue(outcome.container_removed)
        actions = [entry[0] for entry in docker.log if entry[0] != 'state']
        self.assertEqual(actions, ['run', 'kill', 'rm'])
        self.assertEqual(docker.log[[entry[0] for entry in docker.log].index('kill')], ('kill', 'machsentry-j-1', 'SIGINT'))
        kill_index = [entry[0] for entry in docker.log].index('kill')
        grace_polls = [entry for entry in docker.log[kill_index:] if entry[0] == 'state']
        self.assertEqual(len(grace_polls), 30)
        self.assertGreaterEqual(clock(), 1000 + 10 + 30)
        self.assertIsNone(outcome.exit_code)

    def test_container_that_stops_on_sigint_is_still_removed(self):
        clock = support.FakeClock()
        docker = support.FakeDockerCli(exit_after=None, exit_code=130)
        original_kill = docker.kill

        def kill(name, signal):
            docker.containers[name]['running'], docker.containers[name]['exit'] = False, 130
            return original_kill(name, signal)
        docker.kill = kill
        outcome = self.runner(docker, clock).run_static('c', ['run', '--name', 'c'], deadline=clock() + 4)
        self.assertTrue(outcome.timed_out)
        self.assertEqual(outcome.exit_code, 130)
        self.assertEqual([entry[0] for entry in docker.log if entry[0] != 'state'], ['run', 'kill', 'rm'])
        self.assertEqual(failure_code(outcome), ('deadline_exceeded', False))

    def test_normal_exit_reads_the_envelope_code_only(self):
        clock = support.FakeClock()
        docker = support.FakeDockerCli(exit_code=2, stdout='noise\n{"ok": false, "error": {"code": "rea_not_built", '
                                                            '"message": "TEST DATA ONLY secret-ish text"}}\n')
        outcome = self.runner(docker, clock).run_static('c', ['run', '--name', 'c'], deadline=clock() + 900)
        self.assertEqual((outcome.exit_code, outcome.error_code, outcome.timed_out), (2, 'rea_not_built', False))
        self.assertEqual(failure_code(outcome), ('engine_unavailable', False))

    def test_oom_is_reported(self):
        clock = support.FakeClock()
        docker = support.FakeDockerCli(exit_code=137, oom=True)
        outcome = self.runner(docker, clock).run_static('c', ['run', '--name', 'c'], deadline=clock() + 900)
        self.assertTrue(outcome.oom_killed)
        self.assertEqual(failure_code(outcome), ('oom', False))

    def test_stop_reason_removes_at_once(self):
        clock = support.FakeClock()
        docker = support.FakeDockerCli(exit_after=None)
        outcome = self.runner(docker, clock).run_static('c', ['run', '--name', 'c'], deadline=clock() + 900,
                                                        stop=lambda: 'cancelled')
        self.assertEqual(outcome.stopped, 'cancelled')
        self.assertNotIn('kill', [entry[0] for entry in docker.log])
        self.assertTrue(outcome.container_removed)

    def test_start_failure_is_retryable_infrastructure(self):
        clock = support.FakeClock()
        docker = support.FakeDockerCli(run_error=125)
        outcome = self.runner(docker, clock).run_static('c', ['run', '--name', 'c'], deadline=clock() + 900)
        self.assertTrue(outcome.start_failed)
        self.assertEqual(failure_code(outcome), ('engine_unavailable', True))
        self.assertEqual(failure_code(StaticOutcome(exit_code=3)), ('analysis_failed', False))

    def test_envelope_parser_ignores_messages(self):
        self.assertIsNone(envelope_code('{"ok": true, "value": {}}'))
        self.assertIsNone(envelope_code('{"ok": false, "error": {"code": "Bad Code"}}'))
        self.assertEqual(envelope_code('{"ok": false, "error": {"code": "cancelled"}}'), 'cancelled')


class CgroupTests(unittest.TestCase):
    def test_peak_and_cpu_come_from_the_container_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scope = root / 'cgroup' / 'system.slice' / 'docker-abc.scope'
            scope.mkdir(parents=True)
            (root / 'proc' / '77').mkdir(parents=True)
            (root / 'proc' / '77' / 'cgroup').write_text('0::/system.slice/docker-abc.scope\n')
            (scope / 'memory.peak').write_text('1048576\n')
            (scope / 'cpu.stat').write_text('usage_usec 2500000\nuser_usec 2000000\n')
            probe = CgroupProbe(root / 'cgroup', root / 'proc')
            probe.locate(77, 'abc')
            probe.sample()
            (scope / 'memory.peak').write_text('524288\n')
            (scope / 'cpu.stat').write_text('usage_usec 4000000\n')
            probe.sample()
            self.assertEqual((probe.peak, probe.cpu_seconds), (1048576, 4.0))


if __name__ == '__main__':
    unittest.main()
