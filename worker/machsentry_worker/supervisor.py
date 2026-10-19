"""Worker supervisor (contract sections 4 and 6-9): boot reconcile, readiness, claim loop, one job
at a time, idle stop.

Entry point: `python -m machsentry_worker.supervisor` (root, systemd). Per job: download and admit
the sample, run MachSentry in a fresh container under the static deadline, copy the outputs, then
delete sample, container and loop image before the AI stage, publish and complete. A job ends with
/complete or /fail; when neither can be delivered, its termination goes into state.json for the
next /worker/boot.
"""

import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request

from . import __version__
from .ai_stage import AiStage, AiStageResult
from .config import (ConfigError, HostConfig, Release, load_host_config, load_parameters, load_release, read_mode,
                     ssm_client)
from .docker_runner import DockerCli, DockerError, DockerRunner, StaticOutcome, analysis_command
from .job import Claim, ClaimInvalid, identity, parse_claim
from .jobdir import HostOpError, HostOps, JobDir, sweep
from .logs import log
from . import publish
from .publish import PublishError
from . import sample as samples
from .site_api import LeaseLost, SiteApi, SiteError, SiteUnavailable, Unauthorized
from .state import State

POLL_SECONDS = 10
HEARTBEAT_SECONDS = 15
LEASE_SECONDS = 90
DEFAULT_IDLE_SECONDS = 300
UNREACHABLE_SECONDS = 600
BOOT_RETRY_SECONDS = 30
ENGINE_UNAVAILABLE = frozenset({'rea_not_built', 'rea_not_installed', 'invalid_runtime'})


class Heartbeat:
    """Keeps the lease alive every 15 s with the current phase; learns cancel and lease loss."""

    def __init__(self, site, claim: Claim, *, interval: float = HEARTBEAT_SECONDS, lease_seconds: float = LEASE_SECONDS,
                 clock=time.monotonic, touch=lambda: None):
        self.site, self.claim, self.interval, self.lease_seconds = site, claim, interval, lease_seconds
        self.clock, self.touch = clock, touch
        self.phase = 'static_analysis'
        self.cancel, self.lease_lost, self._stop = threading.Event(), threading.Event(), threading.Event()
        self._lock = threading.Lock()
        self._last_ok = clock()
        self._thread = threading.Thread(target=self._loop, name='heartbeat', daemon=True)

    def start(self):
        self._thread.start()

    def beat(self):
        with self._lock:
            if self.lease_lost.is_set():
                return
            try:
                response = self.site.heartbeat(self.claim.id, self.claim.attempt, self.claim.lease_token, self.phase)
            except (LeaseLost, Unauthorized) as error:
                log('lease_lost', 'warning', jobId=self.claim.id, attempt=self.claim.attempt, code=error.code)
                self.lease_lost.set()
                return
            except SiteError as error:
                if self.clock() - self._last_ok > self.lease_seconds:
                    log('lease_expired', 'warning', jobId=self.claim.id, attempt=self.claim.attempt, code=error.code)
                    self.lease_lost.set()
                return
            self._last_ok = self.clock()
            if response.get('cancel') is True and not self.cancel.is_set():
                log('cancel_requested', jobId=self.claim.id, attempt=self.claim.attempt, phase=self.phase)
                self.cancel.set()

    def set_phase(self, phase: str):
        self.phase = phase
        self.beat()

    def _loop(self):
        while True:
            self.touch()
            self.beat()
            if self._stop.wait(self.interval):
                return

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=60)


def failure_code(outcome: StaticOutcome) -> tuple[str, bool]:
    """Contract error code and retryability when the engine published no report."""
    if outcome.start_failed or outcome.exit_code in (125, 126, 127):
        return 'engine_unavailable', True
    if outcome.timed_out:
        return 'deadline_exceeded', False
    if outcome.oom_killed:
        return 'oom', False
    if outcome.error_code in ENGINE_UNAVAILABLE:
        return 'engine_unavailable', False
    return 'analysis_failed', False


def _load_json(path: Path | None) -> dict | None:
    if path is None:
        return None
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


class Supervisor:
    def __init__(self, *, site, cli: DockerCli, runner: DockerRunner, ops: HostOps, state: State,
                 ai_stage: AiStage, config: HostConfig, release: Release, instance_id: str, boot_id: str,
                 mode: str = 'active', read_mode=None, poweroff=lambda: None, clock=time.monotonic, wall=time.time,
                 stop_event: threading.Event | None = None, download=samples.download,
                 poll_seconds: float = POLL_SECONDS, heartbeat_seconds: float = HEARTBEAT_SECONDS):
        self.site, self.cli, self.runner, self.ops, self.state, self.ai_stage = site, cli, runner, ops, state, ai_stage
        self.config, self.release, self.instance_id, self.boot_id = config, release, instance_id, boot_id
        # `mode` follows the SSM parameter (re-read through `read_mode` before each claim); a drain
        # answered by /worker/boot holds for the whole run.
        self.mode, self.read_mode, self.site_drain = mode, read_mode, False
        self.poweroff, self.clock, self.wall = poweroff, clock, wall
        self.stop_event = stop_event or threading.Event()
        self.download, self.poll_seconds, self.heartbeat_seconds = download, poll_seconds, heartbeat_seconds
        self.run_id: str | None = None
        self.host_clean = True
        self.idle_seconds = DEFAULT_IDLE_SECONDS

    @property
    def results_dir(self) -> Path:
        return self.config.state_dir / 'results'

    def touch(self):
        try:
            self.config.heartbeat_file.parent.mkdir(parents=True, exist_ok=True)
            self.config.heartbeat_file.touch()
            os.utime(self.config.heartbeat_file)
        except OSError:
            pass

    def wait(self, seconds: float):
        self.stop_event.wait(seconds)

    @property
    def draining(self) -> bool:
        return self.mode == 'drain' or self.site_drain

    def refresh_mode(self):
        """Lets `worker drain` and `worker resume` reach a running supervisor. An unreadable
        parameter keeps the last mode."""
        if self.read_mode is None:
            return
        try:
            mode = self.read_mode()
        except ConfigError as error:
            log('mode_unavailable', 'warning', code=error.code)
            return
        if mode != self.mode:
            log('mode_changed', mode=mode)
            self.mode = mode

    # Boot -------------------------------------------------------------------------------------

    def reconcile(self) -> list[dict]:
        """Removes leftover labeled containers and job directories; every attempt found is reported
        with cleanupConfirmed true only when its container and directories are proven gone."""
        found: dict[tuple, dict] = {}

        def note(job_id, attempt, confirmed: bool, reason: str):
            if not isinstance(job_id, str) or not isinstance(attempt, int):
                return
            previous = found.get((job_id, attempt))
            found[(job_id, attempt)] = {'jobId': job_id, 'attempt': attempt,
                                        'cleanupConfirmed': confirmed and (previous is None or previous['cleanupConfirmed']),
                                        'reason': previous['reason'] if previous else reason}

        for item in self.state.terminated:
            note(item['jobId'], item['attempt'], bool(item.get('cleanupConfirmed')), str(item.get('reason') or 'worker_restart'))
        try:
            containers = self.cli.labeled()
        except DockerError:
            containers = None
            self.host_clean = False
        active = self.state.active
        if active:
            note(active.get('jobId'), active.get('attempt'), containers is not None, 'worker_restart')
        for container in containers or []:
            removed = self.cli.remove(container['id'])
            self.host_clean &= removed
            note(container['jobId'], container['attempt'], removed, 'worker_restart')
        for entry in sweep(self.config.jobs_dir, self.results_dir, self.ops):
            self.host_clean &= entry['removed']
            note(entry['jobId'], entry['attempt'], entry['removed'], 'worker_restart')
        log('boot_reconciled', count=len(found), check='host_clean' if self.host_clean else 'host_unclean')
        return list(found.values())

    def boot(self) -> str:
        terminated = self.reconcile()
        started = self.clock()
        while True:
            self.touch()
            try:
                response = self.site.boot(self.instance_id, self.boot_id, self.release.image_id, self.release.commit,
                                          terminated)
                break
            except Unauthorized:
                log('boot_unauthorized', 'error')
                return 'unauthorized'
            except SiteError as error:
                log('boot_failed', 'warning', code=error.code)
                if self.clock() - started >= UNREACHABLE_SECONDS or self.stop_event.is_set():
                    return 'unreachable'
                self.wait(BOOT_RETRY_SECONDS)
        run_id = response.get('runId')
        if not isinstance(run_id, str) or not run_id:
            log('boot_bad_response', 'error')
            return 'unreachable'
        self.run_id = run_id
        self.site_drain = response.get('mode') == 'drain'
        self.state.set_run(run_id)
        self.state.acknowledged(terminated)
        log('booted', runId=run_id, mode='drain' if self.draining else 'active', count=len(terminated))
        return 'ok'

    def readiness(self) -> bool:
        image_id = self.cli.image_id(self.config.image)
        checks = {'hostClean': self.host_clean, 'image': image_id == self.release.image_id}
        checks['doctor'] = checks['image'] and self.runner.doctor(self.release.image_id,
                                                                  f'machsentry-doctor-{self.boot_id[:8]}')
        log('readiness', check=','.join(key for key, ok in checks.items() if not ok) or 'ok')
        if not all(checks.values()):
            return False
        versions = {'worker': __version__, 'release': self.release.commit, 'image': image_id,
                    'docker': self.cli.server_version(), 'python': platform.python_version()}
        try:
            self.site.ready(self.run_id, self.instance_id, checks, versions)
        except SiteError as error:
            log('ready_failed', 'warning', code=error.code)
            return False
        return True

    # Claim loop -------------------------------------------------------------------------------

    def serve(self) -> str:
        idle_since = unreachable_since = None
        while not self.stop_event.is_set():
            self.touch()
            self.refresh_mode()
            response = None
            if self.draining:
                response = {'job': None, 'reason': 'drain'}
            else:
                try:
                    response = self.site.claim(self.run_id, self.instance_id)
                    unreachable_since = None
                except Unauthorized:
                    return 'unauthorized'
                except SiteError as error:
                    log('claim_failed', 'warning', code=error.code)
                    if unreachable_since is None:
                        unreachable_since = self.clock()
            if response is not None and isinstance(response.get('job'), dict):
                idle_since = None
                if not self.process(response['job']):
                    return 'host_unclean'
                continue
            now = self.clock()
            if response is not None:
                seconds = response.get('workerIdleSeconds')
                self.idle_seconds = seconds if isinstance(seconds, int) and 0 < seconds <= 3600 else DEFAULT_IDLE_SECONDS
            if idle_since is None:
                idle_since = now
            if unreachable_since is not None and now - unreachable_since >= UNREACHABLE_SECONDS:
                return 'unreachable'
            if now - idle_since >= self.idle_seconds:
                if self.draining:
                    return 'drain'
                try:
                    answer = self.site.idle(self.run_id, self.instance_id)
                    unreachable_since = None
                    log('idle', stop=answer.get('stop') is True)
                    if answer.get('stop') is True:
                        return 'idle'
                    idle_since = now
                except Unauthorized:
                    return 'unauthorized'
                except SiteError as error:
                    log('idle_failed', 'warning', code=error.code)
                    if unreachable_since is None:
                        unreachable_since = now
            self.wait(self.poll_seconds)
        return 'stopped'

    def run(self) -> str:
        outcome = self.boot()
        if outcome == 'ok':
            ready = self.readiness()
            outcome = self.serve() if ready else ('host_unclean' if not self.host_clean else 'not_ready')
        if self.stop_event.is_set():
            # SIGTERM (systemctl stop, maintenance): the host stays up; any job was already failed back.
            log('supervisor_stopped', reason=outcome)
            return 'stopped'
        # After {stop:true} the site already marked the run stopping; unreachable/unauthorized cannot be told.
        if outcome not in ('idle', 'unreachable', 'unauthorized') and self.run_id:
            try:
                self.site.stopping(self.run_id, outcome)
            except SiteError as error:
                log('stopping_failed', 'warning', code=error.code)
        log('powering_off', reason=outcome)
        self.poweroff()
        return outcome

    # One job ----------------------------------------------------------------------------------

    def _monotonic(self, epoch: float) -> float:
        return self.clock() + (epoch - self.wall())

    def process(self, raw: dict) -> bool:
        """Runs one claimed attempt to /complete or /fail. Returns False when the host is no longer clean."""
        try:
            claim = parse_claim(raw)
        except ClaimInvalid as error:
            ids = identity(raw)
            log('claim_invalid', 'error', jobId=ids[0] if ids else None, code=str(error))
            if ids:
                self._deliver_fail(ids[0], ids[1], ids[2], 'internal', False,
                                   {'containerRemoved': True, 'workdirRemoved': True, 'sampleDeleted': True}, None)
            return True
        name = self.runner.container_name(claim.id, claim.attempt)
        job = JobDir(self.config.jobs_dir, self.results_dir, claim.id, claim.attempt, self.ops)
        deadline = self._monotonic(claim.deadline_epoch)
        limits = claim.limits
        static_deadline = min(self.clock() + limits['staticSeconds'],
                              deadline - limits['aiSeconds'] - limits['finalizeSeconds'])
        self.state.begin(claim.id, claim.attempt, name, claim.deadline_epoch, self.wall())
        heartbeat = Heartbeat(self.site, claim, interval=self.heartbeat_seconds, clock=self.clock, touch=self.touch)
        heartbeat.start()
        log('job_started', jobId=claim.id, attempt=claim.attempt, phase='static_analysis')
        started = self.clock()

        def stop_reason():
            if heartbeat.lease_lost.is_set():
                return 'lease_lost'
            if self.stop_event.is_set():
                return 'shutdown'
            return 'cancelled' if heartbeat.cancel.is_set() else None

        failure, outcome, copied, oversized, disk = None, None, {}, [], None
        try:
            try:
                job.create()
                self.download(claim.download_url, job.input_file, claim.sample['size'], claim.sample['sha256'])
                samples.inspect_file(job.input_file, claim.sample['name'])
                job.protect_input()
                if not stop_reason():
                    job.prepare_work(limits['diskBytes'])
                if not stop_reason():
                    argv = analysis_command(name, claim.id, claim.attempt, self.release.image_id, job.input_file,
                                            job.work, limits['maxFunctions'], limits['memoryBytes'], limits['pids'])
                    outcome = self.runner.run_static(name, argv, static_deadline, stop_reason)
                    disk = job.work_usage()
                    copied, oversized = job.collect_outputs()
            except samples.SampleRejected as error:
                failure = (error.code, False)
            except samples.DownloadUnavailable:
                failure = ('internal', True)
            except (HostOpError, OSError, ValueError) as error:
                log('job_setup_failed', 'error', jobId=claim.id, attempt=claim.attempt, code=type(error).__name__)
                failure = ('internal', True)
            cleanup = self._cleanup_static(job, name)
            log('static_done', jobId=claim.id, attempt=claim.attempt,
                exitCode=outcome.exit_code if outcome else None, timedOut=outcome.timed_out if outcome else False,
                oomKilled=outcome.oom_killed if outcome else False, **cleanup)
            reason = stop_reason() or (outcome.stopped if outcome else None)
            if reason:
                self._stopped(claim, job, reason, cleanup)
                return cleanup['containerRemoved'] and cleanup['workdirRemoved']
            metrics = self._metrics(started, outcome, disk)
            report = _load_json(copied.get('report.json'))
            if failure is None and report is None:
                failure = failure_code(outcome) if outcome else ('internal', False)
            artifact = report.get('artifact') if report is not None else None
            if failure is None and (report.get('analysis_status') not in ('partial', 'failed')
                                    or not isinstance(artifact, dict) or artifact.get('sha256') != claim.sample['sha256']):
                failure = ('analysis_failed', False)
            if failure is None and oversized:
                failure = ('publish_failed', False)
            if failure is not None:
                service = self._service(claim, None, None, outcome, 'not_requested', metrics, cleanup)
                self._fail(claim, job, failure[0], failure[1], cleanup, service)
                return cleanup['containerRemoved'] and cleanup['workdirRemoved']
            heartbeat.set_phase('ai_review')
            ai_started = self.clock()
            try:
                ai_result = self.ai_stage.run(claim, report, deadline - limits['finalizeSeconds'],
                                              lambda: stop_reason() is not None)
            except LeaseLost:
                raise
            except Exception as error:
                # report.json comes from the analysis container; a malformed one must not end the job.
                log('ai_stage_error', 'error', jobId=claim.id, attempt=claim.attempt, code=type(error).__name__)
                ai_result = AiStageResult('failed', claim.locale, claim.ai['model'], claim.ai['promptVersion'],
                                          claim.ai.get('priceVersion'), error_code='ai_stage_error')
            metrics.update({'aiSeconds': round(self.clock() - ai_started, 3), 'inputTokens': ai_result.input_tokens,
                            'cachedInputTokens': ai_result.cached_input_tokens, 'outputTokens': ai_result.output_tokens,
                            'aiCostMicros': ai_result.cost_micros})
            reason = stop_reason()
            if reason:
                self._stopped(claim, job, reason, cleanup)
                return cleanup['containerRemoved'] and cleanup['workdirRemoved']
            heartbeat.set_phase('publishing')
            view = _load_json(copied.get('report-view.json'))
            metrics['elapsedSeconds'] = round(self.clock() - started, 3)
            service = self._service(claim, report, view, outcome, ai_result.status, metrics, cleanup)
            self._publish(claim, job, copied, report, ai_result, service, metrics, cleanup, deadline, heartbeat)
            return cleanup['containerRemoved'] and cleanup['workdirRemoved']
        except LeaseLost:
            heartbeat.lease_lost.set()
            cleanup = self._cleanup_static(job, name)
            self._stopped(claim, job, 'lease_lost', cleanup)
            return cleanup['containerRemoved'] and cleanup['workdirRemoved']
        except Exception as error:
            log('job_crashed', 'error', jobId=claim.id, attempt=claim.attempt, code=type(error).__name__)
            cleanup = self._cleanup_static(job, name)
            self._deliver_fail(claim.id, claim.attempt, claim.lease_token, 'internal', False, cleanup, None)
            return cleanup['containerRemoved'] and cleanup['workdirRemoved']
        finally:
            heartbeat.stop()
            job.remove_results()
            log('job_finished', jobId=claim.id, attempt=claim.attempt)

    def _cleanup_static(self, job: JobDir, name: str) -> dict:
        """Container, sample and loop image go before anything else happens to the job."""
        container_removed = self.cli.remove(name)
        sample_deleted = job.delete_sample()
        workdir_removed = job.remove()
        return {'containerRemoved': container_removed, 'workdirRemoved': workdir_removed,
                'sampleDeleted': sample_deleted and not os.path.lexists(job.input_file)}

    def _metrics(self, started: float, outcome: StaticOutcome | None, disk: int | None) -> dict:
        return {'elapsedSeconds': round(self.clock() - started, 3),
                'staticSeconds': outcome.elapsed_seconds if outcome else 0.0, 'aiSeconds': 0.0,
                'cpuSeconds': outcome.cpu_seconds if outcome else None,
                'peakMemoryBytes': outcome.peak_memory_bytes if outcome else None, 'diskBytes': disk,
                'inputTokens': 0, 'cachedInputTokens': 0, 'outputTokens': 0, 'aiCostMicros': 0}

    def _service(self, claim: Claim, report, view, outcome, ai_status: str, metrics: dict, cleanup: dict) -> dict:
        engine = publish.engine_identity(report, (view or {}).get('schema_version')) if report else None
        return publish.service_result(claim.id, claim.attempt, engine, self.release.image_id, self.release.commit,
                                      report.get('analysis_status') if report else None,
                                      outcome.exit_code if outcome else None, ai_status, metrics, cleanup)

    def _stopped(self, claim: Claim, job: JobDir, reason: str, cleanup: dict):
        """Cancel, lease loss or shutdown: the attempt ends without publication."""
        code, retryable = {'cancelled': ('cancelled', False), 'shutdown': ('worker_lost', True),
                           'lease_lost': ('worker_lost', True)}[reason]
        log('job_stopped', jobId=claim.id, attempt=claim.attempt, reason=reason, **cleanup)
        self._deliver_fail(claim.id, claim.attempt, claim.lease_token, code, retryable, cleanup, None,
                           reason=reason)

    def _fail(self, claim: Claim, job: JobDir, code: str, retryable: bool, cleanup: dict, service: dict | None):
        """Publishes service-result.json when possible (diagnostics), then reports the failure."""
        log('job_failed', 'warning', jobId=claim.id, attempt=claim.attempt, code=code, retryable=retryable)
        artifacts = None
        if service is not None:
            try:
                artifacts = publish.prepare(job.results, {}, None, None, service)
                publish.upload(self.site, claim.id, claim.attempt, claim.lease_token, job.results, artifacts)
            except LeaseLost:
                raise
            except (PublishError, SiteError, OSError) as error:
                log('fail_artifacts_skipped', 'warning', jobId=claim.id, attempt=claim.attempt,
                    code=getattr(error, 'code', type(error).__name__))
                artifacts = None
        self._deliver_fail(claim.id, claim.attempt, claim.lease_token, code, retryable, cleanup, artifacts)

    def _deliver_fail(self, job_id: str, attempt: int, lease_token: str, code: str, retryable: bool, cleanup: dict,
                      artifacts, reason: str = 'fail_unreported'):
        try:
            response = self.site.fail(job_id, attempt, lease_token, code, retryable, cleanup, artifacts)
            log('fail_reported', jobId=job_id, attempt=attempt, code=code, status=response.get('status'))
            self.state.finish()
        except SiteError as error:
            # The site still needs termination proof for this attempt: keep it for the next boot.
            log('fail_unreported', 'warning', jobId=job_id, attempt=attempt, code=error.code)
            self.state.finish({'jobId': job_id, 'attempt': attempt,
                               'cleanupConfirmed': bool(cleanup['containerRemoved'] and cleanup['workdirRemoved']),
                               'reason': reason})

    def _publish(self, claim: Claim, job: JobDir, copied: dict, report: dict, ai_result, service: dict, metrics: dict,
                 cleanup: dict, deadline: float, heartbeat: Heartbeat):
        try:
            descriptors = publish.prepare(job.results, copied, report, ai_result.assessment(), service)
        except (PublishError, OSError) as error:
            log('publish_prepare_failed', 'error', jobId=claim.id, attempt=claim.attempt,
                code=getattr(error, 'code', type(error).__name__))
            self._deliver_fail(claim.id, claim.attempt, claim.lease_token, 'publish_failed', False, cleanup, None)
            return
        while True:
            try:
                publish.upload(self.site, claim.id, claim.attempt, claim.lease_token, job.results, descriptors)
                response = self.site.complete(claim.id, claim.attempt, claim.lease_token, report['analysis_status'],
                                              ai_result.status, descriptors, metrics, cleanup)
                log('job_completed', jobId=claim.id, attempt=claim.attempt, status=response.get('status'),
                    engineStatus=report['analysis_status'], aiStatus=ai_result.status)
                self.state.finish()
                return
            except LeaseLost:
                raise
            except (SiteUnavailable, PublishError) as error:
                transient = isinstance(error, SiteUnavailable) or error.code == 'upload_unavailable'
                log('publish_retry' if transient else 'publish_failed', 'warning', jobId=claim.id,
                    attempt=claim.attempt, code=error.code)
                if not transient or self.clock() + 15 >= deadline or heartbeat.lease_lost.is_set():
                    break
                self.wait(5)
            except SiteError as error:
                log('publish_failed', 'warning', jobId=claim.id, attempt=claim.attempt, code=error.code)
                break
        self._deliver_fail(claim.id, claim.attempt, claim.lease_token, 'publish_failed', False, cleanup, None)


def instance_identity(timeout: float = 2.0) -> str:
    """Instance id through IMDSv2 (session token, hop limit 1)."""
    from .site_api import opener
    client = opener()
    token_request = urllib.request.Request('http://169.254.169.254/latest/api/token', method='PUT',
                                           headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'})
    with client.open(token_request, timeout=timeout) as response:
        token = response.read(4096).decode()
    request = urllib.request.Request('http://169.254.169.254/latest/meta-data/instance-id',
                                     headers={'X-aws-ec2-metadata-token': token})
    with client.open(request, timeout=timeout) as response:
        return response.read(256).decode().strip()


def boot_id() -> str:
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def poweroff():
    subprocess.run(['systemctl', 'poweroff'], timeout=60, check=False)


def main(argv=None) -> int:
    try:
        config = load_host_config()
        release = load_release(config.release_file)
        ssm = ssm_client(config.region)
        parameters = load_parameters(config, ssm)
        instance_id, current_boot = instance_identity(), boot_id()
    except ConfigError as error:
        log('config_error', 'error', code=error.code)
        return 1
    except (OSError, urllib.error.URLError, ValueError) as error:
        log('identity_unavailable', 'error', code=type(error).__name__)
        return 1
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    site = SiteApi(parameters.site_url, parameters.token)
    cli = DockerCli()
    supervisor = Supervisor(
        site=site, cli=cli, runner=DockerRunner(cli), ops=HostOps(), state=State(config.state_file),
        ai_stage=AiStage(site, parameters.openai_api_key, parameters.openai_model), config=config, release=release,
        instance_id=instance_id, boot_id=current_boot, mode=parameters.mode,
        read_mode=lambda: read_mode(config, ssm), poweroff=poweroff, stop_event=stop_event)
    supervisor.run()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
