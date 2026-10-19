"""Runs MachSentry in a fresh, isolated container per attempt (contract section 9).

The container gets the input read-only, the job's loop image at /work and a fixed environment:
no AWS or AI credentials, no Docker socket, no network. On the static deadline it receives SIGINT,
30 s of grace, then `docker rm -f`. Cgroup teardown is the only guaranteed stop for REA's detached
JVM, so every attempt ends with the container removed and its absence verified.
"""

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import time

LABEL = 'machsentry.worker'
CONTAINER_USER = '10001:10001'
GRACE_SECONDS = 30
POLL_SECONDS = 2
REA_TIMEOUT_SECONDS = 840
REA_ROOT = '/opt/machsentry'
ENVIRONMENT = (('HOME', '/work/home'), ('TMPDIR', '/work/tmp'), ('GHIDRA_HEADLESS_MAXMEM', '1536M'),
               ('REA_GHIDRA_STARTUP_TIMEOUT_MS', '780000'), ('PYTHONDONTWRITEBYTECODE', '1'), ('LANG', 'C.UTF-8'))
_CLI_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
_CODE = re.compile(r'^[a-z0-9_]{1,64}$')
GIB = 1024 * 1024 * 1024


class DockerError(Exception):
    def __init__(self, code: str, exit_code: int | None = None):
        super().__init__(code)
        self.code, self.exit_code = code, exit_code


def isolation_flags(memory_bytes: int = 3 * GIB, pids: int = 256) -> list[str]:
    memory = f'{memory_bytes // GIB}g' if memory_bytes % GIB == 0 else str(memory_bytes)
    return ['--network', 'none', '--read-only', '--init', '--user', CONTAINER_USER, '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', str(pids), '--memory', memory,
            '--memory-swap', memory, '--cpus', '2', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m']


def analysis_command(name: str, job_id: str, attempt: int, image: str, input_file: Path, work: Path,
                     max_functions: int, memory_bytes: int = 3 * GIB, pids: int = 256) -> list[str]:
    argv = ['run', '--detach', '--name', name, '--label', f'{LABEL}=1', '--label', f'machsentry.job={job_id}',
            '--label', f'machsentry.attempt={attempt}', *isolation_flags(memory_bytes, pids),
            '--mount', f'type=bind,source={Path(input_file).as_posix()},target=/input/sample.macho,readonly',
            '--mount', f'type=bind,source={Path(work).as_posix()},target=/work']
    for key, value in ENVIRONMENT:
        argv += ['--env', f'{key}={value}']
    return argv + [image, 'python', '-m', 'machsentry', 'analyze', '/input/sample.macho',
                   '--output', '/work/out/report', '--rea-root', REA_ROOT, '--max-functions', str(max_functions),
                   '--rea-timeout', str(REA_TIMEOUT_SECONDS), '--report-brand', 'unpacked']


def doctor_command(name: str, image: str) -> list[str]:
    return ['run', '--name', name, '--label', f'{LABEL}=1', '--label', 'machsentry.role=doctor',
            *isolation_flags(), '--env', 'HOME=/tmp', '--env', 'TMPDIR=/tmp', '--env', 'LANG=C.UTF-8',
            '--workdir', REA_ROOT, image, 'node', 'scripts/rea.mjs', 'doctor', '--provider', 'ghidra', '--json']


def _created(value: str) -> float | None:
    match = re.match(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$', value.strip())
    if not match:
        return None
    fraction = (match.group(2) or '.0')[:7]
    zone = '+00:00' if match.group(3) == 'Z' else match.group(3)
    return datetime.fromisoformat(match.group(1) + fraction + zone).timestamp()


class DockerCli:
    """Bounded docker CLI calls with a minimal environment; returns parsed facts."""

    def __init__(self, docker: str = 'docker', run=subprocess.run):
        self._docker, self._run = docker, run

    def call(self, args: list[str], timeout: float = 60) -> tuple[int, str, str]:
        try:
            completed = self._run([self._docker, *args], capture_output=True, timeout=timeout, env=_CLI_ENV, check=False)
        except subprocess.TimeoutExpired:
            raise DockerError('docker_timeout') from None
        except OSError:
            raise DockerError('docker_unavailable') from None
        return (completed.returncode, completed.stdout.decode(errors='replace')[:1024 * 1024],
                completed.stderr.decode(errors='replace')[:4096])

    def run_detached(self, argv: list[str]) -> str:
        code, stdout, _ = self.call(argv, timeout=120)
        if code != 0:
            raise DockerError('docker_run_failed', code)
        return stdout.strip()

    def state(self, name: str) -> dict | None:
        code, stdout, stderr = self.call(['container', 'inspect', '--format', '{{json .State}}', name])
        if code != 0:
            if 'no such' in stderr.lower():
                return None
            raise DockerError('docker_inspect_failed', code)
        try:
            state = json.loads(stdout)
        except ValueError:
            raise DockerError('docker_inspect_failed') from None
        return state if isinstance(state, dict) else None

    def kill(self, name: str, signal: str) -> bool:
        return self.call(['kill', '--signal', signal, name])[0] == 0

    def remove(self, name: str) -> bool:
        """`docker rm -f`, then confirms the container no longer exists."""
        try:
            self.call(['rm', '--force', name], timeout=120)
            return self.state(name) is None
        except DockerError:
            return False

    def stdout_tail(self, name: str) -> str:
        code, stdout, _ = self.call(['logs', '--tail', '20', name])
        return stdout if code == 0 else ''

    def labeled(self, label: str = LABEL) -> list[dict]:
        code, stdout, _ = self.call(['ps', '--all', '--quiet', '--no-trunc', '--filter', f'label={label}'])
        if code != 0:
            raise DockerError('docker_ps_failed', code)
        containers = []
        template = ('{{json .Name}}|{{json .Created}}|{{json (index .Config.Labels "machsentry.job")}}|'
                    '{{json (index .Config.Labels "machsentry.attempt")}}')
        for identifier in stdout.split():
            code, line, stderr = self.call(['container', 'inspect', '--format', template, identifier])
            if code != 0:
                if 'no such' in stderr.lower():
                    continue
                raise DockerError('docker_inspect_failed', code)
            try:
                name, created, job, attempt = (json.loads(part) for part in line.strip().split('|'))
            except ValueError:
                name, created, job, attempt = identifier, '', None, None
            containers.append({'id': identifier, 'name': str(name).lstrip('/'), 'created': _created(str(created)),
                               'jobId': job if isinstance(job, str) else None,
                               'attempt': int(attempt) if isinstance(attempt, str) and attempt.isdigit() else None})
        return containers

    def image_id(self, reference: str) -> str | None:
        code, stdout, _ = self.call(['image', 'inspect', '--format', '{{.Id}}', reference])
        return stdout.strip() if code == 0 else None

    def server_version(self) -> str | None:
        code, stdout, _ = self.call(['version', '--format', '{{.Server.Version}}'])
        return stdout.strip() if code == 0 else None


@dataclass
class StaticOutcome:
    exit_code: int | None = None
    oom_killed: bool = False
    timed_out: bool = False
    # Why the supervisor stopped the container early: cancelled, lease_lost or shutdown.
    stopped: str | None = None
    start_failed: bool = False
    container_removed: bool = False
    elapsed_seconds: float = 0.0
    cpu_seconds: float | None = None
    peak_memory_bytes: int | None = None
    error_code: str | None = None


class CgroupProbe:
    """Samples memory.peak and cpu.stat usage_usec of the container's cgroup v2 while it runs.

    memory.peak is the cgroup's own high-water mark, so each sample already covers all earlier
    peaks; the scope disappears when the container stops, so the last sample is the result.
    """

    def __init__(self, cgroup_root: Path = Path('/sys/fs/cgroup'), proc_root: Path = Path('/proc')):
        self.cgroup_root, self.proc_root = Path(cgroup_root), Path(proc_root)
        self.path: Path | None = None
        self.peak: int | None = None
        self.cpu_seconds: float | None = None

    def locate(self, pid: int | None, container_id: str):
        candidates = []
        if pid:
            try:
                for line in (self.proc_root / str(pid) / 'cgroup').read_text().splitlines():
                    if line.startswith('0::/'):
                        candidates.append(self.cgroup_root / line[4:].strip())
            except OSError:
                pass
        candidates += [self.cgroup_root / 'system.slice' / f'docker-{container_id}.scope',
                       self.cgroup_root / 'docker' / container_id]
        self.path = next((path for path in candidates if (path / 'memory.peak').exists()), None)

    def sample(self):
        if self.path is None:
            return
        try:
            peak = int((self.path / 'memory.peak').read_text().strip())
            self.peak = peak if self.peak is None else max(self.peak, peak)
            for line in (self.path / 'cpu.stat').read_text().splitlines():
                key, _, value = line.partition(' ')
                if key == 'usage_usec':
                    self.cpu_seconds = int(value) / 1_000_000
        except (OSError, ValueError):
            pass


class DockerRunner:
    def __init__(self, cli: DockerCli, *, clock=time.monotonic, sleep=time.sleep, probe_factory=CgroupProbe):
        self.cli, self.clock, self.sleep, self.probe_factory = cli, clock, sleep, probe_factory

    @staticmethod
    def container_name(job_id: str, attempt: int) -> str:
        return f'machsentry-{job_id}-{attempt}'

    def run_static(self, name: str, argv: list[str], deadline: float, stop=lambda: None) -> StaticOutcome:
        """`deadline` is monotonic. `stop()` returns a reason to remove the container at once, or None."""
        outcome, started = StaticOutcome(), self.clock()
        probe = self.probe_factory()
        try:
            container_id = self.cli.run_detached(argv)
        except DockerError as error:
            outcome.start_failed, outcome.exit_code = True, error.exit_code
            outcome.container_removed = self.cli.remove(name)
            return outcome
        try:
            state = self.cli.state(name)
            probe.locate((state or {}).get('Pid'), container_id)
            while True:
                probe.sample()
                state = self.cli.state(name)
                if state is None or not state.get('Running'):
                    break
                reason = stop()
                if reason:
                    outcome.stopped = reason
                    break
                if self.clock() >= deadline:
                    outcome.timed_out = True
                    self.cli.kill(name, 'SIGINT')
                    grace = self.clock() + GRACE_SECONDS
                    while self.clock() < grace:
                        self.sleep(1)
                        probe.sample()
                        state = self.cli.state(name)
                        if state is None or not state.get('Running'):
                            break
                    break
                self.sleep(POLL_SECONDS)
            if state is not None and not state.get('Running'):
                outcome.exit_code = state.get('ExitCode')
                outcome.oom_killed = bool(state.get('OOMKilled'))
                if not outcome.stopped:
                    outcome.error_code = envelope_code(self.cli.stdout_tail(name))
        except DockerError:
            pass
        finally:
            outcome.elapsed_seconds = round(self.clock() - started, 3)
            outcome.cpu_seconds, outcome.peak_memory_bytes = probe.cpu_seconds, probe.peak
            outcome.container_removed = self.cli.remove(name)
        return outcome

    def doctor(self, image: str, name: str, timeout: float = 180) -> bool:
        """REA doctor for Ghidra inside the same isolation; healthy means exit 0 and healthy: true."""
        try:
            code, stdout, _ = self.cli.call(doctor_command(name, image), timeout=timeout)
            report = json.loads(stdout) if code == 0 else None
            return isinstance(report, dict) and report.get('healthy') is True
        except (DockerError, ValueError):
            return False
        finally:
            self.cli.remove(name)


def envelope_code(stdout: str) -> str | None:
    """Error code from MachSentry's single-line Result envelope; messages are never kept."""
    for line in reversed(stdout.splitlines()):
        try:
            envelope = json.loads(line)
        except ValueError:
            continue
        if isinstance(envelope, dict) and 'ok' in envelope:
            error = envelope.get('error')
            code = error.get('code') if isinstance(error, dict) else None
            return code if isinstance(code, str) and _CODE.match(code) else None
    return None
