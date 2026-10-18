"""Independent watchdog, run by a systemd timer; it shares nothing with the supervisor process.

- Uptime above workerMaxSessionSeconds + 5 min (2 h 05 min): power off.
- A job container past its deadline + 2 min (from state.json; creation time + 20 min when the
  container is not the recorded attempt): `docker rm -f`.
- Supervisor heartbeat file older than 10 min, or missing after 10 min of uptime: power off.
Logs carry decisions and identifiers only. Entry point: `python -m machsentry_worker.watchdog`.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
import time

from .config import ConfigError, HostConfig, load_host_config
from .docker_runner import DockerCli, DockerError
from .logs import log
from .state import State

MAX_UPTIME_SECONDS = 2 * 60 * 60 + 5 * 60
CONTAINER_GRACE_SECONDS = 2 * 60
UNKNOWN_CONTAINER_SECONDS = 15 * 60 + 3 * 60 + 2 * 60
HEARTBEAT_STALE_SECONDS = 10 * 60


@dataclass
class Decision:
    poweroff: str | None = None
    remove: list = field(default_factory=list)


def decide(now: float, uptime: float, heartbeat_mtime: float | None, active: dict | None,
           containers: list[dict]) -> Decision:
    """Pure decision from the wall clock, uptime, heartbeat mtime, state.json's active attempt and
    the labeled containers ({id, name, created, jobId, attempt})."""
    decision = Decision()
    for container in containers:
        recorded = active is not None and container.get('jobId') == active.get('jobId') \
            and container.get('attempt') == active.get('attempt')
        if recorded and isinstance(active.get('deadlineEpoch'), (int, float)):
            limit = active['deadlineEpoch'] + CONTAINER_GRACE_SECONDS
        elif isinstance(container.get('created'), (int, float)):
            limit = container['created'] + UNKNOWN_CONTAINER_SECONDS + CONTAINER_GRACE_SECONDS
        else:
            limit = None
        if limit is not None and now > limit:
            decision.remove.append(container)
    if uptime > MAX_UPTIME_SECONDS:
        decision.poweroff = 'max_session'
    elif heartbeat_mtime is None and uptime > HEARTBEAT_STALE_SECONDS:
        decision.poweroff = 'supervisor_silent'
    elif heartbeat_mtime is not None and now - heartbeat_mtime > HEARTBEAT_STALE_SECONDS:
        decision.poweroff = 'supervisor_stale'
    return decision


def read_uptime(path: Path = Path('/proc/uptime')) -> float:
    return float(path.read_text().split()[0])


def heartbeat_mtime(path: Path) -> float | None:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return None


def notify_stopping(config: HostConfig, run_id: str | None, reason: str):
    """Best effort /worker/stopping; a failure never delays the power-off for long."""
    if not run_id:
        return
    try:
        from .config import load_parameters, ssm_client
        from .site_api import SiteApi
        parameters = load_parameters(config, ssm_client(config.region))
        SiteApi(parameters.site_url, parameters.token, timeout=5, attempts=1).stopping(run_id, reason)
    except Exception as error:
        log('watchdog_notify_failed', 'warning', code=type(error).__name__)


def run_once(config: HostConfig, cli: DockerCli, *, now: float, uptime: float, notify=notify_stopping,
             poweroff=lambda: None) -> Decision:
    state = State(config.state_file)
    try:
        containers = cli.labeled()
    except DockerError as error:
        log('watchdog_docker_unavailable', 'warning', code=error.code)
        containers = []
    decision = decide(now, uptime, heartbeat_mtime(config.heartbeat_file), state.active, containers)
    for container in decision.remove:
        removed = cli.remove(container['id'])
        log('watchdog_container_removed', 'warning', jobId=container.get('jobId'), attempt=container.get('attempt'),
            containerRemoved=removed)
    if decision.poweroff:
        log('watchdog_poweroff', 'warning', reason=decision.poweroff)
        notify(config, state.data.get('runId'), decision.poweroff)
        poweroff()
    return decision


def main(argv=None) -> int:
    from .supervisor import poweroff
    try:
        config = load_host_config()
    except ConfigError as error:
        log('watchdog_config_default', 'warning', code=error.code)
        config = HostConfig(region='us-east-2')
    try:
        uptime = read_uptime()
    except (OSError, ValueError, IndexError):
        uptime = 0.0
    run_once(config, DockerCli(), now=time.time(), uptime=uptime, poweroff=poweroff)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
