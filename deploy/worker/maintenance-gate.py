"""ExecCondition of machsentry-supervisor.service: skip this start while the deploy script holds the instance.

scripts/deploy_machsentry_aws.py tags the worker `unpacked-analysis:maintenance` before it starts a stopped
instance for a bootstrap or a rollback, so the previous release's supervisor claims no job before
bootstrap.sh takes over. The template exposes instance tags in IMDS. A tag whose `since=` is an hour old
belongs to an operator process that ended before its cleanup and no longer blocks; the deploy script's
next command removes it. Any other outcome (IMDS unreachable, tags not exposed, a value without `since=`)
starts the supervisor. Exit 0 starts it; exit 1 makes systemd skip this start without a failure.

bootstrap.sh installs this file as /opt/machsentry-worker/bin/maintenance-gate.py; it runs with the system
python3 (-I), outside the supervisor venv.
"""

import datetime as dt
import sys
import urllib.error
import urllib.request

IMDS = 'http://169.254.169.254/latest'
TAG = 'unpacked-analysis:maintenance'
# scripts/deploy_machsentry_aws.py MAINTENANCE_START_SECONDS: longer than starting the instance and
# waiting for its SSM agent.
MAX_AGE_SECONDS = 3600


def read_tag(urlopen) -> str | None:
    token_request = urllib.request.Request(f'{IMDS}/api/token', method='PUT',
                                           headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'})
    with urlopen(token_request, timeout=2) as response:
        token = response.read().decode('ascii')
    request = urllib.request.Request(f'{IMDS}/meta-data/tags/instance/{TAG}', headers={'X-aws-ec2-metadata-token': token})
    try:
        with urlopen(request, timeout=2) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise


def blocks(value: str, now: dt.datetime) -> bool:
    since = next((word.removeprefix('since=') for word in value.split() if word.startswith('since=')), None)
    if since is None:
        return False
    try:
        started = dt.datetime.strptime(since, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return False
    return (now - started).total_seconds() < MAX_AGE_SECONDS


def main(urlopen=urllib.request.urlopen, now=None) -> int:
    try:
        value = read_tag(urlopen)
        blocked = value is not None and blocks(value, now or dt.datetime.now(dt.timezone.utc))
    except Exception as error:  # an unreadable gate never keeps the worker down
        print(f'maintenance tag unreadable ({type(error).__name__}); starting the supervisor', file=sys.stderr)
        return 0
    if blocked:
        print(f'{TAG} = {value}; skipping this start', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
