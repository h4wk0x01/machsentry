"""Host configuration file plus SSM parameters. Secrets stay in process memory only.

Nothing read here is written to disk, logged or passed to the analysis container.
"""

from dataclasses import dataclass
import json
from pathlib import Path
import re

DEFAULT_CONFIG = Path('/etc/machsentry-worker/config.json')
_REGION = re.compile(r'^[a-z]{2}(-[a-z]+)+-\d$')
_COMMIT = re.compile(r'^[0-9a-f]{7,40}$')
_IMAGE_ID = re.compile(r'^sha256:[0-9a-f]{64}$')


class ConfigError(Exception):
    def __init__(self, code: str, detail: str = ''):
        super().__init__(f'{code}: {detail}' if detail else code)
        self.code = code


class Secret:
    """Holds a credential; repr/str never show it, so accidental logging prints a placeholder."""
    __slots__ = ('_value',)

    def __init__(self, value: str):
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self):
        return 'Secret(***)'

    __str__ = __repr__


@dataclass(frozen=True)
class HostConfig:
    region: str
    ssm_prefix: str = '/unpacked/analysis'
    state_dir: Path = Path('/var/lib/machsentry-worker')
    image: str = 'machsentry-analyzer:current'
    release_file: Path = Path('/etc/machsentry-worker/release.json')
    heartbeat_file: Path = Path('/run/machsentry-worker/heartbeat')

    @property
    def jobs_dir(self) -> Path:
        return self.state_dir / 'jobs'

    @property
    def state_file(self) -> Path:
        return self.state_dir / 'state.json'


@dataclass(frozen=True)
class Parameters:
    token: Secret
    site_url: str
    mode: str
    openai_api_key: Secret | None
    openai_model: str | None


@dataclass(frozen=True)
class Release:
    commit: str
    image_id: str


def load_host_config(path: Path = DEFAULT_CONFIG) -> HostConfig:
    try:
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise ConfigError('config_unreadable', type(error).__name__) from error
    if not isinstance(raw, dict) or not isinstance(raw.get('region'), str) or not _REGION.match(raw['region']):
        raise ConfigError('config_invalid', 'region')
    prefix = raw.get('ssmPrefix', '/unpacked/analysis')
    if not isinstance(prefix, str) or not re.match(r'^(/[A-Za-z0-9_.-]+)+$', prefix):
        raise ConfigError('config_invalid', 'ssmPrefix')
    paths = {}
    for key, field, default in (('stateDir', 'state_dir', HostConfig.state_dir),
                                ('releaseFile', 'release_file', HostConfig.release_file),
                                ('heartbeatFile', 'heartbeat_file', HostConfig.heartbeat_file)):
        value = raw.get(key, default.as_posix())
        if not isinstance(value, str) or not value.startswith('/') or '..' in Path(value).parts:
            raise ConfigError('config_invalid', key)
        paths[field] = Path(value)
    image = raw.get('image', HostConfig.image)
    if not isinstance(image, str) or not re.match(r'^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9_.-]{1,128})?$', image):
        raise ConfigError('config_invalid', 'image')
    return HostConfig(region=raw['region'], ssm_prefix=prefix, image=image, **paths)


def load_release(path: Path) -> Release:
    try:
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise ConfigError('release_unreadable', type(error).__name__) from error
    commit, image_id = (raw.get('commit'), raw.get('image_id')) if isinstance(raw, dict) else (None, None)
    if not isinstance(commit, str) or not _COMMIT.match(commit):
        raise ConfigError('release_invalid', 'commit')
    if not isinstance(image_id, str) or not _IMAGE_ID.match(image_id):
        raise ConfigError('release_invalid', 'image_id')
    return Release(commit, image_id)


def ssm_client(region: str):
    import boto3
    from botocore.config import Config
    return boto3.client('ssm', region_name=region, config=Config(
        connect_timeout=5, read_timeout=10, retries={'max_attempts': 3, 'mode': 'standard'}))


def _not_found(error: Exception) -> bool:
    response = getattr(error, 'response', None)
    return isinstance(response, dict) and response.get('Error', {}).get('Code') == 'ParameterNotFound'


def _parameter(config: HostConfig, client, name: str, required: bool = True) -> str | None:
    """Reads one parameter per call: the worker role grants ssm:GetParameter only."""
    try:
        value = client.get_parameter(Name=f'{config.ssm_prefix}/{name}', WithDecryption=True)['Parameter']['Value']
    except Exception as error:
        if _not_found(error) and not required:
            return None
        raise ConfigError('parameter_unavailable', name) from None
    if not isinstance(value, str) or not value.strip():
        if required:
            raise ConfigError('parameter_invalid', name)
        return None
    return value.strip()


def read_mode(config: HostConfig, client) -> str:
    """`worker drain` and `worker resume` write this parameter; the supervisor reads it before each claim."""
    mode = _parameter(config, client, 'worker/mode')
    if mode not in ('active', 'drain'):
        raise ConfigError('parameter_invalid', 'worker/mode')
    return mode


def load_parameters(config: HostConfig, client=None) -> Parameters:
    client = client or ssm_client(config.region)
    token = _parameter(config, client, 'worker/token')
    site_url = _parameter(config, client, 'worker/site-url').rstrip('/')
    if not re.match(r'^https://[A-Za-z0-9.-]+(:\d{1,5})?$', site_url):
        raise ConfigError('parameter_invalid', 'worker/site-url')
    mode = read_mode(config, client)
    api_key = _parameter(config, client, 'openai/api-key', required=False)
    model = _parameter(config, client, 'openai/model', required=False)
    return Parameters(Secret(token), site_url, mode, Secret(api_key) if api_key else None, model)
