"""Builds the attempt's artifacts and publishes them (contract section 7).

`prepare` writes every artifact once into the results directory and returns their descriptors;
`send` asks the site for presigned PUTs bound to size + SHA-256, uploads with exactly the returned
headers and then reports completion. Repeating `send` with the same descriptors is safe: the files
do not change, the PUTs overwrite identical objects and the site answers a repeated completion
with the stored result.
"""

from base64 import b64encode
from hashlib import sha256
import http.client
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import USER_AGENT
from .site_api import opener

SERVICE_SCHEMA = 'unpacked-analysis-service/1'
KIB, MIB = 1024, 1024 * 1024
CAPS = {
    'service-result.json': 256 * KIB,
    'report-view.json': 4 * MIB,
    'report.html': 4 * MIB,
    'functions.json': 4 * MIB,
    'report.json': 32 * MIB,
    'detection.yar': 256 * KIB,
    'candidate-rejected.yar.txt': 256 * KIB,
    'ai-assessment.json': MIB,
}
PSEUDOCODE_BYTES = 64 * KIB
_HEADER = re.compile(r'^[A-Za-z0-9-]{1,64}$')


class PublishError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _json(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def _clip_utf8(text: str, limit: int) -> tuple[str, bool]:
    data = text.encode()
    if len(data) <= limit:
        return text, False
    return data[:limit].decode(errors='ignore'), True


def functions_json(report: dict) -> bytes:
    """Pseudocode is capped at 64 KiB per function; smaller caps apply only if 4 MiB is exceeded."""
    functions = [item for item in report.get('functions') or [] if isinstance(item, dict)]
    for cap in (PSEUDOCODE_BYTES, 32 * KIB, 16 * KIB, 8 * KIB, 4 * KIB, 0):
        entries = []
        for function in functions:
            pseudocode = function.get('pseudocode') if isinstance(function.get('pseudocode'), str) else None
            source_digest = sha256(pseudocode.encode('utf-8')).hexdigest() if pseudocode is not None else None
            source_characters = len(pseudocode) if pseudocode is not None else None
            truncated = False
            if pseudocode is not None:
                pseudocode, truncated = _clip_utf8(pseudocode, cap)
            entries.append({'architecture': function.get('architecture'), 'slice': function.get('slice'),
                            'address': function.get('address'), 'names': function.get('names') or [],
                            'findingIds': function.get('finding_ids') or [], 'pseudocode': pseudocode,
                            'pseudocodeTruncated': truncated, 'pseudocodeSha256': source_digest,
                            'pseudocodeCharacters': source_characters})
        data = _json(entries)
        if len(data) <= CAPS['functions.json']:
            return data
    raise PublishError('functions_too_large')


def engine_identity(report: dict, view_schema: str | None) -> dict:
    engine = report.get('engine') if isinstance(report.get('engine'), dict) else {}
    presentation = report.get('presentation') if isinstance(report.get('presentation'), dict) else {}
    return {'name': engine.get('name'), 'version': engine.get('version'),
            'rulesetVersion': engine.get('ruleset_version'), 'provider': engine.get('provider'),
            'reportSchema': report.get('schema_version'),
            'viewSchema': view_schema or presentation.get('schema_version')}


def service_result(job_id: str, attempt: int, engine: dict | None, image: str, release: str,
                   engine_status: str | None, exit_code: int | None, ai_status: str, metrics: dict,
                   cleanup: dict) -> dict:
    return {'schema': SERVICE_SCHEMA, 'jobId': job_id, 'attempt': attempt, 'engine': engine, 'image': image,
            'release': release, 'engineStatus': engine_status, 'exitCode': exit_code, 'aiStatus': ai_status,
            'metrics': metrics, 'cleanup': cleanup}


def describe(path: Path) -> dict:
    data = path.read_bytes()
    return {'name': path.name, 'size': len(data), 'sha256': sha256(data).hexdigest()}


def write(results: Path, name: str, data: bytes) -> dict:
    """Writes an artifact once; a later call with other bytes is refused to keep publication stable."""
    if len(data) > CAPS[name]:
        raise PublishError(f'artifact_too_large:{name}')
    path = results / name
    if path.exists():
        if path.read_bytes() != data:
            raise PublishError('artifact_changed')
    else:
        with open(path, 'xb') as output:
            output.write(data)
    return {'name': name, 'size': len(data), 'sha256': sha256(data).hexdigest()}


def prepare(results: Path, copied: dict, report: dict | None, ai_assessment: dict | None, service: dict) -> list[dict]:
    """`copied` maps engine output names already in `results` to their paths."""
    descriptors = [write(results, 'service-result.json', _json(service))]
    for name in ('report-view.json', 'report.html'):
        if name in copied:
            descriptors.append(describe(copied[name]))
    if report is not None:
        descriptors.append(write(results, 'functions.json', functions_json(report)))
    for name in ('report.json', 'detection.yar', 'candidate-rejected.yar.txt'):
        if name in copied:
            descriptors.append(describe(copied[name]))
    if ai_assessment is not None:
        descriptors.append(write(results, 'ai-assessment.json', _json(ai_assessment)))
    for descriptor in descriptors:
        if descriptor['size'] > CAPS[descriptor['name']]:
            raise PublishError(f'artifact_too_large:{descriptor["name"]}')
    return descriptors


def _put(url: str, data: bytes, headers: dict, timeout: float) -> int:
    request = urllib.request.Request(url, data=data, method='PUT', headers={**headers, 'User-Agent': USER_AGENT})
    try:
        with opener().open(request, timeout=timeout) as response:
            response.read(64 * KIB)
            return response.status
    except urllib.error.HTTPError as error:
        error.close()
        return error.code
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError):
        return 0


def _headers(raw) -> dict:
    if not isinstance(raw, dict):
        raise PublishError('bad_upload_grant')
    headers = {}
    for key, value in raw.items():
        if not (isinstance(key, str) and _HEADER.match(key) and isinstance(value, str)
                and '\r' not in value and '\n' not in value):
            raise PublishError('bad_upload_grant')
        if key.lower() not in ('host', 'content-length'):
            headers[key] = value
    return headers


def _require_transport(url) -> str:
    parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    if parsed is None or not (parsed.scheme == 'https' or (
            parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1'))):
        raise PublishError('bad_upload_grant')
    return url


def upload(site, job_id: str, attempt: int, lease_token: str, results: Path, descriptors: list[dict], *,
           timeout: float = 60.0, attempts: int = 3, sleep=time.sleep):
    pending = {descriptor['name']: descriptor for descriptor in descriptors}
    for grant_round in range(2):
        grant = site.artifacts(job_id, attempt, lease_token, list(pending.values()))
        uploads = grant.get('uploads') if isinstance(grant.get('uploads'), list) else None
        if uploads is None:
            raise PublishError('bad_upload_grant')
        granted = {item.get('name'): item for item in uploads if isinstance(item, dict)}
        if set(granted) != set(pending):
            raise PublishError('bad_upload_grant')
        expired = False
        for name, descriptor in list(pending.items()):
            url, headers = _require_transport(granted[name].get('url')), _headers(granted[name].get('headers'))
            if not any(key.lower() == 'x-amz-checksum-sha256' for key in headers):
                raise PublishError('bad_upload_grant')
            expected = b64encode(bytes.fromhex(descriptor['sha256'])).decode()
            if next(value for key, value in headers.items() if key.lower() == 'x-amz-checksum-sha256') != expected:
                raise PublishError('bad_upload_grant')
            data = (results / name).read_bytes()
            if len(data) != descriptor['size'] or sha256(data).hexdigest() != descriptor['sha256']:
                raise PublishError('artifact_changed')
            for index in range(attempts):
                status = _put(url, data, headers, timeout)
                if 200 <= status < 300:
                    del pending[name]
                    break
                if status == 403:
                    expired = True
                    break
                if status and 400 <= status < 500 and status not in (408, 429):
                    raise PublishError(f'upload_rejected_{status}')
                if index + 1 < attempts:
                    sleep(2 ** index)
            else:
                raise PublishError('upload_unavailable')
            if expired:
                break
        if not pending:
            return
    raise PublishError('upload_rejected_403')
