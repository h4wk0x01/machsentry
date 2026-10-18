"""Client of the site's worker API (`/api/internal/analysis`, contract section 6).

Idempotent calls retry transient failures (network, 429, 5xx) with bounded backoff. Calls whose
repetition could create a second effect (claim, AI reservation, idle) are sent once. Redirects and
environment proxies are refused so the bearer token only reaches the configured site.
"""

import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import USER_AGENT
from .config import Secret

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
_CODE = re.compile(r'^[a-z0-9_]{1,64}$')


class SiteError(Exception):
    def __init__(self, code: str, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


class Unauthorized(SiteError):
    pass


class LeaseLost(SiteError):
    pass


class SiteUnavailable(SiteError):
    """Network failure, 429 or 5xx that outlasted the retries."""


class _Transient(Exception):
    def __init__(self, code: str, status: int | None = None, retry_after: float | None = None):
        super().__init__(code)
        self.code, self.status, self.retry_after = code, status, retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _retry_after(headers) -> float | None:
    try:
        return min(30.0, max(0.0, float(headers.get('Retry-After'))))
    except (TypeError, ValueError):
        return None


class SiteApi:
    def __init__(self, site_url: str, token: Secret, *, timeout: float = 20.0, attempts: int = 4,
                 backoff: float = 1.0, sleep=time.sleep):
        self._base = site_url.rstrip('/') + '/api/internal/analysis'
        self._token = token
        self._timeout, self._attempts, self._backoff, self._sleep = timeout, attempts, backoff, sleep
        self._opener = opener()

    def _send(self, path: str, body: dict) -> dict:
        data = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode()
        if len(data) > MAX_REQUEST_BYTES:
            raise SiteError('request_too_large')
        request = urllib.request.Request(self._base + path, data=data, method='POST', headers={
            'Authorization': f'Bearer {self._token.reveal()}', 'Content-Type': 'application/json',
            'Accept': 'application/json', 'User-Agent': USER_AGENT})
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                status, payload = response.status, response.read(MAX_RESPONSE_BYTES + 1)
                retry_after = None
        except urllib.error.HTTPError as error:
            status, retry_after = error.code, _retry_after(error.headers)
            try:
                payload = error.read(MAX_RESPONSE_BYTES + 1)
            except (OSError, http.client.HTTPException):
                payload = b''
            finally:
                error.close()
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError):
            raise _Transient('network') from None
        try:
            parsed = json.loads(payload) if payload and len(payload) <= MAX_RESPONSE_BYTES else None
        except ValueError:
            parsed = None
        error_code = parsed.get('error') if isinstance(parsed, dict) else None
        error_code = error_code if isinstance(error_code, str) and _CODE.match(error_code) else None
        if 200 <= status < 300:
            if not isinstance(parsed, dict):
                raise SiteError('bad_response', status)
            return parsed
        if status == 429 or status >= 500:
            raise _Transient(error_code or f'http_{status}', status, retry_after)
        if status == 401:
            raise Unauthorized(error_code or 'unauthorized', status)
        if status == 409 and error_code == 'lease_lost':
            raise LeaseLost('lease_lost', status)
        raise SiteError(error_code or f'http_{status}', status)

    def _post(self, path: str, body: dict, *, idempotent: bool, attempts: int | None = None) -> dict:
        tries = (attempts or self._attempts) if idempotent else 1
        for index in range(tries):
            try:
                return self._send(path, body)
            except _Transient as error:
                last = error
                if index + 1 < tries:
                    delay = self._backoff * 2 ** index
                    self._sleep(min(8.0, max(delay, error.retry_after or 0.0)))
        raise SiteUnavailable(last.code, last.status)

    @staticmethod
    def _job(job_id: str, action: str) -> str:
        return f'/jobs/{urllib.parse.quote(job_id, safe="")}/{action}'

    def boot(self, instance_id, boot_id, image, release, terminated_attempts) -> dict:
        return self._post('/worker/boot', {'instanceId': instance_id, 'bootId': boot_id, 'image': image,
                                           'release': release, 'terminatedAttempts': terminated_attempts},
                          idempotent=True)

    def ready(self, run_id, instance_id, checks, versions) -> dict:
        return self._post('/worker/ready', {'runId': run_id, 'instanceId': instance_id, 'checks': checks,
                                            'versions': versions}, idempotent=True)

    def claim(self, run_id, instance_id) -> dict:
        return self._post('/worker/claim', {'runId': run_id, 'instanceId': instance_id}, idempotent=False)

    def heartbeat(self, job_id, attempt, lease_token, phase) -> dict:
        return self._post(self._job(job_id, 'heartbeat'),
                          {'attempt': attempt, 'leaseToken': lease_token, 'phase': phase},
                          idempotent=True, attempts=2)

    def ai_reserve(self, job_id, attempt, lease_token, call_index, input_tokens, max_output_tokens,
                   model, prompt_version) -> dict:
        return self._post(self._job(job_id, 'ai/reserve'), {
            'attempt': attempt, 'leaseToken': lease_token, 'callIndex': call_index, 'inputTokens': input_tokens,
            'maxOutputTokens': max_output_tokens, 'model': model, 'promptVersion': prompt_version},
            idempotent=False)

    def ai_settle(self, job_id, attempt, lease_token, call_id, outcome, usage=None, request_id=None,
                  error_code=None) -> dict:
        body = {'attempt': attempt, 'leaseToken': lease_token, 'callId': call_id, 'outcome': outcome}
        body.update({key: value for key, value in (('usage', usage), ('requestId', request_id),
                                                   ('errorCode', error_code)) if value is not None})
        return self._post(self._job(job_id, 'ai/settle'), body, idempotent=True)

    def artifacts(self, job_id, attempt, lease_token, artifacts) -> dict:
        return self._post(self._job(job_id, 'artifacts'),
                          {'attempt': attempt, 'leaseToken': lease_token, 'artifacts': artifacts}, idempotent=True)

    def complete(self, job_id, attempt, lease_token, engine_status, ai_status, artifacts, metrics, cleanup) -> dict:
        return self._post(self._job(job_id, 'complete'), {
            'attempt': attempt, 'leaseToken': lease_token, 'engineStatus': engine_status, 'aiStatus': ai_status,
            'artifacts': artifacts, 'metrics': metrics, 'cleanup': cleanup}, idempotent=True)

    def fail(self, job_id, attempt, lease_token, code, retryable, cleanup, artifacts=None) -> dict:
        body = {'attempt': attempt, 'leaseToken': lease_token, 'code': code, 'retryable': retryable,
                'cleanup': cleanup}
        if artifacts:
            body['artifacts'] = artifacts
        return self._post(self._job(job_id, 'fail'), body, idempotent=True)

    def idle(self, run_id, instance_id) -> dict:
        return self._post('/worker/idle', {'runId': run_id, 'instanceId': instance_id}, idempotent=False)

    def stopping(self, run_id, reason) -> dict:
        return self._post('/worker/stopping', {'runId': run_id, 'reason': reason}, idempotent=True)
