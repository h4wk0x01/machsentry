"""One OpenAI Responses API call over the standard library, sent exactly once (contract section 8).

There are no retries here or in callers: a repeated request after an uncertain failure could be
billed twice. The outcome tells the site how to settle the reservation:
- succeeded: a response body with usage was received;
- failed_not_billed: an HTTP error response was received, or the connection never opened;
- usage_unknown: timeout, connection loss after sending, or a body without usable usage.
`output_text` is an SDK convenience, so the text is read from the `output` message items.
"""

from dataclasses import dataclass
import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request

from . import USER_AGENT
from .ai_schema import text_format
from .config import Secret
from .site_api import opener

URL = 'https://api.openai.com/v1/responses'
TIMEOUT_SECONDS = 150
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_CODE = re.compile(r'^[a-z0-9_.-]{1,64}$')


@dataclass
class CallResult:
    outcome: str
    usage: dict | None = None
    request_id: str | None = None
    error_code: str | None = None
    status: str | None = None
    incomplete_reason: str | None = None
    text: str | None = None
    refusal: str | None = None


def request_body(model: str, instructions: str, input_text: str, max_output_tokens: int) -> dict:
    return {'model': model, 'instructions': instructions, 'input': input_text,
            'text': {'format': text_format()}, 'max_output_tokens': max_output_tokens,
            'store': False, 'reasoning': {'effort': 'low'}}


def _request_id(headers) -> str | None:
    value = headers.get('x-request-id') if headers is not None else None
    return value if isinstance(value, str) and _ID.match(value) else None


def _usage(payload: dict) -> dict | None:
    usage = payload.get('usage')
    if not isinstance(usage, dict):
        return None
    details = usage.get('input_tokens_details')
    cached = details.get('cached_tokens', 0) if isinstance(details, dict) else 0
    values = (usage.get('input_tokens'), cached, usage.get('output_tokens'))
    if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
        return None
    return {'inputTokens': values[0], 'cachedInputTokens': values[1], 'outputTokens': values[2]}


def _output(payload: dict) -> tuple[str | None, str | None]:
    texts, refusals = [], []
    for item in payload.get('output') if isinstance(payload.get('output'), list) else []:
        if not isinstance(item, dict) or item.get('type') != 'message':
            continue
        for content in item.get('content') if isinstance(item.get('content'), list) else []:
            if isinstance(content, dict) and content.get('type') == 'output_text' and isinstance(content.get('text'), str):
                texts.append(content['text'])
            elif isinstance(content, dict) and content.get('type') == 'refusal' and isinstance(content.get('refusal'), str):
                refusals.append(content['refusal'])
    return (''.join(texts) if texts else None), ('\n'.join(refusals) if refusals else None)


def _http_error_code(error: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(error.read(64 * 1024) or b'null')
    except (ValueError, OSError, http.client.HTTPException):
        body = None
    detail = body.get('error') if isinstance(body, dict) else None
    for key in ('code', 'type'):
        value = detail.get(key) if isinstance(detail, dict) else None
        if isinstance(value, str) and _CODE.match(value):
            return value
    return f'http_{error.code}'


def _not_sent(reason) -> bool:
    """Failures that happen before any request byte leaves: DNS, refused connection, bad certificate."""
    return isinstance(reason, (socket.gaierror, ConnectionRefusedError, ssl.SSLCertVerificationError))


def call(api_key: Secret, body: dict, *, url: str = URL, timeout: float = TIMEOUT_SECONDS,
         client_request_id: str | None = None, clock=time.monotonic) -> CallResult:
    data = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode()
    headers = {'Authorization': f'Bearer {api_key.reveal()}', 'Content-Type': 'application/json',
               'Accept': 'application/json', 'User-Agent': USER_AGENT}
    if client_request_id and _ID.match(client_request_id):
        # Lets support find a request whose x-request-id never arrived (timeouts).
        headers['X-Client-Request-Id'] = client_request_id
    request = urllib.request.Request(url, data=data, method='POST', headers=headers)
    deadline = clock() + timeout
    try:
        response = opener().open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        try:
            return CallResult('failed_not_billed', request_id=_request_id(error.headers),
                              error_code=_http_error_code(error))
        finally:
            error.close()
    except urllib.error.URLError as error:
        if _not_sent(error.reason):
            return CallResult('failed_not_billed', error_code='connect_failed')
        timed_out = isinstance(error.reason, (TimeoutError, socket.timeout))
        return CallResult('usage_unknown', error_code='timeout' if timed_out else 'transport_error')
    except (TimeoutError, socket.timeout):
        return CallResult('usage_unknown', error_code='timeout')
    except (OSError, http.client.HTTPException, ValueError):
        return CallResult('usage_unknown', error_code='transport_error')
    with response:
        request_id = _request_id(response.headers)
        chunks, total = [], 0
        try:
            while total <= MAX_RESPONSE_BYTES:
                if clock() > deadline:
                    return CallResult('usage_unknown', request_id=request_id, error_code='timeout')
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except (TimeoutError, socket.timeout):
            return CallResult('usage_unknown', request_id=request_id, error_code='timeout')
        except (OSError, http.client.HTTPException, ValueError):
            return CallResult('usage_unknown', request_id=request_id, error_code='transport_error')
    if total > MAX_RESPONSE_BYTES:
        return CallResult('usage_unknown', request_id=request_id, error_code='response_too_large')
    try:
        payload = json.loads(b''.join(chunks))
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        return CallResult('usage_unknown', request_id=request_id, error_code='bad_response')
    usage = _usage(payload)
    status = payload.get('status') if isinstance(payload.get('status'), str) else None
    details = payload.get('incomplete_details')
    reason = details.get('reason') if isinstance(details, dict) and isinstance(details.get('reason'), str) else None
    error = payload.get('error')
    code = error.get('code') if isinstance(error, dict) else None
    text, refusal = _output(payload)
    return CallResult('succeeded' if usage else 'usage_unknown', usage, request_id,
                      code if isinstance(code, str) and _CODE.match(code) else (None if usage else 'usage_missing'),
                      status, reason, text, refusal)
