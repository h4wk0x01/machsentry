"""A claimed job as granted by `/worker/claim`, parsed and clamped to the worker's own ceilings.

The ceilings mirror ANALYSIS_LIMITS / ANALYSIS_AI in Unpacked lib/config.ts: a site value above
them is lowered, never trusted to raise host usage or AI spend.
"""

from dataclasses import dataclass
from datetime import datetime
import re

from .jobdir import JOB_ID

_SHA256 = re.compile(r'^[a-f0-9]{64}$')
LIMIT_CEILINGS = {'staticSeconds': 1200, 'aiSeconds': 540, 'finalizeSeconds': 120, 'maxFunctions': 128,
                  'memoryBytes': 3 * 1024 ** 3, 'pids': 256, 'diskBytes': 4 * 1024 ** 3}
AI_CEILINGS = {'maxCalls': 12, 'maxInputTokensPerCall': 40_000, 'maxOutputTokensFirstCall': 6_000,
               'maxOutputTokensPerJob': 16_000}


class ClaimInvalid(Exception):
    pass


@dataclass(frozen=True)
class Claim:
    id: str
    attempt: int
    lease_token: str
    locale: str
    sample: dict
    download_url: str
    deadline_epoch: float
    limits: dict
    ai: dict

    def lease(self) -> dict:
        return {'job_id': self.id, 'attempt': self.attempt, 'lease_token': self.lease_token}


def epoch(value) -> float:
    if not isinstance(value, str):
        raise ClaimInvalid('timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ClaimInvalid('timestamp') from None
    if parsed.tzinfo is None:
        raise ClaimInvalid('timestamp')
    return parsed.timestamp()


def _positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def identity(raw) -> tuple[str, int, str] | None:
    """Enough of a claim to answer /fail even when the rest is malformed."""
    if not isinstance(raw, dict):
        return None
    job_id, attempt, token = raw.get('id'), raw.get('attempt'), raw.get('leaseToken')
    if isinstance(job_id, str) and JOB_ID.match(job_id) and _positive_int(attempt) and isinstance(token, str) and token:
        return job_id, attempt, token
    return None


def parse_claim(raw) -> Claim:
    ids = identity(raw)
    if ids is None:
        raise ClaimInvalid('identity')
    locale = raw.get('locale')
    if locale not in ('pt-BR', 'en-US'):
        raise ClaimInvalid('locale')
    sample = raw.get('sample')
    if not (isinstance(sample, dict) and isinstance(sample.get('name'), str) and _positive_int(sample.get('size'))
            and isinstance(sample.get('sha256'), str) and _SHA256.match(sample['sha256'])
            and isinstance(sample.get('architectures'), list)
            and all(isinstance(item, str) for item in sample['architectures'])):
        raise ClaimInvalid('sample')
    download = raw.get('download')
    if not isinstance(download, dict) or not isinstance(download.get('url'), str):
        raise ClaimInvalid('download')
    limits, ai = raw.get('limits'), raw.get('ai')
    if not isinstance(limits, dict) or not all(_positive_int(limits.get(key)) for key in LIMIT_CEILINGS):
        raise ClaimInvalid('limits')
    if not (isinstance(ai, dict) and isinstance(ai.get('model'), str) and isinstance(ai.get('promptVersion'), str)
            and all(_positive_int(ai.get(key)) for key in AI_CEILINGS)):
        raise ClaimInvalid('ai')
    clamped_ai = {**ai, **{key: min(ai[key], ceiling) for key, ceiling in AI_CEILINGS.items()}}
    return Claim(ids[0], ids[1], ids[2], locale,
                 {key: sample[key] for key in ('name', 'size', 'sha256', 'architectures')}, download['url'],
                 epoch(raw.get('deadlineAt')),
                 {key: min(limits[key], ceiling) for key, ceiling in LIMIT_CEILINGS.items()}, clamped_ai)
