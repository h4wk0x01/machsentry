"""Structured JSON logs for journald: identifiers, phases, counters and codes only.

Sample strings, prompts, scripts, URLs and secrets never reach a log line. Fields outside the
allow-list are dropped and text values that are not short identifiers are redacted.
"""

import json
import re
import sys
import time

FIELDS = frozenset({
    'jobId', 'attempt', 'phase', 'code', 'reason', 'status', 'outcome', 'exitCode', 'httpStatus',
    'callIndex', 'granted', 'retryable', 'count', 'seconds', 'bytes', 'mode', 'stop', 'runId',
    'engineStatus', 'aiStatus', 'oomKilled', 'timedOut', 'cancelled', 'leaseLost',
    'containerRemoved', 'workdirRemoved', 'sampleDeleted', 'check',
})
_TEXT = re.compile(r'^[A-Za-z0-9_.:-]{0,128}$')
# None writes to the current sys.stdout (journald under systemd); tests capture with set_stream.
_stream = None


def set_stream(stream):
    global _stream
    _stream = stream


def _value(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str) and _TEXT.match(value):
        return value
    return '[redacted]'


def log(event: str, level: str = 'info', **fields):
    record = {'ts': round(time.time(), 3), 'level': level, 'event': _value(event)}
    record.update({key: _value(value) for key, value in fields.items() if key in FIELDS})
    stream = _stream or sys.stdout
    try:
        stream.write(json.dumps(record, ensure_ascii=True) + '\n')
        stream.flush()
    except (OSError, ValueError):
        pass
