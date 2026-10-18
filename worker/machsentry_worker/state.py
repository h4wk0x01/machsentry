"""`state.json`: what the supervisor must remember across a crash or reboot, shared with the watchdog.

It holds the run id, the attempt in progress (container name and wall-clock deadline) and attempts
whose termination has not yet been acknowledged by `/worker/boot`. No secrets or payloads.
Writes are atomic (temporary file, fsync, rename).
"""

import json
import os
from pathlib import Path
import threading

SCHEMA = 1


class State:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.data = self._load()

    def _load(self) -> dict:
        try:
            raw = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            raw = None
        if not isinstance(raw, dict) or raw.get('schema') != SCHEMA:
            raw = {}
        active = raw.get('active') if isinstance(raw.get('active'), dict) else None
        terminated = [item for item in raw.get('terminated', []) if isinstance(item, dict)
                      and isinstance(item.get('jobId'), str) and isinstance(item.get('attempt'), int)]
        return {'schema': SCHEMA, 'runId': raw.get('runId') if isinstance(raw.get('runId'), str) else None,
                'active': active, 'terminated': terminated}

    def _save(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + '.tmp')
        with open(temporary, 'w', encoding='utf-8') as output:
            json.dump(self.data, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.path)

    @property
    def active(self) -> dict | None:
        return self.data['active']

    @property
    def terminated(self) -> list[dict]:
        return list(self.data['terminated'])

    def set_run(self, run_id: str):
        with self._lock:
            self.data['runId'] = run_id
            self._save()

    def begin(self, job_id: str, attempt: int, container: str, deadline_epoch: float, started_epoch: float):
        with self._lock:
            self.data['active'] = {'jobId': job_id, 'attempt': attempt, 'container': container,
                                   'deadlineEpoch': deadline_epoch, 'startedEpoch': started_epoch}
            self._save()

    def finish(self, terminated: dict | None = None):
        """Clears the active attempt; `terminated` keeps it for the next boot report."""
        with self._lock:
            self.data['active'] = None
            if terminated is not None:
                self.data['terminated'] = [item for item in self.data['terminated']
                                           if (item['jobId'], item['attempt']) != (terminated['jobId'], terminated['attempt'])]
                self.data['terminated'].append(terminated)
            self._save()

    def acknowledged(self, reported: list[dict]):
        """Called after /worker/boot accepted the report; leftovers from before are forgotten."""
        keys = {(item['jobId'], item['attempt']) for item in reported}
        with self._lock:
            self.data['terminated'] = [item for item in self.data['terminated']
                                       if (item['jobId'], item['attempt']) not in keys]
            if self.data['active'] and (self.data['active'].get('jobId'), self.data['active'].get('attempt')) in keys:
                self.data['active'] = None
            self._save()
