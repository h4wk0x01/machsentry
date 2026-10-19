"""Shared test doubles: local HTTP fakes for the site, S3 and OpenAI, a scripted docker CLI, fake
host operations and inert Mach-O bytes. Nothing here executes a sample or reaches the network."""

from hashlib import sha256
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import struct
import sys
import threading
import time

WORKER_ROOT = Path(__file__).resolve().parents[1]
if str(WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_ROOT))

from machsentry_worker.config import Secret  # noqa: E402
from machsentry_worker.docker_runner import DockerError  # noqa: E402
from machsentry_worker import logs  # noqa: E402
import io  # noqa: E402

# Every log line of the suite lands here; tests inspect it to check that payloads never leak.
LOGS = io.StringIO()
logs.set_stream(LOGS)

_FIXTURES = WORKER_ROOT.parent / 'macos_static' / 'tests' / 'fixtures.py'
_spec = importlib.util.spec_from_file_location('machsentry_inert_fixtures', _FIXTURES)
fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixtures)

TOKEN = Secret('test-worker-token-not-a-secret')
API_KEY = Secret('test-openai-key-not-a-secret')


def thin_header(cpu=0x01000007, subtype=3, sizeofcmds=0, little=True, length=64) -> bytes:
    order = '<' if little else '>'
    header = struct.pack(order + '8I', 0xFEEDFACF, cpu, subtype, 2, 0, sizeofcmds, 0, 0)
    return header + bytes(max(0, length - len(header)))


def fat(slices, wide=False, offsets=None) -> bytes:
    """Universal file with the given thin slices (FAT or FAT64), slice data aligned at 4096."""
    stride = 32 if wide else 20
    header = bytearray(struct.pack('>II', 0xCAFEBABF if wide else 0xCAFEBABE, len(slices)))
    offset, body = 4096, bytearray()
    placements = []
    for index, data in enumerate(slices):
        at = offsets[index] if offsets else offset
        cpu = struct.unpack_from('<I', data, 4)[0]
        placements.append((at, data))
        if wide:
            header += struct.pack('>IIQQII', cpu, 0, at, len(data), 12, 0)
        else:
            header += struct.pack('>IIIII', cpu, 0, at, len(data), 12)
        offset = at + ((len(data) + 4095) // 4096) * 4096
    assert len(header) == 8 + stride * len(slices)
    size = max(at + len(data) for at, data in placements)
    blob = bytearray(size)
    blob[:len(header)] = header
    for at, data in placements:
        blob[at:at + len(data)] = data
    return bytes(blob)


# HTTP fakes -----------------------------------------------------------------------------------

class _Server:
    def __init__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def _handle(self):
                length = int(self.headers.get('Content-Length') or 0)
                data = self.rfile.read(length) if length else b''
                owner.dispatch(self, data)

            do_POST = do_PUT = do_GET = _handle

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.server.handle_error = lambda request, address: None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.lock = threading.Lock()

    @property
    def url(self) -> str:
        return f'http://127.0.0.1:{self.server.server_address[1]}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    @staticmethod
    def reply(handler, status: int, body=None, headers=None, raw: bytes | None = None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b'')
        handler.send_response(status)
        for key, value in (headers or {}).items():
            handler.send_header(key, value)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Content-Length', str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)


class FakeSite(_Server):
    """Worker API plus an S3-like PUT endpoint. Responses are queued per route; the last one repeats."""

    PREFIX = '/api/internal/analysis'

    def __init__(self):
        super().__init__()
        self.requests: list[dict] = []
        self.routes: dict[str, list] = {}
        self.objects: dict[str, dict] = {}
        self.put_status: list[int] = []

    def respond(self, route: str, *responses):
        self.routes[route] = list(responses)

    def calls(self, route: str) -> list[dict]:
        with self.lock:
            return [item['body'] for item in self.requests if item['route'] == route]

    def routes_called(self) -> list[str]:
        with self.lock:
            return [item['route'] for item in self.requests]

    sample = b''

    def dispatch(self, handler, data: bytes):
        path = handler.path
        if handler.command == 'GET' and path.startswith('/sealed/'):
            with self.lock:
                self.requests.append({'route': 'GET sample', 'headers': dict(handler.headers), 'body': None})
            return self.reply(handler, 200, raw=self.sample)
        if handler.command == 'PUT' and path.startswith('/s3/'):
            name = path[4:]
            with self.lock:
                status = self.put_status.pop(0) if self.put_status else 200
                self.requests.append({'route': f'PUT {name}', 'headers': dict(handler.headers), 'body': None})
                if status == 200:
                    self.objects[name] = {'data': data,
                                          'headers': {key.lower(): value for key, value in handler.headers.items()}}
            return self.reply(handler, status, raw=b'')
        route = path[len(self.PREFIX):] if path.startswith(self.PREFIX) else path
        route = re.sub(r'^/jobs/[^/]+/', '/jobs/:id/', route)
        try:
            body = json.loads(data) if data else None
        except ValueError:
            body = None
        with self.lock:
            self.requests.append({'route': route, 'headers': dict(handler.headers), 'body': body})
            queue = self.routes.get(route)
            response = (queue.pop(0) if len(queue) > 1 else queue[0]) if queue else (404, {'error': 'not_found'})
        if callable(response):
            response = response(body)
        if response == 'drop':
            handler.close_connection = True
            handler.connection.close()
            return
        status, payload = response
        return self.reply(handler, status, payload)

    def upload_grant(self, body):
        return 200, {'uploads': [{
            'name': item['name'], 'url': f'{self.url}/s3/{item["name"]}',
            'headers': {'x-amz-checksum-sha256': __import__('base64').b64encode(bytes.fromhex(item['sha256'])).decode(),
                        'Content-Type': 'application/octet-stream'}} for item in body['artifacts']]}


class FakeOpenAI(_Server):
    """POST /v1/responses with scripted outcomes: ('json', status, body), ('sleep', seconds), ('drop',)."""

    def __init__(self, *script):
        super().__init__()
        self.script = list(script)
        self.requests: list[dict] = []

    @property
    def endpoint(self) -> str:
        return self.url + '/v1/responses'

    def dispatch(self, handler, data: bytes):
        with self.lock:
            self.requests.append({'headers': dict(handler.headers), 'body': json.loads(data)})
            step = self.script.pop(0) if self.script else ('json', 500, {'error': {'code': 'unscripted'}})
        if step[0] == 'sleep':
            time.sleep(step[1])
            return self.reply(handler, 200, response_body('{}'))
        if step[0] == 'drop':
            handler.close_connection = True
            handler.connection.close()
            return
        return self.reply(handler, step[1], step[2], headers={'x-request-id': 'req_test_123'})


def response_body(text=None, *, refusal=None, status='completed', input_tokens=1200, cached=200, output_tokens=300,
                  incomplete=None) -> dict:
    content = []
    if text is not None:
        content.append({'type': 'output_text', 'text': text, 'annotations': []})
    if refusal is not None:
        content.append({'type': 'refusal', 'refusal': refusal})
    return {'id': 'resp_test', 'object': 'response', 'status': status, 'error': None,
            'incomplete_details': {'reason': incomplete} if incomplete else None,
            'output': [{'type': 'reasoning', 'id': 'rs_1', 'summary': []},
                       {'type': 'message', 'id': 'msg_1', 'role': 'assistant', 'status': 'completed',
                        'content': content}],
            'usage': {'input_tokens': input_tokens, 'input_tokens_details': {'cached_tokens': cached},
                      'output_tokens': output_tokens, 'output_tokens_details': {'reasoning_tokens': 50},
                      'total_tokens': input_tokens + output_tokens}}


# Engine report --------------------------------------------------------------------------------

SAMPLE_BYTES = None


def sample_bytes() -> bytes:
    global SAMPLE_BYTES
    if SAMPLE_BYTES is None:
        SAMPLE_BYTES = fixtures.universal_fixture()
    return SAMPLE_BYTES


def report(sha=None, status='partial', strings_per_finding=4, pseudocode_chars=2000) -> dict:
    """A report.json v2.1-shaped document over synthetic TEST DATA strings."""
    sha = sha or sha256(sample_bytes()).hexdigest()
    categories = [('credential_prompt', 20), ('keychain_access', 20), ('outbound_upload', 20), ('persistence', 10)]
    evidence, findings, functions = [], [], []
    for slice_index, architecture in ((0, 'x86_64'), (1, 'arm64')):
        for position, (category, weight) in enumerate(categories):
            ids = []
            for n in range(strings_per_finding):
                identifier = f's{slice_index}:str:{position * 10 + n}'
                ids.append(identifier)
                evidence.append({'id': identifier, 'slice': slice_index, 'address': hex(0x100000400 + position * 64 + n),
                                 'text': f'TEST DATA ONLY: {category} literal {n} ' + 'x' * 40, 'encoding': 'ascii',
                                 'offset': 1024 + n, 'byte_length': 60, 'kind': 'provider_observation'})
            address = hex(0x100000200 + 64 * position)
            findings.append({'id': f's{slice_index}:{category}', 'category': category, 'slice': slice_index,
                             'title': f'Indicador {category}', 'interpretation': 'Texto em pt-BR', 'weight': weight,
                             'evidence_ids': ids, 'confidence': 'medium', 'function_addresses': [address],
                             'kind': 'static_inference'})
            functions.append({'slice': slice_index, 'architecture': architecture, 'address': address,
                              'names': [f'_inert_reference_{position}'], 'finding_ids': [f's{slice_index}:{category}'],
                              'pseudocode': 'int f(void) { return 0; } /* TEST DOUBLE */ ' + 'y' * pseudocode_chars,
                              'references': []})
    return {
        'schema_version': '2.1', 'analysis_status': status, 'mode': 'static_offline',
        'engine': {'name': 'machsentry', 'version': '0.4.0', 'analysis_engine': 'REA', 'provider': 'ghidra',
                   'ruleset_version': '2.0.0'},
        'artifact': {'path': '/input/sample.macho', 'sha256': sha, 'size_bytes': len(sample_bytes())},
        'risk': {'value': 75, 'maximum': 100, 'verdict': 'high_risk_indicators', 'maliciousness': 'unconfirmed',
                 'method': 'machsentry-static-heuristic-v2', 'contributions': {'credential_prompt': 20}},
        'slices': [{'index': 0, 'architecture': 'x86_64', 'status': 'analyzed', 'path': '/tmp/x'},
                   {'index': 1, 'architecture': 'arm64', 'status': 'analyzed', 'path': '/tmp/y'}],
        'findings': findings, 'evidence': evidence, 'functions': functions,
        'scripts': [{'evidence_id': 's0:str:0', 'slice': 0, 'offset': 1024, 'address': '0x100000400',
                     'language': 'applescript_or_launcher', 'content': 'TEST DATA ONLY: display dialog'}],
        'ioc_candidates': [{'kind': 'url', 'value': 'https://example.invalid/test', 'evidence_id': 's0:str:20',
                            'offset': None, 'classification': 'unverified_candidate', 'contacted': False}],
        'coverage': {'analyzed_slice_count': 2, 'slices': [
            {'slice': 0, 'functions_inspected': 4, 'functions_omitted': 0,
             'strings_complete_over_provider_inventory': True, 'reference_budget_exhausted': False},
            {'slice': 1, 'functions_inspected': 4, 'functions_omitted': 0,
             'strings_complete_over_provider_inventory': True, 'reference_budget_exhausted': False}]},
        'yara': {'status': 'positive_only', 'requested_mode': 'auto', 'effective_mode': 'hybrid',
                 'rule': 'rule machsentry_hybrid_test\n{\n    strings:\n        $b0 = "TEST DATA ONLY"\n'
                         '    condition:\n        all of ($b*)\n}\n',
                 'validation': {'compiled': True, 'sample_matched': True, 'negative_count': 0, 'negative_matches': 0}},
        'presentation': {'schema_version': '1.0'},
    }


UNLINKED_SCRIPT, UNLINKED_IOC = 's0:str:900', 's0:str:901'


def unlinked_script_and_ioc(rep: dict) -> dict:
    """Adds a script and a URL candidate whose strings no finding references, as the engine
    reports for most IOC candidates."""
    for identifier, text in ((UNLINKED_SCRIPT, 'TEST DATA ONLY: do shell script "true"'),
                             (UNLINKED_IOC, 'https://c2.invalid/api')):
        rep['evidence'].append({'id': identifier, 'slice': 0, 'address': '0x100000900', 'text': text,
                                'encoding': 'ascii', 'offset': 2304, 'byte_length': len(text),
                                'kind': 'provider_observation'})
    rep['scripts'].append({'evidence_id': UNLINKED_SCRIPT, 'slice': 0, 'offset': 2304, 'address': '0x100000900',
                           'language': 'applescript_or_launcher', 'content': 'TEST DATA ONLY: do shell script "true"'})
    rep['ioc_candidates'].append({'kind': 'url', 'value': 'https://c2.invalid/api', 'evidence_id': UNLINKED_IOC,
                                  'offset': 2304, 'classification': 'unverified_candidate', 'contacted': False})
    return rep


def valid_output(rep=None) -> dict:
    rep = rep or report()
    return {
        'summary': 'O sample tem strings de prompt de credencial ligadas a funções analisadas.',
        'behaviors': [{'title': 'Prompt de senha', 'explanation': 'A string aparece em uma função da arquitetura x86_64.',
                       'confidence': 'medium', 'evidence_ids': ['s0:str:0', 's0:credential_prompt'],
                       'functions': [{'architecture': 'x86_64', 'address': '0x100000200'}]}],
        'techniques': [{'id': 'T1056.002', 'name': 'GUI Input Capture', 'rationale': 'Diálogo pedindo senha.',
                        'evidence_ids': ['s0:str:0']}],
        'functions': [{'architecture': 'arm64', 'address': '0x100000240', 'title': 'Acesso ao Keychain',
                       'explanation': 'Carrega a string do comando security.', 'evidence_ids': ['s1:keychain_access']}],
        'gaps': ['Sem execução, a chamada real ao Keychain fica em aberto.'],
        'next_steps': ['Rodar o sample em VM isolada com log do Unified Logging.'],
    }


MODEL = 'gpt-5.4-mini-2026-03-17'


def raw_claim(download_url='http://127.0.0.1:9/sealed', *, job_id='job_1', attempt=1, seconds_left=1200,
              locale='pt-BR', data=None) -> dict:
    from datetime import datetime, timedelta, timezone
    data = sample_bytes() if data is None else data
    deadline = datetime.now(timezone.utc) + timedelta(seconds=seconds_left)
    return {'id': job_id, 'attempt': attempt, 'leaseToken': 'lease-token-test', 'locale': locale,
            'sample': {'name': 'synthetic.macho', 'size': len(data), 'sha256': sha256(data).hexdigest(),
                       'architectures': ['x86_64', 'arm64']},
            'download': {'url': download_url, 'expiresAt': deadline.isoformat()},
            'deadlineAt': deadline.isoformat().replace('+00:00', 'Z'),
            'limits': {'staticSeconds': 900, 'aiSeconds': 180, 'finalizeSeconds': 120, 'maxFunctions': 64,
                       'memoryBytes': 3 * 1024 ** 3, 'pids': 256, 'diskBytes': 4 * 1024 ** 3},
            'ai': {'model': MODEL, 'promptVersion': 'unpacked-analysis-ai-v3', 'maxCalls': 2,
                   'maxInputTokensPerCall': 40000, 'maxOutputTokensFirstCall': 6000, 'maxOutputTokensPerJob': 8000}}


# Docker and host fakes ------------------------------------------------------------------------

class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeDockerCli:
    """Scripted docker CLI. `on_run(argv)` simulates the engine; containers run until `exit_after`
    state polls have passed (None = until removed)."""

    def __init__(self, *, exit_code=0, oom=False, exit_after=1, on_run=None, image_id=None, stdout='',
                 run_error=None, doctor_stdout='{"healthy": true}', doctor_code=0, labeled=None):
        self.exit_code, self.oom, self.exit_after, self.on_run = exit_code, oom, exit_after, on_run
        self.image, self.stdout, self.run_error = image_id, stdout, run_error
        self.doctor_stdout, self.doctor_code = doctor_stdout, doctor_code
        self.containers: dict[str, dict] = {}
        self.leftovers = list(labeled or [])
        self.log: list[tuple] = []
        self.lock = threading.Lock()

    def _name(self, argv):
        return argv[argv.index('--name') + 1]

    def run_detached(self, argv):
        name = self._name(argv)
        self.log.append(('run', name))
        if self.run_error is not None:
            raise DockerError('docker_run_failed', self.run_error)
        self.containers[name] = {'polls': 0, 'running': True, 'exit': None, 'argv': argv}
        if self.on_run:
            self.on_run(argv)
        return 'f' * 64

    def state(self, name):
        container = self.containers.get(name)
        self.log.append(('state', name))
        if container is None:
            return None
        if container['running'] and self.exit_after is not None:
            container['polls'] += 1
            if container['polls'] > self.exit_after:
                container['running'], container['exit'] = False, self.exit_code
        return {'Running': container['running'], 'ExitCode': container['exit'] if not container['running'] else 0,
                'OOMKilled': self.oom and not container['running'], 'Pid': 0 if not container['running'] else 4242}

    def kill(self, name, signal):
        self.log.append(('kill', name, signal))
        return True

    def remove(self, name):
        self.log.append(('rm', name))
        self.containers.pop(name, None)
        self.leftovers = [item for item in self.leftovers if item['id'] != name]
        return True

    def stdout_tail(self, name):
        return self.stdout

    def labeled(self, label='machsentry.worker'):
        return list(self.leftovers)

    def image_id(self, reference):
        return self.image

    def server_version(self):
        return '27.0.0'

    def call(self, args, timeout=60):
        self.log.append(('call', args[0], args[args.index('--name') + 1] if '--name' in args else None))
        return self.doctor_code, self.doctor_stdout, ''


class FakeOps:
    """Host operations without root: the loop image is a plain file and mounts are a set."""

    def __init__(self, fail_unmount=False):
        self.mounted: set[str] = set()
        self.fail_unmount = fail_unmount
        self.log: list[tuple] = []

    def allocate(self, path, size):
        Path(path).write_bytes(b'')
        self.log.append(('allocate', size))

    def mkfs(self, image):
        self.log.append(('mkfs',))

    def mount(self, image, target):
        self.mounted.add(str(target))
        self.log.append(('mount',))

    def unmount(self, target):
        self.log.append(('umount',))
        if self.fail_unmount:
            from machsentry_worker.jobdir import HostOpError
            raise HostOpError('busy')
        self.mounted.discard(str(target))
        # The files lived inside the loop image: once unmounted the mount point is empty again.
        import shutil
        for child in Path(target).iterdir():
            shutil.rmtree(child) if child.is_dir() else child.unlink()

    def is_mounted(self, target):
        return str(target) in self.mounted

    def loop_devices(self, image):
        return []

    def detach(self, device):
        pass

    def chown(self, path, uid, gid):
        self.log.append(('chown', Path(path).name, uid, gid))

    def usage(self, target):
        return 123456

    def sleep(self, seconds):
        pass


def engine_writer(rep=None, extra=None):
    """Returns an on_run hook that writes MachSentry outputs into the bind-mounted work directory."""
    def write(argv):
        mounts = [argv[i + 1] for i, item in enumerate(argv) if item == '--mount']
        work = Path(next(item for item in mounts if item.endswith('target=/work')).split(',')[1].split('=', 1)[1])
        out = work / 'out' / 'report'
        out.mkdir(parents=True)
        (out / 'report.json').write_text(json.dumps(rep or report()), encoding='utf-8')
        (out / 'report-view.json').write_text(json.dumps({'schema_version': '1.0'}), encoding='utf-8')
        (out / 'report.html').write_text('<!doctype html><title>r</title>', encoding='utf-8')
        (out / 'detection.yar').write_text('rule test { condition: false }\n', encoding='utf-8')
        for name, data in (extra or {}).items():
            (out / name).write_bytes(data)
    return write
