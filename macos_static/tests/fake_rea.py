"""Contract-shaped test double; tests here do not establish real Ghidra support."""

from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import tempfile

from fixtures import fixture


class FakeRea:
    def __init__(self, fail_operation=None, fail_close_count=0, mismatch_digest=False):
        self.calls, self.records = [], []
        self.fail_operation, self.fail_close_count = fail_operation, fail_close_count
        self.mismatch_digest = mismatch_digest
        self.base = 0x100000000
        self.exited = False
        self.opened = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self.exited = True

    def evidence(self, operation, parameters, result):
        identifier = 'ev_' + sha256(str((operation, parameters, result)).encode()).hexdigest()
        record = {'evidence_id': identifier, 'operation': operation, 'parameters': parameters,
                  'provider': {'id': 'ghidra', 'name': 'TEST DOUBLE', 'version': 'synthetic'},
                  'normalized_result': result, 'raw_result': None, 'limitations': ['TEST DOUBLE: no real provider'],
                  'subject': {'digest': {'sha256': sha256(self.data).hexdigest()}, 'architecture': 'x86_64'},
                  'evidence_links': []}
        self.records.append(record)
        return record

    async def call_tool(self, operation, parameters):
        self.calls.append((operation, parameters))
        if operation == self.fail_operation or (operation == 'close_binary' and self.fail_close_count > 0):
            if operation == 'close_binary':
                self.fail_close_count -= 1
            return SimpleNamespace(is_error=True, structured_content={'code': 'synthetic_failure'},
                                   content=[SimpleNamespace(text='synthetic failure')])
        if operation == 'open_binary':
            self.path = Path(parameters['path'])
            self.data = self.path.read_bytes()
            self.opened = True
            suspicious = self.data == fixture(True)
            self.literals = ([b'osascript -e display dialog "Synthetic test" with hidden answer',
                              b'security find-generic-password -ga "Synthetic test"', b'Login Data', b'/Cookies',
                              b'/.electrum/wallets/', b'Exodus/exodus.wallet/',
                              b'POST /synthetic-test HTTP/1.1\r\n', b'multipart/form-data',
                              b'system_profiler SPHardwareDataType'] if suspicious else [b'Hello inert test fixture'])
            self.locations = [self.data.index(literal) for literal in self.literals]
            self.procedure = {'address': hex(self.base + 512), 'name': '_inert_fixture', 'classification': None,
                              'body': {'available': True, 'ranges': [{'start': hex(self.base + 512),
                                       'end': hex(self.base + 512 + len(self.literals) * 7)}],
                                       'total_bytes': len(self.literals) * 7 + 1, 'span_bytes': len(self.literals) * 7 + 1,
                                       'non_contiguous': False, 'contains_entry': True, 'provenance': 'TEST DOUBLE'}}
            value = {'result': {'path': str(self.path), 'sha256': '0' * 64 if self.mismatch_digest else sha256(self.data).hexdigest(),
                                'format': 'mach-o', 'architecture': 'x86_64', 'kind': 'executable'}}
        elif operation == 'close_binary':
            self.opened = False
            value = {'result': None}
        elif operation == 'get_evidence_bundle':
            value = {'result': {'artifacts': [], 'providers': [], 'environments': [], 'scenarios': [],
                                'captures': [], 'unknowns': [], 'records': list(self.records)}}
        else:
            assert self.opened
            if operation == 'list_strings':
                result = [{'address': hex(self.base + offset), 'value': literal.decode(),
                           'string': {'encoding': 'UTF-8', 'termination': 'present_or_not_required', 'byte_length': len(literal)}}
                          for offset, literal in zip(self.locations, self.literals)]
            elif operation == 'address_to_file_offset':
                result = {'address': parameters['address'], 'file_offset': int(parameters['address'], 16) - self.base}
            elif operation == 'xrefs':
                index = self.locations.index(int(parameters['address'], 16) - self.base)
                result = [hex(self.base + 512 + 7 * index)]
            elif operation == 'resolve_containing_procedure':
                result = {'found': True, 'query_address': parameters['address'], 'procedure': self.procedure}
            elif operation == 'analyze_function':
                result = {'procedure': self.procedure, 'pseudocode': '/* TEST DOUBLE */\nvoid inert_fixture(void) { return; }',
                          'assembly': ['100000200 LEA RAX,[test_literal]', '10000023f RET'],
                          'callees': [], 'limitations': ['TEST DOUBLE'], 'facet_availability': {'pseudocode': {'available': True}}}
            elif operation == 'read_bytes':
                start, size = int(parameters['address'], 16) - self.base, parameters['length']
                result = {'bytes_hex': self.data[start:start + size].hex(), 'complete': True}
            elif operation == 'inspect_native_instruction':
                start = int(parameters['address'], 16) - self.base
                index = (start - 512) // 7
                result = {'status': 'decoded', 'bytes': self.data[start:start + 7].hex(),
                          'references': [{'target_address': hex(self.base + self.locations[index]), 'indirect': False,
                                          'computed': False, 'data': True}]}
            else:
                raise AssertionError(f'Unexpected tool {operation}')
            value = self.evidence(operation, parameters, result)
        return SimpleNamespace(is_error=False, structured_content=value, content=[])


class FakeFatRea(FakeRea):
    """Two synthetic occurrences whose graph intentionally has unknown architecture."""
    def __init__(self):
        super().__init__()
        self.payloads = [fixture(True), fixture(False)]
        self.container = b'\xca\xfe\xba\xbe' + b''.join(self.payloads)
        self.output_root = None
        self.manifest = {'root_sha256': sha256(self.container).hexdigest(), 'root_format': 'mach-o-universal'}

    async def call_tool(self, operation, parameters):
        if operation in ('inspect_artifact', 'extract_artifact'):
            self.calls.append((operation, parameters))
            nodes, occurrences, artifacts = [], [], []
            offset = 4
            for index, payload in enumerate(self.payloads):
                digest = sha256(payload).hexdigest()
                identifier, logical = 'art_' + digest, f'slices/fixture-{index}'
                nodes.append({'artifact_id': identifier, 'sha256': digest, 'architecture': None})
                occurrences.append({'artifact_id': identifier, 'logical_path': logical, 'entry_kind': 'slice',
                                    'source_location': {'offset': offset, 'length': len(payload)}})
                artifacts.append({'artifact_id': identifier, 'relative_path': logical, 'sha256': digest,
                                  'bytes_written': len(payload), 'created': True})
                offset += len(payload)
            if operation == 'inspect_artifact':
                inventory = {'manifest': self.manifest, 'nodes': nodes, 'occurrences': occurrences}
                result = {'substeps': [{'evidence': {'normalized_result': inventory}}]}
            else:
                self.output_root = Path(tempfile.mkdtemp(prefix='rea-test-owned-'))
                (self.output_root / 'slices').mkdir()
                for index, payload in enumerate(self.payloads):
                    (self.output_root / 'slices' / f'fixture-{index}').write_bytes(payload)
                result = {'manifest': self.manifest, 'output_root': str(self.output_root),
                          'containment_verified': True, 'artifacts': artifacts}
            return SimpleNamespace(is_error=False, structured_content=self.evidence(operation, parameters, result), content=[])
        response = await super().call_tool(operation, parameters)
        if operation == 'open_binary' and self.data == self.container:
            response.structured_content['result'].update({'format': 'mach-o-universal', 'architecture': None})
        return response
