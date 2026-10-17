"""Local MCP client. REA owns format interpretation, analysis, and provider cleanup."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from .source import AnalysisError


@dataclass(frozen=True)
class ReaOptions:
    root: Path | None = None
    node: str | None = None
    architecture: str | None = None
    request_timeout_seconds: float = 900
    max_decompiled_functions: int = 64


def server_parameters(options: ReaOptions) -> StdioServerParameters:
    root = (options.root or Path(__file__).resolve().parents[2]).resolve()
    entry = root / 'scripts' / 'rea.mjs'
    if not entry.is_file() or not (root / 'dist' / 'mcp' / 'main.js').is_file():
        raise AnalysisError('rea_not_built', f'Build the REA repository first: {root}; run its MachSentry setup command')
    environment = dict(os.environ)
    node = options.node
    manifest_path = root / '.tools' / 'runtime.json'
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            if manifest['schema_version'] != 1:
                raise ValueError('Unsupported runtime manifest version')
            node = node or manifest['executables']['node']
            for key in ('GHIDRA_INSTALL_DIR', 'JAVA_HOME', 'REA_ANALYSIS_PROVIDER'):
                value = manifest['environment'].get(key)
                if value is not None:
                    if not isinstance(value, str):
                        raise ValueError(f'Invalid runtime manifest field {key}')
                    environment.setdefault(key, value)
        except (KeyError, ValueError, TypeError, OSError) as error:
            raise AnalysisError('invalid_runtime', str(error)) from error
    node = node or shutil.which('node')
    if not node:
        raise AnalysisError('rea_not_installed', 'Node.js is unavailable; run the project setup or supply --rea-node')
    prefix = [str(Path(node).parent)]
    if environment.get('JAVA_HOME'):
        prefix.append(str(Path(environment['JAVA_HOME']) / 'bin'))
    environment['PATH'] = os.pathsep.join([*prefix, environment.get('PATH', '')])
    # Inherit controls, but never serialize the ambient environment into a report.
    return StdioServerParameters(command=node, args=[str(entry), 'mcp'], cwd=root, env=environment)


def make_client(options: ReaOptions) -> Client:
    return Client(server_parameters(options), read_timeout_seconds=options.request_timeout_seconds,
                  mode='legacy', cache=None)


class ReaSession:
    def __init__(self, client):
        self.client = client
        self.records = {}
        self.calls = []
        self.errors = []
        self.bundles = []
        self.opened = False
        self.queried = False
        self.cleanup = []

    async def call(self, operation, parameters=None, *, required=True):
        parameters = parameters or {}
        if operation not in ('open_binary', 'close_binary', 'get_evidence_bundle', 'binary_session'):
            self.queried = True
        try:
            response = await self.client.call_tool(operation, parameters)
            value = response.structured_content
            if response.is_error:
                message = '\n'.join(item.text for item in response.content if hasattr(item, 'text'))
                raise AnalysisError('rea_tool_error', f'{operation}: {message}', details={'operation': operation, 'response': value})
            if not isinstance(value, dict):
                raise AnalysisError('rea_contract_error', f'{operation} returned no structured result')
            self.calls.append({'operation': operation, 'parameters': parameters,
                               'evidence_id': value.get('evidence_id')})
            if 'normalized_result' in value:
                if not isinstance(value.get('evidence_id'), str) or value.get('operation') != operation:
                    raise AnalysisError('rea_contract_error', f'{operation} returned mismatched Evidence')
                self.records[value['evidence_id']] = value
                return value
            if 'result' not in value:
                raise AnalysisError('rea_contract_error', f'{operation} returned no lifecycle result')
            return value
        except Exception as error:
            failure = error if isinstance(error, AnalysisError) else AnalysisError('rea_transport_error', str(error))
            self.errors.append({'operation': operation, 'parameters': parameters, **failure.as_dict()})
            if required:
                raise failure
            return None

    async def open(self, path: Path, provider: str):
        # A lost response does not establish that the remote side acquired nothing.
        self.opened = True
        self.queried = False
        result = await self.call('open_binary', {'path': str(path.absolute()), 'provider_id': provider})
        return result['result']

    async def finish(self):
        if not self.opened:
            return
        bundle = await self.call('get_evidence_bundle', {'detail': 'complete'}, required=False) if self.queried else None
        if bundle is not None:
            bundle = bundle['result']
            if isinstance(bundle, dict) and isinstance(bundle.get('records'), list):
                self.bundles.append(bundle)
                for record in bundle['records']:
                    self.records[record['evidence_id']] = record
                self.queried = False
        closed = await self.call('close_binary', {}, required=False)
        if closed is not None and closed.get('result') is not None:
            self.errors.append({'operation': 'close_binary', 'code': 'rea_contract_error',
                                'message': 'Unexpected close receipt without a requested snapshot'})
            closed = None
        self.cleanup.append({'operation': 'close_binary', 'confirmed': closed is not None})
        if closed is not None:
            self.opened = False

    def facts(self):
        return {'transport': 'official MCP stdio', 'provider_requested': 'ghidra',
                'calls': self.calls, 'records': list(self.records.values()),
                'evidence_bundles': [{**{key: value for key, value in bundle.items() if key != 'records'},
                                      'record_ids': [record['evidence_id'] for record in bundle['records']]}
                                     for bundle in self.bundles],
                'errors': self.errors, 'cleanup': self.cleanup, 'closure_confirmed': not self.opened}
