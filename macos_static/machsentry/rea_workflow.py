"""Malware-report composition over public REA tools; no binary parser lives here."""

from hashlib import sha256
from dataclasses import dataclass
import errno
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

import anyio

from .behavior import find_behaviors
from .rea_client import ReaOptions, ReaSession, make_client
from .source import AnalysisError, Limits, Source


def value(evidence):
    return evidence['normalized_result']


def eid(evidence):
    return evidence['evidence_id']


@dataclass(frozen=True)
class OwnedDirectory:
    path: Path
    ancestors: tuple
    source_path: Path


@dataclass(frozen=True)
class OwnedFile:
    root: Path
    path: Path
    digest: str
    directories: tuple
    identity: tuple
    size_bytes: int


def _identity(metadata, directory):
    if (stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
        raise OSError('Owned artifact became a symlink, junction, or reparse point')
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode) or not metadata.st_ino:
        raise OSError('Owned artifact filesystem identity is unavailable or has the wrong type')
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _register_owned_directory(path):
    source_path = Path(os.path.abspath(path))
    identity = _identity(source_path.lstat(), True)
    path = source_path.parent.resolve(strict=True) / source_path.name
    ancestors = tuple((item, _identity(item.lstat(), True))
                      for item in (*reversed(path.parents), path))
    if ancestors[-1][1] != identity:
        raise OSError('Owned root identity changed during canonical parent admission')
    return OwnedDirectory(path, ancestors, source_path)


def _register_owned_file(root, path, digest):
    admitted = root if isinstance(root, OwnedDirectory) else _register_owned_directory(root)
    path = Path(os.path.abspath(path))
    if path == admitted.source_path or not path.is_relative_to(admitted.source_path):
        raise OSError('Created artifact is outside its owned output root')
    if not _verify_directories(admitted.ancestors):
        raise OSError('Owned output root disappeared before file registration')
    path = admitted.path / path.relative_to(admitted.source_path)
    descendants = tuple(item for item in (*reversed(path.parent.parents), path.parent)
                        if item != admitted.path and item.is_relative_to(admitted.path))
    directories = admitted.ancestors + tuple((item, _identity(item.lstat(), True)) for item in descendants)
    metadata = path.lstat()
    return OwnedFile(admitted.path, path, digest, directories, _identity(metadata, False), metadata.st_size)


def _verify_directories(ancestors):
    for path, expected in ancestors:
        try:
            observed = _identity(path.lstat(), True)
        except FileNotFoundError:
            return False
        if observed != expected:
            raise OSError(f'Owned directory identity changed: {path}')
    return True


def _verify_file_contents(owned):
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(owned.path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if _identity(before, False) != owned.identity:
            raise OSError('Owned artifact file identity changed while opening it')
        if before.st_size != owned.size_bytes:
            raise OSError('Owned artifact size changed; retained for inspection')
        digest = sha256()
        remaining = before.st_size + 1
        while remaining:
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(stream.fileno())
        if (_identity(after, False) != owned.identity
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or digest.hexdigest() != owned.digest):
            raise OSError('Owned artifact content changed; retained for inspection')


def _remove_owned_directory(owned, cleanup):
    try:
        if not _verify_directories(owned.ancestors):
            cleanup.append({'path': str(owned.path), 'confirmed': True, 'state': 'already_absent'})
            return
        owned.path.rmdir()
        cleanup.append({'path': str(owned.path), 'confirmed': True})
    except OSError as error:
        cleanup.append({'path': str(owned.path), 'confirmed': False, 'reason': str(error)})


def _source_file(source, root):
    if source.member is None:
        return Path(source.path)
    path = root / 'selected-member.macho'
    with path.open('xb') as stream:
        stream.write(source.data)
    return path


def _owned_child(root, relative):
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(part in ('..', '.') for part in parts):
        raise AnalysisError('rea_contract_error', 'Invalid extracted relative path')
    path = root.joinpath(*parts)
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise AnalysisError('rea_contract_error', 'Extracted artifact escapes its REA output root')
    return path


async def _select_slices(session, source, path, options, owned):
    target = await session.open(path, 'auto')
    if target['sha256'] != source.sha256:
        raise AnalysisError('source_changed', 'REA target digest differs from admitted source bytes')
    if target['format'] == 'mach-o':
        candidates = [{'index': 0, 'architecture': target['architecture'], 'file_offset': 0,
                       'size_bytes': len(source.data), 'sha256': source.sha256, 'path': str(path)}]
    elif target['format'] == 'mach-o-universal':
        inspection = await session.call('inspect_artifact')
        inventory = value(inspection)['substeps'][0]['evidence']['normalized_result']
        extraction = await session.call('extract_artifact')
        extracted = value(extraction)
        if not extracted['containment_verified'] or extracted['manifest'] != inventory['manifest']:
            raise AnalysisError('rea_contract_error', 'REA extraction and inventory commitments disagree')
        nodes = {item['artifact_id']: item for item in inventory['nodes']}
        root = Path(extracted['output_root'])
        root_identity = _register_owned_directory(root)
        candidates = []
        for item in extracted['artifacts']:
            occurrences = [entry for entry in inventory['occurrences']
                           if entry['artifact_id'] == item['artifact_id'] and entry['logical_path'] == item['relative_path']
                           and entry['entry_kind'] == 'slice']
            if len(occurrences) != 1 or not item['created']:
                raise AnalysisError('rea_contract_error', 'Missing unique owned slice occurrence')
            occurrence, node = occurrences[0], nodes[item['artifact_id']]
            location = occurrence['source_location']
            if not location:
                raise AnalysisError('rea_contract_error', 'Slice has no source byte range')
            start, size = location['offset'], location['length']
            if start < 0 or size < 1 or start + size > len(source.data):
                raise AnalysisError('rea_contract_error', 'REA slice range exceeds admitted container')
            digest = sha256(source.data[start:start + size]).hexdigest()
            if digest != item['sha256'] or digest != node['sha256'] or size != item['bytes_written']:
                raise AnalysisError('source_changed', 'Extracted slice identity differs from admitted container')
            child = _owned_child(root, item['relative_path'])
            owned.append(_register_owned_file(root_identity, child, digest))
            candidates.append({'index': len(candidates), 'architecture': node['architecture'],
                               'file_offset': start, 'size_bytes': size, 'sha256': digest, 'path': str(child),
                               'extraction_evidence_id': eid(extraction), 'inventory_evidence_id': eid(inspection)})
        if not candidates:
            raise AnalysisError('rea_contract_error', 'Universal Mach-O inventory yielded no slices')
    else:
        raise AnalysisError('unsupported_format', f"REA identified {target['format']}; MachSentry accepts Mach-O only")
    await session.finish()
    if session.opened:
        raise AnalysisError('rea_cleanup_failed', 'REA did not confirm container session closure')
    for candidate in candidates:
        if candidate['architecture'] is None:
            target = await session.open(Path(candidate['path']), 'auto')
            if target['format'] != 'mach-o' or target['sha256'] != candidate['sha256']:
                raise AnalysisError('source_changed', 'REA thin target differs from extracted slice identity')
            candidate['architecture'] = target['architecture']
            candidate['header_observation'] = target
            await session.finish()
            if session.opened:
                raise AnalysisError('rea_cleanup_failed', 'REA did not confirm slice discovery session closure')
    if options.architecture is not None and not any(item['architecture'] == options.architecture for item in candidates):
        raise AnalysisError('architecture_unavailable', f'Requested architecture {options.architecture} is absent')
    for candidate in candidates:
        candidate['selected'] = options.architecture is None or candidate['architecture'] == options.architecture
    return candidates


async def _mapping(session, address, slice_info, source):
    evidence = await session.call('address_to_file_offset', {'address': address}, required=False)
    if evidence is None:
        return None, None
    offset = value(evidence)['file_offset']
    if not isinstance(offset, int) or not 0 <= offset < slice_info['size_bytes']:
        raise AnalysisError('rea_contract_error', 'Provider file mapping is outside selected thin slice')
    return slice_info['file_offset'] + offset, eid(evidence)


async def _analyze_slice(session, source, info, limits, options):
    target = await session.open(Path(info['path']), 'ghidra')
    if target['sha256'] != info['sha256'] or target['architecture'] != info['architecture']:
        raise AnalysisError('source_changed', 'Ghidra input identity differs from selected slice')
    inventory = await session.call('list_strings')
    rows = value(inventory)
    if not isinstance(rows, list):
        raise AnalysisError('rea_contract_error', 'Expected REA string inventory')
    strings, byte_count = [], 0
    for row in rows:
        retained_bytes = len(row['value'].encode('utf-8'))
        if len(strings) >= limits.max_strings or byte_count + retained_bytes > limits.max_string_bytes:
            break
        byte_count += retained_bytes
        encoding = row.get('string', {}).get('encoding', 'unknown').lower().replace('_', '-')
        if encoding in ('utf-8', 'us-ascii') and row['value'].isascii():
            encoding = 'ascii'
        if encoding in ('utf-16', 'utf-16le', 'utf-16-le'):
            encoding = 'utf-16le'
        strings.append({'id': f"s{info['index']}:str:{len(strings)}", 'slice': info['index'],
                        'address': row['address'], 'text': row['value'], 'encoding': encoding,
                        'offset': None, 'byte_length': row.get('string', {}).get('byte_length'),
                        'kind': 'provider_observation', 'rea_evidence_id': eid(inventory),
                        'provider_record': row, 'yara_eligible': False})
    findings = find_behaviors(strings, [info['index']])
    evidence_findings = {}
    for finding in findings:
        finding['rea_evidence_ids'] = [eid(inventory)]
        for identifier in finding['evidence_ids']:
            evidence_findings.setdefault(identifier, []).append(finding)
    candidates, examined_references = {}, 0
    reference_limit = False
    for record in strings:
        if record['id'] not in evidence_findings:
            continue
        offset, mapping_id = await _mapping(session, record['address'], info, source)
        record.update({'offset': offset, 'mapping_evidence_id': mapping_id})
        if offset is not None and record['encoding'] in ('ascii', 'utf-16le') and record['text'].isascii():
            literal = record['text'].encode(record['encoding'])
            record['yara_eligible'] = (offset + len(literal) <= info['file_offset'] + info['size_bytes']
                                       and source.data[offset:offset + len(literal)] == literal)
        xrefs = await session.call('xrefs', {'address': record['address']}, required=False)
        if xrefs is None:
            continue
        for address in value(xrefs):
            if examined_references >= limits.max_references:
                reference_limit = True
                break
            examined_references += 1
            containing = await session.call('resolve_containing_procedure', {'address': address}, required=False)
            if containing is None or not value(containing)['found']:
                continue
            procedure = value(containing)['procedure']
            candidate = candidates.setdefault(procedure['address'], {'procedure': procedure, 'references': [], 'findings': {}})
            candidate['findings'].update({finding['id']: finding for finding in evidence_findings[record['id']]})
            candidate['references'].append({'evidence_id': record['id'], 'instruction_address': address,
                                           'target_address': record['address'], 'xref_evidence_id': eid(xrefs),
                                           'containment_evidence_id': eid(containing)})
        if reference_limit:
            break
    functions = []
    for address, candidate in list(candidates.items())[:options.max_decompiled_functions]:
        dossier_evidence = await session.call('analyze_function', {'procedure': address}, required=False)
        dossier = value(dossier_evidence) if dossier_evidence else None
        procedure = dossier['procedure'] if dossier else candidate['procedure']
        function = {'slice': info['index'], 'architecture': info['architecture'], 'address': procedure['address'],
                    'names': [procedure['name']], 'body': procedure['body'], 'boundary_basis': ['REA provider body ranges'],
                    'end_upper_bound': None, 'file_offset': None, 'references': [],
                    'finding_ids': sorted(candidate['findings']), 'classification': 'suspected_behavior_related',
                    'rea_evidence_id': eid(dossier_evidence) if dossier_evidence else None,
                    'direct_calls': dossier['callees'] if dossier else [],
                    'pseudocode': dossier['pseudocode'] if dossier else None,
                    'assembly': dossier['assembly'] if dossier else [],
                    'facet_availability': dossier.get('facet_availability', {}) if dossier else {},
                    'limitations': dossier['limitations'] if dossier else ['Function dossier unavailable'],
                    'opcode_bytes_verified': False}
        for finding in candidate['findings'].values():
            if address not in finding['function_addresses']:
                finding['function_addresses'].append(address)
            finding['confidence'] = 'medium_with_provider_code_references'
            finding['rea_evidence_ids'].extend(ref['xref_evidence_id'] for ref in candidate['references'])
            finding['rea_evidence_ids'] = sorted(set(finding['rea_evidence_ids']))
        body = procedure['body']
        if body.get('available') and len(body['ranges']) == 1 and body['ranges'][0]['start'] == address:
            end = int(body['ranges'][0]['end'], 16) + 1
            length = end - int(address, 16)
            if 0 < length <= 256 * 1024:
                offset, mapping_id = await _mapping(session, address, info, source)
                memory = await session.call('read_bytes', {'address': address, 'length': length}, required=False)
                if offset is not None and memory and value(memory)['complete']:
                    raw = bytes.fromhex(value(memory)['bytes_hex'])
                    if (offset + length <= info['file_offset'] + info['size_bytes']
                            and len(raw) == length and source.data[offset:offset + length] == raw):
                        function.update({'file_offset': offset, 'end_upper_bound': hex(end), 'opcode_bytes_verified': True,
                                         'mapping_evidence_id': mapping_id, 'bytes_evidence_id': eid(memory)})
        for reference in candidate['references']:
            ref = {**reference, 'kind': 'provider_static_reference'}
            if function['opcode_bytes_verified']:
                instruction = await session.call('inspect_native_instruction', {'address': reference['instruction_address']}, required=False)
                if instruction and value(instruction)['status'] == 'decoded':
                    decoded = value(instruction)
                    direct = [edge for edge in decoded['references'] if edge['target_address'] == ref['target_address']
                              and not edge['indirect'] and not edge['computed'] and edge.get('data') is True]
                    if direct:
                        ref.update({'kind': 'derived_direct_reference', 'rea_instruction_evidence_id': eid(instruction),
                                    'provider_references': direct, 'bytes': decoded['bytes'],
                                    'file_offset': function['file_offset'] + int(ref['instruction_address'], 16) - int(address, 16)})
            function['references'].append(ref)
        functions.append(function)
    return {'strings': strings, 'findings': findings, 'functions': functions,
            'coverage': {'string_inventory_count': len(rows), 'strings_retained': len(strings),
                         'strings_complete_over_provider_inventory': len(rows) == len(strings),
                         'candidate_functions': len(candidates), 'functions_inspected': len(functions),
                         'functions_omitted': max(0, len(candidates) - len(functions)),
                         'references_examined': examined_references, 'reference_budget_exhausted': reference_limit,
                         'pseudocode_available': sum(bool(function['pseudocode']) for function in functions),
                         'selection': 'Functions containing REA references to configured behavior indicators'}}


def _remove_owned_files(owned, cleanup):
    for record in reversed(owned):
        path, root = record.path, record.root
        try:
            parents_present = _verify_directories(record.directories)
            try:
                metadata = path.lstat() if parents_present else None
            except FileNotFoundError:
                metadata = None
            if metadata is None:
                cleanup.append({'path': str(path), 'confirmed': True, 'state': 'already_absent'})
            else:
                if _identity(metadata, False) != record.identity:
                    raise OSError('Owned artifact file identity changed')
                _verify_file_contents(record)
                if not _verify_directories(record.directories) or _identity(path.lstat(), False) != record.identity:
                    raise OSError('Owned artifact identity changed before removal')
                path.unlink()
                cleanup.append({'path': str(path), 'confirmed': True})
            for index in range(len(record.directories) - 1, -1, -1):
                parent = record.directories[index][0]
                if not parent.is_relative_to(root):
                    break
                try:
                    if _verify_directories(record.directories[:index + 1]):
                        parent.rmdir()
                except OSError as error:
                    if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                        cleanup.append({'path': str(parent), 'confirmed': False, 'reason': str(error)})
                    break
        except (OSError, AnalysisError) as error:
            cleanup.append({'path': str(path), 'confirmed': False, 'reason': str(error)})


async def collect(source: Source, limits: Limits, options: ReaOptions):
    result = {'slices': [], 'strings': [], 'findings': [], 'functions': [], 'coverage': []}
    root = Path(tempfile.mkdtemp(prefix='machsentry-source-'))
    root_identity = None
    owned, cleanup = [], []
    session = None
    try:
        root_identity = _register_owned_directory(root)
        path = _source_file(source, root)
        if source.member is not None:
            owned.append(_register_owned_file(root_identity, path, source.sha256))
        async with make_client(options) as client:
            session = ReaSession(client)
            try:
                result['slices'] = await _select_slices(session, source, path, options, owned)
                for info in result['slices']:
                    if not info['selected']:
                        info['status'] = 'not_selected'
                        continue
                    try:
                        analysis = await _analyze_slice(session, source, info, limits, options)
                        info['status'] = 'analyzed'
                        for key in ('strings', 'findings', 'functions'):
                            result[key].extend(analysis[key])
                        result['coverage'].append({'slice': info['index'], **analysis['coverage']})
                    except AnalysisError as error:
                        info.update({'status': 'failed', 'error': error.as_dict()})
                    finally:
                        with anyio.CancelScope(shield=True):
                            await session.finish()
                    if session.opened:
                        break
            except AnalysisError as error:
                result['error'] = error.as_dict()
            finally:
                with anyio.CancelScope(shield=True):
                    await session.finish()
    except Exception as error:
        result['error'] = error.as_dict() if isinstance(error, AnalysisError) else {'code': 'rea_transport_error', 'message': str(error)}
    finally:
        _remove_owned_files(owned, cleanup)
        if root_identity is not None:
            _remove_owned_directory(root_identity, cleanup)
        else:
            cleanup.append({'path': str(root), 'confirmed': False, 'reason': 'Staging root identity was not admitted'})
        result['rea'] = session.facts() if session else {'errors': [], 'records': [], 'evidence_bundles': [], 'cleanup': [], 'calls': [], 'closure_confirmed': True}
        result['rea']['staging_cleanup'] = cleanup
    return result
