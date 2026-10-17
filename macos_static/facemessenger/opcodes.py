"""Evidence-centred instruction signatures; relocation tolerance is not family coverage."""

from collections import Counter, deque
import capstone as cs
from capstone import arm64_const as arm, x86_const as x86

from .evidence import decoder


MIN_BYTES = 24
MAX_BYTES = 128
MIN_FIXED_BYTES = 16
MAX_WILDCARD_RATIO = 0.4
MAX_FUNCTION_SCAN_BYTES = 256 * 1024


def _integer(value):
    if isinstance(value, bool):
        raise ValueError("Boolean is not an address")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.startswith('0x'):
        result = int(value, 16)
    else:
        raise ValueError("Expected integer or hexadecimal address")
    if not 0 <= result <= 0xffffffffffffffff:
        raise ValueError("Address outside unsigned 64-bit range")
    return result


def _function_input(data, function):
    start = _integer(function['address'])
    end = _integer(function['end_upper_bound'])
    offset = _integer(function['file_offset'])
    slice_id = _integer(function['slice'])
    architecture = function['architecture']
    if start >= end or offset + end - start > len(data):
        raise ValueError("Function outside supplied source bytes")
    if architecture == 'arm64' and start % 4:
        raise ValueError("Misaligned ARM64 function")
    if not isinstance(function['finding_ids'], list) or not function['finding_ids']:
        raise ValueError("Function lacks finding provenance")
    if not all(isinstance(value, str) and value for value in function['finding_ids']):
        raise ValueError("Invalid finding provenance")
    if not isinstance(function['references'], list):
        raise ValueError("Invalid reference inventory")
    references = []
    for reference in function['references']:
        if not isinstance(reference, dict) or reference.get('kind') != 'derived_direct_reference':
            continue
        try:
            site = _integer(reference['instruction_address'])
            physical = _integer(reference['file_offset'])
            _integer(reference['target_address'])
            raw = bytes.fromhex(reference['bytes'])
            if (not isinstance(reference['evidence_id'], str) or not reference['evidence_id']
                    or not 1 <= len(raw) <= 15 or site < start or site + len(raw) > end
                    or physical != offset + site - start
                    or data[physical:physical + len(raw)] != raw):
                continue
            references.append(reference)
        except (KeyError, TypeError, ValueError):
            continue
    return start, end, offset, slice_id, architecture, sorted(
        references, key=lambda reference: _integer(reference['instruction_address']))


def _instruction_mask(instruction, architecture, references):
    masks = bytearray(instruction.size)
    fields = []
    limitations = []

    def byte_field(offset, size, kind):
        if offset > 0 and size > 0 and offset + size <= instruction.size:
            masks[offset:offset + size] = b'\xff' * size
            fields.append(kind)

    if architecture == 'x86_64':
        if any(operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP
               for operand in instruction.operands):
            byte_field(instruction.disp_offset, instruction.disp_size, 'rip_relative_displacement')
        if (instruction.group(cs.CS_GRP_BRANCH_RELATIVE)
                and any(operand.type == x86.X86_OP_IMM for operand in instruction.operands)):
            byte_field(instruction.imm_offset, instruction.imm_size, 'relative_control_flow')
        if instruction.id in (x86.X86_INS_MOV, x86.X86_INS_MOVABS):
            # Only an upstream direct-reference fact establishes a pointer here.
            targets = {_integer(reference['target_address']) for reference in references}
            if any(operand.type == x86.X86_OP_IMM and operand.imm in targets
                   for operand in instruction.operands):
                byte_field(instruction.imm_offset, instruction.imm_size, 'evidence_linked_pointer')
        return masks, fields, limitations

    variable_bits, kind = 0, None
    if instruction.id in (arm.ARM64_INS_ADR, arm.ARM64_INS_ADRP):
        variable_bits, kind = (0x7ffff << 5) | (3 << 29), 'pc_relative_address'
    elif instruction.id == arm.ARM64_INS_BL:
        variable_bits, kind = (1 << 26) - 1, 'relative_control_flow'
    elif instruction.id == arm.ARM64_INS_B:
        variable_bits = ((1 << 26) - 1 if instruction.cc == arm.ARM64_CC_INVALID
                         else 0x7ffff << 5)
        kind = 'relative_control_flow'
    elif instruction.id in (arm.ARM64_INS_CBZ, arm.ARM64_INS_CBNZ):
        variable_bits, kind = 0x7ffff << 5, 'relative_control_flow'
    elif instruction.id in (arm.ARM64_INS_TBZ, arm.ARM64_INS_TBNZ):
        variable_bits, kind = 0x3fff << 5, 'relative_control_flow'
    elif (instruction.id == arm.ARM64_INS_ADD and references
          and len(instruction.operands) == 3
          and instruction.operands[2].type == arm.ARM64_OP_IMM):
        variable_bits, kind = 0xfff << 10, 'evidence_linked_address_add'
    if kind is not None and instruction.size == 4:
        # A64 fields share bytes with opcodes/registers. Mask only complete
        # immediate nibbles; never broaden a shared nibble into a wildcard.
        represented = 0
        for shift in range(0, 32, 4):
            nibble = 0xf << shift
            if variable_bits & nibble == nibble:
                represented |= nibble
        masks[:] = represented.to_bytes(4, 'little')
        fields.append(kind)
        if represented != variable_bits:
            limitations.append('ARM64 immediate bits sharing opcode/register nibbles remain fixed; relocation tolerance is partial')
    return masks, fields, limitations


def _window(data, start, end, offset, architecture, references):
    anchor = _integer(references[0]['instruction_address'])
    if anchor + 15 - start > MAX_FUNCTION_SCAN_BYTES:
        return None, 'function_scan_budget'
    stop = min(end, start + MAX_FUNCTION_SCAN_BYTES, anchor + 80)
    engine = decoder(architecture)
    if engine is None:
        return None, 'unsupported_architecture'
    before, selected = deque(), []
    anchored = False
    for instruction in engine.disasm(data[offset:offset + stop - start], start):
        if not anchored:
            if instruction.address > anchor:
                return None, 'reference_not_on_instruction_boundary'
            if instruction.address < anchor:
                before.append(instruction)
                while len(before) > 1 and instruction.address + instruction.size - before[1].address >= 32:
                    before.popleft()
                continue
            if bytes(instruction.bytes).hex() != references[0]['bytes'].lower():
                return None, 'reference_instruction_mismatch'
            selected = list(before)
            anchored = True
        if selected and instruction.address + instruction.size - selected[0].address > MAX_BYTES:
            break
        selected.append(instruction)
        if instruction.address + instruction.size >= anchor + 64 or instruction.group(cs.CS_GRP_RET):
            break
    if not anchored:
        return None, 'reference_not_decoded'
    return selected, None


def _pattern(data, function, parsed, instructions):
    start, _, offset, slice_id, architecture, references = parsed
    begin = instructions[0].address
    end = instructions[-1].address + instructions[-1].size
    by_site = {}
    for reference in references:
        by_site.setdefault(_integer(reference['instruction_address']), []).append(reference)
    masks = bytearray()
    fields, limitations = [], []
    for instruction in instructions:
        matching = [reference for reference in by_site.get(instruction.address, [])
                    if bytes(instruction.bytes).hex() == reference['bytes'].lower()]
        instruction_mask, kinds, caveats = _instruction_mask(instruction, architecture, matching)
        masks.extend(instruction_mask)
        limitations.extend(caveats)
        for kind in kinds:
            fields.append({'kind': kind, 'instruction_address': hex(instruction.address),
                           'instruction_bytes_hex': bytes(instruction.bytes).hex(),
                           'masked_bits_hex': instruction_mask.hex()})
    left, right = 0, len(masks)
    while left < right and masks[left]:
        left += 1
    while right > left and masks[right - 1]:
        right -= 1
    retained = masks[left:right]
    matched_references = [reference for instruction in instructions
                          for reference in by_site.get(instruction.address, [])
                          if begin + left <= instruction.address
                          and instruction.address + instruction.size <= begin + right
                          and bytes(instruction.bytes).hex() == reference['bytes'].lower()]
    if not matched_references:
        return None, 'trimmed_direct_reference'
    fixed = sum(mask == 0 for mask in retained)
    wildcard_ratio = 1 - fixed / len(retained) if retained else 1
    longest = run = 0
    for mask in retained:
        run = run + 1 if mask == 0 else 0
        longest = max(longest, run)
    if (not MIN_BYTES <= len(retained) <= MAX_BYTES or fixed < MIN_FIXED_BYTES
            or wildcard_ratio > MAX_WILDCARD_RATIO or longest < 4):
        return None, 'insufficient_fixed_instruction_context'
    file_offset = offset + begin + left - start
    original = data[file_offset:file_offset + len(retained)]
    tokens = []
    for value, mask in zip(original, retained):
        pair = f'{value:02X}'
        tokens.append(('?' if mask & 0xf0 else pair[0]) + ('?' if mask & 0x0f else pair[1]))
    return {'slice': slice_id, 'architecture': architecture, 'address': hex(begin + left),
            'end_address': hex(begin + right), 'file_offset': file_offset,
            'length': len(original), 'hex_pattern': ' '.join(tokens),
            'source_bytes_hex': original.hex(), 'wildcard_bits_hex': retained.hex(),
            'fixed_bytes': fixed, 'wildcard_ratio': round(wildcard_ratio, 6),
            'longest_fixed_run': longest, 'function_address': function['address'],
            'function_names': function.get('names', []), 'finding_ids': function['finding_ids'],
            'references': matched_references, 'masked_fields': fields,
            'decoded_window': {'address': hex(begin), 'end_address': hex(end),
                               'trimmed_prefix_bytes': left, 'trimmed_suffix_bytes': len(masks) - right},
            'kind': 'derived_instruction_pattern',
            'limitations': sorted(set(limitations))}, None


def build_opcode_patterns(data: bytes, functions: list[dict], max_patterns_per_slice=3) -> dict:
    """Select at most one direct-reference window per function; never execute bytes.

    Input function/reference facts belong to behavior.attribute_functions and
    evidence.correlate. Decode from their function start, never from a guessed
    x86 byte alignment. Budget/invalid/weak outcomes remain explicit coverage.
    """
    if not isinstance(max_patterns_per_slice, int) or isinstance(max_patterns_per_slice, bool) or not 0 <= max_patterns_per_slice <= 3:
        raise ValueError('max_patterns_per_slice must be an integer from 0 to 3')
    patterns, rejected = [], Counter()
    per_slice = Counter()
    seen = set()
    examined = 0
    for function in functions:
        try:
            parsed = _function_input(data, function)
        except (KeyError, TypeError, ValueError):
            rejected['invalid_function_or_provenance'] += 1
            continue
        start, _, _, slice_id, architecture, references = parsed
        identity = slice_id, architecture, start
        if identity in seen:
            rejected['duplicate_function'] += 1
            continue
        seen.add(identity)
        if per_slice[slice_id] >= max_patterns_per_slice:
            rejected['slice_pattern_budget'] += 1
            continue
        examined += 1
        if not references:
            rejected['no_verified_direct_reference'] += 1
            continue
        instructions, reason = _window(data, *parsed[:3], architecture, references)
        if reason:
            rejected[reason] += 1
            continue
        pattern, reason = _pattern(data, function, parsed, instructions)
        if reason:
            rejected[reason] += 1
            continue
        pattern['id'] = f's{slice_id}:opcode:{pattern["file_offset"]:x}'
        patterns.append(pattern)
        per_slice[slice_id] += 1
    return {'patterns': patterns,
            'engine': f'capstone/{cs.__version__}',
            'coverage': {'status': 'bounded_candidate_selection', 'functions_supplied': len(functions),
                         'functions_examined': examined, 'patterns_selected': len(patterns),
                         'max_patterns_per_slice': max_patterns_per_slice,
                         'max_function_scan_bytes': MAX_FUNCTION_SCAN_BYTES,
                         'rejected_functions': dict(rejected)},
            'limitations': ['Windows are selected around the first verified direct reference in each function',
                            'Linear decoding and indicator references do not prove execution, reachability or malicious intent',
                            'Masks cover decoded relocation-sensitive fields; stability across malware variants is unverified',
                            'Patterns are sample-derived candidates and require contextual indicators plus positive and negative corpus testing',
                            'Function ends are producer-supplied upper bounds; weak or undecodable windows are omitted']}
