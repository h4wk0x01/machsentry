"""Extract source-bound strings and resolve direct static code references."""

from bisect import bisect_right
import re
import capstone as cs
from capstone import x86_const as x86, arm64_const as arm

from .macho import Image
from .source import Limits


ASCII = re.compile(rb'[\x20-\x7e\t\r\n]{5,}')
UTF16 = re.compile(rb'(?:[\x20-\x7e\t\r\n]\x00){5,}')


def extract_strings(data: bytes, images: list[Image], limits: Limits) -> tuple[list[dict], dict]:
    records = []
    retained = 0
    scanned = 0
    for image in images:
        for section in image.sections:
            if section.executable or image.metadata['encrypted']:
                continue
            content = memoryview(data)[section.offset:section.offset + section.size]
            for encoding, pattern in (('ascii', ASCII), ('utf-16le', UTF16)):
                for match in pattern.finditer(content):
                    length = len(match.group())
                    if len(records) >= limits.max_strings or retained + length > limits.max_string_bytes:
                        return records, {"status": "partial", "reason": "string_retention_budget",
                                         "retained_bytes": retained, "sections_examined": scanned}
                    offset = section.offset + match.start()
                    records.append({"id": f"s{image.index}:str:{offset:x}", "kind": "observed_bytes",
                                    "slice": image.index, "offset": offset,
                                    "address": hex(section.address + match.start()), "byte_length": length,
                                    "encoding": encoding, "section": section.name,
                                    "text": match.group().decode(encoding)})
                    retained += length
            scanned += 1
    return records, {"status": "complete_for_file_backed_noncode_sections", "retained_bytes": retained,
                     "sections_examined": scanned, "count": len(records)}


def decoder(architecture: str):
    if architecture == 'x86_64':
        engine = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    elif architecture == 'arm64':
        engine = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
    else:
        return None
    engine.detail = True
    return engine


def correlate(data: bytes, image: Image, strings: list[dict], limits: Limits) -> dict:
    engine = decoder(image.architecture)
    if engine is None or image.metadata['encrypted']:
        return {"status": "unavailable", "instructions": 0, "references": 0}
    candidates = sorted((r for r in strings if r['slice'] == image.index), key=lambda r: int(r['address'], 16))
    starts = [int(r['address'], 16) for r in candidates]
    function_starts = {f.address for f in image.functions}
    instructions = references = calls = decoded_bytes = undecoded_bytes = 0
    for function in image.functions:
        pages: dict[str, int] = {}
        cursor = function.address
        code = data[function.offset:function.offset + function.end - function.address]
        for insn in engine.disasm(code, function.address):
            if instructions >= limits.max_instructions or references + calls >= limits.max_references:
                return {"status": "partial", "reason": "disassembly_budget", "instructions": instructions,
                        "references": references, "direct_calls": calls, "decoded_bytes": decoded_bytes, "undecoded_bytes": undecoded_bytes}
            instructions += 1
            decoded_bytes += insn.size
            cursor = insn.address + insn.size
            targets = []
            if image.architecture == 'x86_64':
                for operand in insn.operands:
                    if operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP:
                        targets.append(insn.address + insn.size + operand.mem.disp)
                    elif operand.type == x86.X86_OP_IMM and insn.mnemonic in ('mov', 'movabs', 'push'):
                        targets.append(operand.imm)
            else:
                # Only direct ADR and ADRP+ADD address construction within one basic block.
                operands = insn.operands
                previous = dict(pages)
                def register_key(register):
                    name = insn.reg_name(register)
                    return 'x' + name[1:] if name.startswith('w') else name
                _, written = insn.regs_access()
                for register in written:
                    pages.pop(register_key(register), None)
                if insn.id == arm.ARM64_INS_ADRP and len(operands) == 2:
                    pages[register_key(operands[0].reg)] = operands[1].imm
                elif insn.id == arm.ARM64_INS_ADR and len(operands) == 2:
                    targets.append(operands[1].imm)
                elif (insn.id == arm.ARM64_INS_ADD and len(operands) == 3
                      and operands[2].type == arm.ARM64_OP_IMM
                      and insn.reg_name(operands[0].reg).startswith('x')
                      and insn.reg_name(operands[1].reg).startswith('x')):
                    base = previous.get(register_key(operands[1].reg))
                    if base is not None:
                        shift = operands[2].shift.value
                        target = base + (operands[2].imm << shift)
                        targets.append(target)
                        pages[register_key(operands[0].reg)] = target
                if insn.group(cs.CS_GRP_JUMP) or insn.group(cs.CS_GRP_CALL) or insn.group(cs.CS_GRP_RET):
                    pages.clear()
            if insn.group(cs.CS_GRP_CALL):
                for operand in insn.operands:
                    if operand.type == (x86.X86_OP_IMM if image.architecture == 'x86_64' else arm.ARM64_OP_IMM):
                        if operand.imm in function_starts:
                            function.calls.append({"site": hex(insn.address), "target": hex(operand.imm)})
                            calls += 1
            for target in set(targets):
                position = bisect_right(starts, target) - 1
                if position < 0:
                    continue
                record = candidates[position]
                if target >= starts[position] + record['byte_length']:
                    continue
                function.references.append({"evidence_id": record['id'], "instruction_address": hex(insn.address),
                    "target_address": hex(target), "target_delta": target - starts[position],
                    "file_offset": function.offset + insn.address - function.address,
                    "instruction": f"{insn.mnemonic} {insn.op_str}", "bytes": bytes(insn.bytes).hex(),
                    "kind": "derived_direct_reference"})
                references += 1
        undecoded_bytes += function.end - cursor
    return {"status": "partial" if undecoded_bytes else "complete_for_declared_function_ranges",
            "instructions": instructions, "references": references, "direct_calls": calls, "decoded_bytes": decoded_bytes,
            "undecoded_bytes": undecoded_bytes, "function_count": len(image.functions),
            "limitations": ["Linear disassembly does not prove reachability or runtime execution",
                            "Indirect calls, pointer tables, constructed strings and data flow are not resolved",
                            "Function ends are upper bounds from the next start or section end"]}
