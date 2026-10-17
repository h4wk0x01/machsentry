"""LIEF owns format interpretation; consumers receive normalized physical facts."""

from dataclasses import dataclass, field
import struct
import lief

from .source import AnalysisError, Limits


@dataclass
class Section:
    name: str
    address: int
    offset: int
    size: int
    executable: bool


@dataclass
class Function:
    address: int
    end: int
    offset: int
    names: list[str]
    basis: list[str]
    references: list[dict] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)


@dataclass
class Image:
    index: int
    architecture: str
    offset: int
    size: int
    sections: list[Section]
    functions: list[Function]
    metadata: dict
    limitations: list[str]


def _envelope(data: bytes, limits: Limits) -> list[tuple[int, int]]:
    """Admission validation before native parsing, not a second semantic parser."""
    magic = data[:4]
    thin = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce'}
    fat = {b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf', b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca'}
    if magic in thin:
        ranges = [(0, len(data))]
    elif magic in fat and len(data) >= 8:
        endian = '>' if magic[:2] == b'\xca\xfe' else '<'
        count = struct.unpack_from(endian + 'I', data, 4)[0]
        wide = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
        width = 32 if wide else 20
        if not 1 <= count <= 128 or 8 + count * width > len(data):
            raise AnalysisError("invalid_macho", "Invalid universal architecture table")
        ranges = []
        for index in range(count):
            position = 8 + index * width
            offset, size = struct.unpack_from(endian + ('QQ' if wide else 'II'), data, position + 8)
            alignment = struct.unpack_from(endian + 'I', data, position + (24 if wide else 16))[0]
            if offset < 8 + count * width or size < 28 or offset + size > len(data):
                raise AnalysisError("invalid_macho", "Universal slice outside file")
            if alignment > 63 or offset % (1 << alignment):
                raise AnalysisError("invalid_macho", "Invalid universal slice alignment")
            for other, length in ranges:
                if offset < other + length and other < offset + size:
                    raise AnalysisError("invalid_macho", "Overlapping universal slices")
            ranges.append((offset, size))
            slice_endian = '<' if data[offset:offset+2] in (b'\xcf\xfa', b'\xce\xfa') else '>'
            if data[offset:offset+4] not in thin:
                raise AnalysisError("invalid_macho", "Universal entry is not Mach-O")
            if struct.unpack_from(endian + 'II', data, position) != struct.unpack_from(slice_endian + 'II', data, offset + 4):
                raise AnalysisError("invalid_macho", "Universal and embedded CPU identity disagree")
    else:
        raise AnalysisError("unsupported_format", "Expected a thin or universal Mach-O file")
    expanded_symbol_bytes = 0
    for offset, size in ranges:
        magic = data[offset:offset+4]
        endian = '<' if magic[:2] in (b'\xcf\xfa', b'\xce\xfa') else '>'
        header_size = 32 if magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') else 28
        if size < header_size:
            raise AnalysisError("invalid_macho", "Truncated Mach-O header")
        commands, command_bytes = struct.unpack_from(endian + 'II', data, offset + 16)
        end = offset + header_size + command_bytes
        if end > offset + size or commands > command_bytes // 8:
            raise AnalysisError("invalid_macho", "Load commands exceed slice")
        if commands > 8192:
            raise AnalysisError("resource_limit", "Load-command inventory exceeds parser budget")
        cursor = offset + header_size
        for _ in range(commands):
            if cursor + 8 > end:
                raise AnalysisError("invalid_macho", "Truncated load command")
            command, length = struct.unpack_from(endian + 'II', data, cursor)
            if length < 8 or length % 4 or cursor + length > end:
                raise AnalysisError("invalid_macho", "Invalid load-command length")
            if command in (1, 0x19):
                segment_size, section_size = (72, 80) if command == 0x19 else (56, 68)
                if length < segment_size:
                    raise AnalysisError("invalid_macho", "Truncated segment")
                count = struct.unpack_from(endian + 'I', data, cursor + (64 if command == 0x19 else 48))[0]
                if segment_size + count * section_size > length:
                    raise AnalysisError("invalid_macho", "Truncated section table")
            if command == 2:
                if length < 24:
                    raise AnalysisError("invalid_macho", "Truncated symbol-table command")
                symoff, nsyms, stroff, strsize = struct.unpack_from(endian + '4I', data, cursor + 8)
                if nsyms > limits.max_symbols:
                    raise AnalysisError("resource_limit", "Symbol inventory exceeds parser budget")
                if symoff + nsyms * (16 if header_size == 32 else 12) > size or stroff + strsize > size:
                    raise AnalysisError("invalid_macho", "Symbol/string table exceeds slice")
                lengths = {}
                for symbol_index in range(nsyms):
                    string_index = struct.unpack_from(endian + 'I', data, offset + symoff + symbol_index * (16 if header_size == 32 else 12))[0]
                    if string_index == 0:
                        continue
                    if string_index >= strsize:
                        raise AnalysisError("invalid_macho", "Symbol name index exceeds string table")
                    if string_index not in lengths:
                        begin = offset + stroff + string_index
                        name_end = data.find(b'\x00', begin, min(offset + stroff + strsize, begin + 4097))
                        if name_end < 0:
                            code = 'resource_limit' if strsize - string_index > 4096 else 'invalid_macho'
                            raise AnalysisError(code, "Symbol name is unterminated or exceeds 4096 bytes")
                        lengths[string_index] = name_end - begin
                    expanded_symbol_bytes += lengths[string_index]
                    if expanded_symbol_bytes > limits.max_expanded_symbol_bytes:
                        raise AnalysisError("resource_limit", "Expanded symbol names exceed parser allocation budget")
            if command in (0xC, 0xD, 0x80000018, 0x8000001F, 0x20, 0x80000023, 0xE, 0xF, 0x8000001C):
                minimum = 24 if command in (0xC, 0xD, 0x80000018, 0x8000001F, 0x20, 0x80000023) else 12
                if length < minimum:
                    raise AnalysisError("invalid_macho", "Truncated load-command string")
                name_offset = struct.unpack_from(endian + 'I', data, cursor + 8)[0]
                if name_offset < minimum or name_offset >= length or data.find(b'\x00', cursor + name_offset, cursor + length) < 0:
                    raise AnalysisError("invalid_macho", "Load-command string is outside command or unterminated")
            if command in (0x22, 0x80000022):
                if length < 48:
                    raise AnalysisError("invalid_macho", "Truncated dyld-info command")
                for field in range(5):
                    streamoff, streamsize = struct.unpack_from(endian + 'II', data, cursor + 8 + field * 8)
                    if streamoff + streamsize > size:
                        raise AnalysisError("invalid_macho", "Dyld-info payload exceeds slice")
            if command == 0xB:
                if length < 80:
                    raise AnalysisError("invalid_macho", "Truncated dynamic symbol-table command")
                for field, width in ((32, 8), (40, 56 if header_size == 32 else 52), (48, 4), (56, 4), (64, 8), (72, 8)):
                    tableoff, entries = struct.unpack_from(endian + 'II', data, cursor + field)
                    if tableoff + entries * width > size:
                        raise AnalysisError("invalid_macho", "Dynamic symbol payload exceeds slice")
            if command in (0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034):
                if length < 16:
                    raise AnalysisError("invalid_macho", "Truncated link-edit command")
                dataoff, datasize = struct.unpack_from(endian + 'II', data, cursor + 8)
                if dataoff + datasize > size:
                    raise AnalysisError("invalid_macho", "Link-edit payload exceeds slice")
            cursor += length
        if cursor != end:
            raise AnalysisError("invalid_macho", "Load-command count/size mismatch")
    return ranges


def parse_images(data: bytes, limits: Limits) -> list[Image]:
    ranges = _envelope(data, limits)
    parsed = lief.MachO.parse(data)
    if parsed is None or parsed.size != len(ranges):
        raise AnalysisError("invalid_macho", "LIEF could not parse every declared slice")
    images = []
    for index, binary in enumerate(parsed):
        offset, size = ranges[index]
        if binary.fat_offset != offset:
            raise AnalysisError("invalid_macho", "Parser slice identity mismatch")
        sections = []
        limitations = []
        for segment in binary.segments:
            if segment.file_offset + segment.file_size > size:
                raise AnalysisError("invalid_macho", "Segment exceeds slice bytes")
            for section in segment.sections:
                if int(section.type) in (1, 0xC, 0x12) or not section.size:
                    continue  # Zero-fill has virtual extent but no source bytes.
                if section.offset + section.size > size:
                    raise AnalysisError("invalid_macho", "Section exceeds slice bytes")
                if not (segment.file_offset <= section.offset and section.offset + section.size <= segment.file_offset + segment.file_size):
                    raise AnalysisError("invalid_macho", "Section exceeds containing segment")
                if not (segment.virtual_address <= section.virtual_address and section.virtual_address + section.size <= segment.virtual_address + segment.virtual_size):
                    raise AnalysisError("invalid_macho", "Section exceeds virtual segment")
                if section.virtual_address - segment.virtual_address != section.offset - segment.file_offset:
                    raise AnalysisError("invalid_macho", "Section and segment address mappings disagree")
                executable = bool(int(segment.init_protection) & 4 and int(section.flags) & 0x80000400)
                sections.append(Section(f"{segment.name},{section.name}", int(section.virtual_address),
                                        offset + section.offset, section.size, executable))
        # Ambiguous ranges must not produce invented addresses or function ownership.
        for left, right in zip(sorted(sections, key=lambda s: s.offset), sorted(sections, key=lambda s: s.offset)[1:]):
            if left.offset + left.size > right.offset:
                raise AnalysisError("invalid_macho", "Overlapping file-backed sections")
        ordered_virtual = sorted(sections, key=lambda s: s.address)
        for left, right in zip(ordered_virtual, ordered_virtual[1:]):
            if left.address + left.size > right.address:
                raise AnalysisError("invalid_macho", "Ambiguous overlapping virtual section ranges")
        text = [s for s in sections if s.executable and not s.name.endswith(('__stubs', '__stub_helper'))]
        starts: dict[int, dict] = {}
        base = next((s.virtual_address for s in binary.segments if s.name == '__TEXT'), 0)
        if binary.has_function_starts:
            for relative in binary.function_starts.functions:
                address = base + relative
                if any(s.address <= address < s.address + s.size for s in text):
                    starts[address] = {"names": [], "basis": ["LC_FUNCTION_STARTS"]}
        for symbol in binary.symbols:
            if symbol.raw_type & 0xE0 or symbol.raw_type & 0x0E != 0x0E:
                continue
            address = int(symbol.value)
            if any(s.address <= address < s.address + s.size for s in text):
                entry = starts.setdefault(address, {"names": [], "basis": []})
                if symbol.name not in entry['names']:
                    entry['names'].append(symbol.name)
                if 'defined-symbol' not in entry['basis']:
                    entry['basis'].append('defined-symbol')
        if len(starts) > limits.max_functions:
            raise AnalysisError("resource_limit", "Function inventory exceeds configured budget")
        functions = []
        for section in text:
            addresses = sorted(address for address in starts if section.address <= address < section.address + section.size)
            for position, address in enumerate(addresses):
                end = addresses[position + 1] if position + 1 < len(addresses) else section.address + section.size
                functions.append(Function(address, end, section.offset + address - section.address,
                                          starts[address]['names'], starts[address]['basis']))
        encrypted = bool(binary.has_encryption_info and binary.encryption_info.crypt_id)
        if encrypted:
            limitations.append("Encrypted slice: code and strings cannot establish payload behavior")
        architecture = binary.header.cpu_type.name.lower()
        if architecture not in ('x86_64', 'arm64'):
            limitations.append(f"Disassembly unsupported for {architecture}")
        if not functions:
            limitations.append("No function boundaries recovered; string addresses are not function addresses")
        images.append(Image(index, architecture, offset, size, sections, sorted(functions, key=lambda f: f.address), {
            "cpu_subtype": int(binary.header.cpu_subtype), "file_type": binary.header.file_type.name,
            "platform": str(binary.platform), "encrypted": encrypted,
            "entrypoint": hex(binary.entrypoint) if binary.has_entrypoint else None,
            "code_signature_present": binary.has_code_signature, "signature_validity": "not_verified",
            "libraries": [library.name for library in binary.libraries],
            "imports": sorted({symbol.name for symbol in binary.imported_symbols}),
            "function_count": len(functions), "section_count": len(sections),
        }, limitations))
    return images
