"""Inert, self-owned Mach-O test bytes; never executed."""
import struct


def multi_function_fixture(architecture='x86_64', *, literals=None):
    """Functions return pointers to test data; no imports, syscalls or execution."""
    literals = literals if literals is not None else [
        b'TEST DATA ONLY: display dialog "Inert fixture" with hidden answer',
        b'TEST DATA ONLY: security find-generic-password -ga "Inert fixture"',
        b'TEST DATA ONLY: POST /synthetic-test HTTP/1.1 multipart/form-data',
        b'TEST DATA ONLY: browser Login Data and /Cookies paths',
        b'TEST DATA ONLY: /.electrum/wallets/ and Exodus/exodus.wallet/',
    ]
    base, code_offset, stride = 0x100000000, 512, 64
    string_offset = max(1024, ((code_offset + stride * len(literals) + 255) // 256) * 256)
    strings, code, symbols, names = b'', bytearray(stride * len(literals)), b'', b'\0'
    for index, literal in enumerate(literals):
        start = base + code_offset + stride * index
        target = base + string_offset + len(strings)
        if architecture == 'x86_64':
            body = b'\x55\x48\x89\xe5\x48\x8d\x05' + struct.pack('<i', target - (start + 11))
            body += b'\xb9' + struct.pack('<I', 0x13572468 + index * 0x123456)
            body += b'\x31\xd2\x83\xc1' + bytes([7 + index])
            body += b'\x6b\xc9' + bytes([3 + index]) + b'\x5d\xc3'
        elif architecture == 'arm64':
            page_delta = ((target & ~4095) - ((start + 8) & ~4095)) >> 12
            immediate = page_delta & 0x1fffff
            adrp = 0x90000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5)
            body = struct.pack('<10I', 0xa9bf7bfd, 0x910003fd, adrp,
                               0x91000000 | ((target & 4095) << 10),
                               0x52800001 | ((0x1234 + index * 113) << 5), 0x4a020042,
                               0x11000021 | ((7 + index) << 10), 0xd503201f, 0xa8c17bfd, 0xd65f03c0)
        else:
            raise ValueError('Fixture architecture must be x86_64 or arm64')
        code[index * stride:index * stride + len(body)] = body
        name = f'_inert_reference_{index}'.encode() + b'\0'
        symbols += struct.pack('<IBBHQ', len(names), 0xF, 1, 0, start)
        names += name
        strings += literal + b'\0'
    symbol_offset = string_offset + len(strings)
    size = symbol_offset + len(symbols) + len(names)
    section = lambda name, address, length, offset, flags: struct.pack(
        '<16s16sQQIIIIIIII', name, b'__TEXT', address, length, offset, 0, 0, 0, flags, 0, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 232, b'__TEXT', base, size, 0, size, 7, 5, 2, 0)
    segment += section(b'__text', base + code_offset, len(code), code_offset, 0x80000400)
    segment += section(b'__cstring', base + string_offset, len(strings), string_offset, 2)
    symtab = struct.pack('<6I', 2, 24, symbol_offset, len(literals), symbol_offset + len(symbols), len(names))
    cpu, subtype = (0x1000007, 3) if architecture == 'x86_64' else (0x100000c, 0)
    header = struct.pack('<8I', 0xfeedfacf, cpu, subtype, 2, 2, len(segment + symtab), 0, 0)
    data = bytearray(size)
    data[:len(header + segment + symtab)] = header + segment + symtab
    data[code_offset:code_offset + len(code)] = code
    data[string_offset:symbol_offset] = strings
    data[symbol_offset:] = symbols + names
    return bytes(data)


def universal_fixture():
    x64, arm64 = multi_function_fixture('x86_64'), multi_function_fixture('arm64')
    return _universal_fixture(x64, arm64)


def _universal_fixture(x64, arm64):
    data = bytearray(8192 + len(arm64))
    struct.pack_into('>II', data, 0, 0xcafebabe, 2)
    struct.pack_into('>5I', data, 8, 0x1000007, 3, 4096, len(x64), 12)
    struct.pack_into('>5I', data, 28, 0x100000c, 0, 8192, len(arm64), 12)
    data[4096:4096 + len(x64)] = x64
    data[8192:] = arm64
    return bytes(data)


def clipboard_reference_fixture(architecture='x86_64'):
    """Return data pointers and call a local zero-return stub named _dlsym."""
    base, code_offset, pointer_offset, string_offset = 0x100000000, 512, 896, 1024
    literal = b'INERT TEST DATA: NSPasteboard generalPasteboard _dlopen _dlsym\0'
    code, symbols, names = bytearray(256), b'', b'\0'
    for index, indirect in enumerate((False, True)):
        address = base + code_offset + 64 * index
        target = base + (pointer_offset if indirect else string_offset)
        if architecture == 'x86_64':
            operation = b'\x48\x8b\x05' if indirect else b'\x48\x8d\x05'
            body = b'\x55\x48\x89\xe5' + operation + struct.pack('<i', target - (address + 11)) + b'\x5d\xc3'
        elif architecture == 'arm64':
            page_delta = ((target & ~4095) - ((address + 8) & ~4095)) >> 12
            immediate = page_delta & 0x1fffff
            adrp = 0x90000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5)
            access = (0xf9400000 | (((target & 4095) // 8) << 10) if indirect
                      else 0x91000000 | ((target & 4095) << 10))
            body = struct.pack('<6I', 0xa9bf7bfd, 0x910003fd, adrp, access, 0xa8c17bfd, 0xd65f03c0)
        else:
            raise ValueError('Fixture architecture must be x86_64 or arm64')
        code[64 * index:64 * index + len(body)] = body
        name = f'_inert_clipboard_{"indirect" if indirect else "direct"}'.encode() + b'\0'
        symbols += struct.pack('<IBBHQ', len(names), 0xf, 1, 0, address)
        names += name
    for index, name in [(2, b'_dlsym\0'), (3, b'_inert_api_stub_caller\0')]:
        address = base + code_offset + 64 * index
        helper = base + code_offset + 128
        if architecture == 'x86_64':
            body = (b'\x31\xc0\xc3' if index == 2 else
                    b'\x55\x48\x89\xe5\xe8' + struct.pack('<i', helper - (address + 9)) + b'\x5d\xc3')
        else:
            branch = 0x94000000 | (((helper - (address + 8)) >> 2) & 0x3ffffff)
            body = (struct.pack('<2I', 0x52800000, 0xd65f03c0) if index == 2 else
                    struct.pack('<5I', 0xa9bf7bfd, 0x910003fd, branch, 0xa8c17bfd, 0xd65f03c0))
        code[64 * index:64 * index + len(body)] = body
        symbols += struct.pack('<IBBHQ', len(names), 0xf, 1, 0, address)
        names += name
    symbol_offset = string_offset + len(literal)
    size = symbol_offset + len(symbols) + len(names)
    section = lambda name, offset, length, alignment, flags: struct.pack(
        '<16s16sQQIIIIIIII', name, b'__TEXT', base + offset, length, offset,
        alignment, 0, 0, flags, 0, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 312, b'__TEXT', base, size, 0, size, 7, 5, 3, 0)
    segment += section(b'__text', code_offset, len(code), 2, 0x80000400)
    segment += section(b'__literal_ptr', pointer_offset, 8, 3, 5)
    segment += section(b'__cstring', string_offset, len(literal), 0, 2)
    symtab = struct.pack('<6I', 2, 24, symbol_offset, 4, symbol_offset + len(symbols), len(names))
    cpu, subtype = (0x1000007, 3) if architecture == 'x86_64' else (0x100000c, 0)
    header = struct.pack('<8I', 0xfeedfacf, cpu, subtype, 2, 2, len(segment + symtab), 0, 0)
    data = bytearray(size)
    data[:len(header + segment + symtab)] = header + segment + symtab
    data[code_offset:code_offset + len(code)] = code
    struct.pack_into('<Q', data, pointer_offset, base + string_offset)
    data[string_offset:symbol_offset] = literal
    data[symbol_offset:] = symbols + names
    return bytes(data)


def clipboard_reference_universal_fixture():
    return _universal_fixture(clipboard_reference_fixture('x86_64'), clipboard_reference_fixture('arm64'))

def fixture(suspicious=False):
    strings = ([b'osascript -e display dialog "Synthetic test" with hidden answer',
                b'security find-generic-password -ga "Synthetic test"', b'Login Data', b'/Cookies',
                b'/.electrum/wallets/', b'Exodus/exodus.wallet/',
                b'POST /synthetic-test HTTP/1.1\r\n', b'multipart/form-data',
                b'system_profiler SPHardwareDataType'] if suspicious else [b'Hello inert test fixture'])
    base, code_offset, text_offset = 0x100000000, 512, 1024
    body = b''
    code = b''
    for literal in strings:
        address = base + text_offset + len(body)
        site = base + code_offset + len(code)
        code += b'\x48\x8d\x05' + struct.pack('<i', address - (site + 7))
        body += literal + b'\0'
    code += b'\xc3'
    symoff = text_offset + len(body)
    symbol = struct.pack('<IBBHQ', 1, 0xF, 1, 0, base + code_offset)
    names = b'\0_inert_fixture\0'
    size = symoff + len(symbol) + len(names)
    section = lambda name, addr, length, offset, flags: struct.pack('<16s16sQQIIIIIIII', name, b'__TEXT', addr,
        length, offset, 0, 0, 0, flags, 0, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 232, b'__TEXT', base, size, 0, size, 7, 5, 2, 0)
    segment += section(b'__text', base + code_offset, len(code), code_offset, 0x80000400)
    segment += section(b'__cstring', base + text_offset, len(body), text_offset, 2)
    symtab = struct.pack('<6I', 2, 24, symoff, 1, symoff + len(symbol), len(names))
    header = struct.pack('<8I', 0xFEEDFACF, 0x1000007, 3, 2, 2, len(segment + symtab), 0, 0)
    data = bytearray(size)
    data[:len(header + segment + symtab)] = header + segment + symtab
    data[code_offset:code_offset + len(code)] = code
    data[text_offset:text_offset + len(body)] = body
    data[symoff:] = symbol + names
    return bytes(data)
