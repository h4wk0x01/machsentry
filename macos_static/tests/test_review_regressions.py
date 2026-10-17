"""Regressions for malformed parser inputs and lost YARA indicator specificity."""

from hashlib import sha256
import struct
import unittest
from unittest.mock import patch

import yara

from machsentry.behavior import attribute_functions, find_behaviors
from machsentry.detection import generate_rule
from machsentry.evidence import correlate, extract_strings
from machsentry.macho import Function, Image, Section, parse_images
from machsentry.source import AnalysisError, Limits


def header(command_count=0, command_bytes=0):
    return struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 2,
                       command_count, command_bytes, 0, 0)


def segment_image(section_specs):
    command_size = 72 + 80 * len(section_specs)
    segment = struct.pack("<II16sQQQQIIII", 0x19, command_size, b"__TEXT",
                          0x1000, 0x1000, 0, 1024, 7, 5, len(section_specs), 0)
    sections = b"".join(
        struct.pack("<16s16sQQIIIIIIII", name, b"__TEXT", address, 16,
                    offset, 0, 0, 0, flags, 0, 0, 0)
        for name, address, offset, flags in section_specs
    )
    data = header(1, command_size) + segment + sections
    return data + b"\0" * (1024 - len(data))


def aliased_symbol_image(count, name):
    symbol_offset = 56
    string_offset = symbol_offset + count * 16
    string_table = b"\0" + name + b"\0"
    command = struct.pack("<6I", 2, 24, symbol_offset, count,
                          string_offset, len(string_table))
    symbol = struct.pack("<IBBHQ", 1, 1, 0, 0, 0)
    return header(1, 24) + command + symbol * count + string_table


class MalformedPayloadTests(unittest.TestCase):
    def assert_invalid(self, data):
        with self.assertRaises(AnalysisError) as caught:
            parse_images(data, Limits())
        self.assertEqual(caught.exception.code, "invalid_macho")

    def test_out_of_file_symbol_and_linkedit_payloads_are_not_empty_inventories(self):
        commands = {
            "symbol_table": struct.pack("<6I", 2, 24, 0x100000, 100, 0x200000, 100),
            "function_starts": struct.pack("<4I", 0x26, 16, 0x100000, 100),
            "code_signature": struct.pack("<4I", 0x1D, 16, 0x100000, 100),
        }
        for name, command in commands.items():
            with self.subTest(command=name):
                self.assert_invalid(header(1, len(command)) + command)

    def test_dylib_name_outside_command_does_not_become_empty_library(self):
        command = struct.pack("<6I", 0xC, 24, 0xFFFFFFFF, 0, 0, 0)
        self.assert_invalid(header(1, len(command)) + command)

    def test_disjoint_file_sections_cannot_claim_the_same_virtual_bytes(self):
        data = segment_image([
            (b"__text", 0x1200, 512, 0x80000400),
            (b"__cstring", 0x1200, 768, 0),
        ])
        self.assert_invalid(data)

    def test_section_virtual_address_must_match_its_file_backed_segment(self):
        for address in (0x1500, 0x3000):
            with self.subTest(address=hex(address)):
                self.assert_invalid(segment_image([
                    (b"__text", address, 512, 0x80000400),
                ]))

    def test_consistent_section_mapping_remains_accepted(self):
        images = parse_images(segment_image([
            (b"__text", 0x1200, 512, 0x80000400),
            (b"__cstring", 0x1300, 768, 0),
        ]), Limits())
        self.assertEqual(len(images), 1)
        self.assertEqual([(s.address, s.offset) for s in images[0].sections],
                         [(0x1200, 512), (0x1300, 768)])


class SymbolExpansionTests(unittest.TestCase):
    def test_repeated_names_are_budgeted_before_native_parser_allocation(self):
        limits = Limits()
        name = b"A" * 4096
        count = limits.max_expanded_symbol_bytes // len(name) + 1
        data = aliased_symbol_image(count, name)
        self.assertLess(count, limits.max_symbols)
        self.assertLess(len(data), limits.max_file_bytes)
        with patch("machsentry.macho.lief.MachO.parse",
                   side_effect=AssertionError("Native parser must not receive an expansion bomb")) as native:
            with self.assertRaises(AnalysisError) as caught:
                parse_images(data, limits)
            self.assertEqual(caught.exception.code, "resource_limit")
            native.assert_not_called()

    def test_small_aliased_symbol_names_remain_valid(self):
        name = b"_synthetic_external_symbol"
        images = parse_images(aliased_symbol_image(4, name), Limits())
        self.assertEqual(len(images), 1)
        self.assertEqual(images[0].metadata["imports"], [name.decode("ascii")])


class YaraSpecificityTests(unittest.TestCase):
    def test_long_shared_benign_prefix_cannot_replace_behavior_indicators(self):
        prefix = "Normal product release notes. " * 8
        content = (prefix + 'display dialog "Password" with hidden answer; '
                   'security find-generic-password; POST /upload multipart/form-data').encode()
        code = b"\x48\x8d\x3d" + struct.pack("<i", 0x2080 - 0x1007) + b"\xc3"
        data = header() + code + b"\0" * 24 + content + b"\0"
        function = Function(0x1000, 0x1008, 32, ["fixture"], ["synthetic"])
        image = Image(0, "x86_64", 0, len(data), [
            Section("__TEXT,__text", 0x1000, 32, len(code), True),
            Section("__TEXT,__cstring", 0x2080, 64, len(content) + 1, False),
        ], [function], {"encrypted": False}, [])
        strings, _ = extract_strings(data, [image], Limits())
        correlate(data, image, strings, Limits())
        findings = find_behaviors(strings, [0])
        attribute_functions([image], findings, strings)
        self.assertEqual({finding["category"] for finding in findings},
                         {"credential_prompt", "keychain_access", "outbound_upload"})
        self.assertTrue(all(finding["function_addresses"] for finding in findings))

        result = generate_rule(data, sha256(data).hexdigest(), findings, strings, [])
        if result["rule"] is None:
            self.assertEqual(result["status"], "not_generated")
            return
        compiled = yara.compile(source=result["rule"])
        self.assertTrue(compiled.match(data=data))
        unrelated_control = header() + prefix.encode() + b"\0"
        self.assertFalse(compiled.match(data=unrelated_control),
                         "A shared benign prefix must not satisfy all behavior categories")


if __name__ == "__main__":
    unittest.main()
