"""Decode static instruction fixtures and verify emitted signatures with real YARA."""

from copy import deepcopy
import struct
import unittest

import yara

from machsentry.opcodes import MAX_FUNCTION_SCAN_BYTES, build_opcode_patterns


def attributed_function(code, site, reference_bytes, architecture='x86_64', offset=0,
                        address=0x1000, slice_id=0, target=0x2000):
    return {'slice': slice_id, 'architecture': architecture,
            'address': hex(address), 'end_upper_bound': hex(address + len(code)),
            'file_offset': offset, 'names': ['fixture_function'],
            'finding_ids': [f's{slice_id}:keychain_access'],
            'references': [{'kind': 'derived_direct_reference', 'evidence_id': f's{slice_id}:str:5000',
                            'instruction_address': hex(address + site),
                            'target_address': hex(target), 'target_delta': 0,
                            'file_offset': offset + site, 'bytes': reference_bytes.hex(),
                            'instruction': 'fixture: use Capstone for interpretation'}]}


def x64_fixture():
    prefix = bytes.fromhex('554889e54883ec3048897de8488975e0488955d8488b45e8488b4de0')
    reference = bytes.fromhex('488d3d10000000')
    suffix = bytes.fromhex('e810000000488945e0488b45e04883c001488945d8b9010000004883c4305dc3')
    code = prefix + reference + suffix
    return code, attributed_function(code, len(prefix), reference)


def arm64_fixture():
    words = [0xa9be7bfd, 0x910003fd, 0xf9000fe0, 0xf9400fe1,
             0x90000000, 0x91000000 | (0x123 << 10), 0x94000004,
             0xf9400fe0, 0x91000421, 0xaa0103e0, 0xa8c27bfd, 0xd65f03c0]
    code = struct.pack('<' + 'I' * len(words), *words)
    return code, attributed_function(code, 20, code[20:24], architecture='arm64', target=0x1123)


def compile_pattern(pattern):
    return yara.compile(source='rule InstructionFixture { strings: $op = { '
                        + pattern['hex_pattern'] + ' } condition: $op }', error_on_warning=True)


class OpcodePatternTests(unittest.TestCase):
    def pattern_for(self, data, function):
        result = build_opcode_patterns(data, [function])
        self.assertEqual(len(result['patterns']), 1, result)
        return result['patterns'][0]

    def test_x64_source_identity_masks_and_actual_yara(self):
        data, function = x64_fixture()
        pattern = self.pattern_for(data, function)
        compiled = compile_pattern(pattern)
        self.assertTrue(compiled.match(data=data))
        start = pattern['file_offset']
        self.assertEqual(data[start:start + pattern['length']].hex(), pattern['source_bytes_hex'])
        self.assertEqual(pattern['function_address'], function['address'])
        self.assertEqual(pattern['references'], function['references'])
        self.assertEqual({field['kind'] for field in pattern['masked_fields']},
                         {'rip_relative_displacement', 'relative_control_flow'})
        self.assertTrue(all('?' not in token for token in
                            (pattern['hex_pattern'].split()[0], pattern['hex_pattern'].split()[-1])))
        self.assertLessEqual(pattern['wildcard_ratio'], 0.4)
        self.assertGreaterEqual(pattern['fixed_bytes'], 16)
        self.assertGreaterEqual(pattern['longest_fixed_run'], 4)
        mutated = bytearray(data)
        for index, mask in enumerate(bytes.fromhex(pattern['wildcard_bits_hex'])):
            mutated[start + index] ^= mask
        self.assertNotEqual(mutated, data)
        self.assertTrue(compiled.match(data=bytes(mutated)))
        # Fixed changes are tested independently, not hidden by wildcard changes.
        for index, mask in enumerate(bytes.fromhex(pattern['wildcard_bits_hex'])):
            if mask == 0:
                fixed_change = bytearray(data)
                fixed_change[start + index] ^= 1
                self.assertFalse(compiled.match(data=bytes(fixed_change)), index)

    def test_arm64_only_immediate_nibbles_vary_and_shared_bits_stay_fixed(self):
        data, function = arm64_fixture()
        pattern = self.pattern_for(data, function)
        compiled = compile_pattern(pattern)
        self.assertTrue(compiled.match(data=data))
        masks = bytes.fromhex(pattern['wildcard_bits_hex'])
        self.assertEqual(masks[16:20], bytes.fromhex('00ffff00'))
        self.assertEqual(masks[20:24], bytes.fromhex('00f00f00'))
        self.assertEqual(masks[24:28], bytes.fromhex('ffffff00'))
        self.assertEqual(masks[32:36], b'\x00' * 4, 'ordinary ADD is not a pointer')
        self.assertTrue(any('partial' in limitation for limitation in pattern['limitations']))
        mutated = bytes(value ^ mask for value, mask in zip(data, masks))
        self.assertTrue(compiled.match(data=mutated))
        # The opcode and register bits in partially variable bytes cannot widen.
        for index, bit in ((16, 1), (20, 1), (21, 1), (22, 0x80), (27, 0x80)):
            mutated = bytearray(data)
            mutated[index] ^= bit
            self.assertFalse(compiled.match(data=bytes(mutated)))

    def test_pointer_mov_requires_matching_direct_reference_target(self):
        prefix = bytes.fromhex('554889e54883ec3048897de8488975e0488955d8')
        pointer = bytes.fromhex('48b80020000000000000')
        suffix = bytes.fromhex('488945e0488b45e04883c001488945d8b9010000004883c4305dc3')
        data = prefix + pointer + suffix
        function = attributed_function(data, len(prefix), pointer, target=0x2000)
        pattern = self.pattern_for(data, function)
        self.assertIn('evidence_linked_pointer', [field['kind'] for field in pattern['masked_fields']])
        different_target = deepcopy(function)
        different_target['references'][0]['target_address'] = '0x3000'
        pattern = self.pattern_for(data, different_target)
        self.assertNotIn('evidence_linked_pointer', [field['kind'] for field in pattern['masked_fields']])

    def test_arm64_branch_classes_keep_register_condition_and_opcode_bits(self):
        original, function = arm64_fixture()
        for word, expected_mask in ((0x14000004, 'ffffff00'), (0x54000080, '00ffff00'),
                                    (0x34000080, '00ffff00'), (0x35000080, '00ffff00'),
                                    (0x36000080, '00ff0000'), (0x37000080, '00ff0000')):
            with self.subTest(instruction=hex(word)):
                data = original[:24] + struct.pack('<I', word) + original[28:]
                pattern = self.pattern_for(data, function)
                masks = bytes.fromhex(pattern['wildcard_bits_hex'])
                self.assertEqual(masks[24:28].hex(), expected_mask)
                compiled = compile_pattern(pattern)
                self.assertTrue(compiled.match(data=data))
                mutated = bytearray(data)
                for index in range(24, 28):
                    mutated[index] ^= masks[index]
                self.assertTrue(compiled.match(data=bytes(mutated)))
                # Top opcode bits remain fixed for every supported branch class.
                mutated = bytearray(data)
                mutated[27] ^= 0x80
                self.assertFalse(compiled.match(data=bytes(mutated)))

    def test_trimmed_tail_preserves_concrete_extremities_and_source_range(self):
        data, function = x64_fixture()
        data = data[:-2] + bytes.fromhex('e801000000')
        function['end_upper_bound'] = hex(0x1000 + len(data))
        pattern = self.pattern_for(data, function)
        self.assertEqual(pattern['decoded_window']['trimmed_suffix_bytes'], 4)
        self.assertEqual(pattern['hex_pattern'].split()[-1], 'E8')
        self.assertEqual(pattern['end_address'], hex(0x1000 + len(data) - 4))
        self.assertTrue(compile_pattern(pattern).match(data=data))

    def test_fixed_leading_byte_is_retained_for_arm64_reference(self):
        data, function = arm64_fixture()
        # Start on a branch: its first three bytes are variable, its opcode byte is fixed.
        branch = struct.pack('<I', 0x94000004)
        data = branch + data
        function['end_upper_bound'] = hex(0x1000 + len(data))
        function['references'][0]['instruction_address'] = hex(0x1000 + 24)
        function['references'][0]['file_offset'] = 24
        pattern = self.pattern_for(data, function)
        self.assertEqual(pattern['decoded_window']['trimmed_prefix_bytes'], 3)
        self.assertEqual(pattern['address'], '0x1003')
        self.assertEqual(pattern['file_offset'], 3)
        self.assertEqual(pattern['hex_pattern'].split()[0], '94')
        self.assertEqual(pattern['source_bytes_hex'], data[3:].hex())
        self.assertTrue(compile_pattern(pattern).match(data=data))

    def test_distinct_function_and_slice_budgets_preserve_offsets(self):
        code, function = x64_fixture()
        functions = []
        data = code * 5
        for number in range(5):
            selected = deepcopy(function)
            shift = len(code) * number
            selected['slice'] = 0 if number < 4 else 1
            selected['address'] = hex(0x1000 + shift)
            selected['end_upper_bound'] = hex(0x1000 + shift + len(code))
            selected['file_offset'] = shift
            selected['references'][0]['instruction_address'] = hex(
                int(function['references'][0]['instruction_address'], 16) + shift)
            selected['references'][0]['file_offset'] += shift
            functions.append(selected)
        result = build_opcode_patterns(data, functions + [functions[0]])
        self.assertEqual([pattern['slice'] for pattern in result['patterns']], [0, 0, 0, 1])
        self.assertEqual(result['coverage']['rejected_functions'],
                         {'slice_pattern_budget': 1, 'duplicate_function': 1})
        for pattern in result['patterns']:
            self.assertEqual(data[pattern['file_offset']:pattern['file_offset'] + pattern['length']].hex(),
                             pattern['source_bytes_hex'])

    def test_invalid_or_unverified_boundaries_are_explicitly_rejected(self):
        data, function = x64_fixture()
        variants = []
        for key, value in [('address', True), ('address', '-1'), ('address', -1),
                           ('end_upper_bound', '0xffffffffff'), ('file_offset', len(data)),
                           ('finding_ids', []), ('references', None)]:
            changed = deepcopy(function)
            changed[key] = value
            variants.append(changed)
        for key, value in [('bytes', '00'), ('file_offset', 0), ('kind', 'unverified'),
                           ('evidence_id', None), ('instruction_address', '0x1')]:
            changed = deepcopy(function)
            changed['references'][0][key] = value
            variants.append(changed)
        for changed in variants:
            result = build_opcode_patterns(data, [changed])
            self.assertFalse(result['patterns'], changed)
            self.assertEqual(sum(result['coverage']['rejected_functions'].values()), 1)

    def test_reference_inside_instruction_is_not_guessed_into_alignment(self):
        data, function = x64_fixture()
        reference = function['references'][0]
        reference['instruction_address'] = hex(int(reference['instruction_address'], 16) + 1)
        reference['file_offset'] += 1
        reference['bytes'] = reference['bytes'][2:]
        result = build_opcode_patterns(data, [function])
        self.assertFalse(result['patterns'])
        self.assertIn('reference_not_on_instruction_boundary', result['coverage']['rejected_functions'])

    def test_scan_budget_and_missing_disassembly_do_not_claim_coverage(self):
        data = b'\x90' * (MAX_FUNCTION_SCAN_BYTES + 32)
        function = attributed_function(data, MAX_FUNCTION_SCAN_BYTES + 1, b'\x90')
        result = build_opcode_patterns(data, [function])
        self.assertIn('function_scan_budget', result['coverage']['rejected_functions'])
        data = b'\x06' + bytes.fromhex('488d3d10000000') + b'\x90' * 32
        function = attributed_function(data, 1, data[1:8])
        result = build_opcode_patterns(data, [function])
        self.assertFalse(result['patterns'])
        self.assertIn('reference_not_decoded', result['coverage']['rejected_functions'])

    def test_weak_pattern_is_omitted_and_budget_arguments_are_validated(self):
        data = bytes.fromhex('488d3d10000000c3')
        function = attributed_function(data, 0, data[:7])
        result = build_opcode_patterns(data, [function])
        self.assertFalse(result['patterns'])
        self.assertIn('insufficient_fixed_instruction_context', result['coverage']['rejected_functions'])
        for value in (-1, 4, True, '3'):
            with self.assertRaises(ValueError):
                build_opcode_patterns(data, [function], max_patterns_per_slice=value)
        self.assertFalse(build_opcode_patterns(data, [function], max_patterns_per_slice=0)['patterns'])


if __name__ == '__main__':
    unittest.main()
