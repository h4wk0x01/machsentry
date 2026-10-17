from copy import deepcopy
from hashlib import sha256
import unittest

import yara

from machsentry.detection import generate_rule
from machsentry.opcodes import build_opcode_patterns
from test_opcodes import x64_fixture
import test_cli


class OpcodeRuleTests(unittest.TestCase):
    def setUp(self):
        code, function = x64_fixture()
        second = code.replace(bytes.fromhex('b901000000'), bytes.fromhex('b902000000'))
        self.data = bytes.fromhex('cffaedfe') + b'\0' * 28 + code + second
        functions = []
        for offset, address in ((32, 0x1000), (32 + len(code), 0x2000)):
            current = deepcopy(function)
            current['file_offset'] = offset
            current['address'] = hex(address)
            current['end_upper_bound'] = hex(address + len(code))
            reference = current['references'][0]
            reference['file_offset'] += offset
            reference['instruction_address'] = hex(int(reference['instruction_address'], 16) + address - 0x1000)
            functions.append(current)
        self.patterns = build_opcode_patterns(self.data, functions)
        self.assertEqual(len(self.patterns['patterns']), 2)

    def generate(self, **kwargs):
        return generate_rule(self.data, sha256(self.data).hexdigest(), [], [], [],
                             opcode_analysis=self.patterns, mode='opcodes', **kwargs)

    def test_opcode_rule_requires_two_distinct_windows_from_same_slice(self):
        result = self.generate()
        self.assertEqual(result['status'], 'positive_only')
        self.assertEqual(result['effective_mode'], 'opcodes')
        compiled = yara.compile(source=result['rule'])
        self.assertTrue(compiled.match(data=self.data))
        first = self.patterns['patterns'][0]
        only_one = self.data[:32] + bytes.fromhex(first['source_bytes_hex'])
        self.assertFalse(compiled.match(data=only_one))

    def test_duplicate_code_window_cannot_satisfy_two_pattern_threshold(self):
        self.patterns['patterns'][1]['hex_pattern'] = self.patterns['patterns'][0]['hex_pattern']
        self.assertEqual(self.generate()['status'], 'not_generated')

    def test_related_operand_mutation_matches_but_fixed_mutation_is_reported_as_missed(self):
        varied = bytearray(self.data)
        for pattern in self.patterns['patterns']:
            for index, mask in enumerate(bytes.fromhex(pattern['wildcard_bits_hex'])):
                varied[pattern['file_offset'] + index] ^= mask
        result = self.generate(related=[('synthetic-variable-operands', bytes(varied))])
        self.assertTrue(result['validation']['related_samples'][0]['matched'])
        varied[self.patterns['patterns'][0]['file_offset']] ^= 1
        result = self.generate(related=[('synthetic-fixed-change', bytes(varied))])
        self.assertEqual(result['status'], 'related_samples_missed')
        self.assertFalse(result['validation']['related_samples'][0]['matched'])


class CorpusCliTests(unittest.TestCase):
    setUp = test_cli.CliTests.setUp
    run_cli = test_cli.CliTests.run_cli

    def test_related_miss_is_saved_as_incomplete_candidate(self):
        output = self.root / 'related'
        code, result = self.run_cli(self.positive, '--output', output, '--related-file', self.negative, '--json', '--yara-mode', 'strings')
        self.assertEqual(code, 0)
        self.assertEqual(result['value']['yara']['status'], 'related_samples_missed')
        self.assertFalse((output / 'detection.yar').exists())
        self.assertTrue((output / 'candidate-rejected.yar.txt').exists())

    def test_explicit_opcode_mode_never_silently_becomes_string_rule(self):
        code, result = self.run_cli(self.positive, '--output', self.root / 'explicit', '--yara-mode', 'opcodes', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(result['value']['yara']['status'], 'not_generated')
        self.assertIsNone(result['value']['yara']['rule'])
