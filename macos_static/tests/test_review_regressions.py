"""YARA hypotheses must keep the specific indicator rather than shared text."""

from hashlib import sha256
import unittest
import yara

from machsentry.behavior import find_behaviors
from machsentry.detection import generate_rule


class YaraSpecificityTests(unittest.TestCase):
    def test_long_shared_benign_prefix_cannot_replace_behavior_indicators(self):
        prefix = 'Normal product release notes. ' * 8
        text = prefix + 'display dialog "Password" with hidden answer; security find-generic-password; POST /upload multipart/form-data'
        data = b'\xcf\xfa\xed\xfe' + text.encode() + b'\0'
        strings = [{'id': 'literal', 'slice': 0, 'text': text, 'encoding': 'ascii', 'yara_eligible': True}]
        findings = find_behaviors(strings, [0])
        for finding in findings:
            finding['function_addresses'] = ['0x1000']
        result = generate_rule(data, sha256(data).hexdigest(), findings, strings, [])
        self.assertIsNotNone(result['rule'])
        compiled = yara.compile(source=result['rule'])
        self.assertTrue(compiled.match(data=data))
        self.assertFalse(compiled.match(data=b'\xcf\xfa\xed\xfe' + prefix.encode() + b'\0'))

    def test_unverified_provider_display_is_never_used_as_file_byte_signature(self):
        text = 'display dialog "Password" with hidden answer; security find-generic-password; POST /upload multipart/form-data'
        strings = [{'id': 'literal', 'slice': 0, 'text': text, 'encoding': 'ascii', 'yara_eligible': False}]
        findings = find_behaviors(strings, [0])
        for finding in findings:
            finding['function_addresses'] = ['0x1000']
        result = generate_rule(b'\xcf\xfa\xed\xfe', 'a' * 64, findings, strings, [])
        self.assertIsNone(result['rule'])


if __name__ == '__main__':
    unittest.main()
