import unittest

from machsentry.behavior import risk_score


class SliceVerdictTests(unittest.TestCase):
    def test_separate_slices_do_not_fabricate_a_corroborated_verdict(self):
        findings = [
            {'category': 'keychain_access', 'weight': 20, 'slice': 0, 'function_addresses': ['0x1000']},
            {'category': 'credential_prompt', 'weight': 20, 'slice': 0, 'function_addresses': ['0x1000']},
            {'category': 'outbound_upload', 'weight': 20, 'slice': 1, 'function_addresses': ['0x2000']},
            {'category': 'wallet_collection', 'weight': 15, 'slice': 1, 'function_addresses': ['0x2000']},
        ]
        score = risk_score(findings, True)
        self.assertEqual(score['value'], 40)
        self.assertEqual(score['verdict'], 'suspicious')
