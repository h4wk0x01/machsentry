"""AI input selection: byte budget, priorities, caps and no worker paths."""

import json
import unittest

import worker_support as support
from machsentry_worker.evidence import (PSEUDOCODE_CHARS, STRING_CHARS, YARA_RULE_CHARS, function_keys,
                                        internal_terms, select)

SAMPLE = {'name': 'synthetic.macho', 'sha256': 'a' * 64, 'size': 12345, 'architectures': ['x86_64', 'arm64']}


class EvidenceTests(unittest.TestCase):
    def test_selection_respects_every_budget(self):
        report = support.report(strings_per_finding=12, pseudocode_chars=6000)
        previous = None
        for budget in (3000, 6000, 12000, 25000, 40000, 200000):
            selection = select(report, SAMPLE, 'pt-BR', budget)
            if selection is None:
                continue
            self.assertLessEqual(len(selection.text.encode()), budget)
            document = json.loads(selection.text)
            count = len(document['strings']) + len(document['functions'])
            if previous is not None:
                self.assertGreaterEqual(count, previous)
            previous = count
        self.assertIsNotNone(previous)

    def test_core_too_large_returns_none(self):
        self.assertIsNone(select(support.report(), SAMPLE, 'en-US', 500))

    def test_priorities_and_caps(self):
        report = support.report(strings_per_finding=12, pseudocode_chars=9000)
        report['evidence'][0]['text'] = 'TEST DATA ONLY ' + 'z' * 1000
        selection = select(report, SAMPLE, 'en-US', 14000)
        document = json.loads(selection.text)
        # First pass: up to three strings per finding before any function body.
        self.assertTrue(document['strings'])
        self.assertTrue(all(len(item['text']) <= STRING_CHARS for item in document['strings']))
        self.assertTrue(document['strings'][0]['text_truncated'])
        self.assertTrue(all(len(item['pseudocode']) <= PSEUDOCODE_CHARS for item in document['functions']))
        weights = {finding['id']: finding['weight'] for finding in report['findings']}
        ranked = [sum(weights[i] for i in item['finding_ids']) for item in document['functions']]
        self.assertEqual(ranked, sorted(ranked, reverse=True))
        self.assertGreater(document['omitted']['strings'] + document['omitted']['functions'], 0)
        # Findings only cite strings that were sent.
        sent = {item['id'] for item in document['strings']}
        for finding in document['findings']:
            self.assertTrue(set(finding['evidence_ids']) <= sent)
        self.assertTrue(selection.evidence_ids >= sent)
        self.assertEqual(selection.finding_ids, {finding['id'] for finding in report['findings']})

    def test_identity_comes_from_the_claim_and_paths_stay_private(self):
        selection = select(support.report(), SAMPLE, 'pt-BR', 40000)
        self.assertNotIn('/input/sample.macho', selection.text)
        self.assertNotIn('/tmp/x', selection.text)
        document = json.loads(selection.text)
        self.assertEqual(document['sample'], SAMPLE)
        self.assertEqual(document['coverage']['runtime'], 'not_performed')
        self.assertEqual(document['ioc_candidates'][0]['contacted'], False)
        self.assertIn('s0:str:20', selection.evidence_ids)

    def test_only_ids_the_site_can_resolve_are_citable(self):
        # report-view.json resolves findings and their evidence; strings no finding references stay context.
        report = support.unlinked_script_and_ioc(support.report())
        selection = select(report, SAMPLE, 'en-US', 40000)
        document = json.loads(selection.text)
        linked_evidence = {identifier for finding in report['findings'] for identifier in finding['evidence_ids']}
        self.assertTrue(selection.evidence_ids <= linked_evidence)
        self.assertEqual(selection.evidence_ids, {item['id'] for item in document['strings']})
        self.assertNotIn(support.UNLINKED_SCRIPT, selection.evidence_ids)
        self.assertNotIn(support.UNLINKED_IOC, selection.evidence_ids)
        linked_script, unlinked_script = document['scripts']
        self.assertEqual((linked_script['evidence_id'], linked_script['finding_ids']),
                         ('s0:str:0', ['s0:credential_prompt']))
        self.assertEqual((unlinked_script['evidence_id'], unlinked_script['finding_ids']), (None, []))
        unlinked_ioc = document['ioc_candidates'][1]
        self.assertEqual((unlinked_ioc['value'], unlinked_ioc['evidence_id'], unlinked_ioc['finding_ids']),
                         ('https://c2.invalid/api', None, []))
        self.assertNotIn(support.UNLINKED_SCRIPT, selection.text)
        self.assertNotIn(support.UNLINKED_IOC, selection.text)

    def test_linked_string_left_out_by_the_budget_is_cited_through_its_finding(self):
        report = support.report(strings_per_finding=12)
        # The last string of the lowest-weight finding is the last one the budget takes; it is
        # larger than the script entry, so some budgets drop the string and still send the script.
        target = 's1:str:41'
        next(item for item in report['evidence'] if item['id'] == target)['text'] = 'TEST DATA ONLY ' + 'q' * 280
        report['scripts'][0]['evidence_id'] = target
        full = len(select(report, SAMPLE, 'en-US', 200000).text.encode()) + 24
        checked = 0
        for budget in range(full, full - 2000, -10):
            selection = select(report, SAMPLE, 'en-US', budget)
            scripts = json.loads(selection.text)['scripts']
            if target in selection.evidence_ids or not scripts:
                continue
            self.assertEqual((scripts[0]['evidence_id'], scripts[0]['finding_ids']), (None, ['s1:persistence']))
            checked += 1
        self.assertGreater(checked, 0)

    def test_function_keys(self):
        keys = function_keys(support.report())
        self.assertIn(('x86_64', '0x100000200'), keys)
        self.assertIn(('arm64', '0x1000002c0'), keys)
        self.assertNotIn(('arm64', '0x100000999'), keys)

    def test_malformed_report_does_not_raise(self):
        selection = select({'findings': 'nope', 'evidence': [1, 2], 'functions': [None]}, SAMPLE, 'pt-BR', 40000)
        self.assertEqual(json.loads(selection.text)['findings'], [])




class YaraAndTermsTests(unittest.TestCase):
    def test_the_yara_result_and_rule_reach_the_ai(self):
        document = json.loads(select(support.report(), SAMPLE, 'pt-BR', 40000).text)
        yara = document['yara']
        self.assertEqual((yara['status'], yara['mode'], yara['sample_matched']), ('positive_only', 'hybrid', True))
        self.assertEqual((yara['clean_files_tested'], yara['clean_files_matched']), (0, 0))
        self.assertIn('rule machsentry_hybrid_test', yara['rule'])
        self.assertFalse(yara['rule_truncated'])

    def test_a_long_rule_is_clipped_and_dropped_before_the_budget_breaks(self):
        report = support.report()
        report['yara']['rule'] = 'rule r { strings: $a = "TEST" condition: $a }' + ' ' * 5000
        document = json.loads(select(report, SAMPLE, 'pt-BR', 40000).text)
        self.assertEqual(len(document['yara']['rule']), YARA_RULE_CHARS)
        self.assertTrue(document['yara']['rule_truncated'])
        tight = select(support.report(strings_per_finding=12, pseudocode_chars=6000), SAMPLE, 'pt-BR', 9000)
        if tight is not None:
            self.assertLessEqual(len(tight.text.encode()), 9000)

    def test_internal_terms_cover_keys_and_engine_values_but_not_sample_content(self):
        document = json.loads(select(support.report(), SAMPLE, 'pt-BR', 40000).text)
        terms = internal_terms(document)
        for term in ('positive_only', 'high_risk_indicators', 'unconfirmed', 'partial', 'analyzed', 'not_performed',
                     'unverified_candidate', 'credential_prompt', 'evidence_ids', 'analysis_status',
                     'functions_inspected', 'pseudocode_truncated'):
            self.assertIn(term, terms)
        # Strings, names and pseudocode come from the sample; the AI may quote them. YARA modes are
        # ordinary words ("as strings"), and so is the hyphenated method name.
        for term in ('_inert_reference_0', 'hybrid', 'strings', 'auto', 'machsentry-static-heuristic-v2'):
            self.assertNotIn(term, terms)

    def test_a_strings_mode_rule_keeps_the_glossary_word_free(self):
        report = support.report()
        report['yara']['effective_mode'] = 'strings'
        terms = internal_terms(json.loads(select(report, SAMPLE, 'pt-BR', 40000).text))
        self.assertNotIn('strings', terms)

    def test_the_rule_is_dropped_when_it_does_not_fit(self):
        report = support.report()
        report['yara']['rule'] = 'rule r { strings: $a = "TEST" condition: $a }' + ' ' * 1900
        selection = select(report, SAMPLE, 'pt-BR', 4000)
        self.assertIsNotNone(selection)
        document = json.loads(selection.text)
        self.assertEqual((document['yara']['rule'], document['yara']['rule_truncated']), (None, False))
        self.assertLessEqual(len(selection.text.encode()), 4000)

if __name__ == '__main__':
    unittest.main()
