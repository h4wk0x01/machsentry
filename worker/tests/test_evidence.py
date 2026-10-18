"""AI input selection: byte budget, priorities, caps and no worker paths."""

import json
import unittest

import worker_support as support
from machsentry_worker.evidence import PSEUDOCODE_CHARS, STRING_CHARS, function_keys, select

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


if __name__ == '__main__':
    unittest.main()
