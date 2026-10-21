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
            # Additional budget can replace many short strings with higher-priority code.
            # Compare inspected-code inclusion rather than treating every item as equal work.
            count = len(document['functions'])
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

    def test_empty_findings_keep_inventory_coverage_and_uncitable_context(self):
        report = support.report()
        report.update(findings=[], functions=[], scripts=[], ioc_candidates=[])
        report['evidence'] = [{'id': f's0:str:{index}', 'slice': 0, 'address': hex(0x100000000 + index),
                               'text': f'TEST DATA ONLY ordinary literal {index}'} for index in range(14227)]
        report['evidence'][13000]['text'] = 'NSPasteboard generalPasteboard stringForType:'
        report['coverage']['slices'] = [{'slice': 0, 'string_inventory_count': 15000, 'strings_retained': 14227,
                                        'candidate_functions': 0, 'functions_inspected': 0, 'functions_omitted': 0}]
        selection = select(report, SAMPLE, 'pt-BR', 12000)
        document = json.loads(selection.text)
        self.assertEqual(document['schema'], 'unpacked-analysis-ai-input/3')
        self.assertEqual(document['coverage']['strings'], {'provider_total': 15000, 'retained': 14227,
                         'citable_selected': 0, 'context_selected': 24, 'unlinked_retained': 14227,
                         'context_eligible': 14227})
        self.assertEqual(document['coverage']['functions'], {'provider_total': None, 'not_selected': None,
                                                            'attempted': None, 'inspection_failures': None,
                                                            'candidates': 0, 'inspected': 0, 'omitted': 0,
                                                           'retained': 0, 'selected': 0})
        self.assertEqual(selection.evidence_ids, frozenset())
        self.assertEqual(selection.finding_ids, frozenset())
        self.assertEqual(document['strings'], [])
        self.assertEqual(document['context_strings'][0]['inventory_ordinal'], 13000)
        self.assertIn('NSPasteboard', document['context_strings'][0]['text'])
        self.assertTrue(all('id' not in item and 'evidence_ids' not in item for item in document['context_strings']))
        self.assertLessEqual(len(selection.text.encode()), 12000)

    def test_context_selection_spreads_over_inventory_and_preserves_byte_budget(self):
        report = support.unlinked_script_and_ioc(support.report())
        report['evidence'] += [{'id': f's0:str:extra{index}', 'slice': 0, 'address': '0x100000900',
                                'text': ('TEST DATA ONLY 🕷️ ' * 40) + str(index)} for index in range(80)]
        for budget in (3000, 4000, 6000, 12000, 40000):
            with self.subTest(budget=budget):
                selection = select(report, SAMPLE, 'pt-BR', budget)
                if selection is None:
                    continue
                document = json.loads(selection.text)
                self.assertLessEqual(len(selection.text.encode()), budget)
                context = document['context_strings']
                self.assertEqual(document['coverage']['strings']['context_selected'], len(context))
                self.assertEqual(document['coverage']['strings']['citable_selected'], len(document['strings']))
                self.assertEqual(document['coverage']['functions']['selected'], len(document['functions']))
                self.assertLessEqual(len(context), 24)
                self.assertTrue(all(len(item['text']) <= STRING_CHARS for item in context))
                self.assertEqual(len({item['inventory_ordinal'] for item in context}), len(context))
        full = json.loads(select(report, SAMPLE, 'pt-BR', 40000).text)
        ordinals = {item['inventory_ordinal'] for item in full['context_strings']}
        self.assertIn(len(report['evidence']) - 1, ordinals)

    def test_unknown_producer_counts_stay_unknown(self):
        document = json.loads(select(support.report(), SAMPLE, 'en-US', 40000).text)
        self.assertIsNone(document['coverage']['strings']['provider_total'])
        self.assertIsNone(document['coverage']['functions']['candidates'])
        self.assertTrue(all(item['strings_provider_total'] is None for item in document['coverage']['slices']))

    def test_blank_heavy_inventory_keeps_unique_labels_and_imports_with_original_provenance(self):
        report = support.report()
        report.update(findings=[], functions=[], scripts=[], ioc_candidates=[])
        literals = ['' if index % 2 else ' \t ' for index in range(14000)]
        labels = ['ETH', '"ETH"', 'SUI', '"SUI"', 'BTC_BECH32', 'BTC_TAPROOT', 'DOGE_P2PKH', 'SOL']
        imports = ['_popen', '_fgets', '_fputs', '_usleep']
        literals += labels * 20 + imports * 5
        report['evidence'] = [{'id': f's0:str:{index}', 'slice': 0, 'address': hex(0x100000000 + index),
                               'text': text} for index, text in enumerate(literals)]
        count = len(literals)
        report['coverage']['slices'] = [{'slice': 0, 'string_inventory_count': count, 'strings_retained': count,
                                        'candidate_functions': 0, 'functions_inspected': 0, 'functions_omitted': 0}]
        before = json.dumps(report)
        selection = select(report, SAMPLE, 'pt-BR', 12000)
        document = json.loads(selection.text)
        coverage = document['coverage']['strings']
        self.assertEqual((coverage['provider_total'], coverage['retained'], coverage['unlinked_retained']),
                         (count, count, count))
        self.assertEqual(coverage['context_eligible'], len(labels) + len(imports))
        context = document['context_strings']
        self.assertEqual({item['text'] for item in context}, set(labels + imports))
        self.assertEqual(len(context), len(labels) + len(imports))
        for item in context:
            ordinal = literals.index(item['text'])
            self.assertEqual(item['inventory_ordinal'], ordinal)
            self.assertEqual(item['address'], report['evidence'][ordinal]['address'])
        self.assertTrue(set(imports) <= {item['text'] for item in context[:12]})
        self.assertEqual(document['omitted']['context_strings'], 0)
        self.assertEqual(json.dumps(report), before)
        self.assertEqual(selection.evidence_ids, frozenset())
        self.assertLessEqual(len(selection.text.encode()), 12000)

    def test_context_omissions_count_only_unique_nonblank_eligible_observations(self):
        report = support.report()
        report.update(findings=[], functions=[], scripts=[], ioc_candidates=[])
        literals = ['', '  ', 'same', 'same'] + [f'TEST DATA ONLY unique {index}' for index in range(40)]
        report['evidence'] = [None] + [{'id': f's0:str:{index}', 'slice': 0, 'address': hex(0x100000000 + index),
                                      'text': text} for index, text in enumerate(literals)]
        document = json.loads(select(report, SAMPLE, 'pt-BR', 40000).text)
        coverage = document['coverage']['strings']
        self.assertEqual(coverage['context_eligible'], 41)
        self.assertEqual(coverage['context_selected'], 24)
        self.assertEqual(document['omitted']['context_strings'], 17)
        same = next(item for item in document['context_strings'] if item['text'] == 'same')
        self.assertEqual(same['inventory_ordinal'], 3)

    def test_baseline_pseudocode_cannot_crowd_out_all_inventory_context(self):
        report = support.report(pseudocode_chars=6000)
        report.update(findings=[], scripts=[], ioc_candidates=[])
        for function in report['functions']:
            function['finding_ids'] = []
        report['evidence'][0]['text'] = 'TEST DATA ONLY NSPasteboard generalPasteboard'
        selection = select(report, SAMPLE, 'pt-BR', 12000)
        document = json.loads(selection.text)
        self.assertTrue(document['functions'])
        self.assertTrue(document['context_strings'])
        self.assertIn('NSPasteboard', document['context_strings'][0]['text'])
        self.assertEqual(selection.evidence_ids, frozenset())
        self.assertLessEqual(len(selection.text.encode()), 12000)




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


class CodeContextTests(unittest.TestCase):
    def selected_function(self, source, **metadata):
        report = support.report()
        function = report['functions'][0]
        function.update(pseudocode=source, finding_ids=[], **metadata)
        report.update(findings=[], evidence=[], functions=[function], scripts=[], ioc_candidates=[])
        before = json.dumps(report)
        selection = select(report, SAMPLE, 'pt-BR', 14000)
        self.assertIsNotNone(selection)
        self.assertLessEqual(len(selection.text.encode()), 14000)
        self.assertEqual(json.dumps(report), before)
        return json.loads(selection.text)['functions'][0]

    def test_late_clipboard_and_dynamic_calls_reach_the_ai_with_exact_offsets(self):
        source = ('int main(void) { /* TEST DATA */\n' + 'x' * 6500 +
                  '\nvalue = pbpaste(); handle = dlopen("TEST LIBRARY", 0);\n' + 'y' * 6500 +
                  '\n/* TEST DATA */ pbcopy(value); return 0; }')
        selected = self.selected_function(source)
        self.assertNotIn('pbpaste', selected['pseudocode'])
        excerpts = selected['pseudocode_excerpts']
        self.assertTrue(any('pbpaste' in item['text'] for item in excerpts))
        self.assertTrue(any('dlopen' in item['text'] for item in excerpts))
        self.assertTrue(any('pbcopy' in item['text'] for item in excerpts))
        self.assertTrue(selected['pseudocode_truncated'])
        self.assertEqual(selected['pseudocode_character_count'], len(source))
        previous = len(selected['pseudocode'])
        retained = len(selected['pseudocode'])
        for item in excerpts:
            self.assertGreaterEqual(item['start_character'], previous)
            self.assertEqual(item['text'], source[item['start_character']:item['end_character']])
            previous = item['end_character']
            retained += len(item['text'])
        self.assertLessEqual(retained, PSEUDOCODE_CHARS)

    def test_unicode_text_preserves_the_signal_location(self):
        source = '/* ' + '\u0130' * 6000 + ' */\nNSPasteboard_generalPasteboard();\n' + 'z' * 6000
        selected = self.selected_function(source)
        excerpt = next(item for item in selected['pseudocode_excerpts'] if 'NSPasteboard' in item['text'])
        self.assertLessEqual(excerpt['start_character'], source.index('NSPasteboard'))
        self.assertGreater(excerpt['end_character'], source.index('NSPasteboard'))
        self.assertEqual(excerpt['text'], source[excerpt['start_character']:excerpt['end_character']])

    def test_long_code_without_named_apis_keeps_the_ending_and_marks_omissions(self):
        source = 'int main(void) {\n' + 'x' * 8000 + '\nreturn 4242; }'
        selected = self.selected_function(source)
        self.assertTrue(selected['pseudocode_truncated'])
        self.assertIn('return 4242;', selected['pseudocode_excerpts'][-1]['text'])
        self.assertLess(sum(len(item['text']) for item in selected['pseudocode_excerpts']) +
                        len(selected['pseudocode']), len(source))

    def test_short_code_stays_complete_and_missing_call_coverage_stays_unknown(self):
        source = 'int main(void) { return 0; }'
        selected = self.selected_function(source)
        self.assertEqual(selected['pseudocode'], source)
        self.assertEqual(selected['pseudocode_excerpts'], [])
        self.assertFalse(selected['pseudocode_truncated'])
        self.assertIsNone(selected['callees_omitted'])
        self.assertIsNone(selected['unresolved_call_count'])

    def test_review_call_targets_keep_a_slot_with_bounded_callee_context(self):
        calls = [{'address': hex(0x100001000 + index), 'name': f'context_{index}'} for index in range(40)]
        calls += [{'address': 'EXTERNAL:0x10', 'name': '_dlopen'}, {'address': 'EXTERNAL:0x20', 'name': '_dlsym'}]
        calls += [{'address': f'EXTERNAL:0x{index}', 'name': name}
                  for index, name in enumerate(('_system', '_send', '_strcmp'), 30)]
        selected = self.selected_function('int main(void) { return 0; }', direct_calls=calls,
                                          unresolved_calls=[{'address': '0x100000240'}])
        self.assertEqual(len(selected['callees']), 16)
        self.assertEqual(selected['callees_omitted'], 29)
        self.assertEqual(selected['unresolved_call_count'], 1)
        self.assertEqual({item['name'] for item in selected['callees'][:5]},
                         {'_dlopen', '_dlsym', '_system', '_send', '_strcmp'})

    def test_unresolved_calls_stay_observed_when_resolved_call_coverage_is_unknown(self):
        selected = self.selected_function('int main(void) { return 0; }', direct_calls=None,
                                          unresolved_calls=[{'address': '0x100000240'}])
        self.assertIsNone(selected['callees_omitted'])
        self.assertEqual(selected['unresolved_call_count'], 1)


if __name__ == '__main__':
    unittest.main()
