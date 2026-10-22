"""Code inspection stays independent of the risk rules; fixtures are inert."""

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from machsentry.behavior import find_behaviors, risk_score
from machsentry.rea_client import ReaOptions
from machsentry.service import analyze
from machsentry.source import Limits, load_source
from fake_rea import FakeRea
from fixtures import fixture


def records(*texts):
    return [{'id': f's0:str:{index}', 'slice': 0, 'text': text} for index, text in enumerate(texts)]


class DataReferenceRea(FakeRea):
    """Model string -> data slot -> instruction using public provider Evidence."""
    async def call_tool(self, operation, parameters):
        data_address = hex(self.base + 800)
        if operation == 'xrefs':
            self.calls.append((operation, parameters))
            result = ([hex(self.base + 512)] if parameters['address'] == data_address else [data_address])
        elif operation == 'resolve_containing_procedure' and parameters['address'] == data_address:
            self.calls.append((operation, parameters))
            result = {'found': False, 'query_address': data_address, 'procedure': None}
        else:
            return await super().call_tool(operation, parameters)
        return SimpleNamespace(is_error=False, structured_content=self.evidence(operation, parameters, result), content=[])


class RosterRea(FakeRea):
    """Several provider candidates, including an entry outside the string references."""
    function_count = 10
    entry_index = 9

    def procedure_at(self, address):
        return {**self.procedure, 'address': address,
                'name': '_main' if address == hex(self.base + 512 + self.entry_index * 16) else '_context',
                'body': {'available': False, 'ranges': []}}

    def inventory_rows(self):
        return [{'address': hex(self.base + 512 + index * 16),
                 'value': '_main' if index == self.entry_index else '_context'} for index in range(self.function_count)]

    def dossier_at(self, address):
        return {'procedure': self.procedure_at(address),
                'pseudocode': '/* TEST DOUBLE */ void f(void) { return; }',
                'assembly': [], 'callees': [], 'limitations': ['TEST DOUBLE'], 'facet_availability': {}}

    async def call_tool(self, operation, parameters):
        if operation == 'analyze_function' and self.fail_operation == operation:
            return await super().call_tool(operation, parameters)
        if operation == 'list_procedures':
            result = self.inventory_rows()
        elif operation == 'xrefs':
            result = [hex(self.base + 512 + index * 16) for index in range(8)]
        elif operation == 'resolve_containing_procedure':
            result = {'found': True, 'query_address': parameters['address'],
                      'procedure': self.procedure_at(parameters['address'])}
        elif operation == 'analyze_function':
            result = self.dossier_at(parameters['procedure'])
        else:
            return await super().call_tool(operation, parameters)
        self.calls.append((operation, parameters))
        return SimpleNamespace(is_error=False, structured_content=self.evidence(operation, parameters, result), content=[])


class DynamicCallerRea(RosterRea):
    def inventory_rows(self):
        return super().inventory_rows() + [
            {'address': 'EXTERNAL:0x10', 'value': '_dlopen',
             'procedure': {'external': True, 'thunk': False, 'thunk_target': None}},
            {'address': 'EXTERNAL:0x20', 'value': '_dlsym',
             'procedure': {'external': True, 'thunk': False, 'thunk_target': None}},
        ]

    async def call_tool(self, operation, parameters):
        if operation == 'procedure_callers':
            self.calls.append((operation, parameters))
            result = [hex(self.base + 512 + 8 * 16)]
            return SimpleNamespace(is_error=False, structured_content=self.evidence(operation, parameters, result), content=[])
        return await super().call_tool(operation, parameters)


class WideRosterRea(RosterRea):
    function_count = 80
    entry_index = 79


class GraphRosterRea(RosterRea):
    function_count = 20
    entry_index = 19

    def dossier_at(self, address):
        dossier = super().dossier_at(address)
        index = (int(address, 16) - self.base - 512) // 16
        if index:
            dossier['callees'] = [self.procedure_at(hex(self.base + 512 + (index - 1) * 16))]
        if index < self.function_count - 1:
            dossier['callers'] = [self.procedure_at(hex(self.base + 512 + (index + 1) * 16))]
        return dossier


class DiverseApiRea(RosterRea):
    function_count = 30
    entry_index = 29
    api_names = ('dlopen', 'dlsym', 'objc_getClass', 'sel_registerName', 'NSClassFromString',
                 'NSSelectorFromString', 'popen', 'system', 'connect', 'socket',
                 'SecItemCopyMatching', 'fopen')
    caller_indices = (20, 20, 20, 20, 20, 20, 21, 21, 22, 22, 23, 24)

    def inventory_rows(self):
        return super().inventory_rows() + [
            {'address': f'EXTERNAL:0x{index + 1:x}', 'value': '_' + name,
             'procedure': {'external': True, 'thunk': False, 'thunk_target': None}}
            for index, name in enumerate(self.api_names)]

    async def call_tool(self, operation, parameters):
        if operation == 'procedure_callers':
            self.calls.append((operation, parameters))
            index = int(parameters['procedure'].split(':')[1], 16) - 1
            result = [hex(self.base + 512 + self.caller_indices[index] * 16)]
            return SimpleNamespace(is_error=False, structured_content=self.evidence(operation, parameters, result), content=[])
        return await super().call_tool(operation, parameters)


class CodeSelectionTests(unittest.TestCase):
    def analyze_fixture(self, client, data=None, limits=Limits(), options=ReaOptions()):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'inert.macho'
            path.write_bytes(data or fixture(False))
            with patch('machsentry.rea_workflow.make_client', return_value=client):
                report = analyze(load_source(path, limits), limits=limits, rea_options=options)
            self.assertTrue(client.exited)
            self.assertFalse(client.opened)
            self.assertTrue(report['rea']['closure_confirmed'])
            return report

    def test_zero_rule_matches_still_inspects_provider_code(self):
        report = self.analyze_fixture(FakeRea())
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['risk']['value'], 0)
        self.assertEqual(len(report['functions']), 1)
        self.assertIn('TEST DOUBLE', report['functions'][0]['pseudocode'])
        self.assertEqual(report['functions'][0]['classification'], 'review_context')
        self.assertIn('baseline_code_review', report['functions'][0]['selection_reasons'])
        self.assertEqual(report['coverage']['slices'][0]['procedure_inventory_count'], 1)
        self.assertEqual(report['yara']['status'], 'not_generated')

    def test_clipboard_manager_capabilities_add_no_risk_or_signature(self):
        texts = ('NSPasteboard generalPasteboard stringForType:', 'setString:forType: changeCount')
        findings = find_behaviors(records(*texts), [0])
        self.assertEqual([finding['category'] for finding in findings], ['clipboard_access'])
        self.assertEqual(risk_score(findings, True)['contributions'], {})
        self.assertEqual(risk_score(findings, True)['value'], 0)

    def test_wallet_formats_and_process_api_trigger_review_with_zero_risk(self):
        findings = find_behaviors(records('BTC_BECH32', 'BTC_TAPROOT', '_popen'), [0])
        self.assertEqual({f['category'] for f in findings}, {'wallet_address_processing', 'process_execution'})
        self.assertTrue(all(f['weight'] == 0 for f in findings))
        self.assertEqual(risk_score(findings, True)['verdict'], 'inconclusive')

    def test_dynamic_loading_and_environment_queries_are_neutral_review_capabilities(self):
        findings = find_behaviors(records('_dlopen', '_dlsym', '_proc_pidpath', '_mach_absolute_time'), [0])
        self.assertEqual({f['category'] for f in findings}, {'dynamic_api_resolution', 'analysis_environment_checks'})
        self.assertTrue(all(f['weight'] == 0 for f in findings))
        self.assertEqual(risk_score(findings, True)['contributions'], {})

    def test_dynamic_api_callers_reach_code_review_without_plaintext_clipboard_strings(self):
        client = DynamicCallerRea()
        report = self.analyze_fixture(client, options=ReaOptions(max_decompiled_functions=2))
        self.assertEqual(report['findings'], [])
        function = next(f for f in report['functions'] if f['address'] == hex(client.base + 512 + 8 * 16))
        self.assertEqual(function['selection_reasons'], ['sensitive_api_caller'])
        self.assertTrue(function['pseudocode'])
        self.assertEqual(report['coverage']['slices'][0]['functions_attempted'], 2)
        self.assertEqual(report['risk']['value'], 0)

    def test_selector_data_reference_retains_both_provider_edges(self):
        literal = b'NSPasteboard'
        data = fixture(False).replace(b'Hello inert test fixture', literal + b' ' * (24 - len(literal)))
        client = DataReferenceRea(literals=[literal])
        report = self.analyze_fixture(client, data)
        finding = report['findings'][0]
        self.assertEqual(finding['category'], 'clipboard_access')
        self.assertEqual(finding['function_addresses'], ['0x100000200'])
        reference = report['functions'][0]['references'][0]
        self.assertEqual(len(reference['reference_path']), 2)
        self.assertEqual(reference['kind'], 'provider_static_reference')
        retained = {record['evidence_id'] for record in report['rea']['records']}
        self.assertTrue(all(edge['xref_evidence_id'] in retained for edge in reference['reference_path']))
        self.assertEqual(report['risk']['value'], 0)

    def test_data_reference_walk_honors_shared_reference_budget(self):
        literal = b'NSPasteboard'
        data = fixture(False).replace(b'Hello inert test fixture', literal + b' ' * (24 - len(literal)))
        report = self.analyze_fixture(DataReferenceRea(literals=[literal]), data, Limits(max_references=1))
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['references_examined'], 1)
        self.assertTrue(coverage['reference_budget_exhausted'])
        self.assertEqual(report['findings'][0]['function_addresses'], [])
        self.assertEqual(report['risk']['value'], 0)

    def test_missing_procedure_inventory_is_visible_in_retained_failures(self):
        report = self.analyze_fixture(FakeRea(fail_operation='list_procedures'))
        self.assertEqual(report['functions'], [])
        self.assertIsNone(report['risk']['value'])
        self.assertFalse(report['risk']['assessment_available'])
        self.assertIsNone(report['coverage']['slices'][0]['procedure_inventory_count'])
        self.assertEqual(report['risk']['maliciousness'], 'not_assessed')
        self.assertTrue(any(e['operation'] == 'list_procedures' for e in report['rea']['errors']))

    def test_failed_decompilation_attempts_consume_the_function_budget(self):
        client = RosterRea(fail_operation='analyze_function')
        report = self.analyze_fixture(client, options=ReaOptions(max_decompiled_functions=2))
        self.assertEqual(sum(operation == 'analyze_function' for operation, _ in client.calls), 2)
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['functions_attempted'], 2)
        self.assertEqual(coverage['function_inspection_failures'], 2)
        self.assertEqual(coverage['functions_inspected'], 0)
        self.assertIsNone(report['risk']['value'])

    def test_entry_review_keeps_a_slot_when_string_candidates_fill_the_budget(self):
        literal = b'NSPasteboard'
        data = fixture(False).replace(b'Hello inert test fixture', literal + b' ' * (24 - len(literal)))
        report = self.analyze_fixture(RosterRea(literals=[literal]), data,
                                      options=ReaOptions(max_decompiled_functions=1))
        self.assertEqual(len(report['functions']), 1)
        self.assertEqual(report['functions'][0]['names'], ['_main'])
        self.assertEqual(report['functions'][0]['finding_ids'], [])
        self.assertEqual(report['coverage']['slices'][0]['functions_attempted'], 1)

    def test_no_known_strings_reviews_the_entire_roster_when_it_fits(self):
        client = RosterRea()
        client.function_count, client.entry_index = 13, 12
        report = self.analyze_fixture(client)
        self.assertEqual(report['findings'], [])
        self.assertEqual(len(report['functions']), 13)
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['procedure_inventory_count'], 13)
        self.assertEqual(coverage['functions_not_selected'], 0)
        self.assertEqual(coverage['functions_not_attempted'], 0)
        self.assertFalse(coverage['function_budget_exhausted'])
        self.assertEqual(report['risk']['value'], 0)
        self.assertEqual(report['yara']['status'], 'not_generated')

    def test_full_inventory_uses_64_attempts_and_exposes_remaining_unknown_functions(self):
        client = WideRosterRea()
        report = self.analyze_fixture(client)
        self.assertEqual(len(report['functions']), 64)
        self.assertEqual(report['functions'][0]['names'], ['_main'])
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['candidate_functions'], 80)
        self.assertEqual(coverage['functions_attempted'], 64)
        self.assertEqual(coverage['functions_not_selected'], 16)
        self.assertEqual(coverage['functions_not_attempted'], 16)
        self.assertEqual(coverage['functions_omitted'], 16)
        self.assertTrue(coverage['function_budget_exhausted'])
        self.assertTrue(report['risk']['coverage_limited'])

    def test_failed_full_inventory_attempts_do_not_expand_the_budget(self):
        client = WideRosterRea(fail_operation='analyze_function')
        report = self.analyze_fixture(client)
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['functions_attempted'], 64)
        self.assertEqual(coverage['function_inspection_failures'], 64)
        self.assertEqual(coverage['functions_not_selected'], 16)
        self.assertEqual(report['functions'], [])
        self.assertIsNone(report['risk']['value'])

    def test_observed_call_graph_promotes_neighbors_beyond_the_previous_eight_callees(self):
        client = GraphRosterRea()
        report = self.analyze_fixture(client, options=ReaOptions(max_decompiled_functions=16))
        self.assertEqual([f['address'] for f in report['functions']],
                         [hex(client.base + 512 + index * 16) for index in range(19, 3, -1)])
        self.assertTrue(all('provider_callee' in f['selection_reasons'] for f in report['functions'][1:]))
        self.assertEqual(len({f['address'] for f in report['functions']}), 16)
        retained = {record['evidence_id'] for record in report['rea']['records']}
        self.assertTrue(all(source['evidence_id'] in retained
                            for f in report['functions'] for source in f['selection_sources']))

    def test_api_queries_interleave_classes_and_share_the_existing_budget(self):
        client = DiverseApiRea()
        report = self.analyze_fixture(client, options=ReaOptions(max_decompiled_functions=4))
        queried = [parameters['procedure'] for operation, parameters in client.calls if operation == 'procedure_callers']
        queried_names = [client.api_names[int(address.split(':')[1], 16) - 1] for address in queried]
        self.assertEqual(queried_names, ['dlopen', 'popen', 'connect', 'SecItemCopyMatching'])
        self.assertEqual(len(report['functions']), 4)
        self.assertTrue(all('sensitive_api_caller' in f['selection_reasons'] for f in report['functions'][1:]))
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['api_caller_queries'], 4)
        self.assertEqual(coverage['api_caller_queries_omitted'], 8)
        self.assertEqual(coverage['functions_not_selected'], 26)
        self.assertEqual(report['risk']['value'], 0)

    def test_exhausted_reference_budget_still_allows_inventory_code_review(self):
        client = DiverseApiRea()
        report = self.analyze_fixture(client, limits=Limits(max_references=2),
                                      options=ReaOptions(max_decompiled_functions=4))
        coverage = report['coverage']['slices'][0]
        self.assertEqual(coverage['references_examined'], 2)
        self.assertTrue(coverage['reference_budget_exhausted'])
        self.assertEqual(coverage['api_caller_queries'], 2)
        self.assertEqual(coverage['functions_attempted'], 4)
        self.assertTrue(any(f['selection_reasons'] == ['baseline_code_review'] for f in report['functions']))


if __name__ == '__main__':
    unittest.main()
