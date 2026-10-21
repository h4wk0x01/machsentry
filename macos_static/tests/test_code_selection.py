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
    def procedure_at(self, address):
        return {**self.procedure, 'address': address,
                'name': '_main' if address == hex(self.base + 512 + 9 * 16) else '_context',
                'body': {'available': False, 'ranges': []}}

    def inventory_rows(self):
        return [{'address': hex(self.base + 512 + index * 16),
                 'value': '_main' if index == 9 else '_context'} for index in range(10)]

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
            result = {'procedure': self.procedure_at(parameters['procedure']),
                      'pseudocode': '/* TEST DOUBLE */ void f(void) { return; }',
                      'assembly': [], 'callees': [], 'limitations': ['TEST DOUBLE'], 'facet_availability': {}}
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


if __name__ == '__main__':
    unittest.main()
