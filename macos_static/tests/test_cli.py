"""Public report boundary against contract-shaped REA; real Ghidra runs are separate."""

from contextlib import redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import yara

from machsentry.cli import main, publish
from machsentry.service import analyze
from machsentry.source import AnalysisError, Limits, load_source
from fake_rea import FakeRea, FakeFatRea
from fixtures import fixture


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='machsentry-cli-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.positive = self.root / 'synthetic.macho'
        self.negative = self.root / 'benign.macho'
        self.positive.write_bytes(fixture(True))
        self.negative.write_bytes(fixture(False))
        self.client = FakeRea()

    def run_cli(self, *arguments):
        output = StringIO()
        with patch('machsentry.rea_workflow.make_client', return_value=self.client), redirect_stdout(output):
            code = main(['analyze', *map(str, arguments)])
        return code, json.loads(output.getvalue())

    def test_report_contains_real_contract_evidence_and_provider_pseudocode(self):
        output = self.root / 'result'
        code, envelope = self.run_cli(self.positive, '--output', output, '--benign-file', self.negative, '--json')
        self.assertEqual(code, 0, envelope)
        report = envelope['value']
        self.assertEqual(report['schema_version'], '2.1')
        self.assertEqual(report['risk']['value'], 95)
        self.assertEqual(report['risk']['verdict'], 'high_risk_indicators')
        self.assertEqual(report['risk']['maliciousness'], 'unconfirmed')
        self.assertEqual(report['functions'][0]['address'], '0x100000200')
        self.assertIn('TEST DOUBLE', report['functions'][0]['pseudocode'])
        self.assertEqual(report['engine']['analysis_engine'], 'REA')
        self.assertEqual(report['yara']['status'], 'validated_candidate')
        self.assertFalse(report['yara']['false_positive_guarantee'])
        compiled = yara.compile(filepath=str(output / 'detection.yar'))
        self.assertTrue(compiled.match(data=fixture(True)))
        self.assertFalse(compiled.match(data=fixture(False)))
        self.assertTrue((output / 'function-000-x86_64.pseudo.c.txt').exists())
        self.assertTrue((output / 'rea-evidence-000.json').exists())
        for name, identity in report['exports'].items():
            self.assertEqual(sha256((output / name).read_bytes()).hexdigest(), identity['sha256'])
        records = {record['evidence_id'] for record in report['rea']['records']}
        self.assertIn(report['functions'][0]['rea_evidence_id'], records)
        self.assertEqual(self.positive.read_bytes(), fixture(True))
        self.assertTrue(self.client.exited)
        self.assertFalse(self.client.opened)
        self.assertTrue(any(name == 'open_binary' and params['provider_id'] == 'ghidra' for name, params in self.client.calls))

    def test_no_indicators_is_inconclusive_with_no_invented_yara(self):
        code, envelope = self.run_cli(self.negative, '--output', self.root / 'negative', '--json')
        self.assertEqual(code, 0, envelope)
        self.assertEqual(envelope['value']['risk']['verdict'], 'inconclusive')
        self.assertEqual(envelope['value']['yara']['status'], 'not_generated')

    def test_fat_unknown_node_architecture_is_resolved_from_rea_thin_header(self):
        self.client = FakeFatRea()
        self.positive.write_bytes(self.client.container)
        code, envelope = self.run_cli(self.positive, '--output', self.root / 'fat', '--json')
        self.assertEqual(code, 0, envelope)
        report = envelope['value']
        self.assertEqual([item['architecture'] for item in report['slices']], ['x86_64', 'x86_64'])
        self.assertTrue(all(item['header_observation']['architecture'] == 'x86_64' for item in report['slices']))
        self.assertEqual(report['functions'][0]['file_offset'], 4 + 512)
        self.assertFalse(self.client.output_root.exists())
        self.assertTrue(all(item['confirmed'] for item in report['rea']['staging_cleanup']))

    def test_zip_selection_stages_owned_path_and_removes_it_after_provider_close(self):
        path = self.root / 'input.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('../external.macho', fixture(True))
        code, result = self.run_cli(path, '--member', '../external.macho', '--output', self.root / 'zip', '--json')
        self.assertEqual(code, 0, result)
        self.assertEqual(result['value']['artifact']['archive_member'], '../external.macho')
        self.assertFalse(self.client.path.exists())
        self.assertFalse((self.root.parent / 'external.macho').exists())
        self.assertTrue(all(item['confirmed'] for item in result['value']['rea']['staging_cleanup']))

    def test_failure_retains_evidence_and_never_falls_back_to_independent_analysis(self):
        self.client = FakeRea(fail_operation='list_strings')
        code, result = self.run_cli(self.positive, '--output', self.root / 'failed', '--json')
        self.assertEqual(code, 2, result)
        self.assertFalse(result['ok'])
        self.assertEqual(result['partial_report']['risk']['verdict'], 'inconclusive')
        self.assertEqual(result['partial_report']['functions'], [])
        self.assertEqual(result['partial_report']['slices'][0]['status'], 'failed')
        self.assertFalse(self.client.opened)

    def test_source_identity_mismatch_fails_before_any_provider_analysis(self):
        self.client = FakeRea(mismatch_digest=True)
        code, result = self.run_cli(self.positive, '--output', self.root / 'changed')
        self.assertEqual(code, 2)
        self.assertEqual(result['error']['code'], 'source_changed')
        self.assertFalse(any(name == 'list_strings' for name, _ in self.client.calls))

    def test_lost_open_response_still_closes_remote_acquisition(self):
        class LostOpenResponse(FakeRea):
            async def call_tool(self, operation, parameters):
                response = await super().call_tool(operation, parameters)
                if operation == 'open_binary':
                    raise ConnectionError('Open reply lost after server acquisition')
                return response
        self.client = LostOpenResponse()
        code, result = self.run_cli(self.positive, '--output', self.root / 'lost-open', '--json')
        self.assertEqual(code, 2)
        self.assertIsNone(result['partial_report']['risk']['value'])
        self.assertEqual(result['partial_report']['risk']['maliciousness'], 'not_assessed')
        self.assertFalse(self.client.opened)
        self.assertTrue(any(name == 'close_binary' for name, _ in self.client.calls))
        self.assertTrue(result['partial_report']['rea']['closure_confirmed'])

    def test_failed_close_retains_owner_and_retries_before_transport_shutdown(self):
        self.client = FakeRea(fail_close_count=1)
        code, result = self.run_cli(self.positive, '--output', self.root / 'close', '--json')
        self.assertEqual(code, 2)
        self.assertEqual(len([name for name, _ in self.client.calls if name == 'close_binary']), 2)
        self.assertTrue(result['partial_report']['rea']['closure_confirmed'])
        self.assertFalse(self.client.opened)

    def test_persistent_cleanup_failure_cannot_be_success(self):
        self.client = FakeRea(fail_operation='close_binary')
        code, result = self.run_cli(self.positive, '--output', self.root / 'unclosed', '--json')
        self.assertEqual(code, 2)
        self.assertFalse(result['partial_report']['rea']['closure_confirmed'])

    def test_existing_outputs_are_never_overwritten(self):
        output = self.root / 'owned'
        output.mkdir()
        (output / 'sentinel').write_text('preserve')
        code, result = self.run_cli(self.positive, '--output', output)
        self.assertEqual((code, result['error']['code']), (2, 'output_exists'))
        self.assertEqual((output / 'sentinel').read_text(), 'preserve')
        self.assertFalse(self.client.calls)

    def test_negative_match_rejects_detection_export(self):
        output = self.root / 'collision'
        code, result = self.run_cli(self.positive, '--output', output, '--benign-file', self.positive, '--json')
        self.assertEqual(code, 0)
        self.assertEqual(result['value']['yara']['status'], 'rejected')
        self.assertFalse((output / 'detection.yar').exists())
        self.assertTrue((output / 'candidate-rejected.yar.txt').exists())

    def test_atomic_completion_record_is_absent_after_failed_publication(self):
        source = load_source(self.positive, Limits())
        with patch('machsentry.rea_workflow.make_client', return_value=self.client):
            report = analyze(source)
        output = self.root / 'interrupted'
        with patch.object(Path, 'rename', side_effect=OSError('synthetic publication fault')):
            with self.assertRaises(AnalysisError):
                publish(report, source.data, output)
        self.assertFalse((output / 'report.json').exists())
        self.assertTrue((output / '.report.json.pending').exists())


if __name__ == '__main__':
    unittest.main()
