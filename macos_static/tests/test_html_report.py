"""Public exports, fixed dashboard contract and hostile sample-text rendering."""

from copy import deepcopy
from html.parser import HTMLParser
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

from machsentry.analyst_view import analyst_view
from machsentry.cli import publish
from machsentry.html_report import html_report
from machsentry.report_schema import SCHEMA, validate_view
from machsentry.service import analyze
from machsentry.source import Limits, load_source
from fake_rea import FakeRea
import test_cli


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class AnalystReportTests(unittest.TestCase):
    setUp = test_cli.CliTests.setUp
    run_cli = test_cli.CliTests.run_cli

    def test_public_cli_keeps_identical_sections_for_findings_empty_and_failure(self):
        expected = ['summary', 'identity', 'behaviors', 'functions', 'scripts', 'network', 'yara', 'coverage']
        Draft202012Validator.check_schema(SCHEMA)
        for case, path, failure in [('findings', self.positive, None), ('empty', self.negative, None),
                                    ('failure', self.positive, 'list_strings')]:
            with self.subTest(case=case):
                self.client = FakeRea(fail_operation=failure)
                destination = self.root / case
                code, envelope = self.run_cli(path, '--output', destination, '--json')
                self.assertEqual(code, 2 if failure else 0, envelope)
                view = json.loads((destination / 'report-view.json').read_text(encoding='utf-8'))
                schema = json.loads((destination / 'report-view.schema.json').read_text(encoding='utf-8'))
                Draft202012Validator(schema).validate(view)
                source = (destination / 'report.html').read_text(encoding='utf-8')
                page = Page(source)
                self.assertEqual([attrs['data-section'] for tag, attrs in page.tags if tag == 'section'], expected)
                self.assertEqual(view['section_order'], expected)
                self.assertEqual(envelope['outputs']['html'], str((destination / 'report.html').absolute()))
                self.assertNotIn('Ghidra', source)
                self.assertNotIn('pseudocódigo', source.lower())
                self.assertNotIn('medium_with_provider_code_references', source)
                if failure:
                    self.assertIsNone(view['assessment']['score'])
                    self.assertIsNone(view['detection']['download'])
                    self.assertIn('não avaliados', source)
                if case == 'empty':
                    self.assertEqual(view['assessment']['score'], 0)
                    self.assertEqual(view['detection']['status'], 'not_generated')

    def test_sample_markup_is_only_text_and_internal_paths_do_not_leak_into_view(self):
        source = load_source(self.positive, Limits())
        with patch('machsentry.rea_workflow.make_client', return_value=self.client):
            report = analyze(source)
        hostile = '<img src=x onerror=alert(1)><script>alert(2)</script><a href="https://ioc.invalid">x</a>'
        report['functions'][0]['names'] = [hostile]
        report['scripts'][0]['content'] = hostile
        report['evidence'][0]['text'] = hostile
        report['ioc_candidates'] = [{'kind': 'url', 'value': 'https://ioc.invalid/' + hostile,
                                     'evidence_id': report['evidence'][0]['id'], 'offset': 123}]
        report['artifact']['path'] = r'C:\private-worker\jobs\tenant-secret\sample.macho'
        destination = self.root / 'hostile'
        publish(report, source.data, destination)
        html = (destination / 'report.html').read_text(encoding='utf-8')
        view = json.loads((destination / 'report-view.json').read_text(encoding='utf-8'))
        self.assertEqual(view['scripts'][0]['content'], hostile)
        self.assertNotIn('tenant-secret', html)
        self.assertNotIn('tenant-secret', json.dumps(view))
        self.assertIn('&lt;script&gt;', html)
        tags = Page(html).tags
        self.assertFalse(any(tag in ('script', 'img', 'iframe', 'object', 'form') for tag, _ in tags))
        for tag, attrs in tags:
            self.assertFalse(any(name.startswith('on') for name in attrs))
            if 'href' in attrs:
                self.assertTrue(attrs['href'].startswith('#') or attrs['href'] == 'detection.yar')
        policies = [attrs['content'] for tag, attrs in tags if tag == 'meta' and attrs.get('http-equiv') == 'Content-Security-Policy']
        self.assertEqual(len(policies), 1)
        self.assertIn("default-src 'none'", policies[0])
        self.assertIn("style-src 'sha256-", policies[0])

    def test_rejected_or_unclosed_analysis_never_exposes_a_detection_download(self):
        class UnclosedAnalysis(FakeRea):
            deep = False

            async def call_tool(self, operation, parameters):
                if operation == 'open_binary':
                    self.deep = parameters.get('provider_id') == 'ghidra'
                if operation == 'close_binary' and self.deep:
                    self.fail_close_count = 1
                return await super().call_tool(operation, parameters)

        for failed_cleanup in (False, True):
            with self.subTest(cleanup=failed_cleanup):
                self.client = UnclosedAnalysis() if failed_cleanup else FakeRea()
                target = self.root / ('unclosed' if failed_cleanup else 'rejected')
                args = [] if failed_cleanup else ['--benign-file', self.positive]
                self.run_cli(self.positive, '--output', target, *args)
                view = json.loads((target / 'report-view.json').read_text(encoding='utf-8'))
                self.assertIsNone(view['detection']['download'])
                self.assertFalse((target / 'detection.yar').exists())
                self.assertTrue((target / 'candidate-rejected.yar.txt').exists())
                self.assertFalse(any(attrs.get('download') for _, attrs in Page(html_report(view)).tags))

    def test_selection_explanations_are_bound_to_emitted_string_symbols(self):
        code, envelope = self.run_cli(self.positive, '--output', self.root / 'selection', '--json')
        self.assertEqual(code, 0)
        report = envelope['value']
        view = analyst_view(report)
        selection = report['yara']['selection']['strings']
        self.assertEqual(len(selection), len(view['detection']['criteria']))
        for chosen, criterion in zip(selection, view['detection']['criteria']):
            self.assertEqual(chosen['symbol'], criterion['symbol'])
            self.assertEqual(chosen['literal'], criterion['value'])
            self.assertIn(chosen['symbol'] + ' = ', report['yara']['rule'])
            self.assertTrue(criterion['meaning'])
            self.assertTrue(criterion['selection_reason'])
        broken = deepcopy(view)
        del broken['assessment']['score']
        with self.assertRaises(ValidationError):
            validate_view(broken)
        broken = deepcopy(view)
        broken['detection']['download'] = 'https://ioc.invalid/'
        with self.assertRaises(ValidationError):
            html_report(broken)


if __name__ == '__main__':
    unittest.main()
