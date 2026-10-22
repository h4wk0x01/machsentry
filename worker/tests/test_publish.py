"""Artifacts: functions.json caps, stable descriptors, presigned PUTs with the signed checksum, repeatable send."""

from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

import worker_support as support
from machsentry_worker import publish
from machsentry_worker.publish import PublishError
from machsentry_worker.site_api import SiteApi


class FunctionsJsonTests(unittest.TestCase):
    def test_fields_and_per_function_cap(self):
        report = support.report(pseudocode_chars=70 * 1024)
        entries = json.loads(publish.functions_json(report))
        self.assertEqual(set(entries[0]), {'architecture', 'slice', 'address', 'names', 'findingIds', 'pseudocode',
                                           'pseudocodeTruncated', 'pseudocodeSha256', 'pseudocodeCharacters'})
        self.assertTrue(all(len(item['pseudocode'].encode()) <= 64 * 1024 for item in entries))
        self.assertTrue(all(item['pseudocodeTruncated'] for item in entries))
        for source, entry in zip(report['functions'], entries):
            self.assertEqual(entry['pseudocodeSha256'], sha256(source['pseudocode'].encode('utf-8')).hexdigest())
            self.assertEqual(entry['pseudocodeCharacters'], len(source['pseudocode']))

    def test_total_cap_lowers_the_per_function_cap(self):
        report = support.report(pseudocode_chars=70 * 1024)
        report['functions'] = report['functions'] * 10
        data = publish.functions_json(report)
        self.assertLessEqual(len(data), 4 * 1024 * 1024)
        entries = json.loads(data)
        self.assertTrue(all(len(item['pseudocode'].encode()) <= 32 * 1024 for item in entries))
        self.assertEqual(len(entries), len(report['functions']))
        for source, entry in zip(report['functions'], entries):
            self.assertEqual(entry['pseudocodeSha256'], sha256(source['pseudocode'].encode('utf-8')).hexdigest())
            self.assertEqual(entry['pseudocodeCharacters'], len(source['pseudocode']))

    def test_utf8_cut_keeps_valid_text(self):
        text, truncated = publish._clip_utf8('é' * 10, 5)
        self.assertEqual((text, truncated), ('éé', True))

    def test_unicode_prefix_keeps_the_digest_and_character_count_of_complete_code(self):
        prefix = 'é' * (64 * 1024 // 2 - 1)
        sources = [prefix + '🙂END_OF_SOURCE', prefix + '🙂DIFFERENT_END']
        report = support.report()
        report['functions'] = [dict(report['functions'][index], pseudocode=source)
                               for index, source in enumerate(sources)]
        entries = json.loads(publish.functions_json(report))
        for source, entry in zip(sources, entries):
            self.assertEqual(entry['pseudocode'], prefix)
            self.assertTrue(entry['pseudocodeTruncated'])
            self.assertEqual(entry['pseudocodeCharacters'], len(source))
            self.assertEqual(entry['pseudocodeSha256'], sha256(source.encode('utf-8')).hexdigest())
            self.assertNotEqual(entry['pseudocodeSha256'], sha256(prefix.encode('utf-8')).hexdigest())
        self.assertNotEqual(entries[0]['pseudocodeSha256'], entries[1]['pseudocodeSha256'])

    def test_missing_code_metadata_remains_unknown_and_empty_code_has_its_own_digest(self):
        report = support.report()
        report['functions'] = [dict(report['functions'][index], pseudocode=source)
                               for index, source in enumerate((None, 7, ''))]
        entries = json.loads(publish.functions_json(report))
        for entry in entries[:2]:
            self.assertIsNone(entry['pseudocode'])
            self.assertIsNone(entry['pseudocodeSha256'])
            self.assertIsNone(entry['pseudocodeCharacters'])
            self.assertFalse(entry['pseudocodeTruncated'])
        self.assertEqual(entries[2]['pseudocode'], '')
        self.assertEqual(entries[2]['pseudocodeSha256'], sha256(b'').hexdigest())
        self.assertEqual(entries[2]['pseudocodeCharacters'], 0)
        self.assertFalse(entries[2]['pseudocodeTruncated'])


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.results = Path(self.temp.name)
        self.site = support.FakeSite()
        self.addCleanup(self.site.close)
        self.site.respond('/jobs/:id/artifacts', self.site.upload_grant)
        self.site.respond('/jobs/:id/complete', (200, {'id': 'job_1', 'status': 'completed'}))
        self.api = SiteApi(self.site.url, support.TOKEN, timeout=5, sleep=lambda _: None)
        self.report = support.report()
        (self.results / 'report.json').write_text(json.dumps(self.report))
        (self.results / 'report-view.json').write_text('{"schema_version": "1.0"}')
        self.copied = {name: self.results / name for name in ('report.json', 'report-view.json')}
        self.service = publish.service_result('job_1', 1, publish.engine_identity(self.report, '1.0'),
                                              'sha256:' + 'a' * 64, 'abc1234', 'partial', 0, 'completed',
                                              {'elapsedSeconds': 1.0}, {'containerRemoved': True,
                                                                        'workdirRemoved': True, 'sampleDeleted': True})

    def prepare(self):
        return publish.prepare(self.results, self.copied, self.report, {'schema': 'unpacked-analysis-ai/1'},
                               self.service)

    def test_service_result_shape(self):
        self.assertEqual(self.service['schema'], 'unpacked-analysis-service/1')
        self.assertEqual(self.service['engine'], {'name': 'machsentry', 'version': '0.4.0', 'rulesetVersion': '2.0.0',
                                                  'provider': 'ghidra', 'reportSchema': '2.1', 'viewSchema': '1.0'})

    def test_descriptors_are_stable(self):
        first = self.prepare()
        self.assertEqual([item['name'] for item in first], ['service-result.json', 'report-view.json', 'functions.json',
                                                            'report.json', 'ai-assessment.json'])
        self.assertEqual(self.prepare(), first)
        for item in first:
            data = (self.results / item['name']).read_bytes()
            self.assertEqual((item['size'], item['sha256']), (len(data), sha256(data).hexdigest()))
        with self.assertRaises(PublishError):
            publish.prepare(self.results, self.copied, self.report, {'schema': 'changed'}, self.service)

    def test_upload_uses_the_signed_headers_and_is_repeatable(self):
        descriptors = self.prepare()
        for _ in range(2):
            publish.upload(self.api, 'job_1', 1, 'lease', self.results, descriptors, sleep=lambda _: None)
            self.api.complete('job_1', 1, 'lease', 'partial', 'completed', descriptors, {}, {})
        grants = self.site.calls('/jobs/:id/artifacts')
        self.assertEqual(grants[0], grants[1])
        self.assertEqual(grants[0]['artifacts'], descriptors)
        completes = self.site.calls('/jobs/:id/complete')
        self.assertEqual(completes[0], completes[1])
        for item in descriptors:
            stored = self.site.objects[item['name']]
            self.assertEqual(stored['data'], (self.results / item['name']).read_bytes())
            self.assertEqual(stored['headers']['x-amz-checksum-sha256'],
                             b64encode(bytes.fromhex(item['sha256'])).decode())

    def test_expired_put_gets_a_new_grant_once(self):
        descriptors = self.prepare()
        self.site.put_status = [403]
        publish.upload(self.api, 'job_1', 1, 'lease', self.results, descriptors, sleep=lambda _: None)
        grants = self.site.calls('/jobs/:id/artifacts')
        self.assertEqual(len(grants), 2)
        self.assertEqual(len(grants[1]['artifacts']), len(descriptors))
        self.site.put_status = [403, 403]
        with self.assertRaises(PublishError) as caught:
            publish.upload(self.api, 'job_1', 1, 'lease', self.results, descriptors, sleep=lambda _: None)
        self.assertEqual(caught.exception.code, 'upload_rejected_403')

    def test_grant_must_match_the_descriptors(self):
        descriptors = self.prepare()
        self.site.respond('/jobs/:id/artifacts', lambda body: (200, {'uploads': [
            {'name': item['name'], 'url': f'{self.site.url}/s3/{item["name"]}',
             'headers': {'x-amz-checksum-sha256': 'AAAA'}} for item in body['artifacts']]}))
        with self.assertRaises(PublishError) as caught:
            publish.upload(self.api, 'job_1', 1, 'lease', self.results, descriptors, sleep=lambda _: None)
        self.assertEqual(caught.exception.code, 'bad_upload_grant')
        self.assertFalse(self.site.objects)

    def test_size_caps(self):
        with self.assertRaises(PublishError):
            publish.write(self.results, 'ai-assessment.json', b'x' * (1024 * 1024 + 1))


if __name__ == '__main__':
    unittest.main()
