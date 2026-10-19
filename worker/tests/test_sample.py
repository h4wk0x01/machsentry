"""Header admission mirrors Unpacked inspectMachO; downloads are capped and verified."""

from hashlib import sha256
from pathlib import Path
import struct
import tempfile
import unittest

import worker_support as support
from machsentry_worker.sample import (MAX_SAMPLE_BYTES, DownloadUnavailable, SampleRejected, download,
                                      inspect_file, inspect_macho)


def inspect(data: bytes, name='sample'):
    return inspect_macho(len(data), name, lambda offset, length: data[offset:offset + length])


class HeaderTests(unittest.TestCase):
    def rejected(self, data, code, name='sample'):
        with self.assertRaises(SampleRejected) as caught:
            inspect(data, name)
        self.assertEqual(caught.exception.code, code)

    def test_inert_fixtures_are_accepted(self):
        self.assertEqual(inspect(support.fixtures.multi_function_fixture('x86_64')), ['x86_64'])
        self.assertEqual(inspect(support.fixtures.multi_function_fixture('arm64')), ['arm64'])
        self.assertEqual(inspect(support.fixtures.universal_fixture()), ['x86_64', 'arm64'])

    def test_fat64_and_duplicate_slices(self):
        x64 = support.thin_header(sizeofcmds=8)
        arm = support.thin_header(cpu=0x0100000C, subtype=0, sizeofcmds=8)
        self.assertEqual(inspect(support.fat([x64, arm], wide=True)), ['x86_64', 'arm64'])
        self.assertEqual(inspect(support.fat([x64, x64])), ['x86_64'])

    def test_big_endian_thin_header(self):
        self.assertEqual(inspect(support.thin_header(little=False)), ['x86_64'])

    def test_rejections_match_the_site(self):
        self.rejected(b'', 'invalid_format')
        self.rejected(support.thin_header(), 'invalid_format', name='sample.ZIP')
        self.rejected(b'\0' * 31, 'invalid_format')
        self.rejected(b'\x7fELF' + b'\0' * 60, 'invalid_format')
        self.rejected(struct.pack('<I', 0xFEEDFACE) + b'\0' * 60, 'invalid_format')
        self.rejected(support.thin_header(cpu=0x00000007), 'architecture')
        self.rejected(support.thin_header(sizeofcmds=64), 'invalid_format')
        self.rejected(support.fat([support.thin_header(cpu=12)]), 'architecture')

    def test_fat_layout_rejections(self):
        x64 = support.thin_header()
        self.rejected(struct.pack('>II', 0xCAFEBABE, 0) + bytes(60), 'invalid_format')
        self.rejected(struct.pack('>II', 0xCAFEBABE, 17) + bytes(4096), 'invalid_format')
        inside_header = bytearray(support.fat([x64]))
        struct.pack_into('>I', inside_header, 16, 16)
        self.rejected(bytes(inside_header), 'invalid_format')
        mismatched = bytearray(support.fat([x64]))
        struct.pack_into('>I', mismatched, 8, 0x0100000C)
        self.rejected(bytes(mismatched), 'invalid_format')
        truncated = support.fat([x64])
        self.rejected(truncated[:4096 + 16], 'invalid_format')

    def test_size_limit(self):
        with self.assertRaises(SampleRejected):
            inspect_macho(MAX_SAMPLE_BYTES + 1, 'sample', lambda offset, length: b'')

    def test_inspect_file_reads_only_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.macho'
            path.write_bytes(support.sample_bytes())
            self.assertEqual(inspect_file(path, 'uploaded'), ['x86_64', 'arm64'])


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.site = support.FakeSite()
        self.addCleanup(self.site.close)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = support.sample_bytes()
        self.target = Path(self.temp.name) / 'sample.macho'

    def serve(self, status=200, data=None):
        payload = self.data if data is None else data

        def dispatch(handler, _):
            self.site.reply(handler, status, raw=payload)
        self.site.dispatch = dispatch
        return self.site.url + '/sealed/job/sample?X-Amz-Signature=test'

    def test_verified_download(self):
        download(self.serve(), self.target, len(self.data), sha256(self.data).hexdigest())
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_size_mismatch_is_rejected_before_writing_past_the_claim(self):
        url = self.serve(data=self.data + b'extra')
        with self.assertRaises(SampleRejected) as caught:
            download(url, self.target, len(self.data), sha256(self.data).hexdigest())
        self.assertEqual(caught.exception.code, 'digest_mismatch')
        self.assertLessEqual(self.target.stat().st_size, len(self.data))

    def test_short_body_and_hash_mismatch(self):
        with self.assertRaises(SampleRejected):
            download(self.serve(data=self.data[:-1]), self.target, len(self.data), sha256(self.data).hexdigest())
        self.target.unlink()
        with self.assertRaises(SampleRejected) as caught:
            download(self.serve(), self.target, len(self.data), '0' * 64)
        self.assertEqual(caught.exception.code, 'digest_mismatch')

    def test_claim_size_above_cap(self):
        with self.assertRaises(SampleRejected):
            download(self.serve(), self.target, MAX_SAMPLE_BYTES + 1, '0' * 64)

    def test_expired_url_and_server_error(self):
        with self.assertRaises(SampleRejected) as caught:
            download(self.serve(status=403, data=b''), self.target, len(self.data), '0' * 64)
        self.assertEqual(caught.exception.code, 'upload_missing')
        with self.assertRaises(DownloadUnavailable):
            download(self.serve(status=503, data=b''), Path(self.temp.name) / 'other', len(self.data), '0' * 64)

    def test_plain_http_is_refused_off_loopback(self):
        with self.assertRaises(SampleRejected):
            download('http://example.invalid/sample', self.target, len(self.data), '0' * 64)


if __name__ == '__main__':
    unittest.main()
