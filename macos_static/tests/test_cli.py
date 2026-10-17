"""Public CLI workflow using inert, self-owned Mach-O fixtures."""

from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import yara
from facemessenger.cli import publish
from facemessenger.service import analyze
from facemessenger.source import AnalysisError, Limits, load_source


def fixture(suspicious=False):
    strings = ([b'osascript -e display dialog "Synthetic test" with hidden answer',
                b'security find-generic-password -ga "Synthetic test"', b'Login Data', b'/Cookies',
                b'/.electrum/wallets/', b'Exodus/exodus.wallet/',
                b'POST /synthetic-test HTTP/1.1\r\n', b'multipart/form-data',
                b'system_profiler SPHardwareDataType'] if suspicious else [b'Hello inert test fixture'])
    base, code_offset, text_offset = 0x100000000, 512, 1024
    body = b''
    code = b''
    for literal in strings:
        address = base + text_offset + len(body)
        site = base + code_offset + len(code)
        code += b'\x48\x8d\x05' + struct.pack('<i', address - (site + 7))
        body += literal + b'\0'
    code += b'\xc3'
    symoff = text_offset + len(body)
    symbol = struct.pack('<IBBHQ', 1, 0xF, 1, 0, base + code_offset)
    names = b'\0_inert_fixture\0'
    size = symoff + len(symbol) + len(names)
    section = lambda name, addr, length, offset, flags: struct.pack('<16s16sQQIIIIIIII', name, b'__TEXT', addr,
        length, offset, 0, 0, 0, flags, 0, 0, 0)
    segment = struct.pack('<II16sQQQQIIII', 0x19, 232, b'__TEXT', base, size, 0, size, 7, 5, 2, 0)
    segment += section(b'__text', base + code_offset, len(code), code_offset, 0x80000400)
    segment += section(b'__cstring', base + text_offset, len(body), text_offset, 2)
    symtab = struct.pack('<6I', 2, 24, symoff, 1, symoff + len(symbol), len(names))
    header = struct.pack('<8I', 0xFEEDFACF, 0x1000007, 3, 2, 2, len(segment + symtab), 0, 0)
    data = bytearray(size)
    data[:len(header + segment + symtab)] = header + segment + symtab
    data[code_offset:code_offset + len(code)] = code
    data[text_offset:text_offset + len(body)] = body
    data[symoff:] = symbol + names
    return bytes(data)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='unpack-cli-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.positive = self.root / 'synthetic.macho'
        self.negative = self.root / 'benign.macho'
        self.positive.write_bytes(fixture(True))
        self.negative.write_bytes(fixture(False))

    def run_cli(self, *arguments):
        result = subprocess.run([sys.executable, '-m', 'facemessenger', 'analyze', *map(str, arguments)],
                                capture_output=True, text=True, timeout=30)
        return result.returncode, json.loads(result.stdout)

    def test_complete_cli_report_has_source_linked_functions_and_verified_yara(self):
        output = self.root / 'result'
        code, envelope = self.run_cli(self.positive, '--output', output, '--benign-file', self.negative, '--json')
        self.assertEqual(code, 0, envelope)
        report = envelope['value']
        self.assertEqual(report['schema_version'], '1.0')
        self.assertEqual(report['artifact']['sha256'], sha256(fixture(True)).hexdigest())
        self.assertEqual(report['risk']['verdict'], 'likely_malicious')
        self.assertEqual(report['risk']['value'], 95)
        self.assertEqual(report['functions'][0]['address'], '0x100000200')
        self.assertEqual(len(report['functions']), 1)
        self.assertEqual(report['yara']['status'], 'validated_candidate')
        self.assertFalse(report['yara']['false_positive_guarantee'])
        compiled = yara.compile(filepath=str(output / 'detection.yar'))
        self.assertTrue(compiled.match(data=fixture(True)))
        self.assertFalse(compiled.match(data=fixture(False)))
        self.assertEqual(json.loads((output / 'report.json').read_text(encoding='utf-8')), report)
        self.assertFalse((output / '.report.json.pending').exists())
        for name, identity in report['exports'].items():
            self.assertEqual(sha256((output / name).read_bytes()).hexdigest(), identity['sha256'])
        known = {record['id'] for record in report['evidence']}
        for function in report['functions']:
            self.assertTrue(all(ref['evidence_id'] in known for ref in function['references']))
        self.assertEqual(self.positive.read_bytes(), fixture(True))

    def test_clean_fixture_is_inconclusive_without_inventing_yara(self):
        code, envelope = self.run_cli(self.negative, '--output', self.root / 'negative', '--json')
        self.assertEqual(code, 0)
        self.assertEqual(envelope['value']['risk']['verdict'], 'inconclusive')
        self.assertEqual(envelope['value']['yara']['status'], 'not_generated')

    def test_zip_cli_preserves_member_and_never_extracts_it(self):
        path = self.root / 'input.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('../external.macho', fixture(True))
        code, result = self.run_cli(path, '--member', '../external.macho', '--output', self.root / 'zip')
        self.assertEqual(code, 0)
        self.assertEqual(result['value']['artifact']['archive_member'], '../external.macho')
        self.assertEqual(result['value']['yara_status'], 'positive_only')
        self.assertFalse((self.root.parent / 'external.macho').exists())

    def test_invalid_input_and_existing_output_fail_closed(self):
        output = self.root / 'owned'
        output.mkdir()
        (output / 'sentinel').write_text('preserve')
        code, result = self.run_cli(self.positive, '--output', output)
        self.assertEqual((code, result['error']['code']), (2, 'output_exists'))
        self.assertEqual((output / 'sentinel').read_text(), 'preserve')
        self.negative.write_bytes(b'not a binary')
        code, result = self.run_cli(self.negative, '--output', self.root / 'invalid')
        self.assertEqual((code, result['error']['code']), (2, 'unsupported_format'))
        self.assertFalse((self.root / 'invalid').exists())

    def test_negative_match_rejects_rule_without_publishing_detection_file(self):
        output = self.root / 'collision'
        code, result = self.run_cli(self.positive, '--output', output, '--benign-file', self.positive, '--json')
        self.assertEqual(code, 0)
        self.assertEqual(result['value']['yara']['status'], 'rejected')
        self.assertFalse((output / 'detection.yar').exists())
        self.assertTrue((output / 'candidate-rejected.yar.txt').exists())

    def test_failed_final_publication_does_not_leave_a_completion_record(self):
        source = load_source(self.positive, Limits())
        report = analyze(source)
        output = self.root / 'interrupted'
        with patch.object(Path, 'rename', side_effect=OSError('synthetic publication fault')):
            with self.assertRaises(AnalysisError):
                publish(report, source.data, output)
        self.assertFalse((output / 'report.json').exists())
        self.assertTrue((output / '.report.json.pending').exists())


if __name__ == '__main__':
    unittest.main()
