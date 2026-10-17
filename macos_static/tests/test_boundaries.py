"""Synthetic hostile-input and evidence-attribution boundary regressions."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile

from machsentry.behavior import find_behaviors, risk_score
from machsentry.evidence import correlate, extract_strings
from machsentry.macho import Function, Image, Section, parse_images
from machsentry.source import AnalysisError, Limits, load_source


def thin_header(cpu=0x01000007, subtype=3, commands=0, command_bytes=0):
    return struct.pack("<8I", 0xFEEDFACF, cpu, subtype, 2, commands,
                       command_bytes, 0, 0)


def zip_bytes(entries, compression=zipfile.ZIP_STORED):
    output = BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            for name, contents in entries:
                archive.writestr(name, contents)
    return output.getvalue()


class BoundaryAssertions(unittest.TestCase):
    def assert_analysis_error(self, code, operation):
        with self.assertRaises(AnalysisError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        self.assertTrue(str(caught.exception))


class SourceAdmissionTests(BoundaryAssertions):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="unpack-boundary-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_source(self, data, name="sample.bin"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_plain_file_retains_exact_digest_and_selected_path(self):
        payload = thin_header()
        path = self.write_source(payload, "chosen Mach-O.bin")
        source = load_source(path, Limits())
        identity = source.identity()
        self.assertEqual(source.data, payload)
        self.assertEqual(identity["path"], str(path.absolute()))
        self.assertEqual(identity["sha256"], sha256(payload).hexdigest())
        self.assertEqual(identity["carrier_sha256"], identity["sha256"])
        self.assertEqual(identity["size_bytes"], len(payload))
        self.assertIsNone(identity["archive_member"])
        self.assertEqual(identity["offset_space"], "file")

    def test_oversized_carrier_is_rejected_before_parsing(self):
        path = self.write_source(b"x" * 33)
        self.assert_analysis_error(
            "resource_limit", lambda: load_source(path, Limits(max_file_bytes=32)))

    def test_compressed_member_cannot_expand_past_input_budget(self):
        archive = zip_bytes([("payload", b"x" * 8192)], zipfile.ZIP_DEFLATED)
        self.assertLess(len(archive), 1024)
        path = self.write_source(archive, "compressed.zip")
        self.assert_analysis_error(
            "resource_limit",
            lambda: load_source(path, Limits(max_file_bytes=1024), member="payload"))

    def test_duplicate_member_name_is_ambiguous_even_with_identical_bytes(self):
        payload = thin_header()
        path = self.write_source(zip_bytes([
            ("payload", payload), ("payload", payload), ("chosen", payload)
        ]), "duplicate.zip")
        self.assert_analysis_error(
            "invalid_input", lambda: load_source(path, Limits(), member="payload"))
        self.assertEqual(load_source(path, Limits(), member="chosen").data, payload)

    def test_zip_member_identity_is_preserved_without_disk_extraction(self):
        payload = thin_header() + b"synthetic evidence\0"
        member = "../escaped/payload.macho"
        carrier = zip_bytes([(member, payload), ("other", b"not selected")])
        path = self.write_source(carrier, "inbox/archive.zip")
        before = sorted(str(item.relative_to(self.root)) for item in self.root.rglob("*"))
        source = load_source(path, Limits(), member=member)
        after = sorted(str(item.relative_to(self.root)) for item in self.root.rglob("*"))
        identity = source.identity()
        self.assertEqual(source.data, payload)
        self.assertEqual(identity["path"], str(path.absolute()))
        self.assertEqual(identity["archive_member"], member)
        self.assertEqual(identity["offset_space"], "uncompressed-member")
        self.assertEqual(identity["sha256"], sha256(payload).hexdigest())
        self.assertEqual(identity["carrier_sha256"], sha256(carrier).hexdigest())
        self.assertNotEqual(identity["sha256"], identity["carrier_sha256"])
        self.assertEqual(before, after)
        self.assertFalse((self.root / "escaped").exists())

    def test_missing_directory_and_symlink_members_are_not_regular_inputs(self):
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        path = self.write_source(zip_bytes([
            ("folder/", b""), (symlink, b"target"), ("payload", thin_header())
        ]), "types.zip")
        for member in ("missing", "folder/", "link"):
            with self.subTest(member=member):
                self.assert_analysis_error(
                    "invalid_input", lambda: load_source(path, Limits(), member=member))


class MachoAdmissionTests(BoundaryAssertions):
    def test_recognized_but_truncated_headers_are_invalid(self):
        for data in (thin_header()[:4], thin_header()[:27], thin_header()[:31]):
            with self.subTest(length=len(data)):
                self.assert_analysis_error(
                    "invalid_macho", lambda: parse_images(data, Limits()))

    def test_load_commands_cannot_claim_missing_bytes(self):
        for data in (
            thin_header(commands=1, command_bytes=8),
            thin_header(commands=2, command_bytes=8) + struct.pack("<II", 0, 8),
            thin_header(commands=1, command_bytes=8) + struct.pack("<II", 0, 0),
        ):
            with self.subTest(data=data.hex()):
                self.assert_analysis_error(
                    "invalid_macho", lambda: parse_images(data, Limits()))

    def test_universal_slices_must_not_overlap(self):
        data = bytearray(144)
        struct.pack_into(">II", data, 0, 0xCAFEBABE, 2)
        struct.pack_into(">IIIII", data, 8, 0x01000007, 3, 64, 64, 4)
        struct.pack_into(">IIIII", data, 28, 0x01000007, 3, 80, 64, 4)
        data[64:96] = thin_header()
        data[80:112] = thin_header()
        self.assert_analysis_error(
            "invalid_macho", lambda: parse_images(bytes(data), Limits()))

    def test_universal_and_embedded_cpu_identity_must_agree(self):
        data = bytearray(64)
        struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
        struct.pack_into(">IIIII", data, 8, 0x0100000C, 0, 32, 32, 4)
        data[32:] = thin_header()
        self.assert_analysis_error(
            "invalid_macho", lambda: parse_images(bytes(data), Limits()))


class VerdictTests(unittest.TestCase):
    def test_no_indicators_never_certify_benign_even_with_full_coverage(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                score = risk_score([], coverage_limited=partial)
                self.assertEqual(score["value"], 0)
                self.assertEqual(score["verdict"], "inconclusive")
                self.assertFalse(score["calibrated_probability"])
                self.assertEqual(score["coverage_limited"], partial)

    def test_repeated_indicators_across_architectures_do_not_inflate_score(self):
        text = "display dialog \"Password\" default answer \"\" with hidden answer"
        strings = [
            {"id": "first", "slice": 0, "text": text},
            {"id": "copy", "slice": 1, "text": text},
        ]
        single = risk_score(find_behaviors(strings[:1], [0]), False)
        universal = risk_score(find_behaviors(strings, [0, 1]), False)
        self.assertGreater(single["value"], 0)
        self.assertEqual(single["value"], universal["value"])
        self.assertEqual(single["contributions"], universal["contributions"])
        self.assertEqual(single["verdict"], universal["verdict"])


class DirectReferenceTests(unittest.TestCase):
    def synthetic_image(self, code, architecture):
        text = b"synthetic indicator\0"
        string_offset = 64
        data = code + b"\0" * (string_offset - len(code)) + text
        function = Function(0x1000, 0x1000 + len(code), 0, ["fixture"], ["synthetic"])
        image = Image(0, architecture, 0, len(data), [
            Section("__TEXT,__text", 0x1000, 0, len(code), True),
            Section("__TEXT,__cstring", 0x2080, string_offset, len(text), False),
        ], [function], {"encrypted": False}, [])
        strings, coverage = extract_strings(data, [image], Limits())
        self.assertEqual(coverage["count"], 1)
        self.assertEqual(strings[0]["offset"], string_offset)
        self.assertEqual(strings[0]["address"], "0x2080")
        return data, image, function, strings

    def test_x86_rip_reference_preserves_instruction_and_string_coordinates(self):
        code = b"\x48\x8d\x3d" + struct.pack("<i", 0x2080 - (0x1000 + 7)) + b"\xc3"
        data, image, function, strings = self.synthetic_image(code, "x86_64")
        result = correlate(data, image, strings, Limits())
        self.assertEqual(result["references"], 1)
        reference = function.references[0]
        self.assertEqual(reference["evidence_id"], strings[0]["id"])
        self.assertEqual(reference["instruction_address"], "0x1000")
        self.assertEqual(reference["target_address"], "0x2080")
        self.assertEqual(reference["file_offset"], 0)
        self.assertEqual(reference["bytes"], code[:7].hex())
        self.assertEqual(reference["target_delta"], 0)

    def test_references_do_not_cross_universal_slice_identity(self):
        code = b"\x48\x8d\x3d" + struct.pack("<i", 0x2080 - (0x1000 + 7)) + b"\xc3"
        data, image, function, strings = self.synthetic_image(code, "x86_64")
        unrelated = [{**strings[0], "slice": 1, "id": "different-slice"}]
        result = correlate(data, image, unrelated, Limits())
        self.assertEqual(result["references"], 0)
        self.assertEqual(function.references, [])

    def test_arm64_adrp_add_resolves_a_direct_reference(self):
        # adrp x0, 0x2000; add x1, x0, #0x80; ret
        code = struct.pack("<III", 0xB0000000, 0x91020001, 0xD65F03C0)
        data, image, function, strings = self.synthetic_image(code, "arm64")
        result = correlate(data, image, strings, Limits())
        self.assertEqual(result["references"], 1)
        self.assertEqual(function.references[0]["instruction_address"], "0x1004")
        self.assertEqual(function.references[0]["target_address"], "0x2080")

    def test_arm64_address_base_is_invalidated_by_register_clobbers(self):
        # Writing W0 also overwrites X0; neither form can retain the ADRP base.
        for name, clobber in (("x0", 0xD2800000), ("w0", 0x52800000)):
            with self.subTest(register=name):
                code = struct.pack("<IIII", 0xB0000000, clobber, 0x91020001, 0xD65F03C0)
                data, image, function, strings = self.synthetic_image(code, "arm64")
                result = correlate(data, image, strings, Limits())
                self.assertEqual(result["references"], 0)
                self.assertEqual(function.references, [])

    def test_string_retention_limit_is_partial_not_a_clean_result(self):
        data, image, _, _ = self.synthetic_image(b"\xc3", "x86_64")
        strings, coverage = extract_strings(data, [image], replace(Limits(), max_strings=0))
        self.assertEqual(strings, [])
        self.assertEqual(coverage["status"], "partial")
        self.assertTrue(coverage["reason"])


if __name__ == "__main__":
    unittest.main()
