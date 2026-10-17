from hashlib import sha256
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from machsentry.rea_workflow import (
    _identity,
    _register_owned_directory,
    _register_owned_file,
    _remove_owned_directory,
    _remove_owned_files,
)


class OwnedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'extracted'
        self.root.mkdir()
        self.parent = self.root / 'slices'
        self.parent.mkdir()
        self.path = self.parent / 'arm64'
        self.path.write_bytes(b'owned inert fixture')
        self.record = _register_owned_file(
            self.root, self.path, sha256(self.path.read_bytes()).hexdigest())

    def test_removes_owned_file_and_empty_owned_directories(self):
        cleanup = []
        _remove_owned_files([self.record], cleanup)
        self.assertFalse(self.root.exists())
        self.assertTrue(all(item['confirmed'] for item in cleanup))
        self.assertTrue(self.base.exists())

    def test_retains_same_bytes_in_replaced_file(self):
        original = self.parent / 'original'
        self.path.rename(original)
        self.path.write_bytes(original.read_bytes())
        cleanup = []
        _remove_owned_files([self.record], cleanup)
        self.assertTrue(self.path.exists())
        self.assertTrue(original.exists())
        self.assertFalse(cleanup[0]['confirmed'])
        self.assertIn('identity changed', cleanup[0]['reason'])

    def test_retains_replaced_root_and_all_descendants(self):
        self.root.rename(self.base / 'original-root')
        self.parent.mkdir(parents=True)
        self.path.write_bytes(b'owned inert fixture')
        cleanup = []
        _remove_owned_files([self.record], cleanup)
        self.assertTrue(self.path.exists())
        self.assertFalse(cleanup[0]['confirmed'])
        self.assertIn('directory identity changed', cleanup[0]['reason'])

    def test_retains_replaced_intermediate_directory(self):
        self.parent.rename(self.root / 'original-slices')
        self.parent.mkdir()
        self.path.write_bytes(b'owned inert fixture')
        cleanup = []
        _remove_owned_files([self.record], cleanup)
        self.assertTrue(self.path.exists())
        self.assertFalse(cleanup[0]['confirmed'])

    def test_retains_changed_contents_and_can_retry_after_restoration(self):
        original = self.path.read_bytes()
        self.path.write_bytes(b'changed for inspection')
        cleanup = []
        _remove_owned_files([self.record], cleanup)
        self.assertTrue(self.path.exists())
        self.assertFalse(cleanup[0]['confirmed'])
        self.path.write_bytes(original)
        _remove_owned_files([self.record], cleanup)
        self.assertTrue(cleanup[-1]['confirmed'])
        self.assertFalse(self.root.exists())

    def test_handles_known_missing_file_and_directory_without_deleting_peers(self):
        peer = self.base / 'keep.txt'
        peer.write_text('keep')
        self.path.unlink()
        cleanup = []
        _remove_owned_files([self.record], cleanup)
        self.assertEqual(cleanup[0]['state'], 'already_absent')
        self.assertFalse(self.root.exists())
        self.assertEqual(peer.read_text(), 'keep')

    def test_empty_staging_root_replacement_is_retained(self):
        empty = self.base / 'staging'
        empty.mkdir()
        recorded = _register_owned_directory(empty)
        empty.rename(self.base / 'original-staging')
        empty.mkdir()
        cleanup = []
        _remove_owned_directory(recorded, cleanup)
        self.assertTrue(empty.exists())
        self.assertFalse(cleanup[0]['confirmed'])

    def test_reparse_and_symbolic_link_metadata_cannot_grant_ownership(self):
        for mode, attributes in ((stat.S_IFDIR, 0x400), (stat.S_IFLNK, 0)):
            with self.subTest(mode=mode, attributes=attributes):
                metadata = SimpleNamespace(st_mode=mode, st_file_attributes=attributes,
                                           st_ino=42, st_dev=1)
                with self.assertRaisesRegex(OSError, 'symlink, junction, or reparse'):
                    _identity(metadata, True)

    def test_admits_canonical_external_parent_and_preserves_source_coordinates(self):
        alias = self.base / 'external-parent-alias'
        source_root = alias / self.root.name
        original_lstat, original_resolve = Path.lstat, Path.resolve

        def resolve(path, *args, **kwargs):
            return self.base.resolve() if path == alias else original_resolve(path, *args, **kwargs)

        def lstat(path, *args, **kwargs):
            return original_lstat(self.root) if path == source_root else original_lstat(path, *args, **kwargs)

        with patch.object(Path, 'resolve', resolve), patch.object(Path, 'lstat', lstat):
            admitted = _register_owned_directory(source_root)
        self.assertEqual(admitted.path, self.root.resolve())
        self.assertEqual(admitted.source_path, source_root)
        record = _register_owned_file(admitted, source_root / 'slices' / 'arm64', self.record.digest)
        cleanup = []
        _remove_owned_files([record], cleanup)
        self.assertTrue(cleanup[0]['confirmed'])
        self.assertFalse(self.root.exists())

    def test_stable_external_parent_symlink_is_supported_on_filesystem(self):
        alias = self.base / 'external-parent-alias'
        try:
            alias.symlink_to(self.base, target_is_directory=True)
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Creating symbolic links requires unavailable Windows privileges')
            raise
        admitted = _register_owned_directory(alias / self.root.name)
        self.assertEqual(admitted.path, self.root.resolve())
        record = _register_owned_file(admitted, alias / self.root.name / 'slices' / 'arm64', self.record.digest)
        cleanup = []
        _remove_owned_files([record], cleanup)
        self.assertTrue(cleanup[0]['confirmed'])
        self.assertFalse(self.root.exists())
        self.assertTrue(alias.is_symlink())

    def test_rejects_linked_owned_root_or_descendant_during_registration(self):
        original_lstat = Path.lstat
        for linked in (self.root, self.parent):
            with self.subTest(linked=linked):
                canonical_linked = linked.resolve()
                def lstat(path, *args, **kwargs):
                    if path in (linked, canonical_linked):
                        return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400,
                                               st_ino=42, st_dev=1)
                    return original_lstat(path, *args, **kwargs)

                with patch.object(Path, 'lstat', lstat):
                    with self.assertRaisesRegex(OSError, 'symlink, junction, or reparse'):
                        _register_owned_file(self.root, self.path, self.record.digest)

    def test_previously_admitted_root_replacement_is_not_readmitted_for_new_file(self):
        admitted = _register_owned_directory(self.root)
        self.root.rename(self.base / 'original-root')
        self.parent.mkdir(parents=True)
        self.path.write_bytes(b'owned inert fixture')
        with self.assertRaisesRegex(OSError, 'directory identity changed'):
            _register_owned_file(admitted, self.path, self.record.digest)


if __name__ == '__main__':
    unittest.main()
