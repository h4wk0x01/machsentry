"""Job directory lifecycle: loop image, output copy without following links, verified removal, boot sweep."""

import os
from pathlib import Path
import tempfile
import unittest

import worker_support as support
from machsentry_worker.jobdir import ANALYZER_UID, OUTPUT_CAPS, JobDir, parse_name, sweep


class JobDirTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ops = support.FakeOps()
        self.job = JobDir(self.root / 'jobs', self.root / 'results', 'job_1', 2, self.ops)

    def prepared(self) -> JobDir:
        self.job.create()
        self.job.input_file.write_bytes(support.sample_bytes())
        self.job.protect_input()
        self.job.prepare_work(4096)
        return self.job

    def test_layout_and_ownership(self):
        job = self.prepared()
        self.assertEqual(job.path, self.root / 'jobs' / 'job_1-2')
        self.assertEqual(job.results, self.root / 'results' / 'job_1-2')
        self.assertTrue(self.ops.is_mounted(job.work))
        self.assertEqual([entry for entry in self.ops.log if entry[0] == 'chown'],
                         [('chown', 'sample.macho', ANALYZER_UID, ANALYZER_UID),
                          ('chown', 'home', ANALYZER_UID, ANALYZER_UID), ('chown', 'tmp', ANALYZER_UID, ANALYZER_UID),
                          ('chown', 'out', ANALYZER_UID, ANALYZER_UID)])
        self.assertEqual(job.work_usage(), 123456)

    def test_outputs_are_copied_with_caps(self):
        job = self.prepared()
        out = job.work / 'out' / 'report'
        out.mkdir()
        (out / 'report.json').write_text('{}')
        (out / 'report.html').write_bytes(b'x' * (OUTPUT_CAPS['report.html'] + 1))
        (out / 'script-000.txt').write_text('not copied')
        copied, oversized = job.collect_outputs()
        self.assertEqual(set(copied), {'report.json'})
        self.assertEqual(oversized, ['report.html'])
        self.assertEqual((job.results / 'report.json').read_text(), '{}')
        self.assertFalse((job.results / 'script-000.txt').exists())

    def test_symlinked_outputs_are_not_followed(self):
        job = self.prepared()
        outside = self.root / 'host-secret.json'
        outside.write_text('{"host": true}')
        out = job.work / 'out' / 'report'
        out.mkdir()
        try:
            os.symlink(outside, out / 'report.json')
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable')
        copied, _ = job.collect_outputs()
        self.assertEqual(copied, {})

    def test_removal_is_verified(self):
        job = self.prepared()
        self.assertTrue(job.delete_sample())
        self.assertTrue(job.remove())
        self.assertFalse(job.path.exists())
        self.assertFalse(self.ops.is_mounted(job.work))
        self.assertTrue(job.results.exists())
        self.assertTrue(job.remove_results())
        self.assertFalse(job.results.exists())

    def test_failed_unmount_keeps_the_tree(self):
        job = self.prepared()
        self.ops.fail_unmount = True
        self.assertFalse(job.remove())
        self.assertTrue(job.path.exists())

    def test_boot_sweep_reports_attempts(self):
        self.prepared()
        stray = self.root / 'results' / 'other-1'
        stray.mkdir(parents=True)
        outcomes = sweep(self.root / 'jobs', self.root / 'results', self.ops)
        self.assertIn({'jobId': 'job_1', 'attempt': 2, 'removed': True}, outcomes)
        self.assertIn({'jobId': 'other', 'attempt': 1, 'removed': True}, outcomes)
        self.assertEqual(list((self.root / 'jobs').iterdir()), [])
        self.assertEqual(list((self.root / 'results').iterdir()), [])

    def test_names_and_identity_validation(self):
        self.assertEqual(parse_name('3f2a-uuid-like-7'), ('3f2a-uuid-like', 7))
        self.assertIsNone(parse_name('../etc-1'))
        self.assertIsNone(parse_name('job-0'))
        with self.assertRaises(ValueError):
            JobDir(self.root, self.root, '../escape', 1, self.ops)


if __name__ == '__main__':
    unittest.main()
