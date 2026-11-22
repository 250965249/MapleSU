"""Local source-identity and evidence-retention regressions, without device materials."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import unittest

from check_boot_materials import checked_repository, run, sha256


class BootMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'repo'
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.git('config', 'core.autocrlf', 'false')
        self.source = self.repo / 'tool.py'
        self.source.write_bytes(b'# pinned source\n')
        self.git('add', 'tool.py')
        self.git('-c', 'user.name=MapleSU tests', '-c', 'user.email=tests@example.invalid',
                 'commit', '-qm', 'fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True)

    def test_clean_pinned_source_identity(self):
        result = checked_repository(self.repo, self.commit, ['tool.py'])
        self.assertEqual(result['commit'], self.commit)
        self.assertEqual(result['files']['tool.py'], sha256(self.source))

    def test_tracked_source_change_rejected(self):
        self.source.write_bytes(b'# changed\n')
        with self.assertRaisesRegex(ValueError, 'differs from fixed clean revision'):
            checked_repository(self.repo, self.commit, ['tool.py'])

    def test_wrong_revision_rejected(self):
        with self.assertRaisesRegex(ValueError, 'differs from fixed clean revision'):
            checked_repository(self.repo, '0' * 40, ['tool.py'])

    def test_missing_recorded_source_rejected(self):
        with self.assertRaises(FileNotFoundError):
            checked_repository(self.repo, self.commit, ['missing.py'])

    def test_existing_output_preserved(self):
        sentinel = self.root / 'materials.json'
        sentinel.write_bytes(b'existing evidence')
        with self.assertRaises(FileExistsError):
            run(argparse.Namespace(output_directory=self.root))
        self.assertEqual(sentinel.read_bytes(), b'existing evidence')


if __name__ == '__main__':
    unittest.main()
