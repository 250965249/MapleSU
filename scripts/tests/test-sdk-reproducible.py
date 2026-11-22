"""Ordinary-file/mock tests; never starts an SDK compiler or operates a device."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'verify-sdk-reproducible.py'
SPEC = importlib.util.spec_from_file_location('sdk_reproducible', PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class ReproducibilityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'ordinary.cpp'
        self.source.write_text('int fixture;\n', encoding='utf-8')
        self.selection = self.root / 'selection.json'
        self.files = [dict(path='ordinary.cpp', **M.identity(self.source))]
        self.selection.write_text(json.dumps({'schema': 'maplesu-sdk-source-selection/1', 'files': self.files}))
        self.args = SimpleNamespace(root=self.root, work_dir=self.root / 'output', source_selection=self.selection,
            minimum_free_bytes=1, source_date_epoch=1700000000, jobs=1, kernel_source_618=self.root,
            kernel_objtree_618=self.root, kernel_toolchain_618=self.root, ndk=None, cmake=None, gate_allow=None)
        self.calls = []

    def fake_build(self, argv, **kwargs):
        self.calls.append(argv)
        directory = Path(argv[argv.index('--build-dir') + 1])
        (directory / 'out').mkdir()
        (directory / 'out/helper').write_bytes(b'\x7fELFordinary-fixture')
        (directory / 'report').mkdir()
        (directory / 'report/build-report.json').write_text('{}')
        self.assertEqual(kwargs['env']['SOURCE_DATE_EPOCH'], '1700000000')
        self.assertIn('--all', argv)
        self.assertNotIn('--policy-bundle-source', argv)
        return SimpleNamespace(returncode=0)

    def fake_validate(self, root, directory):
        return {'source_selection': {'files': self.files}, 'compile': {'rows': []}}, {'ordinary.cpp': M.identity(self.source)}

    def execute(self, build=None, validate=None):
        with patch.object(M.subprocess, 'run', side_effect=build or self.fake_build), \
             patch.object(M, 'validate_build', side_effect=validate or self.fake_validate):
            return M.run(self.args)

    def test_two_sequential_new_builds_and_extensionless_elf(self):
        result = self.execute()
        self.assertTrue(result['passed'])
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all(row['emptyBeforeStart'] for row in result['runs']))
        self.assertEqual(list(result['runs'][0]['products']), ['out/helper'])
        self.assertFalse(result['runtimeAcceptance'])
        self.assertFalse(result['fullMaintainableSourceAcceptance'])

    def test_reused_output_preserved_without_subprocess(self):
        self.args.work_dir.mkdir()
        marker = self.args.work_dir / 'keep'
        marker.write_text('keep')
        with self.assertRaises(FileExistsError):
            self.execute()
        self.assertEqual(marker.read_text(), 'keep')
        self.assertEqual(self.calls, [])

    def test_failed_first_build_keeps_log_and_never_starts_second(self):
        def fail(argv, **kwargs):
            self.calls.append(argv)
            return SimpleNamespace(returncode=9)
        with self.assertRaisesRegex(ValueError, 'clean build failed'):
            self.execute(build=fail)
        result = json.loads((self.args.work_dir / 'REPRODUCIBILITY.json').read_text())
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['runs']), 1)
        self.assertEqual(result['runs'][0]['exitCode'], 9)
        self.assertTrue((self.args.work_dir / 'clean-1.log').exists())

    def test_source_change_fails_before_second_build(self):
        def change(argv, **kwargs):
            value = self.fake_build(argv, **kwargs)
            self.source.write_text('changed')
            return value
        with self.assertRaisesRegex(ValueError, 'source selection mismatch'):
            self.execute(build=change)
        self.assertEqual(len(self.calls), 1)

    def test_product_difference_is_never_waived(self):
        def change(argv, **kwargs):
            value = self.fake_build(argv, **kwargs)
            if len(self.calls) == 2:
                (Path(argv[argv.index('--build-dir') + 1]) / 'out/helper').write_bytes(b'\x7fELFchanged')
            return value
        result = self.execute(build=change)
        self.assertFalse(result['passed'])
        self.assertEqual(result['productDifferences'][0]['path'], 'out/helper')

    def test_metadata_difference_requires_specific_review(self):
        def change(argv, **kwargs):
            value = self.fake_build(argv, **kwargs)
            (Path(argv[argv.index('--build-dir') + 1]) / 'report/build-report.json').write_text(str(len(self.calls)))
            return value
        result = self.execute(build=change)
        self.assertFalse(result['passed'])
        self.assertTrue(result['binaryProductsIdentical'])
        self.assertEqual(result['metadataDifferencesRequiringExplanation'][0]['path'], 'report/build-report.json')

    def test_nonselected_dependency_drift_fails(self):
        def validate(root, directory):
            report, inputs = self.fake_validate(root, directory)
            inputs['toolchain'] = {'size': 1, 'sha256': str(len(self.calls))}
            return report, inputs
        result = self.execute(validate=validate)
        self.assertFalse(result['passed'])
        self.assertEqual(result['inputDifferences'][0]['path'], 'toolchain')

    def test_insufficient_measured_space_starts_no_build(self):
        self.args.minimum_free_bytes = 2**62
        with self.assertRaisesRegex(ValueError, 'insufficient space'):
            self.execute()
        self.assertEqual(self.calls, [])

    def test_selection_escape_and_duplicates_rejected(self):
        for path in ('../ordinary.cpp', 'ordinary.cpp'):
            rows = [*self.files, dict(path=path, **M.identity(self.source))]
            self.selection.write_text(json.dumps({'schema': 'maplesu-sdk-source-selection/1', 'files': rows}))
            with self.assertRaisesRegex(ValueError, 'source selection mismatch'):
                self.execute()
        self.assertFalse(self.args.work_dir.exists())


if __name__ == '__main__':
    unittest.main()
