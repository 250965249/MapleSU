"""Exercise stage() versions and directory ownership with stdlib fixtures, never SDK inputs."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/stage-source-sdk.py'


def identity(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def load_stage():
    # No production delivery/ELF/backend module is loaded. These imports are unused by the
    # directory lifecycle; explicit sentinels catch any accidental expansion of this fixture.
    delivery = types.ModuleType('source_sdk_delivery')
    backend = types.ModuleType('policy_backend_identity')
    sentinels = []
    for module, names in [(delivery, ['checked', 'record', 'source_helper_identity', 'source_inputs',
                                     'verify_source_build_status', 'verify_source_delivery']), (backend, ['describe_backend'])]:
        for name in names:
            sentinel = mock.Mock(side_effect=AssertionError('fixture must not call ' + name))
            setattr(module, name, sentinel)
            sentinels.append(sentinel)
    spec = importlib.util.spec_from_file_location('stage_source_lifecycle_fixture', SOURCE)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {'source_sdk_delivery': delivery, 'policy_backend_identity': backend}):
        spec.loader.exec_module(module)
    return module, sentinels


class StageLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maplesu-stage-fixture-')
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / 'candidate'
        self.module, self.sentinels = load_stage()
        self.module.ROOT = self.root
        self.stderr = io.StringIO()

    def tearDown(self):
        for sentinel in self.sentinels:
            sentinel.assert_not_called()
        self.temporary.cleanup()

    def run_stage(self, candidate, **versions):
        with mock.patch.object(self.module, '_stage_candidate', side_effect=candidate) as producer:
            with contextlib.redirect_stderr(self.stderr):
                result = self.module.stage(self.root / 'not-a-build', self.output, self.root / 'not-a-release', **versions)
            producer.assert_called_once()
            return result

    @staticmethod
    def write_fixture(build, output, base, bundle, validation_review=None,
                      app_version=None, version_code=None):
        assert not build.exists() and not base.exists() and bundle is None and validation_review is None
        assert app_version is None and version_code is None
        marker = output / 'ordinary-fixture.txt'
        marker.write_text('fixture bytes\n', encoding='utf-8')
        return marker

    def test_success_keeps_only_fixture_output(self):
        result = self.run_stage(self.write_fixture)
        self.assertEqual(self.output / 'ordinary-fixture.txt', result)
        self.assertEqual('fixture bytes\n', result.read_text(encoding='utf-8'))
        self.assertEqual('', self.stderr.getvalue())

    def test_product_version_reaches_candidate_without_sdk_inputs(self):
        def candidate(build, output, base, bundle, validation_review, app_version, version_code):
            self.assertEqual((app_version, version_code), ('5.2.1', 50201))
            return self.write_fixture(build, output, base, bundle, validation_review)

        marker = self.run_stage(candidate, app_version='5.2.1', version_code=50201)
        self.assertEqual('fixture bytes\n', marker.read_text(encoding='utf-8'))

    def test_invalid_versions_fail_before_creating_candidate(self):
        cases = [('5.2.1', None), (None, 50201), ('5.2', 50201), ('5.2.1', 0)]
        for app_version, version_code in cases:
            with self.subTest(app_version=app_version, version_code=version_code):
                with mock.patch.object(self.module, '_stage_candidate') as producer:
                    with self.assertRaises(AssertionError):
                        self.module.stage(self.root / 'not-a-build', self.output, self.root / 'not-a-release',
                                          app_version=app_version, version_code=version_code)
                    producer.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_failure_cleans_the_new_owned_candidate(self):
        failure = ValueError('fixture construction failed')

        def candidate(*args):
            self.write_fixture(*args)
            raise failure

        with self.assertRaises(ValueError) as caught:
            self.run_stage(candidate)
        self.assertIs(failure, caught.exception)
        self.assertFalse(self.output.exists())
        self.assertEqual('', self.stderr.getvalue())

    def test_existing_candidate_is_not_touched(self):
        self.output.mkdir()
        marker = self.output / 'keep.txt'
        marker.write_text('existing', encoding='utf-8')
        with mock.patch.object(self.module, '_stage_candidate') as producer:
            with self.assertRaises(AssertionError):
                self.module.stage(self.root / 'not-a-build', self.output, self.root / 'not-a-release')
            producer.assert_not_called()
        self.assertEqual('existing', marker.read_text(encoding='utf-8'))

    def test_changed_directory_identity_is_preserved(self):
        moved = self.root / 'renamed-original'
        failure = ValueError('fixture directory was replaced')

        def candidate(*args):
            self.write_fixture(*args)
            self.output.rename(moved)
            self.output.mkdir()
            (self.output / 'replacement.txt').write_text('replacement', encoding='utf-8')
            raise failure

        with self.assertRaises(ValueError) as caught:
            self.run_stage(candidate)
        self.assertIs(failure, caught.exception)
        self.assertEqual('replacement', (self.output / 'replacement.txt').read_text(encoding='utf-8'))
        self.assertEqual('fixture bytes\n', (moved / 'ordinary-fixture.txt').read_text(encoding='utf-8'))
        self.assertIn('unknown or changed ownership', self.stderr.getvalue())

    def test_unknown_inode_is_preserved(self):
        actual_stat = Path.stat
        failure = ValueError('fixture unknown inode')

        def no_inode(path, *args, **kwargs):
            result = actual_stat(path, *args, **kwargs)
            if path == self.output:
                return types.SimpleNamespace(st_ino=0, st_dev=result.st_dev)
            return result

        def candidate(*args):
            self.write_fixture(*args)
            raise failure

        with mock.patch.object(Path, 'stat', no_inode):
            with self.assertRaises(ValueError) as caught:
                self.run_stage(candidate)
        self.assertIs(failure, caught.exception)
        self.assertEqual('fixture bytes\n', (self.output / 'ordinary-fixture.txt').read_text(encoding='utf-8'))
        self.assertIn('unknown or changed ownership', self.stderr.getvalue())

    def test_cleanup_error_keeps_the_first_exception(self):
        failure = ValueError('fixture original error')
        cleanup = PermissionError('fixture cleanup error')

        def candidate(*args):
            self.write_fixture(*args)
            raise failure

        with mock.patch.object(self.module.shutil, 'rmtree', side_effect=cleanup):
            with self.assertRaises(ValueError) as caught:
                self.run_stage(candidate)
        self.assertIs(failure, caught.exception)
        self.assertTrue((self.output / 'ordinary-fixture.txt').is_file())
        self.assertIn('cleanup failed: fixture cleanup error', self.stderr.getvalue())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = [SOURCE, Path(__file__).resolve()]
    before = [identity(p) for p in sources]
    for source in sources:
        (out / source.name).write_bytes(source.read_bytes())
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StageLifecycleTest))
    (out / 'unittest.log').write_text(log.getvalue(), encoding='utf-8')
    stable = before == [identity(p) for p in sources]
    receipt = {'passed': result.wasSuccessful() and stable, 'sources': before,
               'sourcesUnchanged': stable, 'testsRun': result.testsRun,
               'failures': len(result.failures), 'errors': len(result.errors),
               'argv': sys.argv, 'python': identity(sys.executable),
               'scope': 'Only stage() product-version validation/forwarding, new-directory ownership and cleanup with _stage_candidate replaced by ordinary fixture writes. ROOT is a temporary fixture; SDK/build/release/backend modules are replaced by never-called sentinels. No real SDK inputs/reports/delivery verification/ELF parsing/build/device/partition activity.'}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    if not receipt['passed']:
        print(log.getvalue())
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
