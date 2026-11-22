"""Direct clean-validator regressions using ordinary files, never native execution.

Only ar parsing and the three complex source_sdk_delivery validators are mocked.
Runner failure cases also replace the producer with ordinary-file writes.
The selected runner's validate_build, path containment/exactness, SHA/size,
source/runtime helper comparison, generation and six-family checks run unchanged.
Mock calls prove delegation, not archive semantics or real SDK functionality.
"""
import argparse
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
PATH = Path(__file__).resolve().parents[1] / 'verify-sdk-reproducible.py'
OUTPUT = PATH.parents[2]
SPEC = importlib.util.spec_from_file_location('sdk_reproducible_validator_target', PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
FAMILIES = ('android12-5.10', 'android13-5.15', 'android14-6.1',
            'android15-6.6', 'android16-6.12', 'android17-6.18')


class ValidatorTest(unittest.TestCase):
    def setUp(self):
        work = OUTPUT / 'validator-test-work'
        work.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='ordinary-', dir=work)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / 'current/clean-1'
        self.directory.mkdir(parents=True)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(sys, 'path', list(sys.path)))
        self.delivery = ModuleType('source_sdk_delivery')
        self.ar = ModuleType('ar_archive')
        self.delivery.verify_build_provenance = Mock(return_value=[])
        self.delivery.verify_member_source_chain = Mock()
        self.delivery.verify_source_bootstrap = Mock()
        self.ar.parse_ar = Mock(return_value={'members': ['ordinary archive member fixture']})
        self.stack.enter_context(patch.dict(sys.modules, {'source_sdk_delivery': self.delivery,
                                                        'ar_archive': self.ar}))
        self.archive = self.product('out/libkernel_module_kit_static.a', b'!<arch>\nordinary fixture')
        self.core = self.product('bootstrap/sdk/lib/arm64-v8a/libkernel_module_kit_static.a', b'!<arch>\nordinary core')
        self.helper = self.product('out/source/helper/autorun_bootstrap')
        self.runtime_helper = self.product('out/helper/autorun_bootstrap', self.helper.read_bytes())
        self.backend = self.product('backend/cmake/libpolicy.so')
        self.obj = self.product('obj/m0000/core.o')
        self.stage1 = self.product('obj/tu/core.stage1.bc', b'BC\xc0\xdeordinary fixture')
        self.source = self.write(self.root / 'source/ordinary.cpp', b'// ordinary source fixture\n')
        programs = []
        for name in ('autorun_bootstrap.bin', 'su.bin', 'resetprop_file.bin', 'webui_loader.bin'):
            path = self.product('out/assets/' + name)
            programs.append(dict(asset=name, status='built', bytes=path.stat().st_size,
                                 sha256=M.identity(path)['sha256']))
        stability = dict(passed=True, archive=self.record(self.archive))
        for name, path in (('helper', self.helper), ('backend', self.backend)):
            final = self.product('final-archive-stability/' + name + '.elf', path.read_bytes())
            trace = self.product('final-archive-stability/' + name + '-why-extract.tsv',
                                 b'libkernel_module_kit_static.a(core.o)\n')
            stability[name] = dict(identical=True, file=self.record(final), trace=self.record(trace))
        self.kernel_receipt = self.product('kernel/kernel-build.json', json.dumps(dict(
            sourcesUnchanged=True, results=[dict(kernel=f, exitCode=0) for f in FAMILIES])).encode())
        contract = self.product('kernel/kernel-contracts.json', b'{"ordinaryFixture":true}')
        bundle = self.product('kernel/policy-bundles.cpp', b'// ordinary bundle fixture\n')
        for family in FAMILIES:
            for name in ('maplesu_policy_view.payload.o', 'policy-view.so'):
                self.product('kernel/' + family + '/' + name)
        self.report = dict(
            stages_run=['check', 'manifest', 'payloads', 'compile', 'compose', 'pack', 'assets', 'gate', 'report'],
            pack=dict(archive=self.relative(self.archive), bytes=self.archive.stat().st_size,
                      sha256=M.identity(self.archive)['sha256'], members=260),
            bootstrap=dict(pack=dict(archive=self.relative(self.core))), gate=dict(exit_code=0),
            compile=dict(failures=[], rows=[dict(idx=0, status='ok', sources=['source/ordinary.cpp'])]),
            provenance=dict(schema='maplesu-sdk-source-provenance/2',
                closure_complete=True, incomplete_reasons=[], translation_units=[dict(
                object=self.relative(self.obj), bytes=self.obj.stat().st_size,
                sha256=M.identity(self.obj)['sha256'], compile_steps=[dict(
                    object=self.relative(self.stage1), bytes=self.stage1.stat().st_size,
                    sha256=M.identity(self.stage1)['sha256'])])]),
            source_selection=dict(files=[self.record(self.source)]), payloads=dict(programs=programs),
            source_helper=dict(out=self.relative(self.helper), surface=dict(bytes=self.helper.stat().st_size,
                               sha256=M.identity(self.helper)['sha256'])),
            assets=dict(helper=dict(out=self.relative(self.runtime_helper), bytes=self.runtime_helper.stat().st_size,
                                    sha256=M.identity(self.runtime_helper)['sha256'])),
            source_backend=dict(file=self.record(self.backend)), final_archive_stability=stability,
            source_kernel=dict(bundle=self.relative(bundle), kernelBuildReceipt=self.record(self.kernel_receipt),
                               kernelContractReceipt=self.record(contract)),
            compose=dict(rows=[dict(object=self.relative(self.obj), bytes=self.obj.stat().st_size,
                                    sha256=M.identity(self.obj)['sha256'])]))
        self.manifest = [dict(idx=0, name='core.o', sources=['source/ordinary.cpp'])]
        self.product('manifest.jsonl', ('\n'.join(map(json.dumps, self.manifest)) + '\n').encode())
        self.provenance = [self.record(self.source), self.record(self.obj)]
        self.delivery.verify_build_provenance.return_value = self.provenance

    def relative(self, path):
        return path.relative_to(self.root).as_posix()

    def record(self, path):
        return dict(path=self.relative(path), **M.identity(path))

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def product(self, name, data=b'\x7fELFordinary mock bytes; not executable'):
        return self.write(self.directory / name, data)

    def previous_copy(self, path):
        previous = self.root / 'previous-clean' / path.relative_to(self.directory)
        return self.write(previous, path.read_bytes())

    def validate(self):
        self.product('report/build-report.json', json.dumps(self.report).encode())
        return M.validate_build(self.root, self.directory)

    def rejected_before_delegation(self, expected='product is outside this clean build'):
        with self.assertRaisesRegex(ValueError, expected):
            self.validate()
        for name in ('verify_build_provenance', 'verify_member_source_chain', 'verify_source_bootstrap'):
            getattr(self.delivery, name).assert_not_called()
        self.ar.parse_ar.assert_not_called()

    def test_current_files_delegate_all_validators_with_actual_selected_paths(self):
        report, outside = self.validate()
        self.assertEqual(report, self.report)
        self.assertEqual(outside, {str(self.source): M.identity(self.source)})
        self.delivery.verify_build_provenance.assert_called_once_with(report, self.root, self.directory)
        self.ar.parse_ar.assert_called_once_with(str(self.archive))
        self.delivery.verify_member_source_chain.assert_called_once_with(
            self.manifest, report, self.ar.parse_ar.return_value['members'], self.root, self.directory)
        self.delivery.verify_source_bootstrap.assert_called_once_with(
            report, self.archive, self.runtime_helper, self.backend, self.root, self.directory)

    def test_same_bytes_previous_archive_is_rejected(self):
        self.report['pack']['archive'] = self.relative(self.previous_copy(self.archive))
        self.rejected_before_delegation()

    def test_same_bytes_archive_at_wrong_path_inside_current_build_is_rejected(self):
        other = self.product('out/alternate.a', self.archive.read_bytes())
        self.report['pack']['archive'] = self.relative(other)
        self.rejected_before_delegation()

    def test_same_bytes_previous_tu_and_intermediate_are_rejected(self):
        unit = self.report['provenance']['translation_units'][0]
        for row, path in ((unit, self.obj), (unit['compile_steps'][0], self.stage1)):
            with self.subTest(path=path.name):
                original = row['object']
                row['object'] = self.relative(self.previous_copy(path))
                self.rejected_before_delegation()
                row['object'] = original

    def test_same_bytes_previous_source_and_runtime_helper_are_rejected(self):
        for row, path in ((self.report['source_helper'], self.helper),
                          (self.report['assets']['helper'], self.runtime_helper)):
            with self.subTest(path=self.relative(path)):
                original = row['out']
                row['out'] = self.relative(self.previous_copy(path))
                self.rejected_before_delegation()
                row['out'] = original

    def test_same_bytes_previous_backend_is_rejected(self):
        self.report['source_backend']['file'] = self.record(self.previous_copy(self.backend))
        self.rejected_before_delegation()

    def test_complete_previous_report_without_continuation_is_rejected(self):
        previous = self.root / 'previous-complete-build'
        shutil.copytree(self.directory, previous)
        prefix = self.relative(self.directory) + '/'
        replacement = self.relative(previous) + '/'
        def replace(value):
            if isinstance(value, dict):
                return {k: replace(v) for k, v in value.items()}
            if isinstance(value, list):
                return [replace(v) for v in value]
            return replacement + value[len(prefix):] if isinstance(value, str) and value.startswith(prefix) else value
        self.report = replace(self.report)
        self.assertNotIn('continuation', self.report)
        self.assertEqual(self.report['pack']['members'], 260)
        self.rejected_before_delegation()

    def test_pairing_files_tampering_is_rejected_by_real_identity_check(self):
        for name in ('helper', 'backend'):
            with self.subTest(name=name):
                path = self.root / self.report['final_archive_stability'][name]['file']['path']
                original = path.read_bytes()
                path.write_bytes(b'X' + original[1:])
                self.rejected_before_delegation('clean product identity mismatch')
                path.write_bytes(original)

    def test_pairing_traces_tampering_is_rejected_by_real_identity_check(self):
        for name in ('helper', 'backend'):
            with self.subTest(name=name):
                path = self.root / self.report['final_archive_stability'][name]['trace']['path']
                original = path.read_bytes()
                path.write_bytes(b'X' + original[1:])
                self.rejected_before_delegation('clean product identity mismatch')
                path.write_bytes(original)

    def test_previous_bootstrap_and_final_pair_archive_are_rejected(self):
        bootstrap = self.report['bootstrap']['pack']
        original = bootstrap['archive']
        bootstrap['archive'] = self.relative(self.previous_copy(self.core))
        self.rejected_before_delegation()
        bootstrap['archive'] = original
        self.report['final_archive_stability']['archive'] = self.record(self.previous_copy(self.archive))
        self.rejected_before_delegation()

    def test_helper_generation_mismatch_rejected_even_when_each_hash_matches(self):
        self.runtime_helper.write_bytes(b'\x7fELFdifferent ordinary helper generation')
        row = self.report['assets']['helper']
        row.update(bytes=self.runtime_helper.stat().st_size, sha256=M.identity(self.runtime_helper)['sha256'])
        self.rejected_before_delegation('source/runtime helper mismatch')

    def test_payload_byte_drift_rejected(self):
        path = self.directory / 'out/assets/su.bin'
        path.write_bytes(b'X' + path.read_bytes()[1:])
        self.rejected_before_delegation('clean product identity mismatch')

    def test_payload_helper_generation_mismatch_rejected_even_when_each_hash_matches(self):
        path = self.directory / 'out/assets/autorun_bootstrap.bin'
        path.write_bytes(b'\x7fELFprevious ordinary helper generation')
        row = next(row for row in self.report['payloads']['programs']
                   if row['asset'] == 'autorun_bootstrap.bin')
        row.update(bytes=path.stat().st_size, sha256=M.identity(path)['sha256'])
        self.assertNotEqual(M.identity(path), M.identity(self.helper))
        self.rejected_before_delegation('source/payload helper mismatch')

    def test_incomplete_kernel_families_rejected_with_matching_receipt_hash(self):
        kernel = json.loads(self.kernel_receipt.read_text())
        kernel['results'].pop()
        self.kernel_receipt.write_text(json.dumps(kernel), encoding='utf-8')
        self.report['source_kernel']['kernelBuildReceipt'] = self.record(self.kernel_receipt)
        self.rejected_before_delegation('incomplete six-family kernel build')

    def test_top_level_bootstrap_and_compile_failures_reject_existing_products(self):
        for stage in ('bootstrap', 'compile'):
            with self.subTest(stage=stage):
                failure = dict(exit_code=4, message=stage + ' first failure')
                self.report['failure'] = failure
                self.rejected_before_delegation('not a full clean SDK/kernel build')
                self.assertEqual(self.report['failure'], failure)
                self.assertTrue(self.obj.is_file() and self.archive.is_file())

    def test_missing_provenance_is_rejected_before_delegation(self):
        del self.report['provenance']
        self.rejected_before_delegation('incomplete provenance receipt')

    def test_missing_compile_is_rejected_before_delegation(self):
        del self.report['compile']
        self.rejected_before_delegation('incomplete compile receipt')

    def test_nonzero_gate_is_rejected_before_delegation(self):
        self.report['gate']['exit_code'] = 7
        self.rejected_before_delegation('not a full clean SDK/kernel build')

    def test_missing_gate_is_rejected_before_delegation(self):
        del self.report['gate']
        self.rejected_before_delegation('not a full clean SDK/kernel build')

    def test_missing_gate_exit_code_is_rejected_before_delegation(self):
        del self.report['gate']['exit_code']
        self.rejected_before_delegation('not a full clean SDK/kernel build')

    def test_incomplete_compile_is_rejected_before_delegation(self):
        original = self.report['compile']
        cases = [
            ('missing rows', dict(failures=[])),
            ('empty rows', dict(failures=[], rows=[])),
            ('missing failures', dict(rows=original['rows'])),
            ('failed member', dict(failures=[dict(idx=1, message='first compile failure')],
                                   rows=original['rows'])),
            ('partial row', dict(failures=[], rows=[dict(idx=0, status='failed')])),
        ]
        for name, receipt in cases:
            with self.subTest(case=name):
                self.report['compile'] = receipt
                self.assertNotIn('failure', self.report)
                self.rejected_before_delegation('incomplete compile receipt')
                self.assertEqual(self.report['compile'], receipt)
                self.assertTrue(self.obj.is_file() and self.archive.is_file())

    def test_incomplete_provenance_is_rejected_before_delegation(self):
        original = self.report['provenance']
        for field, value in (('translation_units', []), ('closure_complete', False),
                             ('incomplete_reasons', ['unrecorded compile input'])):
            with self.subTest(field=field):
                self.report['provenance'] = dict(original, **{field: value})
                self.rejected_before_delegation('incomplete provenance receipt')

    def test_incomplete_producer_never_completes_with_partial_objects_or_old_archive(self):
        selection = self.write(self.root / 'selection.json', json.dumps(dict(
            schema='maplesu-sdk-source-selection/1',
            files=self.report['source_selection']['files'])).encode())
        self.delivery.verify_build_provenance.return_value = [self.record(self.source)]
        for name, exit_code, field in (('bootstrap-exit4', 4, 'bootstrap'),
                                       ('compile-exit4', 4, 'compile'),
                                       ('missing-compile', 0, 'compile'),
                                       ('missing-provenance', 0, 'provenance')):
            with self.subTest(case=name):
                work = self.root / name
                def ordinary_producer(argv, **kwargs):
                    directory = Path(argv[argv.index('--build-dir') + 1])
                    shutil.copytree(self.directory, directory, dirs_exist_ok=True)
                    report = json.loads(json.dumps(self.report).replace(
                        self.relative(self.directory) + '/', self.relative(directory) + '/'))
                    if exit_code:
                        report['failure'] = dict(exit_code=exit_code, message=field + ' first failure')
                    else:
                        del report[field]
                    self.write(directory / 'obj/m0001/partial.o', b'ordinary partial object fixture')
                    self.write(directory / 'report/build-report.json', json.dumps(report).encode())
                    return subprocess.CompletedProcess(argv, exit_code)
                args = argparse.Namespace(root=self.root, work_dir=work, source_selection=selection,
                    minimum_free_bytes=1, source_date_epoch=1700000000, jobs=1,
                    kernel_source_618=None, kernel_objtree_618=None, kernel_toolchain_618=None,
                    ndk=None, cmake=None, gate_allow=None)
                with patch.object(subprocess, 'run', side_effect=ordinary_producer) as producer, \
                        patch.object(M, 'validate_build', wraps=M.validate_build) as validate:
                    message = ('clean build failed: 1' if exit_code
                               else 'incomplete ' + field + ' receipt')
                    with self.assertRaisesRegex(ValueError, message):
                        M.run(args)
                    producer.assert_called_once()
                    if exit_code:
                        validate.assert_not_called()
                    else:
                        validate.assert_called_once()
                receipt = json.loads((work / 'REPRODUCIBILITY.json').read_text())
                self.assertFalse(receipt['passed'])
                self.assertFalse(receipt['runtimeAcceptance'])
                self.assertFalse(receipt['fullMaintainableSourceAcceptance'])
                self.assertEqual(len(receipt['runs']), 1)
                self.assertEqual(receipt['runs'][0]['exitCode'], exit_code)
                self.assertIn(message, receipt['failure'])
                self.assertEqual((work / 'clean-1/out/libkernel_module_kit_static.a').read_bytes(),
                                 self.archive.read_bytes())
                self.assertTrue((work / 'clean-1/obj/m0001/partial.o').is_file())
                if exit_code:
                    report = json.loads((work / 'clean-1/report/build-report.json').read_text())
                    self.assertEqual(report['failure'],
                                     dict(exit_code=exit_code, message=field + ' first failure'))

    def test_complex_validator_failures_propagate(self):
        for name in ('verify_build_provenance', 'verify_member_source_chain', 'verify_source_bootstrap'):
            with self.subTest(validator=name):
                method = getattr(self.delivery, name)
                method.side_effect = AssertionError(name + ' rejected fixture')
                with self.assertRaisesRegex(AssertionError, name + ' rejected fixture'):
                    self.validate()
                self.assertTrue(method.called)
                method.side_effect = None
                for attr in ('verify_build_provenance', 'verify_member_source_chain', 'verify_source_bootstrap'):
                    getattr(self.delivery, attr).reset_mock()
                self.ar.parse_ar.reset_mock()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, default=OUTPUT / 'VALIDATOR-TESTS.json')
    args = parser.parse_args()
    receipt = args.receipt.resolve()
    log_path = receipt.with_suffix('.log')
    if not receipt.is_relative_to(OUTPUT.resolve()) or receipt.exists() or log_path.exists():
        parser.error('choose a new receipt/log pair inside the reproducibility directory')
    sources = [PATH, Path(__file__).resolve()]
    def identities():
        return {str(path): dict(size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                for path in sources}
    before = identities()
    log = io.StringIO()
    attempts = []
    def block(*argv, **kwargs):
        attempts.append(str(argv))
        raise AssertionError('real subprocess creation is outside this test')
    tests = list(unittest.defaultTestLoader.loadTestsFromTestCase(ValidatorTest))
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with patch.object(subprocess, 'run', side_effect=block), patch.object(subprocess, 'Popen', side_effect=block), \
            contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.TestSuite(tests))
    after = identities()
    data = dict(schema='maplesu-clean-validator-tests/1', startedUtc=started,
                finishedUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(), python=sys.version,
                command=sys.argv, methods=result.testsRun, caseIds=[test.id() for test in tests],
                failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
                details=[dict(test=str(test), trace=trace) for test, trace in result.failures + result.errors],
                before=before, after=after, sourcesUnchanged=before == after,
                mocked=['ar_archive.parse_ar', 'source_sdk_delivery.verify_build_provenance',
                        'source_sdk_delivery.verify_member_source_chain', 'source_sdk_delivery.verify_source_bootstrap',
                        'subprocess.run (ordinary-file producer in runner failure cases)'],
                realChecks=['unmodified validate_build', 'exact and contained product paths', 'file sizes/SHA256',
                            'source/runtime helper equality', 'six-family receipt', 'delegation and failure propagation'],
                fixtureScope='ordinary files with ELF/ar magic, no real native objects or 260-member archive semantics',
                subprocessAttempts=attempts, sdkBuilds=0, deviceOperations=False,
                passed=result.wasSuccessful() and before == after and not attempts)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    log_path.write_text(log.getvalue(), encoding='utf-8')
    print(json.dumps({key: data[key] for key in ('methods', 'failures', 'errors', 'sourcesUnchanged', 'subprocessAttempts', 'passed')}))
    return 0 if data['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
