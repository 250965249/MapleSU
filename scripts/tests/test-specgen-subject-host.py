"""Check the read-only subject host protocol without running a patch generator."""
import importlib.util
import json
import os
import shutil
import struct
import zipfile
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('subject_product', ROOT/'tools/specgen/specgen/product.py')
product = importlib.util.module_from_spec(spec)
spec.loader.exec_module(product)


class SubjectHostTests(unittest.TestCase):
    def setUp(self):
        self.runtime = patch.object(product, '_host_runtime', return_value=('java', Path('host.jar'), 'dependencies'), create=True)
        self.runtime.start()
        self.addCleanup(self.runtime.stop)

    def test_readonly_protocol_and_lifetime(self):
        seen = {}
        expected = {'schemaVersion': 1, 'operation': 'PRO_LAYOUT_SUBJECT_DESCRIBE',
                    'implementation': 'manager/ultrakernel', 'fields': {'cred.uid': {'offsetBytes': 4}}}
        def run(argv, **kwargs):
            self.assertEqual(['--operation', 'describe-subject'], argv[-4:-2])
            kernel = Path(argv[argv.index('--kernel')+1])
            output = Path(argv[argv.index('--out')+1])
            self.assertEqual(b'KERNEL', kernel.read_bytes())
            self.assertFalse(output.exists())
            self.assertEqual(subprocess.DEVNULL, kwargs.get('stdin'))
            self.assertNotIn('input', kwargs)
            self.assertFalse(any('credential' in value or 'patched' in value for value in argv))
            output.write_text(json.dumps(expected), encoding='utf-8')
            seen['directory'] = output.parent
            return subprocess.CompletedProcess(argv, 0, 'PRO_LAYOUT_SUBJECT_DESCRIBE_OK\n', '')
        with patch.object(product.subprocess, 'run', side_effect=run):
            self.assertEqual(expected, product.describe_subject(b'KERNEL'))
        self.assertFalse(seen['directory'].exists())

    def test_failure_keeps_exit_and_diagnostics(self):
        result = subprocess.CompletedProcess([], 3, 'detail-out\n', 'PRO_LAYOUT_MISSING:cred.uid\n')
        with patch.object(product.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                product.describe_subject(b'KERNEL')
        for detail in ('3', 'detail-out', 'PRO_LAYOUT_MISSING:cred.uid'):
            self.assertIn(detail, str(raised.exception))

    def test_missing_dependency_is_not_relabelled(self):
        with patch.object(product, '_host_runtime', side_effect=RuntimeError('PRO_HOST_DEPENDENCY_MISSING:kotlin-stdlib'), create=True):
            with self.assertRaisesRegex(RuntimeError, '^PRO_HOST_DEPENDENCY_MISSING:kotlin-stdlib$'):
                product.describe_subject(b'KERNEL')

    def test_invalid_output_is_not_accepted(self):
        def run(argv, **kwargs):
            Path(argv[argv.index('--out')+1]).write_text('[]', encoding='utf-8')
            return subprocess.CompletedProcess(argv, 0, '', '')
        with patch.object(product.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'PRO_HOST_SUBJECT_OUTPUT'):
                product.describe_subject(b'KERNEL')

    def test_boot_credentials_readonly_protocol_and_lifetime(self):
        seen = {}
        expected = {'schemaVersion': 1, 'operation': 'PRO_LAYOUT_BOOT_CREDENTIALS_DESCRIBE',
                    'implementation': 'manager/ultrakernel',
                    'fields': {'cred.securebits': {'offsetBytes': 40, 'widthBytes': 4,
                        'ownerSizeBytes': None, 'source': 'accessor:cap_task_prctl(27)'}}}
        def run(argv, **kwargs):
            self.assertEqual('describe-boot-credentials', argv[argv.index('--operation')+1])
            kernel = Path(argv[argv.index('--kernel')+1])
            output = Path(argv[argv.index('--out')+1])
            self.assertEqual(b'BOOT_KERNEL', kernel.read_bytes())
            self.assertFalse(output.exists())
            self.assertEqual({'Image'}, {path.name for path in output.parent.iterdir()})
            self.assertEqual(subprocess.DEVNULL, kwargs.get('stdin'))
            self.assertNotIn('input', kwargs)
            self.assertTrue(kwargs['capture_output'])
            for option in ('--credential', '--key', '--receipt', '--patched-kernel', '--patched-boot'):
                self.assertNotIn(option, argv)
            output.write_text(json.dumps(expected), encoding='utf-8')
            seen['directory'] = output.parent
            return subprocess.CompletedProcess(argv, 0, 'PRO_LAYOUT_BOOT_CREDENTIALS_DESCRIBE_OK\n', '')
        with patch.object(product.subprocess, 'run', side_effect=run) as invoke:
            self.assertEqual(expected, product.describe_boot_credentials(b'BOOT_KERNEL'))
        invoke.assert_called_once()
        self.assertFalse(seen['directory'].exists())

    def test_boot_credentials_failure_keeps_code_streams_and_cleans_files(self):
        seen = {}
        def run(argv, **kwargs):
            seen['directory'] = Path(argv[argv.index('--out')+1]).parent
            return subprocess.CompletedProcess(argv, 13, 'boot detail\n', 'PRO_LAYOUT_MISSING:cred.securebits\n')
        with patch.object(product.subprocess, 'run', side_effect=run):
            with self.assertRaises(RuntimeError) as raised:
                product.describe_boot_credentials(b'KERNEL')
        self.assertEqual('PRO_HOST_BOOT_CREDENTIALS_FAILED:13\nboot detail\n'
                         'PRO_LAYOUT_MISSING:cred.securebits\n', str(raised.exception))
        self.assertFalse(seen['directory'].exists())

    def test_boot_credentials_missing_dependency_is_not_relabelled(self):
        with patch.object(product, '_host_runtime', side_effect=RuntimeError(
                'PRO_HOST_DEPENDENCY_MISSING:kotlin-stdlib')), patch.object(product.subprocess, 'run') as invoke:
            with self.assertRaisesRegex(RuntimeError, '^PRO_HOST_DEPENDENCY_MISSING:kotlin-stdlib$'):
                product.describe_boot_credentials(b'KERNEL')
        invoke.assert_not_called()

    def test_boot_credentials_output_errors_keep_diagnostics_and_cleanup(self):
        for payload, reason in ((None, 'FileNotFoundError'), ('{', 'JSONDecodeError'),
                                ('[]', 'OBJECT_REQUIRED'), ('null', 'OBJECT_REQUIRED')):
            with self.subTest(payload=payload):
                seen = {}
                def run(argv, **kwargs):
                    output = Path(argv[argv.index('--out')+1])
                    seen['directory'] = output.parent
                    if payload is not None:
                        output.write_text(payload, encoding='utf-8')
                    return subprocess.CompletedProcess(argv, 0, 'output detail\n', 'output diagnostic\n')
                with patch.object(product.subprocess, 'run', side_effect=run):
                    with self.assertRaises(RuntimeError) as raised:
                        product.describe_boot_credentials(b'KERNEL')
                self.assertEqual('PRO_HOST_BOOT_CREDENTIALS_OUTPUT:' + reason + '\n'
                                 'output detail\noutput diagnostic\n', str(raised.exception))
                self.assertFalse(seen['directory'].exists())

    def test_existing_generate_keeps_key_pipe_and_exit(self):
        args = SimpleNamespace(symbols=None, struct_offsets=None,
            recipe=ROOT/'tools/specgen/specgen/recipes/k22.json', java=None, image_core=None,
            out='spec.out', kernel='input.Image', patched_kernel='patched.Image')
        with patch.object(product.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7)) as run:
            self.assertEqual(7, product.generate(args, b'PRIVATE_KEY'))
        self.assertEqual(b'PRIVATE_KEY\n', run.call_args.kwargs['input'])
        self.assertNotIn('PRIVATE_KEY', ' '.join(run.call_args.args[0]))
        self.assertIn('--patched-kernel', run.call_args.args[0])


class SourceCacheTests(unittest.TestCase):
    def test_default_image_core_uses_actual_sources_and_target17(self):
        suffix = '.exe' if os.name == 'nt' else ''
        java = Path(os.environ['JAVA_HOME'])/'bin'/('java'+suffix) if os.environ.get('JAVA_HOME') else Path(shutil.which('java'))
        with tempfile.TemporaryDirectory(prefix='MapleSU-image-cache-test-') as directory:
            root = Path(directory)
            source = root/'image-core/src/main/java/ImageProbe.java'
            source.parent.mkdir(parents=True)
            source.write_text('public class ImageProbe { public static final int VALUE = 1; }', encoding='utf-8')
            stale = root/'image-core/build/libs/image-core.jar'
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b'STALE_REFERENCE')
            with patch.object(product, 'ROOT', root), patch.object(product, 'HOST_CACHE', root/'cache'):
                first = product._image_core_jar(str(java))
                self.assertNotEqual(stale, first)
                with zipfile.ZipFile(first) as jar:
                    self.assertEqual(61, struct.unpack('>H', jar.read('ImageProbe.class')[6:8])[0])
                self.assertEqual(first, product._image_core_jar(str(java)))
                source.write_text('public class ImageProbe { public static final int VALUE = 2; }', encoding='utf-8')
                second = product._image_core_jar(str(java))
                self.assertNotEqual(first, second)
                self.assertTrue(first.is_file() and second.is_file())

    def test_compile_failure_retains_code_and_both_streams(self):
        result = subprocess.CompletedProcess([], 9, 'compiler stdout\n', 'error: invalid source\n')
        with patch.object(product.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                product._checked_build(['compiler'], 'PRO_HOST_COMPILE_FAILED')
        for text in ('PRO_HOST_COMPILE_FAILED:9', 'compiler stdout', 'error: invalid source'):
            self.assertIn(text, str(raised.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
