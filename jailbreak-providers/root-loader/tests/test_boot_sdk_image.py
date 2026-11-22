"""Foreign kernel images must stop before the SDK's first allocation."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'jailbreak-providers/dirtyfrag/tests'))
from test_l3_arm import definition, host_compiler

class BootSdkImageTest(unittest.TestCase):
    def test_foreign_missing_or_unreadable_notes_never_enter_allocator(self):
        source = (ROOT / 'jailbreak-providers/root-loader/module/maplesu_boot_sdk.c').read_text(encoding='utf-8')
        body = '\n'.join(part for name in ('sdk_image_qualified', 'bootstrap') if (part := definition(source, name)))
        compiler = host_compiler()
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix='maplesu-sdk-image-') as directory:
            base = Path(directory)
            (base / 'bootstrap.inc').write_text(body, encoding='utf-8')
            exe = base / 'bootstrap.exe'
            subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                '-I'+str(base), '-I'+str(ROOT / 'jailbreak-providers/root-loader/module'),
                Path(__file__).with_name('boot_sdk_image_test.c'), '-o', exe], check=True, capture_output=True, text=True)
            for case in ('foreign', 'missing', 'extent', 'read-error', 'exact', 'dynamic'):
                with self.subTest(case=case):
                    result = subprocess.run([exe, case], capture_output=True, text=True, check=True)
                    fields = dict(pair.split('=') for pair in result.stdout.split())
                    self.assertEqual('1' if case in ('exact', 'dynamic') else '0', fields['allocations'])
                    self.assertEqual('-12' if case in ('exact', 'dynamic') else '-95', fields['rc'])
                    self.assertEqual('3', fields['state'])
                    self.assertEqual('0', fields['hooks'])
                    self.assertEqual('1', fields['stable'])

if __name__ == '__main__':
    unittest.main()
