"""Compile the actual SDK gateway against tagged ARM64 user-copy fixtures."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "jailbreak-providers/dirtyfrag/tests"))
from test_l3_arm import definition, host_compiler


class BootSdkUserPointerTest(unittest.TestCase):
    def test_tagged_packets_reach_the_real_gateway(self):
        source = (HERE.parent / "module/maplesu_boot_sdk.c").read_text(encoding="utf-8")
        functions = [definition(source, name) for name in ("zero", "sdk_execve")]
        self.assertTrue(all(functions))
        compiler = host_compiler()
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="maplesu-tagged-sdk-") as directory:
            temporary = Path(directory)
            (temporary / "boot_sdk_user_gateway.inc").write_text("\n".join(functions), encoding="utf-8")
            binary = temporary / "gateway.exe"
            subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                "-I" + str(temporary), "-I" + str(HERE.parent / "module"),
                "-I" + str(ROOT / "runtime/ultra/authorization"),
                HERE / "boot_sdk_user_pointer_test.c", "-o", binary], check=True)
            result = subprocess.run([binary], capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
