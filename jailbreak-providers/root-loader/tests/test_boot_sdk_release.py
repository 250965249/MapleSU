"""Exercise SDK allocator releases through the production symbol gateway."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "jailbreak-providers/dirtyfrag/tests"))
from test_l3_arm import definition, host_compiler


class BootSdkReleaseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (HERE.parent / "module/maplesu_boot_sdk.c").read_text(encoding="utf-8")
        functions = [definition(source, name) for name in
                     ("zero", "same_name", "sdk_lookup", "owned", "discard", "sdk_module_free", "dispatch")]
        if not all(functions):
            raise AssertionError("Production release gateway definitions missing")
        compiler = host_compiler()
        if compiler is None:
            raise AssertionError("host compiler missing")
        cls.temporary = tempfile.TemporaryDirectory(prefix="maplesu-sdk-release-")
        cls.addClassCleanup(cls.temporary.cleanup)
        temporary = Path(cls.temporary.name)
        (temporary / "boot_sdk_release.inc").write_text("\n".join(functions), encoding="utf-8")
        cls.binary = temporary / "release.exe"
        subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
            "-I" + str(temporary), "-I" + str(HERE.parent / "module"),
            HERE / "boot_sdk_release_test.c", "-o", cls.binary], check=True)

    def test_tracked_release_clears_ownership_before_address_reuse(self):
        for symbol in ("module_memfree", "execmem_free"):
            for scenario in ("tracked", "untracked", "interior", "protection-failed"):
                with self.subTest(symbol=symbol, scenario=scenario):
                    result = subprocess.run([self.binary, symbol, scenario], capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
