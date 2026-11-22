"""Exercise the production static-ELF boundary without running target code."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("ultra_init_build", Path(__file__).resolve().parents[1] / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def executable():
    data = bytearray(512)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 183, 1, 0x10000, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x10000, 0, len(data), len(data), 65536)
    struct.pack_into("<IIQQQQQQ", data, 120, 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    return data


class StaticElfTest(unittest.TestCase):
    def reject(self, data, code):
        with self.assertRaisesRegex(ValueError, code):
            build.verify_static_executable(data)

    def test_static_page_contract(self):
        self.assertEqual(build.verify_static_executable(executable())["pageSizes"], [4096, 16384, 65536])

    def test_malformed_inputs(self):
        for size in (0, 6, 63, 119):
            self.reject(executable()[:size], "ULTRA_INIT_ELF_")
        data = executable()
        struct.pack_into("<H", data, 18, 62)
        self.reject(data, "ELF_TARGET")
        data = executable()
        struct.pack_into("<Q", data, 32, 2**64 - 1)
        self.reject(data, "PROGRAM_HEADERS")

    def test_dynamic_dependencies(self):
        data = executable()
        struct.pack_into("<I", data, 120, 3)
        self.reject(data, "ELF_INTERPRETER")
        data = executable()
        struct.pack_into("<IIQQQQQQ", data, 120, 2, 6, 256, 256, 0, 16, 16, 8)
        struct.pack_into("<qQ", data, 256, 1, 0)
        self.reject(data, "ELF_NEEDED")

    def test_permissions_and_entry(self):
        data = executable()
        struct.pack_into("<I", data, 68, 7)
        self.reject(data, "LOAD_PERMISSIONS")
        data = executable()
        struct.pack_into("<I", data, 124, 7)
        self.reject(data, "ENTRY_OR_STACK")
        data = executable()
        struct.pack_into("<Q", data, 24, 0x20000)
        self.reject(data, "ENTRY_OR_STACK")

    def test_alignment_and_ranges(self):
        data = executable()
        struct.pack_into("<Q", data, 112, 4096)
        self.reject(data, "LOAD_ALIGNMENT")
        data = executable()
        struct.pack_into("<Q", data, 96, 513)
        self.reject(data, "SEGMENT_RANGE")
        data = executable()
        struct.pack_into("<Q", data, 104, 511)
        self.reject(data, "LOAD_PERMISSIONS")

    def test_rejects_existing_build_directory_before_running_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "ULTRA-INIT-BUILD.json"
            receipt.write_text("previous success", encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", str(spec.origin),
                                     "--ndk", "missing", "--cmake", "missing", "--ninja", "missing",
                                     "--build-dir", directory], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("build-dir must be new", result.stderr)
            self.assertEqual(receipt.read_text(encoding="utf-8"), "previous success")


if __name__ == "__main__":
    unittest.main()
