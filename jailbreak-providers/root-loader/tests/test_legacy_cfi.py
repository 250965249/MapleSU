"""Exercise the real 5.15 compiler/loader ABI, not a KCFI prefix fixture."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("legacy_builder", HERE / "build_root_module.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class LegacyCfiTest(unittest.TestCase):
    def test_image_uses_64bit_cross_dso_types(self):
        contract = builder.load_contract(HERE / "contracts/family-5.15.json")
        self.assertEqual("clang-cfi", contract.get("cfi", {}).get("mode"))
        legacy_cfi = builder.legacy_cfi
        facts = legacy_cfi.image_facts(builder, contract)
        self.assertEqual("0x02b3a43e29242445", facts["initCheckSite"]["typeId"])
        self.assertEqual("0x7e04a0fb7ad8bcd5", facts["exitCheckSite"]["typeId"])
        self.assertEqual("0x6d27ac3c3f910100", facts["preHandler"]["typeId"])
        self.assertEqual("0xae77aa8d3946233d", facts["postHandler"]["typeId"])

    def test_real_root_and_l3_build_and_verify(self):
        for module in ("maplesu_root", "maplesu_l3"):
            with self.subTest(module=module), tempfile.TemporaryDirectory() as directory:
                command = [sys.executable, str(HERE / "build_root_module.py"),
                           "--module", module, "--contract", str(HERE / "contracts/family-5.15.json"),
                           "--out-dir", directory, "--quiet"]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr +
                                 (Path(directory) / "verify-build.txt").read_text(encoding="utf-8"))
                report = json.loads((Path(directory) / "build.json").read_text())
                self.assertTrue(report["gateResult"]["ok"])
                self.assertIn("-fsanitize=cfi", report["cflags"])
                self.assertNotIn("-fsanitize=kcfi", report["cflags"])
                checks = report["facts"]["cfiChecks"]
                self.assertTrue(all(row["acceptsCorrectType"] and row["rejectsWrongType"]
                                    and row["rejectsWrongAddress"] for row in checks))
                result = subprocess.run(command + ["--verify-only"], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr +
                                 (Path(directory) / "verify-build.txt").read_text(encoding="utf-8"))

    def test_dispatcher_and_failure_handler_mutations_are_rejected(self):
        for target in ("__cfi_check", "__cfi_check_fail"):
            with self.subTest(symbol=target), tempfile.TemporaryDirectory() as directory:
                command = [sys.executable, str(HERE / "build_root_module.py"),
                           "--module", "maplesu_l3", "--contract", str(HERE / "contracts/family-5.15.json"),
                           "--out-dir", directory, "--quiet"]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(0, result.returncode)
                path = Path(directory) / "maplesu_l3.ko"
                elf = builder.Elf(path)
                offset = elf.symbol_file_offset(elf.symbol(target))
                raw = bytearray(elf.raw)
                raw[offset:offset + 4] = bytes.fromhex("c0035fd6")  # ret
                path.write_bytes(raw)
                result = subprocess.run(command + ["--verify-only"], capture_output=True, text=True)
                self.assertNotEqual(0, result.returncode, "tampered CFI was accepted: " + target)


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    unittest.main()
