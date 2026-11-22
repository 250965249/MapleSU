"""5.10 uses measured instructions and a reference module, without image BTF."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("builder_510", HERE / "build_root_module.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
CONTRACT = HERE / "contracts/family-5.10.json"


class Legacy510Test(unittest.TestCase):
    def measure(self, contract):
        image = (builder.PROJECT_ROOT / contract["imagePath"]).read_bytes()
        symbols = builder.SymbolTable(builder.PROJECT_ROOT / contract["symbolsPath"])
        return builder.legacy_cfi.legacy_510.image_layouts(builder, contract, image, symbols)

    def test_image_layouts_and_cross_dso_types(self):
        contract = builder.load_contract(CONTRACT)
        facts = builder.legacy_cfi.image_facts(builder, contract)
        self.assertEqual("0x02b3a43e29242445", facts["initCheckSite"]["typeId"])
        self.assertEqual("0x6d27ac3c3f910100", facts["preHandler"]["typeId"])
        layouts = self.measure(contract)
        self.assertEqual(0x88, layouts["kprobe"]["size"])
        self.assertEqual(0x80, layouts["kprobe"]["members"]["flags"])
        self.assertEqual(0x400, layouts["module"]["size"])
        self.assertEqual(0x3b8, layouts["module"]["members"]["exit"])
        self.assertNotIn("defines", layouts)

    def test_contract_layout_drift_is_rejected(self):
        original = builder.load_contract(CONTRACT)
        mutations = [("kprobe", "size", 0x80), ("thisModule", "size", 0x3c0),
                     ("thisModule", "exitOffset", 0x378),
                     ("selinuxState", "initializedOffset", 1),
                     ("cfi", "checkMemberOffset", 0x118)]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                contract = copy.deepcopy(original)
                contract[section][key] = value
                with self.assertRaises(builder.GateFailure):
                    self.measure(contract)

    def test_reference_and_symbols_identity_drift_is_rejected(self):
        original = builder.load_contract(CONTRACT)
        for key in ("symbolsSha256", "referenceModuleSha256"):
            with self.subTest(key=key):
                contract = copy.deepcopy(original)
                contract["abiEvidence"][key] = "0" * 64
                with self.assertRaises(builder.GateFailure):
                    self.measure(contract)

    def test_real_root_and_l3_build_and_verify(self):
        for module in ("maplesu_root", "maplesu_l3"):
            with self.subTest(module=module), tempfile.TemporaryDirectory() as directory:
                command = [sys.executable, str(HERE / "build_root_module.py"),
                           "--module", module, "--contract", str(CONTRACT),
                           "--out-dir", directory, "--quiet"]
                result = subprocess.run(command, capture_output=True, text=True)
                transcript = Path(directory) / "verify-build.txt"
                self.assertEqual(0, result.returncode, result.stdout + result.stderr +
                                 (transcript.read_text() if transcript.exists() else ""))
                report = json.loads((Path(directory) / "build.json").read_text())
                self.assertTrue(report["gateResult"]["ok"])
                self.assertEqual(["printk", "register_kprobe", "unregister_kprobe"],
                                 sorted(report["facts"]["imports"]))
                self.assertIn("-fsanitize=cfi", report["cflags"])
                self.assertNotIn("-fsanitize=kcfi", report["cflags"])
                checks = report["facts"]["cfiChecks"]
                self.assertTrue(all(row["acceptsCorrectType"] and row["rejectsWrongType"]
                                    and row["rejectsWrongAddress"] for row in checks))
                elf = builder.Elf(Path(directory) / (module + ".ko"))
                self.assertEqual(0x400, elf.section(".gnu.linkonce.this_module")["size"])
                if module == "maplesu_l3":
                    self.assertEqual(0x88, elf.symbol("maplesu_probe")["size"])
                    self.assertEqual(0x88, elf.symbol("maplesu_avc_probe")["size"])
                result = subprocess.run(command + ["--verify-only"], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr + transcript.read_text())
                # Verification executes the final module's dispatcher; a RET patch must fail.
                raw = bytearray(elf.raw)
                offset = elf.symbol_file_offset(elf.symbol("__cfi_check"))
                raw[offset:offset + 4] = bytes.fromhex("c0035fd6")
                (Path(directory) / (module + ".ko")).write_bytes(raw)
                result = subprocess.run(command + ["--verify-only"], capture_output=True, text=True)
                self.assertNotEqual(0, result.returncode, "tampered 5.10 CFI was accepted")


if __name__ == "__main__":
    unittest.main()
