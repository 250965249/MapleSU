"""Memory-only stage consumption of the real conditional KMI validators."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

TESTS = Path(os.environ.get("BRIDGE_KMI_FIXTURE_TESTS", str(Path(__file__).parent)))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture_api = load("resident_stage_fixtures", TESTS / "test_stage.py")
fixtures = load("resident_kmi_fixtures", TESTS / "test_target_kmi_resident.py")
kmi = fixtures.kmi
stage = load("resident_candidate_stage", Path(os.environ.get("BRIDGE_KMI_STAGE_SOURCE", str(TESTS.parent / "stage.py"))))
fixture_api.stage = stage
sys.path.insert(0, str(kmi.ROOT / "tools/specgen"))
from specgen import kallsyms


class ResidentStageChecks(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_api.StageChecks(methodName="runTest")
        self.fixture.setUp()
        self.parser = fixtures.ResidentKmiChecks(methodName="runTest")
        self.parser.setUp()
        self.generator_data = Path(kmi.__file__).read_bytes()
        self.imports = {name: (TESTS.parent / name).read_bytes() for name in ("native_imports.c", "native_imports.h")}

    def contract(self, resident):
        f = self.fixture
        f.formal_target_child()
        selected = lambda path: stage.identity(path, f.files[path])
        build = f.repo.parent / "kernel/build"
        generator = f.bridge / "target_kmi.py"
        f.files[generator] = self.generator_data
        f.files[build / "Module.symvers"] = b"DDK exports\n"
        f.files[build / "include/generated/utsrelease.h"] = b'#define UTS_RELEASE "real-ddk"\n'
        paths = {"targetConfig": f.repo / "target.config", "profile": f.repo / "profile.h", "symvers": f.repo / "target.symvers"}
        f.files[paths["targetConfig"]] = b"CONFIG_ARM64_4K_PAGES=y\n"
        f.files[paths["profile"]] = b"target profile fixture\n"
        f.files[paths["symvers"]] = b"target exports\n"
        inputs = {"targetConfig": selected(paths["targetConfig"]), "buildConfig": selected(build / ".config"),
                  "buildSymvers": selected(build / "Module.symvers"), "buildRelease": selected(build / "include/generated/utsrelease.h")}
        contract = {"schema": kmi.SCHEMA, "generator": selected(generator), "kernelProfile": "android15-6.6",
                    "sameMagic": {"policy": "skip-release-word-only-with-actual-crcs"}, "inputs": inputs,
                    "profile": selected(paths["profile"]), "targetSymvers": selected(paths["symvers"])}
        for name, data in self.imports.items():
            f.files[f.bridge / name] = data
        if resident:
            blobs = dict(self.parser.blobs)
            blobs.update({"residentTextOwnerImports" + suffix.upper(): self.imports["native_imports." + suffix] for suffix in ("c", "h")})
            for name, data in blobs.items():
                path = f.repo / (name + ".input")
                f.files[path] = data
                inputs[name] = selected(path)
            contract["residentTextOwner"] = self.parser.qualify()
        path = f.repo / "resident-contract.json"
        f.files[path] = json.dumps(contract).encode()
        f.argv += ["--target-kmi", str(path)]
        f.directories.update(parent for path in f.files for parent in path.parents)
        return contract

    def run_stage(self):
        original = stage.importlib.util.spec_from_file_location
        with patch.object(stage.importlib.util, "spec_from_file_location", side_effect=lambda name, path: original(name, Path(kmi.__file__))), \
                patch.object(kallsyms, "decode", return_value=self.parser.table):
            return self.fixture.run_stage()

    def test_qualification_request_requires_target_contract(self):
        self.fixture.argv += ["--require-resident-text-owner-kmi"]
        with self.assertRaisesRegex(ValueError, "RESIDENT_TARGET_REQUIRED"):
            self.run_stage()
        self.assertNotIn(self.fixture.output, self.fixture.directories)

    def test_old_contract_passes_default_and_fails_resident_request(self):
        self.contract(False)
        receipt = self.run_stage()
        self.assertNotIn("residentTextOwner", receipt["targetBinding"])
        self.fixture.files = {path: data for path, data in self.fixture.files.items() if not path.is_relative_to(self.fixture.output)}
        self.fixture.directories.discard(self.fixture.output)
        self.fixture.argv += ["--require-resident-text-owner-kmi"]
        with self.assertRaisesRegex(ValueError, "RESIDENT_REQUIRED"):
            self.run_stage()
        self.assertNotIn(self.fixture.output / "SOURCE-SELECTION.json", self.fixture.files)

    def test_qualified_actual_selected_imports_reach_receipt_without_target_claim(self):
        contract = self.contract(True)
        self.fixture.argv += ["--require-resident-text-owner-kmi"]
        receipt = self.run_stage()
        self.assertEqual(receipt["targetBinding"]["residentTextOwner"], contract["residentTextOwner"])
        self.assertFalse(receipt["targetQualified"])
        self.assertFalse(receipt["targetBinding"]["targetQualified"])

    def test_different_selected_imports_have_no_success_receipt(self):
        for name in self.imports:
            with self.subTest(name=name):
                self.setUp()
                self.contract(True)
                self.fixture.files[self.fixture.bridge / name] += b"\n/* selected-source drift */\n"
                self.fixture.argv += ["--require-resident-text-owner-kmi"]
                with self.assertRaisesRegex(ValueError, "RESIDENT_SELECTED_IMPORTS:" + name):
                    self.run_stage()
                self.assertNotIn(self.fixture.output / "SOURCE-SELECTION.json", self.fixture.files)


if __name__ == "__main__":
    unittest.main()
