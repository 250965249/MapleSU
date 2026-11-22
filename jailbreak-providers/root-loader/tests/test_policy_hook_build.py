"""Measured resident bridge inputs; page-size cases are host fixtures, not devices."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "resident_policy_builder_fixture", ROOT / "jailbreak-providers/root-loader/build_root_module.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class Symbols:
    def __init__(self, missing=()):
        self.missing = missing

    def address(self, name):
        return None if name in self.missing else 0x1000


def image(config):
    return b"IKCFG_ST" + gzip.compress(config.encode()) + b"IKCFG_ED"


class ResidentPolicyBuildTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.kernel = self.root / "kernel.c"
        self.kernel.write_bytes(b"measured kernel source")
        self.source = self.root / "runtime/ultra/policy/hook-bundles/policy-bundles.cpp"
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"measured policy bundle")
        self.document = dict(controlAbi=2,
            generatedSourceSha256=hashlib.sha256(self.source.read_bytes()).hexdigest(),
            kernelSourceSha256={"kernel.c": hashlib.sha256(self.kernel.read_bytes()).hexdigest()},
            bundles=[dict(payload=dict(imports=["ksys_write"]))])
        self.source.with_suffix(".json").write_text(json.dumps(self.document))
        for patcher in (patch.object(BUILDER, "PROJECT_ROOT", self.root),
                        patch.dict(os.environ, {"MAPLESU_POLICY_HOOK_BUNDLES": ""})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_unregistered_builder_and_all_page_sizes(self):
        self.assertNotIn(SPEC.name, sys.modules)
        for label, size in (("4K", 4096), ("16K", 16384), ("64K", 65536)):
            with self.subTest(page=label):
                facts = BUILDER.derive_l3_policy_bridge(
                    image("CONFIG_ARM64_" + label + "_PAGES=y\n"), Symbols(), 88)
                self.assertEqual(size, facts["defines"]["MSU_PH_PAGE_BYTES"])
                self.assertEqual(88, facts["defines"]["MSU_PH_KPROBE_SIZE"])
                self.assertIn("ksys_write", facts["allowedSymbols"])
                self.assertIn("#define MSU_PH_PAGE_BYTES " + str(size), BUILDER.policy_build.header(facts))

    def test_missing_required_helper_disables_only_optional_bridge(self):
        for missing in (("ksys_write",), ("module_alloc", "execmem_alloc"),
                        ("module_memfree", "execmem_free")):
            with self.subTest(missing=missing):
                self.assertEqual({}, BUILDER.derive_l3_policy_bridge(
                    image("CONFIG_ARM64_4K_PAGES=y\n"), Symbols(missing), 88))

    def test_missing_embedded_config_has_no_guessed_layout(self):
        self.assertEqual({}, BUILDER.derive_l3_policy_bridge(b"no-config", Symbols(), 88))

    def test_ambiguous_page_size_fails(self):
        with self.assertRaisesRegex(ValueError, "measured page size"):
            BUILDER.derive_l3_policy_bridge(image(
                "CONFIG_ARM64_4K_PAGES=y\nCONFIG_ARM64_16K_PAGES=y\n"), Symbols(), 88)

    def test_bundle_identity_drift_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "runtime/ultra/policy/hook-bundles/policy-bundles.json"
            bundle.parent.mkdir(parents=True)
            bundle.write_text(json.dumps(dict(controlAbi=2, generatedSourceSha256="0" * 64)))
            bundle.with_suffix(".cpp").write_text("changed payload")
            with patch.object(BUILDER, "PROJECT_ROOT", root):
                with self.assertRaisesRegex(ValueError, "bundle identity drift"):
                    BUILDER.derive_l3_policy_bridge(image("CONFIG_ARM64_4K_PAGES=y\n"), Symbols(), 88)

    def test_selected_bundle_preserves_source_and_kernel_identity_checks(self):
        selected = self.root / "candidate/policy-bundles.cpp"
        selected.parent.mkdir()
        selected.write_bytes(b"selected current policy bundle")
        document = dict(self.document,
            generatedSourceSha256=hashlib.sha256(selected.read_bytes()).hexdigest(),
            bundles=[dict(payload=dict(imports=["selected_context_helper"]))])
        selected.with_suffix(".json").write_text(json.dumps(document))
        self.source.write_bytes(b"stale default bundle")
        with self.assertRaisesRegex(ValueError, "bundle identity drift"):
            BUILDER.derive_l3_policy_bridge(image("CONFIG_ARM64_4K_PAGES=y\n"), Symbols(), 88)
        with patch.dict(os.environ, {"MAPLESU_POLICY_HOOK_BUNDLES": str(selected)}):
            facts = BUILDER.derive_l3_policy_bridge(image("CONFIG_ARM64_4K_PAGES=y\n"), Symbols(), 88)
            self.assertEqual(document["generatedSourceSha256"], facts["bundleSourceSha256"])
            self.assertIn("selected_context_helper", facts["allowedSymbols"])
            selected.write_bytes(b"changed selected bundle")
            with self.assertRaisesRegex(ValueError, "bundle identity drift"):
                BUILDER.derive_l3_policy_bridge(image("CONFIG_ARM64_4K_PAGES=y\n"), Symbols(), 88)
            selected.write_bytes(b"selected current policy bundle")
            self.kernel.write_bytes(b"changed kernel source")
            with self.assertRaisesRegex(ValueError, "payload source drift: kernel.c"):
                BUILDER.derive_l3_policy_bridge(image("CONFIG_ARM64_4K_PAGES=y\n"), Symbols(), 88)


if __name__ == "__main__":
    unittest.main()
