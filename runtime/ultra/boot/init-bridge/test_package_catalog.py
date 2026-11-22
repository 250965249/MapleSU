#!/usr/bin/env python3
"""Synthetic receipt-closure tests only; no ELF/ABI/device qualification is asserted."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("package_catalog", Path(__file__).with_name("package_catalog.py"))
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(catalog.encoded(value))
        return path

    def fixture(self, name="first", code=b"same software generation\n"):
        root = self.root / name
        root.mkdir()
        source = root / "selected.c"
        source.write_bytes(code)
        selection = self.write(root / "SOURCE-SELECTION.json", {"inputs": [{"repositoryPath": "runtime/fixture.c",
            "selected": {"path": str(source), **catalog.identity(source)}, "staged": "fixture.c"}]})
        original = root / "original.ko"
        original.write_bytes(b"synthetic original " + name.encode())
        build = self.write(root / "BUILD.json", {"exitCode": 0, "inputsUnchanged": True,
            "sources": [{"path": "/module/SOURCE-SELECTION.json", **catalog.identity(selection)}],
            "artifacts": {"path": "/module/bridge.ko", **catalog.identity(original)}})
        bundle = root / "bundle"
        bundle.mkdir()
        components = {"targetBoot": "target.img", "bridge": "bridge.ko", "handoff": "ultra-init",
            "config": "target.config", "moduleSymvers": "Module.symvers", "targetContract": "contract.json"}
        manifest = {"schemaVersion": 1, "kernelSha256": "a" * 64}
        inputs = {}
        for field, path in components.items():
            (bundle / path).write_bytes(b"same handoff" if field == "handoff" else (field + name).encode())
            identity = catalog.identity(bundle / path)
            manifest[field] = path
            manifest[field + "Sha256"] = identity["sha256"]
            inputs[field] = {"path": str(original if field == "bridge" else bundle / path),
                **(catalog.identity(original) if field == "bridge" else identity), "bundledAs": path,
                "bundledBytes": identity["bytes"], "bundledSha256": identity["sha256"]}
        sources = self.write(bundle / "BUNDLE-SOURCES.json", {"schemaVersion": 1, "inputs": inputs})
        manifest.update(bundleSources="BUNDLE-SOURCES.json", bundleSourcesSha256=catalog.identity(sources)["sha256"])
        self.write(bundle / "manifest.json", manifest)
        return {"bundle": str(bundle), "sourceSelection": str(selection), "strictBuild": str(build)}

    def plan(self, rows):
        default = catalog.identity(Path(rows[0]["bundle"]) / "manifest.json")["sha256"]
        return self.write(self.root / "plan.json", {"schema": "maplesu-init-bridge-catalog-plan/1",
            "defaultManifestSha256": default, "variants": rows})

    def test_real_aggregator_copies_two_identity_bound_variants(self):
        rows = [self.fixture(), self.fixture("second")]
        output = self.root / "output"
        result = catalog.package(self.plan(rows), output)
        self.assertEqual(2, len(result["variants"]))
        for item in result["variants"]:
            self.assertEqual(item["manifestSha256"], catalog.identity(output / item["prefix"] / "manifest.json")["sha256"])
            self.assertEqual(item["proofSha256"], catalog.identity(output / item["proof"])["sha256"])
            self.assertFalse(catalog.read_json(output / item["proof"])["deviceQualified"])

    def test_append_preserves_all_default_bytes(self):
        row = self.fixture()
        output = self.root / "output"
        import shutil
        shutil.copytree(row["bundle"], output)
        before = {path.relative_to(output): path.read_bytes() for path in output.iterdir()}
        catalog.package(self.plan([row]), output, append=True)
        for name, original in before.items():
            self.assertEqual(original, (output / name).read_bytes())

    def test_different_source_generation_is_rejected_before_write(self):
        rows = [self.fixture(), self.fixture("other", code=b"different generation")]
        with self.assertRaisesRegex(ValueError, "ULTRA_CATALOG_MIXED_GENERATIONS"):
            catalog.package(self.plan(rows), self.root / "output")
        self.assertFalse((self.root / "output").exists())

    def test_tampered_component_hash_is_rejected(self):
        row = self.fixture()
        (Path(row["bundle"]) / "bridge.ko").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "ULTRA_CATALOG_COMPONENT_HASH:bridge"):
            catalog.package(self.plan([row]), self.root / "output")

    def test_changed_selected_source_is_rejected(self):
        row = self.fixture()
        (Path(row["sourceSelection"]).parent / "selected.c").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "ULTRA_CATALOG_SELECTED_SOURCE_CHANGED"):
            catalog.package(self.plan([row]), self.root / "output")

    def test_failed_native_build_is_not_an_artifact(self):
        row = self.fixture()
        build = catalog.read_json(Path(row["strictBuild"]))
        build["exitCode"] = 1
        self.write(Path(row["strictBuild"]), build)
        with self.assertRaisesRegex(ValueError, "ULTRA_CATALOG_STRICT_BUILD"):
            catalog.package(self.plan([row]), self.root / "output")

    def test_wrong_original_module_generation_is_rejected(self):
        row = self.fixture()
        build = catalog.read_json(Path(row["strictBuild"]))
        build["artifacts"]["sha256"] = "0" * 64
        self.write(Path(row["strictBuild"]), build)
        with self.assertRaisesRegex(ValueError, "ULTRA_CATALOG_STRICT_MODULE"):
            catalog.package(self.plan([row]), self.root / "output")


if __name__ == "__main__":
    unittest.main()
