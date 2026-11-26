from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import ghostsam_patch_dryrun as d  # noqa: E402

KROOT = ROOT / "third_party" / "kernelsu"
PATCH = KROOT / "patches" / "7k" / d.EXTENSION_PATCH
REGISTRY = KROOT / "patches" / "7k" / "ghostsam-patch-registry.json"


class CompatPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.info = d.static_checks(KROOT)
        cls.patch_text = PATCH.read_text(encoding="utf-8")

    def test_base_series_byte_identical_and_matches_manifest(self):
        self.assertTrue(self.info["baseSeriesMatchesManifest"])
        self.assertEqual(26, len(self.info["baseSeriesEntries"]))
        self.assertNotIn(d.EXTENSION_PATCH, self.info["baseSeriesEntries"])
        manifest = json.loads((KROOT / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["patchSeries"]["seriesSha256"], self.info["baseSeriesSha256"])

    def test_extension_series_and_registry_consistent(self):
        self.assertEqual([d.EXTENSION_PATCH], self.info["extensionSeriesEntries"])
        reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(self.info["patchSha256"], reg["patches"][0]["sha256"])
        self.assertEqual(self.info["extensionSeriesSha256"], reg["extensionSeries"]["sha256"])
        self.assertEqual(self.info["baseSeriesSha256"], reg["baseSeries"]["sha256"])
        self.assertEqual(reg["manifestSeriesSha256"], self.info["manifestSeriesSha256"])
        self.assertTrue(reg["patches"][0]["identityPreserved"])

    def test_patch_targets_only_late_load_surface(self):
        targets = self.info["patchTargets"]
        self.assertEqual({"userspace/ksud/src/cli.rs", "userspace/ksud/src/late_load.rs"}, set(targets))
        for t in targets:
            self.assertNotIn("apk_sign", t)
            self.assertNotIn("Kbuild", t)
            self.assertFalse(t.startswith("kernel/"))
            self.assertNotIn("boot_patch", t)

    def test_soft_reboot_and_manager_component_in_added_lines(self):
        added = "\n".join(self.info["patchAddedLines"])
        self.assertIn("--soft-reboot", added)
        self.assertIn("soft_reboot", added)
        self.assertIn("defs::DEFAULT_PACKAGE_NAME", added)
        self.assertIn("MapleSU Manager", added)
        self.assertIn(".ui.MainActivity", added)
        # 不得把上游 me.weishu 组件作为新增内容沿用
        self.assertNotIn("me.weishu", added)

    def test_manager_component_matches_real_manifest(self):
        manifest_xml = (ROOT / "manager/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
        self.assertIn('android:name=".ui.MainActivity"', manifest_xml)
        reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual("dev.maplesu.manager", reg["patches"][0]["managerRestart"]["package"])
        self.assertEqual("dev.maplesu.manager.ui.MainActivity", reg["patches"][0]["managerRestart"]["activity"])

    def test_no_forbidden_partition_write_tokens(self):
        for ln in self.info["patchAddedLines"]:
            low = ln.lower()
            for bad in d.FORBIDDEN_ADDED:
                self.assertNotIn(bad.lower(), low, f"forbidden token {bad!r} in added line: {ln!r}")

    def test_patch_applies_on_top_of_base_serially(self):
        # 真实 dry-run：复制 upstream，按 基础序列(26) -> 扩展序列(0028) 顺序 git apply。
        info = d.static_checks(KROOT)
        res = d.apply_dry_run(KROOT, info)
        self.assertEqual(27, res["appliedCount"])
        self.assertEqual(d.EXTENSION_PATCH, res["appliedEntries"][-1])


if __name__ == "__main__":
    unittest.main()
