"""Samsung delta port checks (offline): patches 0029+, CI matrix, exynos naming.

Real-device Samsung KDP/RKP/DEFEX behaviour is NOT testable here; these are static +
dry-run assertions only.
"""

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
P7K = KROOT / "patches" / "7k"
SAMSUNG = [
    "0029-samsung-kdp.patch",
    "0030-samsung-defex.patch",
    "0031-samsung-selinux-hide.patch",
    "0032-samsung-rkp-no-patch-text.patch",
    "0033-samsung-kbuild-init-order.patch",
    "0034-samsung-exynos-double-name.patch",
]


class SamsungDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.info = d.static_checks(KROOT)
        cls.samsung_info = d.samsung_static_checks(KROOT)

    def test_series_registers_samsung_after_0028(self):
        entries = [ln.strip() for ln in (P7K / "series-ghostsam").read_text(encoding="utf-8").splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(entries, [d.EXTENSION_PATCH] + SAMSUNG)
        self.assertEqual(self.info["fullExtensionEntries"], entries)

    def test_patch_files_lf_and_registered(self):
        for name in SAMSUNG:
            path = P7K / name
            self.assertTrue(path.is_file(), name)
            self.assertNotIn("\r", path.read_bytes().decode("utf-8"), name)
        reg = json.loads((P7K / "ghostsam-patch-registry.json").read_text(encoding="utf-8"))
        self.assertEqual(reg["extensionSeries"]["entries"], [d.EXTENSION_PATCH] + SAMSUNG)
        self.assertEqual(reg["extensionSeries"]["sha256"], self.info["extensionSeriesSha256"])
        self.assertEqual(len(reg["samsungDelta"]["patches"]), len(SAMSUNG))

    def test_macros_are_tree_local(self):
        kdp = (P7K / "0029-samsung-kdp.patch").read_text(encoding="utf-8")
        defex = (P7K / "0030-samsung-defex.patch").read_text(encoding="utf-8")
        sel = (P7K / "0031-samsung-selinux-hide.patch").read_text(encoding="utf-8")
        rkp = (P7K / "0032-samsung-rkp-no-patch-text.patch").read_text(encoding="utf-8")
        kbuild = (P7K / "0033-samsung-kbuild-init-order.patch").read_text(encoding="utf-8")
        self.assertIn("CONFIG_KSU_SAMSUNG_KDP", kdp)
        self.assertIn("prepare_ro_creds", kdp)
        self.assertIn("ksu_samsung_kdp_init", kdp)
        self.assertIn("CONFIG_KSU_SAMSUNG_DEFEX", defex)
        self.assertIn("task_defex_enforce", defex)
        self.assertIn("CONFIG_KSU_RKP_NO_PATCH_TEXT", sel)
        self.assertIn("CONFIG_KSU_RKP_NO_PATCH_TEXT", rkp)
        self.assertIn("ccflags-y += -DCONFIG_KSU_SAMSUNG_KDP=1", kbuild)
        self.assertIn("ccflags-y += -DCONFIG_KSU_SAMSUNG_DEFEX=1", kbuild)
        self.assertIn("ccflags-y += -DCONFIG_KSU_RKP_NO_PATCH_TEXT=1", kbuild)

    def test_selinux_rkp_kprobe_trampolines(self):
        # 0031 overwrites the base selinux_hide.c with the device-proven RKP version:
        # RKP stage-2 write protection forbids text patching, so selinux_hide diverts
        # the original handlers via address-based kprobes + instruction_pointer_set.
        sel = (P7K / "0031-samsung-selinux-hide.patch").read_text(encoding="utf-8")
        for tok in ("CONFIG_KSU_RKP_NO_PATCH_TEXT", "sel_hide_context_write_kprobe",
                    "sel_hide_access_write_kprobe", "sel_hide_setprocattr_kprobe",
                    "sel_hide_status_open_kprobe", "sel_hide_register_probe",
                    "instruction_pointer_set"):
            self.assertIn(tok, sel)
        self.assertIn("sel_hide_guard_enter", sel)   # per-task recursion guard
        self.assertIn("unregister_kprobe", sel)      # clean unhook path
        # no leftover fake five-point probe names
        self.assertNotIn("samsung_context_kprobe", sel)

    def test_init_order_documented_and_called(self):
        patch = (P7K / "0033-samsung-kbuild-init-order.patch").read_text(encoding="utf-8")
        order = ["ksu_init_symbol_resolver", "ksu_samsung_kdp_init", "prepare_creds",
                 "ksu_samsung_defex_init", "ksu_selinux_inode_init"]
        pos = [patch.index(tok) for tok in order]
        self.assertEqual(pos, sorted(pos), "init.c Samsung order is not monotonic")
        self.assertIn("ksu_samsung_kdp_exit", patch)  # kdp failure rollback

    def test_late_load_exynos_double_name(self):
        late = (P7K / "0034-samsung-exynos-double-name.patch").read_text(encoding="utf-8")
        for token in ("-exynos_kernelsu.ko", "KSUD_TREE", "exynos", "{kmi}_kernelsu.ko"):
            self.assertIn(token, late)
        # 0028 stays intact and keeps --soft-reboot safe no-op
        p28 = (P7K / "0028-ghostsam-late-load-compat.patch").read_text(encoding="utf-8")
        self.assertIn("--soft-reboot", p28)
        self.assertIn("MapleSU Manager", p28)

    def test_build_scripts_product_and_exynos_naming(self):
        for rel in ("third_party/kernelsu/scripts/build_ksud.sh",
                    "third_party/kernelsu/scripts/build_userland.sh"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertIn("ksud-maplesu", text)
            self.assertIn("KSUD_TREE", text)
            self.assertIn("exynos", text)

    def test_workflow_matrix_and_triggers(self):
        wf = (ROOT / ".github" / "workflows" / "ghostsam-build.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch", wf)
        self.assertIn("push", wf)
        for kmi in ("android12-5.10", "android13-5.10", "android13-5.15", "android14-5.15",
                    "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18"):
            self.assertIn(kmi, wf)
        for token in ("ksud-maplesu", "exynos", "build_lkm.sh", "build_ksud.sh"):
            self.assertIn(token, wf)

    def test_dry_run_full_series_applies(self):
        applied = d.samsung_apply_dry_run(KROOT)
        self.assertEqual(applied["appliedCount"], 33)  # 26 base + 0028 + six samsung
        self.assertEqual(applied["appliedEntries"][-1], "0034-samsung-exynos-double-name.patch")

    def test_no_forbidden_tokens_in_samsung_added_lines(self):
        for meta in self.samsung_info["samsungPatches"]:
            for ln in meta["added"]:
                low = ln.lower()
                for bad in d.FORBIDDEN_ADDED:
                    self.assertNotIn(bad.lower(), low, f"{meta['name']}: forbidden {bad!r} in {ln!r}")


if __name__ == "__main__":
    unittest.main()
