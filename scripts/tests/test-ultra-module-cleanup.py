"""Exercise the production Ultra module removal script in private host fixtures; no build/device."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "manager/src/main/assets/maplesu/modules/cleanup.sh"
BASH = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"


def shell_path(path):
    value = Path(path).resolve().as_posix()
    return "/" + value[0].lower() + value[2:] if os.name == "nt" else value


class UltraModuleCleanupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ultra-cleanup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = shell_path(self.root)
        self.env = dict(os.environ, MSYS_NO_PATHCONV="1", TEST_ROOT=self.base)
        for name in list(self.env):
            if name.startswith(("KSU", "MAPLESU_", "MAGISK")):
                self.env.pop(name)
        self.env["PATH"] = self.base + "/bin:/usr/bin:/bin"
        self.env["MAPLESU_CLEANUP_BUSYBOX"] = self.base + "/bin/busybox"
        self.write("bin/id", "#!/bin/bash\necho 0\n")
        self.write("bin/getprop", '#!/bin/bash\ncase "$1" in *abi) echo arm64-v8a ;; *) echo 36 ;; esac\n')
        self.write("mountinfo", "")
        self.write("bin/readlink", '''#!/bin/bash
if [ "$*" = "-f $TEST_ROOT/adb/metamodule" ] && [ -f "$TEST_ROOT/meta-target" ]; then
  cat "$TEST_ROOT/meta-target"
else
  exec /usr/bin/readlink "$@"
fi
''')
        self.write("bin/busybox", '''#!/bin/bash
command=$1; shift
case "$command" in
 sh) exec /bin/bash "$@" ;;
 timeout) shift 3; exec "$@" ;;
 mktemp) exec /usr/bin/mktemp "$@" ;;
 umount) printf 'umount %s\\n' "$*" >> "$TEST_ROOT/trace" ;;
 rm)
   for arg in "$@"; do
     case "$arg" in -*) ;; "$TEST_ROOT"/*) ;; *) echo OUTSIDE_FIXTURE >&2; exit 95 ;; esac
   done
   if [ "${FAIL_REMOVE:-}" != "" ] && [ "${*: -1}" = "$FAIL_REMOVE" ]; then exit 74; fi
   exec /usr/bin/rm "$@" ;;
 *) echo UNEXPECTED_APPLET >&2; exit 96 ;;
esac
''')
        text = SCRIPT.read_text(encoding="utf-8")
        text = text.replace("/data/adb", self.base + "/adb")
        text = text.replace("/metadata", self.base + "/metadata")
        text = text.replace("/proc/self/mountinfo", self.base + "/mountinfo")
        text = text.replace("/system/bin/getprop", "getprop")
        text = text.replace("/system/bin/sh", "/bin/bash")
        self.write("cleanup.sh", 'export PATH="$TEST_ROOT/bin:/usr/bin:/bin"\n' + text)
        (self.root / "adb/modules").mkdir(parents=True)

    def write(self, name, text):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8", newline="\n")
        file.chmod(0o755)
        return file

    def module(self, name="fixture", tree="modules", script=None, meta=False):
        self.write(f"adb/{tree}/{name}/module.prop", f"id={name}\nmetamodule={'true' if meta else 'false'}\n")
        if script is not None:
            self.write(f"adb/{tree}/{name}/uninstall.sh", script)
        return self.base + f"/adb/{tree}/{name}"

    def provider(self, disabled=False):
        path = self.module("provider", meta=True, script='echo provider >> "$TEST_ROOT/trace"\n')
        self.write("meta-target", path + "\n")
        self.write("adb/metamodule/module.prop", "id=provider\nmetamodule=true\n")
        self.write("adb/metamodule/metauninstall.sh", 'echo "meta:$MODULE_ID:$KSU_MODULE" >> "$TEST_ROOT/trace"\n')
        if disabled:
            self.write("adb/metamodule/disable", "")
        return path

    def run_phase(self, *args, code=0):
        result = subprocess.run([BASH, shell_path(self.root / "cleanup.sh"), *args], env=self.env,
                                cwd=self.root, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=15)
        self.assertEqual(code, result.returncode, result.stdout + result.stderr)
        return result.stdout

    def remove_all(self):
        lines = self.run_phase("list").splitlines()
        modules = sorted(tuple(line.split("\t")[1:]) for line in lines)
        for _, path in modules:
            self.run_phase("uninstall", path)
        self.assertIn("MODULE_CLEANUP_OK", self.run_phase("finish"))

    def trace(self):
        path = self.root / "trace"
        return path.read_text().splitlines() if path.exists() else []

    def test_inventory_does_not_modify_modules_or_disabled_markers(self):
        self.module(script='echo uninstall >> "$TEST_ROOT/trace"\n')
        self.write("adb/modules/fixture/disable", "")
        self.run_phase("list")
        self.assertTrue((self.root / "adb/modules/fixture/disable").exists())
        self.assertEqual([], self.trace())

    def test_disabled_module_still_runs_uninstaller(self):
        self.module(script='echo uninstall >> "$TEST_ROOT/trace"\n')
        self.write("adb/modules/fixture/disable", "")
        self.remove_all()
        self.assertEqual(["uninstall"], self.trace())

    def test_uninstaller_owns_argv_cwd_and_ksu_environment(self):
        path = self.module(script='printf "%s|%s|%s|%s|%s\\n" "$0" "$PWD" "$KSU_MODULE" "$KSU" "$BOOTMODE" >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        row = self.trace()[0].split("|")
        self.assertTrue(row[0].endswith("/adb/modules/fixture/uninstall.sh"))
        self.assertTrue(row[1].endswith("/adb/modules/fixture"))
        self.assertEqual(["fixture", "true", "true"], row[2:])

    def test_ui_print_works_before_tools_are_deployed_and_stays_silent(self):
        path = self.module(script='set -e\nui_print "uninstalling"\n'
                           'echo after-ui-print >> "$TEST_ROOT/trace"\n')
        result = self.run_phase("uninstall", path)
        self.assertNotIn("MODULE_UNINSTALL_WARNING", result)
        self.assertEqual(["after-ui-print"], self.trace())
        self.assertEqual([], list((self.root / "adb").glob(".maplesu-uninstall.*")))

    def test_provider_hook_then_own_script_then_provider_removal(self):
        self.provider()
        self.module(script='echo own >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["meta:fixture:provider", "own", "provider"], self.trace())

    def test_provider_hook_runs_without_own_uninstaller(self):
        self.provider()
        self.module()
        self.remove_all()
        self.assertEqual(["meta:fixture:provider", "provider"], self.trace())

    def test_provider_is_discovered_when_metamodule_link_is_missing(self):
        self.module("provider", meta=True, script='echo provider >> "$TEST_ROOT/trace"\n')
        self.write("adb/modules/provider/metauninstall.sh", 'echo "meta:$MODULE_ID:$KSU_MODULE" >> "$TEST_ROOT/trace"\n')
        self.module(script='echo own >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["meta:fixture:provider", "own", "provider"], self.trace())

    def test_provider_pointer_is_removed_before_its_own_uninstaller(self):
        self.provider()
        self.write("adb/modules/provider/uninstall.sh",
                   'if [ -e "$TEST_ROOT/adb/metamodule" ]; then echo stale-provider; else echo removed; fi >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["removed"], self.trace())

    def test_empty_or_absent_module_root_can_be_cleaned_repeatedly(self):
        self.remove_all()
        (self.root / "adb/modules").rmdir()
        self.remove_all()
        self.assertFalse((self.root / "adb/modules").exists())
        self.assertEqual([], self.trace())

    def test_disabled_provider_does_not_run_hook(self):
        self.provider(disabled=True)
        self.module(script='echo own >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["own", "provider"], self.trace())

    def test_failing_provider_hook_does_not_skip_own_uninstaller(self):
        self.provider()
        self.write("adb/metamodule/metauninstall.sh", "exit 7\n")
        self.module(script='echo own >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["own", "provider"], self.trace())

    def test_failing_module_script_is_reported_but_tree_removed_like_ksu(self):
        path = self.module(script="exit 9\n")
        result = self.run_phase("uninstall", path)
        self.assertIn("MODULE_UNINSTALL_WARNING\tfixture\t9", result)
        self.assertFalse((self.root / "adb/modules/fixture").exists())

    def test_pending_update_of_live_module_does_not_uninstall_twice(self):
        self.module(script='echo live >> "$TEST_ROOT/trace"\n')
        self.module(tree="modules_update", script='echo pending >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["live"], self.trace())
        self.assertFalse((self.root / "adb/modules_update").exists())

    def test_pending_only_module_runs_its_cleanup(self):
        self.module(tree="modules_update", script='echo pending >> "$TEST_ROOT/trace"\n')
        self.remove_all()
        self.assertEqual(["pending"], self.trace())

    def test_known_residue_and_parked_copies_are_removed_other_files_remain(self):
        for name in ["modules/.hidden/file", "modules/stale.invalid/file", "modules_update/old/file",
                     "ksu/module_configs/old/persist.config", "ksu/hot_install_trash/old/file",
                     "maplesu/module-transactions/old/next", "modules.img", "modules_update.img",
                     "maplesu-workmode/modes/KSU/data/data/adb/modules/old/module.prop"]:
            self.write("adb/" + name, "residue")
        self.write("metadata/vold/ksu/modules.rc", "module init")
        self.write("metadata/vold/ksu/preinit/old/file", "module preinit")
        self.write("adb/ksu/.allowlist", "root grants")
        self.write("adb/ksu/ksu_backup_fixture", "boot backup")
        self.write("metadata/vold/ksu/other", "unrelated")
        self.remove_all()
        self.assertEqual([], list((self.root / "adb/modules").iterdir()))
        self.assertFalse((self.root / "metadata/vold/ksu/modules.rc").exists())
        self.assertTrue((self.root / "adb/ksu/.allowlist").exists())
        self.assertTrue((self.root / "adb/ksu/ksu_backup_fixture").exists())
        self.assertTrue((self.root / "metadata/vold/ksu/other").exists())

    def test_mounts_are_detached_inside_module_only_deepest_first(self):
        path = self.module()
        self.write("mountinfo", f"1 0 0:0 / {path} rw - tmpfs tmpfs rw\n2 1 0:0 / {path}/system rw - tmpfs tmpfs rw\n3 0 0:0 / /unrelated rw - tmpfs tmpfs rw\n")
        self.run_phase("uninstall", path)
        self.assertEqual([f"umount -l {path}/system", f"umount -l {path}"], self.trace())

    def test_path_traversal_is_rejected(self):
        self.module()
        self.write("outside/proof", "keep")
        self.run_phase("uninstall", self.base + "/adb/modules/../../outside", code=1)
        self.assertTrue((self.root / "outside/proof").exists())

    def test_removal_failure_does_not_report_success(self):
        path = self.module()
        self.env["FAIL_REMOVE"] = path
        self.run_phase("uninstall", path, code=74)
        self.assertTrue((self.root / "adb/modules/fixture").exists())

    def test_dialog_copy_is_exact_and_locales_have_matching_keys(self):
        values = {}
        for locale in ("values", "values-zh-rCN"):
            tree = ET.parse(ROOT / f"manager/src/main/res/{locale}/install_sources.xml")
            values[locale] = {row.attrib["name"]: row.text for row in tree.getroot()}
        self.assertEqual(values["values"].keys(), values["values-zh-rCN"].keys())
        self.assertEqual("是否保留原有模块？", values["values-zh-rCN"]["install_keep_modules_title"])
        self.assertEqual("可能会影响MapleSU_Ultra无痕效果且因模块而修改策略", values["values-zh-rCN"]["install_keep_modules_body"])
        self.assertEqual("否", values["values-zh-rCN"]["install_keep_modules_no"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
