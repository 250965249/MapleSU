"""Execute production module shells with platform calls mapped to isolated fixtures."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ASSETS = Path(os.environ.get("MAPLESU_TEST_MODULE_ASSETS", ROOT / "manager/src/main/assets/maplesu/modules"))
BASH = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"


def shell_path(path):
    value = Path(path).resolve().as_posix()
    return "/" + value[0].lower() + value[2:] if os.name == "nt" else value


class ModuleContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ksu-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = shell_path(self.root)
        self.env = dict(os.environ, MSYS_NO_PATHCONV="1", TEST_ROOT=self.base)
        for name in list(self.env):
            if name.startswith(("KSU", "MAPLESU_", "MAGISK")):
                self.env.pop(name)
        self.env["PATH"] = self.base + "/bin:/usr/bin:/bin"
        self.env["MAPLESU_BIN"] = self.base + "/adb/maplesu/bin"
        for name in ("chown", "chcon"):
            self.write("bin/" + name, "#!/bin/bash\nexit 0\n")
        self.write("bin/chmod", '#!/bin/bash\nprintf "%s\\n" "$*" >> "$TEST_ROOT/permissions"\nexec /usr/bin/chmod "$@"\n')
        self.write("bin/getprop", "#!/bin/bash\necho 36\n")
        self.write("bin/readlink", '''#!/bin/bash
case "$*" in
 /proc/self/ns/mnt) echo "${FIXTURE_NS:-init}" ;;
 /proc/1/ns/mnt) echo init ;;
 *) exec /usr/bin/readlink "$@" ;;
esac
''')
        self.write("adb/maplesu/bin/busybox", '''#!/bin/bash
case "$1" in
 sh) shift; exec /bin/bash "$@" ;;
 nsenter) echo nsenter >> "$TEST_ROOT/trace"; shift 5; export FIXTURE_NS=init; exec "$@" ;;
 unzip) echo bundled-unzip >> "$TEST_ROOT/trace"; exit 0 ;;
 *) command="$1"; shift; exec "$command" "$@" ;;
esac
''')
        for name in ("runner.sh", "legacy-install.sh", "run.sh", "ui-print.sh", "mount.sh"):
            text = (ASSETS / name).read_text(encoding="utf-8")
            text = text.replace("/system/bin/getprop", "getprop")
            text = text.replace("/system/bin/", "/usr/bin/")
            text = text.replace("/usr/bin/sh", "/bin/bash")
            text = text.replace("/data/adb", self.base + "/adb")
            if name == "mount.sh":
                text = text.replace("/proc/sys/kernel/random/boot_id", self.base + "/boot_id")
                text = text.replace("/proc/self/mountinfo", self.base + "/mountinfo")
            self.write(name, 'export PATH="$TEST_ROOT/bin:/usr/bin:/bin"\n' + text)
        # The production tool deployment publishes this independent lifecycle command.
        ui_print = (self.root / "ui-print.sh").read_text(encoding="utf-8")
        self.write("adb/maplesu/bin/ui_print", ui_print.removeprefix('export PATH="$TEST_ROOT/bin:/usr/bin:/bin"\n'))
        self.module = self.root / "adb/modules/fixture"
        self.write("adb/modules/fixture/module.prop", "id=fixture\nname=Fixture\nversionCode=1\n")
        self.write("adb/modules/fixture/customize.sh", 'echo customize >> "$TEST_ROOT/trace"\n')
        self.write("boot_id", "fixture-boot\n")
        self.write("mountinfo", "")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        path.chmod(0o755)
        return path

    def meta(self, install=None, uninstall=None):
        self.write("adb/metamodule/module.prop", "id=meta_fixture\nmetamodule=true\n")
        if install is not None:
            self.write("adb/metamodule/metainstall.sh", install)
        if uninstall is not None:
            self.write("adb/metamodule/metauninstall.sh", uninstall)

    def install(self, code=0):
        return self.run_shell("runner.sh", shell_path(self.module), "customize.sh",
                              self.base + "/archive.zip", self.base + "/legacy-install.sh", code=code)

    def run_shell(self, name, *args, code=0):
        result = subprocess.run([BASH, shell_path(self.root / name), *args], cwd=self.root,
                                env=self.env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=15)
        self.assertEqual(code, result.returncode, result.stdout + result.stderr)
        return result

    def trace(self):
        path = self.root / "trace"
        return path.read_text().splitlines() if path.exists() else []

    def test_no_modules_and_no_mount_ledger_performs_no_mutations(self):
        for name in ("mkdir", "chmod", "mount", "umount", "chcon", "setenforce"):
            self.write("bin/" + name, '#!/bin/bash\necho unexpected-mutation >> "$TEST_ROOT/trace"\nexit 89\n')
        self.run_shell("mount.sh")
        self.assertEqual([], self.trace())
        self.assertFalse((self.root / "adb/maplesu/module-mounts").exists())

    def test_no_modules_tears_down_only_its_recorded_mounts(self):
        self.write("adb/maplesu/module-mounts/boot", "fixture-boot\n")
        self.write("adb/maplesu/module-mounts/ledger", "500 /system/etc/fixture\n")
        self.write("mountinfo", "500 1 0:1 / /system/etc/fixture ro - tmpfs tmpfs ro\n")
        self.write("bin/umount", '#!/bin/bash\necho "umount:$*" >> "$TEST_ROOT/trace"\n')
        self.write("bin/mount", '#!/bin/bash\necho unexpected-mount >> "$TEST_ROOT/trace"\nexit 89\n')
        self.run_shell("mount.sh")
        self.assertEqual(["umount:/system/etc/fixture"], self.trace())
        self.assertEqual("", (self.root / "adb/maplesu/module-mounts/ledger").read_text())

    def test_foreign_mount_covering_an_owned_mount_is_preserved(self):
        self.write("adb/maplesu/module-mounts/boot", "fixture-boot\n")
        self.write("adb/maplesu/module-mounts/ledger", "500 /system/etc/fixture\n")
        self.write("mountinfo", "500 1 0:1 / /system/etc/fixture ro - tmpfs tmpfs ro\n"
                   "501 1 0:2 / /system/etc/fixture ro - tmpfs other ro\n")
        self.write("bin/umount", '#!/bin/bash\necho unexpected-unmount >> "$TEST_ROOT/trace"\nexit 89\n')
        self.run_shell("mount.sh", code=1)
        self.assertEqual([], self.trace())
        self.assertEqual("500 /system/etc/fixture\n", (self.root / "adb/maplesu/module-mounts/ledger").read_text())

    def test_busy_early_stage_is_reported_in_progress_not_completed(self):
        self.write("adb/modules/fixture/zygisk/arm64-v8a.so", "fixture")
        self.write("adb/modules/fixture/service.sh", "exit 99\n")
        self.write("adb/maplesu_zygisk/early.boot", Path("/proc/sys/kernel/random/boot_id").read_text() if Path("/proc/sys/kernel/random/boot_id").exists() else "")
        self.write("adb/maplesu/bin/busybox", '#!/bin/bash\nif [ "$1" = flock ]; then exit 1; fi\ncommand="$1"; shift; exec "$command" "$@"\n')
        result = self.run_shell("run.sh", shell_path(self.module), "service")
        self.assertEqual("MAPLESU_SCRIPT_STARTED", result.stdout.strip())
        self.assertEqual([], list((self.root / "adb/maplesu/module-boot").glob("*/service")))

    def test_default_installer_runs_customization_once(self):
        self.install()
        self.assertEqual(["customize"], self.trace())

    def test_self_extracting_installer_uses_bundled_unzip(self):
        self.write("bin/unzip", "#!/bin/bash\nexit 87\n")
        self.write("adb/modules/fixture/customize.sh", 'SKIPUNZIP=1\nunzip -o "$ZIPFILE" verify.sh -d "$TMPDIR" || exit $?\n')
        self.install()
        self.assertEqual(["bundled-unzip"], self.trace())

    def test_legacy_installer_uses_bundled_unzip(self):
        self.write("bin/unzip", "#!/bin/bash\nexit 87\n")
        self.write("adb/modules/fixture/install.sh", '''print_modname() { :; }
on_install() { unzip -o "$ZIPFILE" 'common/*' -d "$TMPDIR" || exit $?; }
set_permissions() { :; }
''')
        self.install()
        self.assertEqual(["bundled-unzip"], self.trace())

    def test_modern_installer_preserves_ksu_legacy_version_variables(self):
        self.write("adb/modules/fixture/customize.sh", '''test "$KSU" = true || exit 41
test -z "${MAGISK:-}" || exit 42
test "$MAGISK_VER" = 25.2 && test "$MAGISK_VER_CODE" = 25200 || exit 43
''')
        self.install()

    def test_legacy_installer_preserves_ksu_legacy_version_variables(self):
        self.write("adb/modules/fixture/install.sh", '''print_modname() { :; }
on_install() {
  test "$KSU" = true && test -z "${MAGISK:-}" || exit 42
  test "$MAGISK_VER" = 25.2 && test "$MAGISK_VER_CODE" = 25200 || exit 43
}
set_permissions() { :; }
''')
        self.install()

    def test_magisk_path_call_in_sourced_helper_finds_compat_entry(self):
        self.write("adb/maplesu/bin/compat/magisk", '#!/bin/bash\nprintf /fixture/magisk\n')
        self.write("adb/modules/fixture/util_functions.sh", '''check_modules() {
  test "$(magisk --path)" = /fixture/magisk || exit 44
}
''')
        self.write("adb/modules/fixture/customize.sh",
                   '. "$MODPATH/util_functions.sh"\ncheck_modules\n')
        self.install()

    def test_ksu_detection_does_not_expose_compat_as_another_root(self):
        self.write("adb/maplesu/bin/compat/magisk", '#!/bin/bash\nprintf /fixture/magisk\n')
        self.write("adb/modules/fixture/customize.sh", '''if which magisk >/dev/null 2>&1; then
  exit 45
fi
''')
        self.install()

    def test_module_without_customization_has_default_permissions(self):
        (self.module / "customize.sh").unlink()
        self.write("adb/modules/fixture/payload", "data")
        self.install()
        permissions = (self.root / "permissions").read_text().splitlines()
        self.assertTrue(any(line.startswith("0644 ") and line.endswith("/payload") for line in permissions))

    def test_metainstall_can_wrap_default_installer(self):
        self.meta('echo meta-before >> "$TEST_ROOT/trace"\ninstall_module\n'
                  'echo meta-after >> "$TEST_ROOT/trace"\n')
        self.install()
        self.assertEqual(["meta-before", "customize", "meta-after"], self.trace())

    def test_failed_metainstall_keeps_its_exit_code(self):
        self.meta('echo meta-failed >> "$TEST_ROOT/trace"\nexit 29\n')
        self.install(code=29)
        self.assertEqual(["meta-failed"], self.trace())

    def test_pending_or_disabled_custom_installer_blocks_regular_installation(self):
        self.meta("install_module\n")
        for marker in ("disable", "remove", "update"):
            with self.subTest(marker=marker):
                path = self.write("adb/metamodule/" + marker, "")
                result = self.install(code=1)
                self.assertIn("METAMODULE_INSTALL_BLOCKED", result.stderr)
                self.assertEqual([], self.trace())
                path.unlink()

    def test_metamodule_update_bypasses_its_custom_installer(self):
        self.meta("exit 29\n")
        self.write("adb/metamodule/disable", "")
        self.write("adb/modules/fixture/module.prop", "id=fixture\nmetamodule=TrUe\n")
        self.install()
        self.assertEqual(["customize"], self.trace())

    def test_metamodule_without_custom_installer_allows_default(self):
        self.meta()
        self.write("adb/metamodule/disable", "")
        self.install()
        self.assertEqual(["customize"], self.trace())

    def test_legacy_installation_is_wrapped_by_metainstall(self):
        self.write("adb/modules/fixture/install.sh", '''print_modname() { :; }
on_install() { echo legacy >> "$TEST_ROOT/trace"; }
set_permissions() { :; }
''')
        self.meta('echo meta-before >> "$TEST_ROOT/trace"\ninstall_module\n'
                  'echo meta-after >> "$TEST_ROOT/trace"\n')
        self.install()
        self.assertEqual(["meta-before", "legacy", "meta-after"], self.trace())

    def test_legacy_replace_and_ksu_identity_are_preserved(self):
        self.write("adb/modules/fixture/install.sh", '''print_modname() { :; }
REPLACE='/system/etc/fixture'
on_install() { test "$KSU" = true && test "$KSU_MODULE" = fixture; }
set_permissions() { :; }
''')
        self.install()
        self.assertTrue((self.module / "system/etc/fixture/.replace").is_file())

    def test_customization_failure_is_not_hidden_by_metainstall(self):
        self.write("adb/modules/fixture/customize.sh", "exit 27\n")
        self.meta("install_module\n")
        self.install(code=27)

    def test_replace_variable_creates_marker(self):
        self.write("adb/modules/fixture/customize.sh", "REPLACE='/system/etc/fixture'\n")
        self.install()
        self.assertTrue((self.module / "system/etc/fixture/.replace").is_file())

    def test_runtime_exposes_ksu_module_identity(self):
        self.write("adb/modules/fixture/action.sh",
                   'test "$KSU" = true && test "$KSU_MODULE" = fixture && test "$ASH_STANDALONE" = 1\n')
        self.run_shell("run.sh", shell_path(self.module), "action")

    def test_uninstall_ui_print_and_nested_shell_preserve_exit_code(self):
        self.write("adb/modules/fixture/nested.sh", 'ui_print "nested hook"\nexit 28\n')
        self.write("adb/modules/fixture/uninstall.sh", '''set -e
ui_print "uninstall hook"
"$MAPLESU_BIN/busybox" sh "${0%/*}/nested.sh"
''')
        result = self.run_shell("run.sh", shell_path(self.module), "uninstall", code=28)
        self.assertEqual(["uninstall hook", "nested hook"], result.stdout.splitlines())

    def test_metamount_receives_module_directory_in_init_namespace(self):
        self.env["FIXTURE_NS"] = "private"
        self.write("adb/modules/fixture/metamount.sh", 'test "$MODULE_DIR" = "$TEST_ROOT/adb/modules"\n'
                   'test "$FIXTURE_NS" = init\n')
        self.run_shell("run.sh", shell_path(self.module), "metamount")
        self.assertEqual(["nsenter"], self.trace())

    def test_metauninstall_precedes_module_uninstaller_with_target_identity(self):
        self.meta(uninstall='test "$MODULE_ID" = fixture || exit 33\n'
                  'test "$KSU_MODULE" = meta_fixture || exit 34\n'
                  'echo meta-uninstall >> "$TEST_ROOT/trace"\n')
        self.write("adb/modules/fixture/uninstall.sh", 'echo uninstall >> "$TEST_ROOT/trace"\n')
        self.run_shell("run.sh", shell_path(self.module), "uninstall")
        self.assertEqual(["meta-uninstall", "uninstall"], self.trace())

    def test_metauninstall_also_runs_without_module_uninstaller(self):
        self.meta(uninstall='echo meta-uninstall >> "$TEST_ROOT/trace"\n')
        self.run_shell("run.sh", shell_path(self.module), "uninstall")
        self.assertEqual(["meta-uninstall"], self.trace())

    def test_failed_metauninstall_warns_and_still_runs_module_uninstaller(self):
        self.meta(uninstall="exit 31\n")
        self.write("adb/modules/fixture/uninstall.sh", 'echo uninstall >> "$TEST_ROOT/trace"\n')
        result = self.run_shell("run.sh", shell_path(self.module), "uninstall")
        self.assertIn("MAPLESU_METAUNINSTALL_WARNING:31", result.stderr)
        self.assertEqual(["uninstall"], self.trace())

    def test_failed_provider_without_module_uninstaller_does_not_block_cleanup(self):
        self.meta(uninstall="exit 31\n")
        result = self.run_shell("run.sh", shell_path(self.module), "uninstall")
        self.assertIn("MAPLESU_METAUNINSTALL_WARNING:31", result.stderr)

    def test_disabled_metamodule_skips_uninstall_hook(self):
        self.meta(uninstall="exit 31\n")
        self.write("adb/metamodule/disable", "")
        self.write("adb/modules/fixture/uninstall.sh", 'echo uninstall >> "$TEST_ROOT/trace"\n')
        self.run_shell("run.sh", shell_path(self.module), "uninstall")
        self.assertEqual(["uninstall"], self.trace())

    def test_removing_metamodule_does_not_call_its_own_metauninstall(self):
        self.meta(uninstall="exit 31\n")
        self.write("adb/modules/fixture/module.prop", "id=fixture\nmetamodule=1\n")
        self.write("adb/modules/fixture/uninstall.sh", 'echo uninstall >> "$TEST_ROOT/trace"\n')
        self.run_shell("run.sh", shell_path(self.module), "uninstall")
        self.assertEqual(["uninstall"], self.trace())


if __name__ == "__main__":
    unittest.main(verbosity=2)
