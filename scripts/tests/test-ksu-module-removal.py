"""Compile the production Kotlin removal generator and execute its shell in private fixtures."""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import tempfile
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get("MAPLESU_REMOVAL_SOURCE", ROOT))
BASH = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"


def shell_path(path):
    value = Path(path).resolve().as_posix()
    return "/" + value[0].lower() + value[2:] if os.name == "nt" else value


def quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


def removal_shell(root, revision, metadata, identity):
    result = subprocess.run([str(KsuModuleRemovalTest.java), "-cp", KsuModuleRemovalTest.classpath,
        "dev.maplesu.manager.modules.RemovalShellGeneratorKt", root, revision, metadata, identity],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


class KsuModuleRemovalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tools/specgen"))
        from specgen.product import cached_jar
        cls.work = tempfile.TemporaryDirectory(prefix="ksu-removal-kotlin-")
        cls.addClassCleanup(cls.work.cleanup)
        work = Path(cls.work.name)
        cls.java = Path(shutil.which("java") or "java")
        stdlib = cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20")
        annotations = cached_jar("org.jetbrains", "annotations", "13.0")
        compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
        coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
        generator = work / "RemovalShellGenerator.kt"
        generator.write_text('''package dev.maplesu.manager.modules
fun main(args: Array<String>) {
    var command: String? = null
    val runner = ModuleScriptRunner { script -> command = script; ModuleScriptOutput(0) }
    val tree = RootModuleTree(runner, args[0] + "/modules", args[0] + "/maplesu/module-transactions")
    tree.remove("fixture", args[1], args[2], args[3])
    print(requireNotNull(command))
}
''', encoding="utf-8")
        sources = [SOURCE / "manager/src/main/java/dev/maplesu/manager/modules/RootModuleTree.kt",
            SOURCE / "manager/src/main/java/dev/maplesu/manager/modules/webui/ModuleWebUiSessions.kt",
            ROOT / "manager/src/test/resources/root-tree-session-shell/Boundaries.kt", generator]
        cls.classpath = os.pathsep.join(map(str, [work / "classes", stdlib]))
        command = [str(cls.java), "-Xmx512m", "-cp",
            os.pathsep.join(map(str, [compiler, stdlib, annotations, coroutines])),
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-nowarn",
            "-jvm-target", "17", "-classpath", str(stdlib), "-d", str(work / "classes"),
            *map(str, sources)]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ksu-removal-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = shell_path(self.root)
        self.adb = self.base + "/adb"
        self.env = dict(os.environ, TEST_ROOT=self.base, MSYS_NO_PATHCONV="1")
        if os.name == "nt":
            self.env["MSYS"] = "winsymlinks:nativestrict"
        self.env["PATH"] = "/usr/bin:/bin"
        self.module = self.root / "adb/modules/fixture"
        self.module.mkdir(parents=True)
        (self.module / "module.prop").write_text("id=fixture\nname=Fixture\n", encoding="utf-8", newline="\n")
        self.metadata = hashlib.sha256((self.module / "module.prop").read_bytes()).hexdigest()
        tools = self.root / "adb/maplesu/bin"
        tools.mkdir(parents=True)
        (tools / "maplesu-tools").write_text("""#!/bin/sh
set -eu
case "$1" in
    module-initrc) exit 0 ;;
    module-sync) shift ;;
    *) exit 64 ;;
esac
if [ "${1:-}" = --tree ]; then shift; fi
for target do sync -f "$target"; done
""", encoding="utf-8", newline="\n")
        self.run_shell("chmod 0755 " + quote(self.adb + "/maplesu/bin/maplesu-tools"))


    def run_shell(self, script, code=0):
        result = subprocess.run([BASH, "-c", script], env=self.env, cwd=self.root,
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(code, result.returncode, result.stdout + result.stderr)
        return result

    def identity(self):
        return self.run_shell("stat -c '%d:%i' " + quote(self.adb + "/modules/fixture")).stdout.strip()

    def remove(self, owned=False, identity=None, code=0):
        identity = identity or self.identity()
        revision = "a" * 64 if owned else ""
        if owned:
            (self.module / ".maplesu-ultra").write_text(revision + "\n")
        return self.run_shell(removal_shell(self.adb, revision, self.metadata, identity), code=code)

    def test_retained_module_is_removed_from_standard_path(self):
        self.remove()
        self.assertFalse(self.module.exists())

    def test_owned_module_is_removed_from_standard_path(self):
        self.remove(owned=True)
        self.assertFalse(self.module.exists())

    def test_same_id_update_is_removed_to_prevent_reappearance_after_boot(self):
        update = self.root / "adb/modules_update/fixture"
        update.mkdir(parents=True)
        (update / "module.prop").write_text("id=fixture\nversionCode=2\n")
        self.remove()
        self.assertFalse(update.exists(), "the staged update can restore the removed module on reboot")

    def test_owned_module_update_is_also_removed(self):
        update = self.root / "adb/modules_update/fixture"
        update.mkdir(parents=True)
        self.remove(owned=True)
        self.assertFalse(update.exists())

    def test_only_removed_module_configuration_is_cleared(self):
        config = self.root / "adb/ksu/module_configs/fixture"
        other = self.root / "adb/ksu/module_configs/other"
        config.mkdir(parents=True)
        other.mkdir()
        self.remove()
        self.assertFalse(config.exists())
        self.assertTrue(other.is_dir())

    def test_identity_mismatch_preserves_module_and_update(self):
        update = self.root / "adb/modules_update/fixture"
        update.mkdir(parents=True)
        self.remove(identity="0:0", code=1)
        self.assertTrue(self.module.is_dir())
        self.assertTrue(update.is_dir())

    def test_changed_metadata_preserves_module(self):
        (self.module / "module.prop").write_text("id=fixture\nname=Replacement\n")
        self.remove(code=1)
        self.assertTrue(self.module.is_dir())

    def test_owned_revision_mismatch_preserves_module(self):
        (self.module / ".maplesu-ultra").write_text("b" * 64 + "\n")
        self.run_shell(removal_shell(self.adb, "a" * 64, self.metadata, self.identity()), code=1)
        self.assertTrue(self.module.is_dir())

    def test_failed_directory_removal_keeps_ownership_for_retry(self):
        identity = self.identity()
        owners = self.root / "adb/modules/.maplesu-ultra"
        owners.mkdir()
        owner = owners / identity.replace(":", "-")
        owner.write_text("a" * 64 + "\n")
        block = ('rm() { if [ "$1" = -rf ] && [ "$3" = ' + quote(self.adb + "/modules/fixture") +
                 ' ]; then return 74; fi; command rm "$@"; }\n')
        self.run_shell(block + removal_shell(self.adb, "a" * 64, self.metadata, identity), code=74)
        self.assertTrue(self.module.is_dir())
        self.assertTrue(owner.is_file())

    def test_successful_rm_without_deletion_is_detected(self):
        self.run_shell("rm() { return 0; }\n" +
                       removal_shell(self.adb, "", self.metadata, self.identity()), code=1)
        self.assertTrue(self.module.is_dir())

    def test_update_still_present_blocks_pruning_the_live_tree(self):
        pending = self.root / "adb/modules_update/fixture"
        pending.mkdir(parents=True)
        block = ('rm() { if [ "${3:-}" = ' + quote(self.adb + "/modules_update/fixture") +
                 ' ]; then return 0; fi; command rm "$@"; }\n')
        self.run_shell(block + removal_shell(self.adb, "", self.metadata, self.identity()), code=1)
        self.assertTrue(self.module.is_dir())
        self.assertTrue(pending.is_dir())

    def test_redirected_update_parent_is_rejected_before_deleting_anything(self):
        outside = self.root / "other"
        outside.mkdir()
        self.run_shell("ln -s " + quote(self.base + "/other") + " " + quote(self.adb + "/modules_update"))
        self.run_shell("test -L " + quote(self.adb + "/modules_update"))
        self.remove(code=1)
        self.assertTrue(outside.is_dir())
        self.assertTrue(self.module.is_dir())

    def test_pending_symlink_does_not_delete_its_target(self):
        outside = self.root / "other"
        outside.mkdir()
        self.run_shell("mkdir -p " + quote(self.adb + "/modules_update") + "\nln -s " +
                       quote(self.base + "/other") + " " + quote(self.adb + "/modules_update/fixture"))
        self.run_shell("test -L " + quote(self.adb + "/modules_update/fixture"))
        self.remove()
        self.assertTrue(outside.is_dir())
        self.run_shell("test ! -L " + quote(self.adb + "/modules_update/fixture"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
