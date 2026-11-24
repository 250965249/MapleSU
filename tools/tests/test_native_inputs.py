import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import prepare_native_inputs as inputs
import build_module_tools as module_tools
import native_toolchain


class NativeInputsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.data = b"pinned input\n"
        self.record = {
            "repository": "https://github.com/owner/project", "commit": "a" * 40,
            "source_path": "inputs/tool", "path": "inputs/tool",
            "bytes": len(self.data), "sha256": hashlib.sha256(self.data).hexdigest(),
        }

    def test_download_verifies_bytes_before_publishing(self):
        with patch.object(inputs, "urlopen", return_value=io.BytesIO(self.data)) as fetch:
            self.assertEqual(inputs.prepare(self.root, self.record), "downloaded")
        self.assertEqual((self.root / self.record["path"]).read_bytes(), self.data)
        self.assertEqual(fetch.call_args.args[0], "https://raw.githubusercontent.com/owner/project/" + "a" * 40 + "/inputs/tool")

    def test_bad_download_is_not_published(self):
        with patch.object(inputs, "urlopen", return_value=io.BytesIO(b"changed")):
            with self.assertRaisesRegex(ValueError, "mismatch"):
                inputs.prepare(self.root, self.record)
        self.assertFalse((self.root / self.record["path"]).exists())

    def test_existing_different_input_is_preserved(self):
        target = self.root / self.record["path"]
        target.parent.mkdir()
        target.write_bytes(b"local input")
        with patch.object(inputs, "urlopen") as fetch:
            with self.assertRaisesRegex(ValueError, "mismatch"):
                inputs.prepare(self.root, self.record)
            fetch.assert_not_called()
        self.assertEqual(target.read_bytes(), b"local input")

    def test_check_does_not_fetch_missing_input(self):
        with patch.object(inputs, "urlopen") as fetch:
            with self.assertRaisesRegex(ValueError, "Missing"):
                inputs.prepare(self.root, self.record, check_only=True)
            fetch.assert_not_called()

    def test_existing_input_is_verified_offline(self):
        target = self.root / self.record["path"]
        target.parent.mkdir()
        target.write_bytes(self.data)
        with patch.object(inputs, "urlopen") as fetch:
            self.assertEqual(inputs.prepare(self.root, self.record, check_only=True), "verified")
            fetch.assert_not_called()

    def test_paths_outside_workspace_are_rejected(self):
        self.record["path"] = "../outside"
        with self.assertRaisesRegex(ValueError, "leaves"):
            inputs.prepare(self.root, self.record)

    def test_source_commit_is_required(self):
        self.record["commit"] = "main"
        with self.assertRaisesRegex(ValueError, "full source commit"):
            inputs.source_url(self.record)

    def test_vendored_source_verifies_without_git(self):
        source = self.root / "src"
        source.mkdir()
        (source / "Cargo.lock").write_bytes(b"lock\r\n")
        manifest = {"commit": module_tools.COMMIT, "hash_normalization": "CRLF to LF",
                    "files": {"Cargo.lock": hashlib.sha256(b"lock\n").hexdigest()}}
        (self.root / "SOURCE.json").write_text(json.dumps(manifest), encoding="utf-8")
        with patch.object(module_tools, "KSU_PROPS", self.root), patch.object(module_tools, "KSU_PROPS_SRC", source), patch.object(module_tools, "ROOT", self.root):
            report = {}
            module_tools.verify_pinned_checkout(report)
            self.assertEqual(report["pinnedCheckout"]["filesVerified"], 1)
            (source / "Cargo.lock").write_bytes(b"changed\n")
            with self.assertRaisesRegex(SystemExit, "source changed"):
                module_tools.verify_pinned_checkout({})

    def test_dispatch_check_runs_without_a_research_checkout(self):
        project = self.root / "host"
        (project / "src").mkdir(parents=True)
        (project / "src/main.rs").write_text("", encoding="utf-8")
        with patch.object(module_tools, "PROJECT", project), patch.object(module_tools, "ROOT", TOOLS.parent):
            with self.assertRaisesRegex(SystemExit, "dispatch"):
                module_tools.verify_contract({})

    def test_ndk_host_directory_is_selected_for_each_platform(self):
        for platform, tag in (("win32", "windows-x86_64"), ("linux", "linux-x86_64"), ("darwin", "darwin-x86_64")):
            directory = self.root / "toolchains/llvm/prebuilt" / tag / "bin"
            directory.mkdir(parents=True)
            with patch.object(native_toolchain.sys, "platform", platform):
                self.assertEqual(native_toolchain.ndk_bin(self.root), directory)

    def test_toolchains_are_found_from_the_environment_never_from_a_machine_path(self):
        sdk = self.root / "sdk"
        for relative in ("ndk/28.2.13676358/source.properties", "platforms/android-37.0/android.jar",
                         "platform-tools/adb", "platform-tools/adb.exe"):
            (sdk / relative).parent.mkdir(parents=True, exist_ok=True)
            (sdk / relative).write_bytes(b"")
        jdk = self.root / "jdk"
        for name in ("java", "java.exe"):
            (jdk / "bin").mkdir(parents=True, exist_ok=True)
            (jdk / "bin" / name).write_bytes(b"")
        clean = {key: value for key, value in os.environ.items()
                 if key not in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "MAPLESU_PROVIDER_NDK", "JAVA_HOME", "ADB")}
        with patch.dict("os.environ", clean, clear=True):
            self.assertEqual(Path(native_toolchain.UNSET_PROVIDER_NDK), native_toolchain.provider_ndk())
            self.assertFalse(native_toolchain.provider_ndk().exists())
            self.assertEqual(Path("android.jar"), native_toolchain.android_jar())
        with patch.dict("os.environ", {**clean, "ANDROID_SDK_ROOT": str(sdk)}, clear=True):
            self.assertEqual(sdk / "ndk/28.2.13676358", native_toolchain.provider_ndk())
            self.assertEqual(sdk / "platforms/android-37.0/android.jar", native_toolchain.android_jar())
            self.assertTrue(native_toolchain.adb_tool().startswith(str(sdk / "platform-tools" / "adb")))
        override = {**clean, "ANDROID_HOME": str(sdk), "MAPLESU_PROVIDER_NDK": str(self.root / "ndk-r28c"),
                    "JAVA_HOME": str(jdk), "ADB": "custom-adb"}
        with patch.dict("os.environ", override, clear=True):
            self.assertEqual(self.root / "ndk-r28c", native_toolchain.provider_ndk())
            self.assertEqual(self.root / "explicit", native_toolchain.provider_ndk(str(self.root / "explicit")))
            self.assertEqual("custom-adb", native_toolchain.adb_tool())
            self.assertEqual("explicit-adb", native_toolchain.adb_tool("explicit-adb"))
            self.assertEqual(jdk / "bin" / ("java.exe" if os.name == "nt" else "java"),
                             native_toolchain.jdk_tool("java"))
        with patch.dict("os.environ", {**clean, "JAVA_HOME": str(self.root / "no-jdk")}, clear=True):
            with patch.object(native_toolchain.shutil, "which", return_value="/usr/bin/javac"):
                self.assertEqual(Path("/usr/bin/javac"), native_toolchain.jdk_tool("javac"))
            with patch.object(native_toolchain.shutil, "which", return_value=None):
                self.assertEqual(Path("javac"), native_toolchain.jdk_tool("javac"))

    def test_policy_offline_preparation_never_clones(self):
        run = subprocess.run([sys.executable, str(TOOLS / "build_module_policy.py"), "--prepare-only",
                              "--offline", "--selinux-source", str(self.root / "absent")],
                             capture_output=True, text=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("--prepare-only first", run.stderr)
        self.assertFalse((self.root / "absent").exists())


if __name__ == "__main__":
    unittest.main()
