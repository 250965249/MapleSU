"""Generate the real root script, then run it against temporary shell fixtures."""
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from test_restore import BASH, ROOT


class UltraDeliveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ghostlock-delivery-")
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        if os.name == "nt":
            candidates = sorted((ROOT.parents[1] / ".research/toolchains").glob(
                "llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe"))
            compiler = candidates[-1] if candidates else None
        else:
            compiler = shutil.which("c++")
        if not compiler or not BASH:
            raise unittest.SkipTest("host C++ compiler and bash are required")
        headers = {
            "attack/ops.hpp": "namespace ghostlock::attack { void write_root_script(); }\n",
            "session/runtime_config.h": "#pragma once\n#include <string>\n"
                "namespace ghostlock::config { struct Runtime { std::string root_script_path; }; "
                "inline Runtime runtime; inline Runtime& runtime_config_snapshot() { return runtime; } }\n",
            "support/fatal_error.hpp": "struct FatalError {};\n",
            "restore_script.hpp": "static const char maplesu_ghostlock_restore_script[] = R\"RESTORE("
                + (ROOT / "adapter/restore.sh").read_text(encoding="utf-8") + ")RESTORE\";\n",
        }
        for name, content in headers.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        main = directory / "main.cpp"
        main.write_text(r'''
#include "handoff.hpp"
#include "attack/ops.hpp"
#include "session/runtime_config.h"
namespace maplesu::ghostlock_adapter { Configuration configuration; }
int main(int argc, char** argv) {
    if (argc != 3) return 64;
    auto& config = maplesu::ghostlock_adapter::configuration;
    config.home = "./home"; config.target = argv[1]; config.attempt = "attempt-1";
    config.helper = "maplesu_fixture_helper"; config.consumer = "./consumer.sh";
    config.enforcing = argv[2][0] - '0'; config.checkreqprot = -2;
    config.arguments = {"endpoint", "NONCE_FIXTURE", "10001", "boot-1", "ghostlock"};
    ghostlock::config::runtime.root_script_path = config.home + "/.ghostlock_root.sh";
    ghostlock::attack::write_root_script();
}
''', encoding="utf-8")
        cls.exe = directory / ("generate.exe" if os.name == "nt" else "generate")
        build = subprocess.run([str(compiler), "-std=c++17", "-static", "-DO_NOFOLLOW=0", "-DO_CLOEXEC=0",
                                "-I" + str(directory), "-I" + str(ROOT / "adapter"),
                                str(ROOT / "adapter/handoff.cpp"), str(main), "-o", str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stderr)

    def run_script(self, target, handover=0, *, deny_after_restore=False, helper_restores=True,
                   policy_succeeds=True, status_window=False, entry_enforcing=1):
        with tempfile.TemporaryDirectory(dir=self.temp.name) as temp:
            directory = Path(temp)
            (directory / "home").mkdir()
            subprocess.run([str(self.exe), target, str(entry_enforcing)], cwd=directory,
                           check=True, capture_output=True)
            path = directory / "home/.ghostlock_root.sh"
            original = path.read_text(encoding="utf-8")
            policy = bytearray(24)
            policy[:15] = bytes.fromhex("8cff7cf9080000005345204c696e7578")
            (directory / "policy").write_bytes(policy)
            (directory / "status").write_bytes(struct.pack('<5I', 1, 2, 1, 0, 1) if status_window else bytes(16))
            (directory / "enforce").write_text("0\n")
            consumer = directory / "consumer.sh"
            consumer.write_text("#!/bin/sh\nprintf 'called\\n' > consumer.called\n", newline="\n")
            consumer.chmod(0o700)
            prefix = (f"FIXTURE=\"$PWD\"\nHANDOVER_EXIT={handover}\n"
                      f"DENY_AFTER_RESTORE={int(deny_after_restore)}\n"
                      f"HELPER_RESTORES={int(helper_restores)}\n"
                      f"STATUS_WINDOW={int(status_window)}\n"
                      f"POLICY_SUCCEEDS={int(policy_succeeds)}\n") + r'''
id() { echo 0; }
sleep() { if [ "$1" = 8 ]; then command sleep .5; fi; }
load_policy() {
  [ "$POLICY_SUCCEEDS" = 1 ] || return 1
  printf '\001\000\000\000' | dd of="$FIXTURE/status" bs=1 seek=12 count=4 conv=notrunc 2>/dev/null
  if [ "$STATUS_WINDOW" = 1 ]; then
    printf '\004\000\000\000' | dd of="$FIXTURE/status" bs=1 seek=4 count=4 conv=notrunc 2>/dev/null
  fi
}
maplesu_fixture_helper() {
  printf 'called\n' > "$FIXTURE/helper.called"
  if [ "$HELPER_RESTORES" = 1 ]; then
    printf '1\n' > "$FIXTURE/enforce"
    printf 'restored\n' > "$FIXTURE/helper.restored"
  fi
  return "$HANDOVER_EXIT"
}
cat() {
  if [ "$DENY_AFTER_RESTORE" = 1 ] && [ -e "$FIXTURE/helper.restored" ]; then
    printf 'fixture: post-restore pathname access denied\n' >&2
    return 1
  fi
  command cat "$@"
}
'''
            path.write_text(prefix + original.replace("/sys/fs/selinux/", "$FIXTURE/"),
                            encoding="utf-8", newline="\n")
            result = subprocess.run([BASH, "home/.ghostlock_root.sh"], cwd=directory,
                                    capture_output=True, text=True, timeout=10)
            log = (directory / "home/root-worker.log").read_text(encoding="utf-8")
            completion = directory / "home/root-worker-result.json"
            self.worker_result = json.loads(completion.read_text(encoding="utf-8")) if completion.is_file() else None
            window = directory / "home/selinux-window.json"
            self.status_window = json.loads(window.read_text(encoding="utf-8")) if window.is_file() else None
            self.enforcing = (directory / "enforce").read_text().strip()
            return result.returncode, log, (directory / "consumer.called").exists(), original

    def test_ultra_captures_the_status_window_before_repair_and_handover(self):
        code, log, _, _ = self.run_script("ultra", status_window=True, deny_after_restore=True)
        self.assertEqual(0, code, log)
        self.assertIsNotNone(self.status_window, "App EACCES leaves no usable SELinux baseline")
        self.assertEqual("maplesu.selinux.window.v1", self.status_window["schema"])
        self.assertEqual("attempt-1", self.status_window["attempt"])
        self.assertEqual("boot-1", self.status_window["bootId"])
        self.assertEqual([1, 2, 1, 0, 1], self.status_window["before"])
        self.assertEqual([1, 4, 1, 1, 1], self.status_window["after"])
        self.assertEqual(0, self.status_window["restoreFrom"])
        self.assertEqual(1, self.status_window["restoreTo"])

    def test_ultra_finishes_through_hook_receipt_without_raw_lease_consumer(self):
        code, log, consumer, script = self.run_script("ultra")
        self.assertEqual(0, code, log)
        self.assertIn("backend handover exit=0", log)
        self.assertIn("restore verified by shared helper", log)
        self.assertFalse(consumer, log)
        self.assertNotIn("NONCE_FIXTURE", script)

    def test_failed_ultra_handover_still_restores_without_dispatching_a_lease(self):
        code, log, consumer, _ = self.run_script("ultra", handover=65)
        self.assertEqual(65, code, log)
        self.assertIn("handover failed rc=65", log)
        self.assertIn("enforcing restored=1", log)
        self.assertFalse(consumer, log)

    def test_ultra_success_ends_at_shared_helper_without_post_restore_path_access(self):
        code, log, consumer, _ = self.run_script("ultra", deny_after_restore=True)
        self.assertEqual(0, code, log)
        self.assertFalse(consumer, log)
        self.assertNotIn("post-restore pathname access denied", log)

    def test_ultra_early_helper_failure_keeps_outer_restore(self):
        code, log, consumer, _ = self.run_script("ultra", handover=65, helper_restores=False)
        self.assertEqual(65, code, log)
        self.assertIn("enforcing restored=1", log)
        self.assertIn("handover failed rc=65", log)
        self.assertFalse(consumer, log)

    def test_ultra_success_writes_bound_worker_completion_after_restore(self):
        code, log, consumer, _ = self.run_script("ultra", deny_after_restore=True)
        self.assertEqual(0, code, log)
        self.assertFalse(consumer, log)
        self.assertEqual({"schema": "maplesu.ghostlock.worker.v1", "provider": "ghostlock",
                          "bootId": "boot-1", "attempt": "attempt-1", "exitCode": 0},
                         self.worker_result)

    def test_ultra_policy_failure_reports_its_original_exit_without_backend_loading(self):
        code, log, consumer, _ = self.run_script("ultra", policy_succeeds=False)
        self.assertEqual(73, code, log)
        self.assertNotIn("backend handover begin", log)
        self.assertFalse(consumer, log)
        self.assertIsNotNone(self.worker_result, "worker failure must not wait for a backend receipt")
        self.assertEqual(73, self.worker_result["exitCode"])

    def test_ultra_restore_failure_takes_priority_over_backend_failure(self):
        code, log, consumer, _ = self.run_script("ultra", handover=65, deny_after_restore=True)
        self.assertEqual(76, code, log)
        self.assertFalse(consumer, log)
        self.assertEqual(76, self.worker_result["exitCode"])

    def test_normal_keeps_its_existing_consumer_delivery(self):
        code, log, consumer, script = self.run_script("normal")
        self.assertEqual(0, code, log)
        self.assertTrue(consumer, log)
        self.assertIn("consumer dispatch restore=0", log)
        self.assertIn("NONCE_FIXTURE", script)

    def test_successful_normal_handover_keeps_enforcing_from_permissive_entry(self):
        for helper_restores in (True, False):
            with self.subTest(helper_restores=helper_restores):
                code, log, consumer, _ = self.run_script("normal", entry_enforcing=0,
                                                        helper_restores=helper_restores)
                self.assertEqual(0, code, log)
                self.assertTrue(consumer, log)
                self.assertEqual("1", self.enforcing)
                self.assertIn("consumer dispatch restore=0 enforce=1", log)

    def test_failed_normal_handover_restores_permissive_entry(self):
        code, log, consumer, _ = self.run_script("normal", handover=65, entry_enforcing=0)
        self.assertEqual(0, code, log)
        self.assertTrue(consumer, log)
        self.assertEqual("0", self.enforcing)
        self.assertIn("handover failed rc=65", log)


if __name__ == "__main__":
    unittest.main()
