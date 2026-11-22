"""Run the production restore body in Android sh using only temporary files.

Opt in with MAPLESU_GHOSTLOCK_TEST_SERIAL. No provider, actual SELinux path,
kernel module, root operation or reboot is executed.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AndroidRestoreScriptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        serial = os.environ.get("MAPLESU_GHOSTLOCK_TEST_SERIAL")
        if not serial:
            raise unittest.SkipTest("Set MAPLESU_GHOSTLOCK_TEST_SERIAL to run Android shell fixtures")
        adb = os.environ.get("ADB") or shutil.which("adb")
        if not adb:
            raise RuntimeError("adb is required for the Android shell fixture")
        cls.adb = [adb, "-s", serial]

    def fixture(self, *, target="ultra", load="success"):
        remote = subprocess.check_output(self.adb + ["shell", "mktemp", "-d",
            "/data/local/tmp/maplesu-gl-fixture.XXXXXX"], text=True).strip()
        self.assertRegex(remote, r"^/data/local/tmp/maplesu-gl-fixture\.[a-zA-Z0-9]+$")
        try:
            body = (ROOT / "adapter/restore.sh").read_text()
            body = body.replace("/sys/fs/selinux/", "$FIXTURE/")
            body = body.replace('load_policy "$POLICY"', 'sh "$FIXTURE/loader.sh" "$POLICY"')
            # Accelerate retries only; retain the production watchdog on success.
            body = body.replace("sleep 2", "sleep .01")
            if load == "timeout":
                body = body.replace("sleep 8", "sleep .1")
            prefix = f'FIXTURE={remote}\nTARGET={target}\n' + r'''
exec > "$FIXTURE/worker.log" 2>&1
HOME_DIR="$FIXTURE"
BASELINE_ENFORCING=1
BASELINE_CHECKREQPROT=-2
id() { echo 0; }
maplesu_handover_pre() { echo "HANDOVER=$TARGET"; }
printf '\214\377\174\371\010\000\000\000SE Linux\000\000\000\000\000\000\000\000\000' > "$FIXTURE/policy"
printf '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' > "$FIXTURE/status"
echo 0 > "$FIXTURE/enforce"
'''
            script = prefix + "(\n" + body + "\n)\nRESTORE_RC=$?\n" + r'''
printf 'CONSUMER restore=%s enforce=%s\n' "$RESTORE_RC" "$(cat "$FIXTURE/enforce")"
'''
            loader = {
                "success": "printf '\\001\\000\\000\\000' | dd of=\"${0%/*}/status\" bs=1 seek=12 count=4 conv=notrunc 2>/dev/null\n",
                "failure": "exit 1\n",
                "unchanged": "exit 0\n",
                "timeout": "exec sleep 2\n",
            }[load]
            with tempfile.TemporaryDirectory() as temp:
                for name, text in [("fixture.sh", script), ("loader.sh", loader)]:
                    path = Path(temp) / name
                    path.write_text(text, encoding="utf-8", newline="\n")
                    subprocess.run(self.adb + ["push", str(path), remote + "/" + name],
                        check=True, capture_output=True)
            result = subprocess.run(self.adb + ["shell", "sh", remote + "/fixture.sh"],
                capture_output=True, text=True, timeout=15)
            log = subprocess.check_output(self.adb + ["shell", "cat", remote + "/worker.log"], text=True)
            self.assertEqual(result.returncode, 0, f"Android sh exited {result.returncode}:\n{log}")
            return log
        finally:
            subprocess.run(self.adb + ["shell", "rm", "-rf", remote], check=True, capture_output=True)

    def test_success_reaches_requested_backend_and_consumer(self):
        for target in ("normal", "ultra"):
            with self.subTest(target=target):
                log = self.fixture(target=target)
                self.assertIn("HANDOVER=" + target, log)
                self.assertIn("CONSUMER restore=0 enforce=1", log)

    def test_failed_or_unconfirmed_load_reports_failure_without_handover(self):
        for load in ("failure", "unchanged", "timeout"):
            with self.subTest(load=load):
                log = self.fixture(load=load)
                self.assertNotIn("HANDOVER=", log)
                self.assertIn("CONSUMER restore=73 enforce=0", log)


if __name__ == "__main__":
    unittest.main(verbosity=2)
