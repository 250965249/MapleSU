# Execute the production restoration script with system paths substituted.
# No Android provider or device code is invoked.
# The adapter passes -1 for a selinuxfs entry the ordinary-App domain cannot read
# (EACCES/EPERM, existence unknown), -2 for a proven ENOENT, and 0/1 for a readable value.
from pathlib import Path
import shutil
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = "C:/Program Files/Git/bin/bash.exe" if Path("C:/Program Files/Git/bin/bash.exe").is_file() else shutil.which("bash")


def baseline_probe():
    source = (ROOT / "adapter/handoff.cpp").read_text()
    match = re.search(r'kCheckreqprotBaselineProbe\[\] = R"sh\((.*?)\)sh";', source, re.S)
    return match.group(1) if match else ""


class RestoreScriptTest(unittest.TestCase):
    def run_fixture(self, *, success=True, increments=True, header=True, enforcing=1,
                    checkreqprot=0, check_present=True, handover=None, deny_enforcing_write=False,
                    deny_handover_log=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "home").mkdir()
            policy = bytearray(24)
            policy[:15] = bytes.fromhex("8cff7cf9080000005345204c696e7578")
            if not header: policy[0] = 0
            (root / "policy").write_bytes(policy)
            (root / "status").write_bytes(bytes(16))
            (root / "enforce").write_text("0\n")
            if check_present: (root / "checkreqprot").write_text("1\n")
            script = (ROOT / "adapter/restore.sh").read_text()
            script = script.replace("/sys/fs/selinux/", "$FIXTURE/")
            prefix = r'''
FIXTURE="$PWD"
HOME_DIR="$PWD/home"
id() { command echo 0; }
echo() {
  # selinuxfs does not allow creating an absent checkreqprot node.
  if [ "$NODE_PRESENT" = 0 ] && [ "$BASELINE_CHECKREQPROT" != -2 ] && [ "$*" = 0 ]; then
    command printf 'checkreqprot node absent\n' >&2
    return 1
  fi
  command echo "$@"
}
sleep() { if [ "$1" = 8 ]; then command sleep 0.5; fi; }
load_policy() {
  echo called >> "$FIXTURE/load.calls"
  [ "$LOAD_SUCCESS" = 1 ] || return 1
  if [ "$INCREMENT" = 1 ]; then
    printf '\001\000\000\000' | dd of="$FIXTURE/status" bs=1 seek=12 count=4 conv=notrunc 2>/dev/null
  fi
}
'''
            if handover is not None:
                prefix += f'''
maplesu_handover_pre() {{
  command printf '1\\n' > "$FIXTURE/enforce"
  ENFORCE_LOCKED={1 if deny_enforcing_write else 0}
  return {handover}
}}
# Model a write denied after KSU switched to enforcing. Reads still work.
echo() {{
  if [ "{1 if deny_handover_log else 0}" = 1 ]; then
    case "$*" in 'maplesu-ghostlock: handover failed rc='*) return 1 ;; esac
  fi
  if [ "${{ENFORCE_LOCKED:-0}}" = 1 ] && [ "$*" = 1 ]; then
    command printf '1\\n'
    command printf 'enforce write denied\\n' >&2
    return 1
  fi
  command echo "$@"
}}
'''
            probe = baseline_probe().replace("/sys/fs/selinux", "$FIXTURE")
            script = (prefix + f"BASELINE_ENFORCING={enforcing}\nBASELINE_CHECKREQPROT={checkreqprot}\n"
                      + probe + "(\n" + script + "\n)\nRESTORE_RC=$?\n")
            script += ('if [ "$RESTORE_RC" = 0 ]; then echo reached > "$FIXTURE/consumer.called"; fi\n'
                       'exit "$RESTORE_RC"\n')
            (root / "fixture.sh").write_text(script, encoding="utf-8", newline="\n")
            import os
            env = dict(os.environ, LOAD_SUCCESS="1" if success else "0", INCREMENT="1" if increments else "0",
                       NODE_PRESENT="1" if check_present else "0")
            process = subprocess.run([BASH, "fixture.sh"], cwd=root, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
            return {"code": process.returncode, "stdout": process.stdout, "stderr": process.stderr,
                    "consumer": (root / "consumer.called").exists(),
                    "enforcing": (root / "enforce").read_text().strip(),
                    "checkreqprot": (root / "checkreqprot").read_text().strip() if (root / "checkreqprot").exists() else None,
                    "loads": len((root / "load.calls").read_text().splitlines()) if (root / "load.calls").exists() else 0,
                    "temporary": list((root / "home").glob(".maplesu_policy.*"))}

    def test_restores_original_booleans_before_consumer(self):
        for enforcing in [0, 1]:
            for check in [0, 1]:
                with self.subTest(enforcing=enforcing, checkreqprot=check):
                    result = self.run_fixture(enforcing=enforcing, checkreqprot=check)
                    self.assertEqual(result["code"], 0, result)
                    self.assertTrue(result["consumer"])
                    self.assertEqual(result["enforcing"], str(enforcing))
                    self.assertEqual(result["checkreqprot"], str(check))
                    self.assertEqual(result["temporary"], [])
                    self.assertNotIn("baseline", result["stderr"])

    def test_observed_absent_unreadable_baseline_matrix(self):
        # Every observed/absent/unreadable combination must reach the consumer
        # with the documented value and label; -2 is only valid when absent.
        for enforcing in [0, 1, -1, -2]:
            for check in [0, 1, -1, -2]:
                with self.subTest(enforcing=enforcing, checkreqprot=check):
                    result = self.run_fixture(enforcing=enforcing, checkreqprot=check,
                                              check_present=check != -2)
                    self.assertEqual(result["code"], 0, result)
                    self.assertTrue(result["consumer"])
                    expected_enforcing = str(enforcing) if enforcing in (0, 1) else "1"
                    self.assertEqual(result["enforcing"], expected_enforcing)
                    if check in (0, 1):
                        self.assertEqual(result["checkreqprot"], str(check))
                    elif check == -1:
                        self.assertEqual(result["checkreqprot"], "0")
                        self.assertIn("checkreqprot baseline 0 applied", result["stderr"])
                    else:
                        self.assertIsNone(result["checkreqprot"])
                    if enforcing in (-1, -2):
                        self.assertIn("enforcing baseline 1 applied", result["stderr"])
                    self.assertEqual(result["temporary"], [])

    def test_absent_checkreqprot_stays_absent(self):
        # -2 means the App domain proved ENOENT; restore must not create it.
        result = self.run_fixture(checkreqprot=-2, check_present=False)
        self.assertEqual(result["code"], 0, result)
        self.assertIsNone(result["checkreqprot"])
        self.assertTrue(result["consumer"])

    def test_absent_checkreqprot_reappearing_rejected(self):
        # The ENOENT contract still fails if restoration creates the entry, and
        # the failed tail leaves the transient booleans untouched.
        result = self.run_fixture(checkreqprot=-2, check_present=True)
        self.assertEqual(result["code"], 74, result)
        self.assertFalse(result["consumer"])
        self.assertEqual(result["enforcing"], "0")
        self.assertEqual(result["checkreqprot"], "1")
        self.assertEqual(result["temporary"], [])

    def test_unreadable_checkreqprot_applies_documented_baseline(self):
        # -1 means the entry exists but the ordinary-App domain cannot read it.
        # This was the rc74 regression: it must not be treated as ENOENT.
        result = self.run_fixture(checkreqprot=-1, check_present=True)
        self.assertEqual(result["code"], 0, result)
        self.assertTrue(result["consumer"])
        self.assertEqual(result["checkreqprot"], "0")
        self.assertIn("checkreqprot baseline 0 applied", result["stderr"])
        self.assertIn("not the observed entry value", result["stderr"])
        self.assertEqual(result["temporary"], [])

    def test_app_eacces_does_not_prove_checkreqprot_exists(self):
        # The App may be denied directory traversal even when the optional node
        # is absent. Resolve absence from the rooted shell before writing it.
        result = self.run_fixture(checkreqprot=-1, check_present=False)
        self.assertEqual(result["code"], 0, result)
        self.assertIsNone(result["checkreqprot"])
        self.assertTrue(result["consumer"])

    def test_unreadable_enforcing_applies_documented_baseline(self):
        result = self.run_fixture(enforcing=-1)
        self.assertEqual(result["code"], 0, result)
        self.assertTrue(result["consumer"])
        self.assertEqual(result["enforcing"], "1")
        self.assertIn("enforcing baseline 1 applied", result["stderr"])
        self.assertIn("not the observed entry value", result["stderr"])

    def test_absent_enforcing_applies_documented_baseline(self):
        # An ENOENT enforce entry cannot be restored as absent: SELinux must end
        # enforcing, so the documented baseline is applied and labelled.
        result = self.run_fixture(enforcing=-2)
        self.assertEqual(result["code"], 0, result)
        self.assertTrue(result["consumer"])
        self.assertEqual(result["enforcing"], "1")
        self.assertIn("enforcing baseline 1 applied", result["stderr"])
        self.assertIn("entry absent from the app domain", result["stderr"])

    def test_invalid_baseline_sentinel_rejected(self):
        for name, options, code in [
                ("checkreqprot", {"checkreqprot": 2}, 72),
                ("enforcing", {"enforcing": 2}, 76)]:
            with self.subTest(field=name):
                result = self.run_fixture(**options)
                self.assertEqual(result["code"], code, result)
                self.assertFalse(result["consumer"])

    def test_success_without_status_increment_rejected(self):
        result = self.run_fixture(increments=False)
        self.assertEqual(result["code"], 73, result)
        self.assertEqual(result["loads"], 10)
        self.assertFalse(result["consumer"])
        self.assertEqual(result["enforcing"], "0")

    def test_failed_load_never_calls_consumer(self):
        result = self.run_fixture(success=False)
        self.assertEqual(result["code"], 73, result)
        self.assertEqual(result["loads"], 10)
        self.assertFalse(result["consumer"])
        self.assertEqual(result["temporary"], [])

    def test_handover_already_enforcing_does_not_require_another_write(self):
        result = self.run_fixture(handover=0, deny_enforcing_write=True)
        self.assertEqual(result["code"], 0, result)
        self.assertTrue(result["consumer"])
        self.assertEqual(result["enforcing"], "1")
        self.assertNotIn("enforce write denied", result["stderr"])

    def test_handover_failure_keeps_restoration_evidence_separate(self):
        result = self.run_fixture(handover=96)
        self.assertEqual(result["code"], 0, result)
        self.assertTrue(result["consumer"])
        self.assertEqual(result["enforcing"], "1")
        self.assertIn("handover failed rc=96", result["stderr"])

    def test_handover_diagnostic_write_failure_does_not_fail_restoration(self):
        result = self.run_fixture(handover=96, deny_handover_log=True)
        self.assertEqual(result["code"], 0, result)
        self.assertTrue(result["consumer"])
        self.assertEqual(result["enforcing"], "1")

    def test_bad_policy_header_never_loaded(self):
        result = self.run_fixture(header=False)
        self.assertEqual(result["code"], 73, result)
        self.assertEqual(result["loads"], 0)
        self.assertFalse(result["consumer"])


if __name__ == "__main__":
    unittest.main()
