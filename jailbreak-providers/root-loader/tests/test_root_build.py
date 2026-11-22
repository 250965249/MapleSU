"""Host tests for the build *edge* itself: the command the acceptance names, and the
determinism it promises.

`test_root_contract.py` proves properties of the artifact through the shared gate
replica. This file proves the two things that only a *process* can show:

  * `build_root_module.py --verify-only` exits 0, prints `[G1]`..`[G7]` PASS, reports
    both gate engines agreeing, and its `build.json` records exactly the four designed
    imports -- the same statement, but made by running the command rather than by
    calling a library function;
  * a clean rebuild from the same sources is byte-identical to the committed artifact,
    so "the .ko we ship" and "the sources we review" cannot drift apart, and a
    non-deterministic toolchain change would fail here instead of being discovered
    during a device attempt.

Every build in this file goes to a temporary directory: no committed artifact, and no
`build.json`, is modified by a test run. There is no device step anywhere in it.

Run: python -m unittest discover -s jailbreak-providers/root-loader/tests
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import native_toolchain  # noqa: E402
ROOT_LOADER = ROOT / "jailbreak-providers" / "root-loader"
BUILDER = ROOT_LOADER / "build_root_module.py"
CONTRACTS = sorted((ROOT_LOADER / "contracts").glob("*.json"))
CONTRACT = CONTRACTS[0] if CONTRACTS else ROOT_LOADER / "contracts" / "missing.json"
GOOD = ROOT_LOADER / "build" / "maplesu_root.ko"
IMAGE = ROOT / ".analysis" / "ace6-20261025" / "boot" / "kernel"
NDK = native_toolchain.provider_ndk()
GATE_IDS = ["G1", "G2", "G3", "G4", "G5", "G6", "G7"]
DESIGN_IMPORTS = {"_printk", "call_usermodehelper", "register_kprobe",
                  "unregister_kprobe"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(BUILDER.is_file(), "build_root_module.py is missing")
class BuildEdgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (CONTRACT, GOOD, IMAGE):
            if not path.is_file():
                raise unittest.SkipTest("missing input: %s" % path)
        if not NDK.is_dir():
            raise unittest.SkipTest("NDK is absent: %s" % NDK)
        cls.committed = sha256(GOOD.read_bytes())

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.dir = Path(self.scratch.name)

    def builder(self, out_dir: Path, *extra: str, verify_only: bool = False):
        argv = [sys.executable, str(BUILDER), "--out-dir", str(out_dir),
                "--contract", str(CONTRACT), "--image", str(IMAGE),
                "--ndk-dir", str(NDK), *extra]
        if verify_only:
            argv.insert(2, "--verify-only")
        return subprocess.run(argv, capture_output=True, text=True)

    # -- acceptance item 1: the exact command, its exit code and its words ------- #
    def test_01_verify_only_exits_zero_and_prints_seven_pass(self):
        # A copy, so the run cannot rewrite the committed build directory.
        shutil.copy2(GOOD, self.dir / GOOD.name)
        result = self.builder(self.dir, verify_only=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        for gate_id in GATE_IDS:
            match = re.search(r"^\[%s\]\s+.*?\sPASS\b" % gate_id, output, re.M)
            self.assertIsNotNone(match, "no PASS line for %s in:\n%s"
                                 % (gate_id, output))
        self.assertIn("RESULT: all gates pass", output)
        # Both engines ran, and the transcript says the replica agreed.
        self.assertIn("loader_contract.run_gates(root=True): PASS", output)

        report = json.loads((self.dir / "build.json").read_text(encoding="utf-8"))
        self.assertTrue(report["gateResult"]["ok"], report["gateResult"])
        self.assertEqual({"internal", "loader_contract"},
                         set(report["gateResult"]["engines"]))
        for name, engine in report["gateResult"]["engines"].items():
            self.assertTrue(engine["ok"], "%s engine: %r" % (name, engine))
        # Acceptance item 1's second half: imports are exactly the four exports, and
        # memset is not silently tolerated when the compiler did not need it.
        self.assertEqual(sorted(DESIGN_IMPORTS), report["undefinedSymbols"])
        self.assertNotIn("memset", report["undefinedSymbols"])
        self.assertEqual(GOOD.stat().st_size, report["bytes"])
        self.assertEqual(self.committed, report["sha256"])
        # The canary hardening, as the build record states it: the two-stage
        # handover (not the dead four-argument wrapper), the BTF path offset it
        # writes, no KCFI trap, no surviving check, and the flag that emits the
        # mandatory prefixes plus the one that reserves the SCS pointer.
        facts = report["facts"]
        self.assertEqual("setup-exec", facts["handoverMode"])
        self.assertEqual([], facts["umhPrimary"]["missing"])
        self.assertEqual(["call_usermodehelper_setup", "call_usermodehelper_exec"],
                         facts["umhPrimary"]["present"])
        self.assertEqual(0x38, facts["subprocessInfoPathOffset"])
        # Step-3: the UMH argument block is file-scope static storage (design R1), and
        # the helper constant is the CE `bs` the App stages (D-5/D3-3).
        self.assertTrue(set(facts["umhArgvStorage"].values()) <= {".bss", ".data"},
                        facts["umhArgvStorage"])
        self.assertEqual({".bss"}, set(facts["umhArgvStorage"].values()))
        self.assertEqual("/data/user/0/dev.maplesu.manager/bs", facts["helperPath"])
        self.assertEqual("contract", facts["helperPathSource"])
        self.assertEqual({}, facts["kcfiTraps"])
        self.assertEqual([], facts["kcfiCompareSites"])
        self.assertIn("-fsanitize=kcfi", report["compileFlags"])
        self.assertIn("-ffixed-x18", report["compileFlags"])
        # One .modinfo, emitted by the template: the side-car `root_modinfo.s` step is
        # gone, so a from-source build cannot ship without `vermagic=`.
        self.assertFalse((self.dir / "root_modinfo.s").is_file(),
                         "the builder still emits the side-car .modinfo; the template "
                         "is supposed to own it")

    def test_02_clean_rebuild_is_byte_identical(self):
        result = self.builder(self.dir, "--quiet")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        rebuilt = self.dir / GOOD.name
        self.assertTrue(rebuilt.is_file(), "the build produced no %s" % GOOD.name)
        self.assertEqual(self.committed, sha256(rebuilt.read_bytes()),
                         "a clean rebuild differs from the committed artifact: the "
                         "shipped .ko is not the one these sources produce")
        self.assertEqual(len(GOOD.read_bytes()), len(rebuilt.read_bytes()))

    # -- acceptance item 5: the evidence file is present and describes this .ko --- #
    def test_03_evidence_file_matches_the_artifact(self):
        evidence = ROOT_LOADER / "build" / "verify-evidence.txt"
        if not evidence.is_file():
            self.fail("build/verify-evidence.txt is missing; regenerate it with "
                      "`python %s --evidence`" % BUILDER.name)
        text = evidence.read_text(encoding="utf-8")
        self.assertIn("OVERALL: PASS", text)
        self.assertIn("NOT_EXERCISED", text)
        summary = text.split("== machine-readable summary ==", 1)
        self.assertEqual(2, len(summary), "the evidence file has no machine summary")
        payload = json.loads(summary[1])
        self.assertEqual("PASS", payload["overall"])
        self.assertEqual("NOT_EXERCISED", payload["deviceSide"])
        self.assertEqual(self.committed, payload["module"]["sha256"],
                         "the evidence file describes a different .ko than the one "
                         "committed: re-run `--evidence`")


if __name__ == "__main__":
    unittest.main()
