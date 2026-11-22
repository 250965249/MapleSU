"""Drive the C unit-test harness and cross-check it with independent Python math.

The C harness proves the implementation's own invariants (531 assertions).  The
tests here prove the harness is actually running, and independently reproduce
the two digests and the exact handover script with Python's hashlib/struct, so
the C code cannot "agree with itself" on a wrong canonical form.

No device, no kernel, no network: only a host compiler and the harness binary.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATES = ROOT / "gates"
sys.path.insert(0, str(GATES))

import toolchain  # noqa: E402  (path set above)

# Synthetic fixture, identical to tests/msk_tests.c. Not a device value.
GOLDEN_SPEC = (
    "msk_spec_version=1\n"
    "release=6.6.89-android15-8-g1234567890ab\n"
    "kernel_phys_load=2818572288\n"
    "kernel_phys_offset=2147483648\n"
    "page_offset=18446744071562067968\n"
    "selinux_enforcing_off=4194304\n"
    "init_cred_off=8388608\n"
    "task_real_cred_off=2104\n"
    "task_cred_off=2112\n"
    "task_seccomp_off=2216\n"
    "task_comm_off=1840\n"
    "waiter_shift=2\n"
    "kernelsnitch_collisions=7\n"
)

BINDING = {
    "version": 1,
    "release": "6.6.89-android15-8-g1234567890ab",
    "kernel_phys_load": 2818572288,
    "kernel_phys_offset": 2147483648,
    "page_offset": 18446744071562067968,
    "selinux_enforcing_off": 4194304,
    "init_cred_off": 8388608,
    "task_real_cred_off": 2104,
    "task_cred_off": 2112,
    "task_seccomp_off": 2216,
    "task_comm_off": 1840,
    "waiter_shift": 2,
    "kernelsnitch_collisions": 7,
}

# (hop, verify, max_rounds, settle_us) -- hop/verify are enum values from msk_plan.h.
STEPS = [
    (0, 1, 1, 0),
    (1, 2, 1, 0),
    (2, 3, 15, 100000),
    (3, 4, 15, 100000),
    (4, 5, 18, 1000),
    (4, 6, 1, 0),
    (5, 7, 1, 0),
    (6, 1, 1, 0),
    (7, 8, 30, 100000),
]
PLAN_FLAGS = 0x0F

EXPECTED_KEYS = [
    "msk_spec_version",
    "release",
    "kernel_phys_load",
    "kernel_phys_offset",
    "page_offset",
    "selinux_enforcing_off",
    "init_cred_off",
    "task_real_cred_off",
    "task_cred_off",
    "task_seccomp_off",
    "task_comm_off",
    "waiter_shift",
    "kernelsnitch_collisions",
]

RESTORE_BODY = "\n".join(
    [
        "# MSK-RESTORE:begin",
        "# MSK-RESTORE:baseline",
        "# MSK-RESTORE:policy",
        "# MSK-RESTORE:enforce",
        "# MSK-RESTORE:readback",
        "printf '%s:%s\\n' \"$BASELINE_ENFORCING\" \"$BASELINE_CHECKREQPROT\"",
        "# MSK-RESTORE:end",
    ]
)


def binding_digest() -> bytes:
    """Canonical form documented in include/msk_spec.h and README §3.2."""
    parts = [
        b"MSK1-BINDING/v1",
        struct.pack("<I", BINDING["version"]),
        struct.pack("<H", len(BINDING["release"])),
        BINDING["release"].encode("ascii"),
    ]
    for key in (
        "kernel_phys_load",
        "kernel_phys_offset",
        "page_offset",
        "selinux_enforcing_off",
        "init_cred_off",
        "task_real_cred_off",
        "task_cred_off",
        "task_seccomp_off",
        "task_comm_off",
    ):
        parts.append(struct.pack("<Q", BINDING[key]))
    parts.append(struct.pack("<i", BINDING["waiter_shift"]))
    parts.append(struct.pack("<I", BINDING["kernelsnitch_collisions"]))
    return hashlib.sha256(b"".join(parts)).digest()


def plan_digest(spec_digest: bytes) -> bytes:
    parts = [
        b"MSK1-PLAN/v1",
        struct.pack("<I", 1),
        struct.pack("<I", PLAN_FLAGS),
        spec_digest,
    ]
    for hop, verify, rounds, settle in STEPS:
        parts.append(bytes([hop, verify, 1, 0]))
        parts.append(struct.pack("<I", rounds))
        parts.append(struct.pack("<I", settle))
    return hashlib.sha256(b"".join(parts)).digest()


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def expected_script() -> str:
    spec = binding_digest()
    plan = plan_digest(spec)
    lines = [
        "#!/bin/sh",
        "# msk-handoff v1 attempt=attempt-0001 plan=%s spec=%s"
        % (plan.hex()[:16], spec.hex()[:16]),
        "# P0 contract bytes only: the caller creates the carrier exclusively and runs it once.",
        "HOME_DIR=" + shell_quote("/host/home/attempt-1"),
        "BASELINE_ENFORCING=1",
        "BASELINE_CHECKREQPROT=0",
        "EXPECT_ENFORCE=1",
        'RESTORE_OUT="$(',
        RESTORE_BODY,
        ")\nRESTORE_RC=$?",
        "ENF=${RESTORE_OUT%%:*}",
        "CRP=${RESTORE_OUT#*:}",
        "READBACK_OK=0",
        'case "$ENF:$CRP" in',
        "  [012u]:[012u]) READBACK_OK=1 ;;",
        "esac",
        '[ "$ENF" = "$EXPECT_ENFORCE" ] || READBACK_OK=0',
        '[ "$READBACK_OK" -eq 1 ] || RESTORE_RC=79',
        'FRAME="r${RESTORE_RC}:${ENF:-u}:${CRP:-u}:o"',
        "printf '%s\\n' \"$FRAME\"",
        '[ "$RESTORE_RC" -eq 0 ] || exit 80',
        "exec '/host/bin/msk-consumer' '--handover' '--attempt=one' \"$FRAME\"",
    ]
    # Join so that the RESTORE_OUT block keeps its exact newlines.
    head = "\n".join(lines[:7]) + "\n"
    body = "\n".join(lines[7:10]) + "\n"
    tail = "\n".join(lines[10:]) + "\n"
    return head + body + tail


class HarnessTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(prefix="msk-harness-")
        try:
            cls.harness = toolchain.build_host_harness(cls._temporary.name)
        except toolchain.ToolchainError as error:  # pragma: no cover - environment
            cls._temporary.cleanup()
            raise unittest.SkipTest("host toolchain unavailable: %s" % error)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def run_harness(self, *arguments):
        completed = subprocess.run(
            [str(self.harness), *arguments],
            cwd=str(toolchain.ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
        return completed.returncode, completed.stdout, completed.stderr

    def test_selftest_passes(self):
        code, stdout, stderr = self.run_harness("--selftest")
        text = (stdout + stderr).decode("utf-8", "replace")
        match = re.search(r"TOTAL (\d+) FAILED (\d+)", text)
        self.assertIsNotNone(match, "harness did not print a TOTAL line:\n" + text[-2000:])
        total, failed = int(match.group(1)), int(match.group(2))
        self.assertEqual(failed, 0, "C harness assertions failed:\n" + text[-4000:])
        self.assertGreaterEqual(total, 400, "unexpectedly few assertions: %d" % total)
        self.assertEqual(code, 0, text[-2000:])

    def test_list_keys_matches_schema_documentation(self):
        code, stdout, _ = self.run_harness("--list-keys")
        self.assertEqual(code, 0)
        keys = stdout.decode("ascii").split()
        self.assertEqual(keys, EXPECTED_KEYS)

    def test_schema_documented_in_readme_matches_code(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        marker = "<!-- MSK1-SCHEMA-KEYS -->"
        self.assertIn(marker, text)
        block = text.split(marker, 1)[1].split("```text", 1)[1].split("```", 1)[0]
        documented = [line.strip() for line in block.splitlines() if line.strip()]
        self.assertEqual(documented, EXPECTED_KEYS)

    def test_binding_digest_matches_python(self):
        code, stdout, _ = self.run_harness("--print-digest")
        self.assertEqual(code, 0)
        self.assertEqual(stdout.decode("ascii").strip(), binding_digest().hex())

    def test_golden_script_matches_python_byte_for_byte(self):
        code, stdout, stderr = self.run_harness("--render-golden")
        self.assertEqual(code, 0, stderr.decode("utf-8", "replace"))
        self.assertNotIn(b"\r", stdout, "renderer output must be LF-only")
        self.assertEqual(
            stdout.decode("utf-8"),
            expected_script(),
            "rendered script drifted from the documented template",
        )

    def test_reference_shaped_body_is_refused(self):
        code, stdout, stderr = self.run_harness("--render-weak")
        self.assertEqual(code, 0, stderr.decode("utf-8", "replace"))
        self.assertIn("RESULT=-83", stdout.decode("ascii"),
                      "a body without restore stages must be refused (ERESTORE_WEAK)")

    def test_harness_help(self):
        code, stdout, _ = self.run_harness("--help")
        self.assertEqual(code, 0)
        self.assertIn(b"usage:", stdout)

    def test_spec_fixture_is_only_a_fixture(self):
        """Guard against someone pasting a real per-device value into tests."""
        self.assertIn("6.6.89-android15-8-g1234567890ab", GOLDEN_SPEC)
        self.assertEqual(BINDING["task_cred_off"], BINDING["task_real_cred_off"] + 8)
        self.assertEqual(BINDING["page_offset"] & 0xFFFF, 0)


if __name__ == "__main__":
    unittest.main()
