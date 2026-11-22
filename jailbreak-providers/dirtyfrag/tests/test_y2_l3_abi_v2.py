"""Host tests for Y2: L3 ABI v2 and the ARM second confirmation.

ABI v2 (controller decision, 2026-10-31) moved the gate onto the kernel's own
``PR_SET_DUMPABLE``:

    prctl(option = 4 (PR_SET_DUMPABLE), arg2 = 0 (ARM),
          arg3 = token_lo, arg4 = token_hi, arg5 = owner_uid)

The magic is ``option == 4 && (arg3 | arg4) != 0``. Because PR_SET_DUMPABLE answers 0
natively for arg2 in {0, 1}, ``prctl() == 0`` is necessary but never sufficient: the
helper must find the module's own ring-buffer line

    maplesu_l3: armed owner=<dir_uid> pool=<n>

*appear* between two bounded reads around the call. This file gates both halves.

What is *structural* (the C is bionic-only and cannot be linked on the host):

  * the ARM tuple is built in exactly one function from the ABI v2 constants (option
    PR_SET_DUMPABLE, op ARM) and the call site passes the five values in order, with
    the attempt directory's uid as arg5;
  * the helper samples the marker before and after the call through the shared
    ``klog_read_all()`` (syslog READ_ALL, non-destructive), and only a positive
    decision flips the gate;
  * a readable-but-unchanged buffer publishes ARM_NOT_OBSERVED, an unreadable one
    KLOG_UNAVAILABLE, and neither publishes a token;
  * the two new reason codes are registered in ``hook_l3_reason_ok`` (so the attest
    worker can echo them) and are the ones the decision returns;
  * stage2 LOAD_FAILED still never calls ARM (B1 holds under ABI v2);
  * no ``log_line`` ever carries the token;
  * the marker format is the module's exact contract, owner only.

What is *dynamic* (a host C harness compiled from the real extracted functions):

  * the argument tuple: option/op/lo/hi/uid order, and the kernel's
    ``(arg4 << 32) | arg3`` reconstruction returns the same token for 1, 2^64-1 and a
    high-half-only value;
  * the marker: exact spelling per uid, including the trailing space that stops
    ``owner=1012`` from matching ``owner=10123``;
  * occurrence counting and the decision matrix: growth => confirmed, equal or
    shrinking => ARM_NOT_OBSERVED, unreadable => KLOG_UNAVAILABLE;
  * ``hook_l3_reason_ok`` accepts exactly the helper's codes;
  * both new reasons produce a parseable unarmed JSON fragment with no ``suToken``.

HOST_ONLY: the prctl call, the kernel's ring buffer and the bytes the helper writes on
a device are NOT verified here. Until a real run this is a host gate, not closure.

Run: python -m unittest discover -s jailbreak-providers/dirtyfrag/tests
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE.parent / "adapter" / "bootstrap.c"

NEW_REASONS = ("ARM_NOT_OBSERVED", "KLOG_UNAVAILABLE")
ALL_REASONS = ("STAGE2_NOT_EXERCISED", "STAGE2_INVALID", "STAGE2_LOAD_FAILED",
               "ARM_REJECTED", "WINDOW_CLOSED") + NEW_REASONS


def definition(text: str, name: str) -> str | None:
    """The full C definition (signature through closing brace) of one function."""
    pattern = re.compile(r"(?m)^[A-Za-z_][^\n;{}]*?(?<![A-Za-z0-9_])" +
                         re.escape(name) + r"\s*\(")
    for match in pattern.finditer(text):
        brace = text.find("{", match.end())
        statement = text.find(";", match.end())
        if brace < 0 or (0 <= statement < brace):
            continue
        depth = 0
        for position in range(brace, len(text)):
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
                if depth == 0:
                    return text[match.start():position + 1]
    return None


def c_define(text: str, name: str) -> str | None:
    match = re.search(r"(?m)^#define\s+" + re.escape(name) + r"\s+(.+?)\s*$", text)
    if match is None:
        return None
    return match.group(1).split("/*")[0].strip()


def host_compiler() -> Path | None:
    """The host C compiler used for the dynamic leg.

    The repo ships the llvm-mingw toolchain it uses for its Windows host analysis
    binaries; a plain cc/gcc is accepted on other hosts. MAPLESU_HOST_CC overrides both.
    """
    explicit = os.environ.get("MAPLESU_HOST_CC")
    if explicit:
        return Path(explicit) if Path(explicit).is_file() else None
    toolchains = REPO / ".research" / "toolchains"
    if toolchains.is_dir():
        candidates = sorted(toolchains.glob(
            "llvm-mingw-*/bin/x86_64-w64-mingw32-clang.exe"))
        if candidates:
            return candidates[-1]
    for name in ("clang", "gcc", "cc"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


HOST_CC = host_compiler()


class Y2SourceShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise unittest.SkipTest("bootstrap.c is missing")
        cls.text = SOURCE.read_text(encoding="utf-8")
        cls.sha_before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        for name in ("hook_arm_l3", "hook_l3_arm_arguments", "hook_l3_arm_marker",
                     "hook_l3_arm_confirm", "hook_l3_count_marker",
                     "klog_count_occurrences", "klog_read_all", "ir_dump_kernel_log",
                     "hook_l3_reason_ok", "hook_l3_su_json"):
            if definition(cls.text, name) is None:
                raise AssertionError("missing function " + name)

    @classmethod
    def tearDownClass(cls):
        if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != cls.sha_before:
            raise AssertionError("a test modified the real bootstrap.c")

    def test_01_the_option_is_pr_set_dumpable_not_a_private_number(self):
        self.assertEqual("4", c_define(self.text, "MAPLESU_L3_PR_SET_DUMPABLE"))
        self.assertEqual("0", c_define(self.text, "MAPLESU_L3_OP_ARM"))
        self.assertEqual("1", c_define(self.text, "MAPLESU_L3_OP_SU"))
        self.assertNotIn("0x4D535503", self.text,
                         "the ABI v1 private option is still somewhere")
        # The header documents the v2 magic: option 4 *and* a non-zero token.
        self.assertIn("(arg3 | arg4) != 0", self.text,
                      "the v2 magic is not documented")
        # The syscall slot itself is unchanged (prctl stays 167).
        self.assertIn("#define MAPLESU_NR_PRCTL 167", self.text)

    def test_02_the_arm_tuple_is_built_and_passed_in_order(self):
        builder = definition(self.text, "hook_l3_arm_arguments")
        self.assertIsNotNone(builder)
        self.assertIn("arguments[0] = (long)MAPLESU_L3_PR_SET_DUMPABLE;", builder)
        self.assertIn("arguments[1] = (long)MAPLESU_L3_OP_ARM;", builder)
        self.assertIn("(token & 0xffffffffULL)", builder)
        self.assertIn("(token >> 32)", builder)
        self.assertIn("arguments[4] = (long)owner_uid;", builder)
        arm = definition(self.text, "hook_arm_l3")
        self.assertIn("hook_l3_arm_arguments(token, state->dir_uid, arguments)", arm,
                      "ARM does not build its tuple from the directory uid")
        self.assertIn("syscall(SYS_prctl, arguments[0], arguments[1], arguments[2],",
                      arm)
        self.assertIn("arguments[3],", arm)
        self.assertIn("arguments[4]);", arm)
        # No hand-written option number survives at the call site.
        self.assertNotIn("SYS_prctl, (long)4", arm)

    def test_03_the_second_sample_decides_and_fails_closed(self):
        arm = definition(self.text, "hook_arm_l3")
        self.assertIsNotNone(arm)
        baseline = arm.find("hook_l3_count_marker(marker, &before)")
        call = arm.find("syscall(SYS_prctl")
        second = arm.find("hook_l3_count_marker(marker, &after)")
        self.assertGreaterEqual(baseline, 0, "no baseline sample")
        self.assertGreater(call, baseline, "the baseline is not before the call")
        self.assertGreater(second, call, "no sample after the call")
        self.assertIn("if (hook_l3_count_marker(marker, &after) != 0) readable = 0;",
                      arm, "a failed second read is not fail-closed")
        decision = arm.find("hook_l3_arm_confirm(readable, before, after)")
        self.assertGreater(decision, second)
        self.assertGreater(arm.find("MAPLESU_L3_GATE_ARMED"), decision,
                           "ARMED is reachable without the confirmation")
        # The failure path publishes the decision's own reason and clears the token.
        self.assertRegex(arm, r"hook_set_state\(state->su_gate_reason,\s*"
                              r"sizeof\(state->su_gate_reason\),\s*unconfirmed\);")
        failure = arm[decision:]
        self.assertIn("state->su_token_hex[0] = '\\0';", failure,
                      "an unconfirmed ARM keeps a token")
        # The token is published only inside the confirmed branch.
        self.assertNotIn("hook_l3_token_hex", arm[arm.find("if (rc == 0)"):decision],
                         "the token is published before the confirmation")

    def test_04_the_confirmation_uses_the_shared_klog_reader(self):
        reader = definition(self.text, "klog_read_all")
        self.assertIn("MAPLESU_NR_SYSLOG", reader)
        self.assertIn("MAPLESU_SYSLOG_READ_ALL", reader,
                      "the read is no longer the non-destructive READ_ALL")
        self.assertIn("(int)(capacity - 1)", reader,
                      "the bounded read lost its one-byte terminator margin")
        self.assertIn("out[size] = '\\0';", reader,
                      "the read does not terminate what it hands to a text scanner")
        self.assertIn("#define MAPLESU_KLOG_READ_MAX (96 * 1024)", self.text)
        dump = definition(self.text, "ir_dump_kernel_log")
        self.assertIn("klog_read_all(", dump,
                      "the dump no longer shares the one klog reader")
        self.assertIn("MAPLESU_KLOG_READ_MAX", dump)
        sampler = definition(self.text, "hook_l3_count_marker")
        self.assertIn("klog_read_all(", sampler)
        self.assertIn("klog_count_occurrences(", sampler)
        self.assertIn("MAPLESU_KLOG_READ_MAX", sampler)
        # Fail-closed on an unreadable buffer or an allocation failure.
        self.assertIn("if (rc <= 0)", sampler)
        self.assertIn("return -1;", sampler)

    def test_05_the_new_reasons_are_registered_and_published(self):
        for name, value in (("MAPLESU_L3_REASON_ARM_NOT_OBSERVED", "ARM_NOT_OBSERVED"),
                            ("MAPLESU_L3_REASON_KLOG_UNAVAILABLE", "KLOG_UNAVAILABLE")):
            self.assertEqual('"%s"' % value, c_define(self.text, name))
        reason_ok = definition(self.text, "hook_l3_reason_ok")
        for name in ("MAPLESU_L3_REASON_ARM_NOT_OBSERVED",
                     "MAPLESU_L3_REASON_KLOG_UNAVAILABLE"):
            self.assertIn(name, reason_ok,
                          "the worker cannot echo " + name)
        confirm = definition(self.text, "hook_l3_arm_confirm")
        self.assertIn("MAPLESU_L3_REASON_KLOG_UNAVAILABLE", confirm)
        self.assertIn("MAPLESU_L3_REASON_ARM_NOT_OBSERVED", confirm)
        self.assertIn("if (!readable)", confirm)
        self.assertIn("if (after <= before)", confirm)

    def test_06_the_marker_is_the_modules_exact_contract(self):
        self.assertEqual('"maplesu_l3: armed owner=%u "',
                         c_define(self.text, "MAPLESU_L3_ARM_MARKER_FMT"))
        marker = definition(self.text, "hook_l3_arm_marker")
        self.assertIn("snprintf(out, capacity, MAPLESU_L3_ARM_MARKER_FMT, owner_uid)",
                      marker)

    def test_07_stage2_load_failed_still_never_arms(self):
        stage2 = definition(self.text, "hook_stage2")
        branch = stage2.find("if (rc == 0 || error == 17)")
        arm = stage2.find("hook_arm_l3(state);")
        failed = stage2.find('"LOAD_FAILED"')
        self.assertGreaterEqual(branch, 0)
        self.assertGreater(arm, branch, "ARM is no longer in the success branch")
        self.assertGreater(failed, arm, "LOAD_FAILED is no longer the else branch")
        tail = stage2[failed:]
        self.assertNotIn("hook_arm_l3", tail, "the LOAD_FAILED branch calls ARM")
        self.assertNotIn("hook_l3_count_marker", tail,
                         "the LOAD_FAILED branch reads the ring buffer")
        self.assertIn("MAPLESU_L3_REASON_LOAD_FAILED", tail)

    def test_08_no_log_line_carries_the_token(self):
        for number, line in enumerate(self.text.splitlines(), start=1):
            if "log_line(" not in line:
                continue
            self.assertNotIn("su_token", line,
                             "line %d logs the token: %s" % (number, line.strip()))
            self.assertNotIn("suToken", line,
                             "line %d logs the token: %s" % (number, line.strip()))
            if "l3 arm" in line:
                self.assertIn("suGate=", line)
                self.assertNotIn("%llx", line)
                self.assertNotIn("token=", line)

    def test_09_the_marker_builder_cannot_leak_the_token(self):
        # The only string this helper builds for the ring buffer is the owner-bearing
        # marker; it has no token parameter at all, so a future format edit cannot
        # start printing the secret by accident.
        marker = definition(self.text, "hook_l3_arm_marker")
        self.assertNotIn("token", marker,
                         "the ring-buffer marker can see the token")
        self.assertNotIn("--su-token", self.text,
                         "the token is still an argv value somewhere")


HARNESS_MAIN = r"""
static void print_tuple(unsigned long long token, unsigned int uid) {
    long arguments[5];
    hook_l3_arm_arguments(token, uid, arguments);
    printf("ARGS|%llu|%llu|%llu|%llu|%llu\n",
           (unsigned long long)arguments[0] & 0xffffffffULL,
           (unsigned long long)arguments[1] & 0xffffffffULL,
           (unsigned long long)arguments[2] & 0xffffffffULL,
           (unsigned long long)arguments[3] & 0xffffffffULL,
           (unsigned long long)arguments[4] & 0xffffffffULL);
    /* The kernel's own reconstruction, from module/maplesu_l3.c:
     * token = (arg4 << 32) | arg3. */
    printf("RECON|%016llx\n",
           ((unsigned long long)arguments[3] << 32) |
           ((unsigned long long)arguments[2] & 0xffffffffULL));
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "args") == 0) {
        print_tuple(strtoull(argv[2], NULL, 0), (unsigned int)strtoul(argv[3], NULL, 0));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "marker") == 0) {
        char out[128];
        hook_l3_arm_marker(out, sizeof(out), (unsigned int)strtoul(argv[2], NULL, 0));
        printf("MARKER|%s|\n", out);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "occ") == 0) {
        char text[65536];
        const size_t used = fread(text, 1, sizeof(text) - 1, stdin);
        text[used] = '\0';
        printf("OCC|%llu\n", (unsigned long long)klog_count_occurrences(text, argv[2]));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "occ-empty") == 0) {
        /* The empty needle is passed inside the harness so no shell/C-runtime
         * command-line quoting can silently turn it into "no argument". */
        char text[65536];
        const size_t used = fread(text, 1, sizeof(text) - 1, stdin);
        text[used] = '\0';
        printf("OCC|%llu\n", (unsigned long long)klog_count_occurrences(text, ""));
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "confirm") == 0) {
        const char *reason = hook_l3_arm_confirm(atoi(argv[2]),
                                                 (size_t)strtoull(argv[3], NULL, 0),
                                                 (size_t)strtoull(argv[4], NULL, 0));
        printf("CONFIRM|%s\n", reason == NULL ? "ARMED" : reason);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "reason") == 0) {
        for (int i = 2; i < argc; ++i)
            printf("REASON|%s|%d\n", argv[i], hook_l3_reason_ok(argv[i]));
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "json") == 0) {
        char out[160];
        hook_l3_su_json(out, sizeof(out), argv[2], argv[3], argv[4]);
        printf("JSON|%s\n", out);
        return 0;
    }
    return 2;
}
"""


@unittest.skipUnless(HOST_CC is not None,
                     "no host C compiler (llvm-mingw, clang, gcc or cc) found")
class Y2HostExecutionTest(unittest.TestCase):
    """Compile the real tuple/marker/count/decision functions and drive them."""

    @classmethod
    def setUpClass(cls):
        cls.text = SOURCE.read_text(encoding="utf-8")
        pieces = [
            "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n",
        ]
        for name in ("MAPLESU_L3_PR_SET_DUMPABLE", "MAPLESU_L3_OP_ARM",
                     "MAPLESU_L3_OP_SU", "MAPLESU_L3_ARM_MARKER_FMT",
                     "MAPLESU_L3_GATE_ARMED", "MAPLESU_L3_GATE_UNAVAILABLE",
                     "MAPLESU_L3_REASON_NOT_EXERCISED", "MAPLESU_L3_REASON_INVALID",
                     "MAPLESU_L3_REASON_LOAD_FAILED", "MAPLESU_L3_REASON_ARM_REJECTED",
                     "MAPLESU_L3_REASON_WINDOW_CLOSED",
                     "MAPLESU_L3_REASON_ARM_NOT_OBSERVED",
                     "MAPLESU_L3_REASON_KLOG_UNAVAILABLE"):
            value = c_define(cls.text, name)
            if value is None:
                raise AssertionError("missing #define " + name)
            pieces.append("#define %s %s\n" % (name, value))
        for name in ("hook_l3_arm_arguments", "hook_l3_arm_marker",
                     "klog_count_occurrences", "hook_l3_arm_confirm",
                     "hook_l3_reason_ok", "hook_l3_su_json"):
            body = definition(cls.text, name)
            if body is None:
                raise AssertionError("missing function " + name)
            pieces.append(body)
        pieces.append(HARNESS_MAIN)
        cls.scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.scratch.cleanup)
        directory = Path(cls.scratch.name)
        source = directory / "y2_harness.c"
        cls.binary = directory / ("y2_harness.exe" if os.name == "nt" else "y2_harness")
        source.write_text("\n\n".join(pieces), encoding="utf-8")
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O1",
                                str(source), "-o", str(cls.binary)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            raise AssertionError("host harness did not compile:\n%s\n%s"
                                 % (build.stdout, build.stderr))

    @classmethod
    def run_harness(cls, *arguments: str, stdin_text: str | None = None) -> list[str]:
        result = subprocess.run([str(cls.binary), *arguments],
                                input=stdin_text, capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError("harness rc=%d: %s%s"
                                 % (result.returncode, result.stdout, result.stderr))
        return [line for line in result.stdout.splitlines() if line]

    def test_01_the_tuple_is_the_abi_v2_one(self):
        cases = [
            ("0x1122334455667788", 10123),
            ("0x1", 10000),
            ("0x0000000100000000", 99999),
            ("0xffffffffffffffff", 10001),
        ]
        for token, uid in cases:
            lines = self.run_harness("args", token, str(uid))
            fields = lines[0].split("|")
            self.assertEqual("ARGS", fields[0])
            option, op, low, high, owner = (int(value) for value in fields[1:])
            self.assertEqual(4, option, "option is not PR_SET_DUMPABLE")
            self.assertEqual(0, op, "arg2 is not the ARM op")
            self.assertEqual(int(token, 0) & 0xffffffff, low)
            self.assertEqual((int(token, 0) >> 32) & 0xffffffff, high)
            self.assertEqual(uid, owner, "arg5 is not the attempt directory uid")
            # The magic the module tests: option 4 and a non-zero token.
            self.assertTrue(low | high, "the harness token is not magic")
            # The kernel's own reconstruction returns what the helper sent.
            self.assertEqual(format(int(token, 0), "016x"),
                             lines[1].split("|")[1])

    def test_02_the_marker_is_exact_for_one_owner(self):
        cases = {10000: "maplesu_l3: armed owner=10000 ",
                 10123: "maplesu_l3: armed owner=10123 ",
                 99999: "maplesu_l3: armed owner=99999 ",
                 4294967295: "maplesu_l3: armed owner=4294967295 "}
        for uid, expected in cases.items():
            line = self.run_harness("marker", str(uid))[0]
            self.assertEqual("MARKER|%s|" % expected, line)

    def test_03_the_owner_prefix_cannot_match_a_longer_uid(self):
        text = ("maplesu_l3: armed owner=101230 pool=1\n"
                "maplesu_l3: armed owner=10123 pool=2\n")
        count = int(self.run_harness("occ", "maplesu_l3: armed owner=10123 ",
                                     stdin_text=text)[0].split("|")[1])
        self.assertEqual(1, count,
                         "owner=10123 matched inside owner=101230 - the trailing "
                         "space is not in the marker")
        self.assertEqual("OCC|0", self.run_harness("occ-empty",
                                                   stdin_text=text)[0],
                         "an empty needle must not loop or match")
        self.assertEqual("OCC|2", self.run_harness("occ", "armed",
                                                   stdin_text=text)[0])

    def test_04_the_decision_matrix_fails_closed(self):
        cases = [
            # readable, before, after -> expected
            (1, 0, 1, "ARMED"),                 # the module's line appeared
            (1, 1, 2, "ARMED"),                 # stale line + this attempt's line
            (1, 2, 3, "ARMED"),
            (1, 1, 1, "ARM_NOT_OBSERVED"),      # rc == 0, nothing new in the buffer
            (1, 0, 0, "ARM_NOT_OBSERVED"),
            (1, 2, 1, "ARM_NOT_OBSERVED"),      # shrank: wrapped/cleared, unknown
            (0, 0, 1, "KLOG_UNAVAILABLE"),      # the baseline read failed
            (0, 1, 2, "KLOG_UNAVAILABLE"),      # the confirmation read failed
            (0, 0, 0, "KLOG_UNAVAILABLE"),
        ]
        for readable, before, after, expected in cases:
            line = self.run_harness("confirm", str(readable), str(before),
                                    str(after))[0]
            self.assertEqual("CONFIRM|%s" % expected, line,
                             "confirm(%d, %d, %d)" % (readable, before, after))

    def test_05_only_the_fixed_codes_are_echoable(self):
        accepted = list(ALL_REASONS)
        rejected = ["", "NOT_ARMED", "ARM_NOT_OBSERVED ", " KLOG_UNAVAILABLE",
                    "arm_not_observed", "KLOG_UNAVAILABLE;", "ARM_NOT_OBSERVEDX"]
        lines = self.run_harness("reason", *accepted, *rejected)
        self.assertEqual(len(accepted) + len(rejected), len(lines))
        for value, line in zip(accepted + rejected, lines):
            _tag, shown, ok = line.split("|", 2)
            self.assertEqual(value, shown)
            self.assertEqual("1" if value in accepted else "0", ok,
                             "hook_l3_reason_ok(%r) == %s" % (value, ok))

    def test_06_both_new_reasons_produce_an_unarmed_fragment(self):
        for reason in NEW_REASONS:
            fragment = self.run_harness("json", "UNAVAILABLE", "", reason)[0][len("JSON|"):]
            document = json.loads("{" + fragment + "}")
            self.assertEqual({"suGate": "UNAVAILABLE", "suGateReason": reason}, document)
            self.assertNotIn("suToken", document)
        # ARMED still keeps exactly the two frozen fields.
        fragment = self.run_harness("json", "ARMED", "0123456789abcdef",
                                    "ARM_NOT_OBSERVED")[0][len("JSON|"):]
        self.assertEqual({"suToken": "0123456789abcdef", "suGate": "ARMED"},
                         json.loads("{" + fragment + "}"))

    def test_07_rc_zero_alone_does_not_arm(self):
        # The exact device failure Y2 closes: prctl() answers 0 (PR_SET_DUMPABLE's
        # native return) while the module never acknowledged *this* ARM. Both samples
        # see the previous attempt's own line - same owner uid, same spelling - so
        # only the count-growth rule keeps the gate shut.
        stale = "maplesu_l3: armed owner=10123 pool=8\n"
        before = int(self.run_harness("occ", "maplesu_l3: armed owner=10123 ",
                                      stdin_text=stale)[0].split("|")[1])
        self.assertEqual(1, before)
        self.assertEqual("CONFIRM|ARM_NOT_OBSERVED",
                         self.run_harness("confirm", "1", str(before),
                                          str(before))[0],
                         "a stale line armed the gate")
        # Once the module does acknowledge, the second sample grows and the same
        # decision confirms - existence plus growth, not existence alone.
        after = int(self.run_harness("occ", "maplesu_l3: armed owner=10123 ",
                                     stdin_text=stale + stale)[0].split("|")[1])
        self.assertEqual(2, after)
        self.assertEqual("CONFIRM|ARMED",
                         self.run_harness("confirm", "1", str(before),
                                          str(after))[0])


if __name__ == "__main__":
    unittest.main()
