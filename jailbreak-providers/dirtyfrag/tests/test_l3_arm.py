"""Host tests for the L3 ARM leg of the UMH helper (W2, ABI v2).

The ABI is the controller's (2026-10-31, ABI v2; replaces v1): the helper generates a
64-bit token and arms the gate with

    prctl(PR_SET_DUMPABLE (4), 0 (ARM), token_lo, token_hi, dir_uid)

after stage-2 is resident and before the restore, and publishes ``suToken`` (16
lowercase hex digits, ARMED only) plus ``suGate`` in both evidence records. The option
is the kernel's own PR_SET_DUMPABLE, so the magic is the argument shape (a non-zero
token in arg3/arg4), and its native return for arg2 in {0, 1} is 0: rc == 0 is only a
*necessary* condition. The gate is ARMED only when the module's ring-buffer line

    maplesu_l3: armed owner=<dir_uid> pool=<n>

*appeared* between two bounded ring-buffer reads around the call (Y2's second
confirmation). The L3 module is a separate deliverable, so every failure here must
leave the existing DAEMON_READY path byte-for-byte alone.

What is *dynamic* (a host C harness compiled from the real extracted functions):

  * ``hook_l3_token_hex`` always produces exactly 16 lowercase hex digits - 0, 1 and
    2^64-1 included - so the JSON spelling cannot drift to ``%llx``;
  * ``hook_l3_token_arg_ok`` accepts exactly the 16-lowercase-hex spelling and
    refuses upper case, short/long values, spaces and non-hex bytes;
  * ``hook_l3_su_json`` emits parseable JSON, with ``suToken`` only in the ARMED form,
    and fails closed to UNAVAILABLE when ARMED has no token;
  * ``hook_verdict`` returns the same verdict for every L3 field shape (ARM failed,
    ARMED, and a token the kernel refused).

What is *structural* (the C is bionic-only and cannot be linked on the host):

  * ARM sits inside ``hook_stage2``'s LOADED/ALREADY_RESIDENT branch, i.e. after the
    load and before ``umh_main``'s restore fork;
  * ``hook_arm_l3`` never calls ``hook_fail``/``hook_set_state(state->token...)`` and
    ``hook_verdict`` reads no L3 field;
  * the ABI v2 numbers are the frozen ones (option 4, ARM op 0, SU op 1) and the
    token's halves go to arg3/arg4 with the owner in arg5;
  * the second confirmation samples the marker before and after the call and only
    flips the gate on a positive decision (the full decision matrix is in
    test_y2_l3_abi_v2.py);
  * both evidence writers use the single fragment helper, and the JSON bounds grew
    (MAPLESU_HOOK_JSON_MAX = 1536) so the added fields cannot truncate a record;
  * no ``log_line`` ever carries the token;
  * the token comes from /dev/urandom with the boot_id/CLOCK_REALTIME/pid fallback;
  * the attest worker receives the token through ``MAPLESU_SU_TOKEN`` in its
    environment (never argv: that is /proc/<pid>/cmdline) and re-validates it;
  * the unload still names ``maplesu_root`` only (L3 stays resident);
  * ``tools/check_attestation_fields.py`` still passes.

HOST_ONLY: the prctl call, the kernel's answer, the ring-buffer read and the bytes the
helper writes on a device are NOT verified here. Until a real run, this is a host gate,
not closure.

Run: python -m unittest discover -s jailbreak-providers/dirtyfrag/tests
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE.parent / "adapter" / "bootstrap.c"
ATTESTATION_GATE = REPO / "tools" / "check_attestation_fields.py"

METHOD_PREFIXES = ("hook_arm_l3", "hook_l3_")


def definition(text: str, name: str) -> str | None:
    """The full C definition (signature through closing brace) of one function.

    Multi-line signatures are fine: the name and its `(` are on the first line, and
    the brace search starts after the match. A prototype is skipped.
    """
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
    binaries (third_party/llvm-mingw-toolchain.json); a plain cc/gcc is accepted on
    other hosts. MAPLESU_HOST_CC overrides both.
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


class L3SourceShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise unittest.SkipTest("bootstrap.c is missing")
        cls.text = SOURCE.read_text(encoding="utf-8")
        cls.sha_before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        missing = [name for name in ("hook_arm_l3", "hook_l3_token_arg_ok",
                                     "hook_l3_token_hex", "hook_l3_fallback_token",
                                     "hook_l3_make_token", "hook_l3_su_json")
                   if definition(cls.text, name) is None]
        if missing:
            raise AssertionError("L3 functions missing from bootstrap.c: %s"
                                 % ", ".join(missing))

    @classmethod
    def tearDownClass(cls):
        if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != cls.sha_before:
            raise AssertionError("a test modified the real bootstrap.c")

    def test_01_arm_is_inside_the_stage2_success_branch(self):
        stage2 = definition(self.text, "hook_stage2")
        self.assertIsNotNone(stage2)
        branch = stage2.find("if (rc == 0 || error == 17)")
        arm = stage2.find("hook_arm_l3(")
        self.assertGreaterEqual(branch, 0, "the success branch is not recognisable")
        self.assertGreater(arm, branch, "ARM is not inside the success branch")
        # ... and the failure path is still the else of that same branch.
        self.assertGreater(stage2.find("MA_HOOK_STAGE2_LOAD_FAILED"), arm)

        umh = definition(self.text, "umh_main")
        self.assertIsNotNone(umh)
        self.assertLess(umh.find("hook_stage2("), umh.find("fork()"),
                        "stage2 must run before the restore fork")
        self.assertNotIn("hook_arm_l3(state)", umh,
                         "ARM must be called from hook_stage2, not from umh_main")
        self.assertNotIn("hook_arm_l3(&state)", umh,
                         "ARM must be called from hook_stage2, not from umh_main")
        # Exactly one call site in the whole file (the definition/comment mentions do
        # not count because they carry no call shape).
        self.assertEqual(1, self.text.count("hook_arm_l3(state);"))
        self.assertNotIn("hook_arm_l3(&state)", self.text)

    def test_02_arm_is_evidence_only(self):
        arm = definition(self.text, "hook_arm_l3")
        self.assertIsNotNone(arm)
        self.assertNotIn("hook_fail(state", arm,
                         "an ARM failure must not add a failure token")
        self.assertNotIn("hook_fail(&state", arm)
        self.assertNotIn("state->failures", arm)
        self.assertNotIn("state->token", arm,
                         "the verdict token is not an ARM sink")
        self.assertIn("suGate=UNAVAILABLE", arm)
        self.assertIn("suGate=ARMED", arm)

        verdict = definition(self.text, "hook_verdict")
        self.assertIsNotNone(verdict)
        self.assertNotIn("su_", verdict,
                         "the verdict must not read any L3 field")
        self.assertNotIn("suToken", verdict)
        self.assertNotIn("suGate", verdict)

    def test_03_both_records_use_the_single_fragment(self):
        for name in ("hook_write_main_json", "attest_write_final", "attest_main"):
            body = definition(self.text, name)
            self.assertIsNotNone(body, "%s is missing" % name)
            self.assertIn("hook_l3_su_json(", body,
                          "%s does not emit the L3 fields" % name)
        fragment = definition(self.text, "hook_l3_su_json")
        self.assertIn(r'\"suToken\":\"%s\",\"suGate\":\"%s\"', fragment)
        self.assertIn(r'\"suGate\":\"%s\"', fragment)
        self.assertIn(r'\"suGate\":\"%s\",\"suGateReason\":\"%s\"', fragment,
                      "the B1 reason is not part of the single fragment helper")
        main = definition(self.text, "hook_write_main_json")
        self.assertIn(r'\"token\":%s,%s,\"ts\":%ld}', main,
                      "the fragment is not spliced into the single document write")

    def test_04_json_bounds_cannot_truncate_the_new_fields(self):
        self.assertIn("#define MAPLESU_HOOK_JSON_MAX 1536", self.text)
        for name in ("hook_write_main_json", "attest_write_final", "attest_main"):
            body = definition(self.text, name)
            self.assertIn("char document[MAPLESU_HOOK_JSON_MAX];", body)
        # A silent snprintf overflow is now logged; the write still happens (the App
        # sees a short record instead of nothing), but the log names it.
        self.assertIn("truncated", definition(self.text, "hook_write_main_json"))

    def test_05_token_is_16_lowercase_hex_from_urandom_or_the_fallback(self):
        hexf = definition(self.text, "hook_l3_token_hex")
        self.assertIn('"%016llx"', hexf,
                      "the token spelling must be zero-padded lowercase hex")
        make = definition(self.text, "hook_l3_make_token")
        self.assertIn('"/dev/urandom"', make)
        self.assertIn("hook_l3_fallback_token(", make)
        fallback = definition(self.text, "hook_l3_fallback_token")
        for needle in ("boot_id", "MAPLESU_NR_CLOCK_GETTIME",
                       "MAPLESU_CLOCK_REALTIME", "getpid"):
            self.assertIn(needle, fallback)
        arg = definition(self.text, "hook_l3_token_arg_ok")
        for needle in ("MAPLESU_L3_TOKEN_DIGITS", "'0'", "'9'", "'a'", "'f'"):
            self.assertIn(needle, arg)
        self.assertEqual("16", c_define(self.text, "MAPLESU_L3_TOKEN_DIGITS"))

    def test_06_no_log_line_carries_the_token(self):
        for number, line in enumerate(self.text.splitlines(), start=1):
            if "log_line(" not in line:
                continue
            # The token field and its hex formatting may never reach a log line. The
            # `%llx` check is scoped to the L3 lines: this file already logs unrelated
            # kernel addresses with the same conversion.
            self.assertNotIn("su_token", line,
                             "line %d logs the token: %s" % (number, line.strip()))
            self.assertNotIn("suToken", line,
                             "line %d logs the token: %s" % (number, line.strip()))
            if "l3 arm" in line:
                self.assertIn("suGate=", line)
                self.assertNotIn("%llx", line)
                self.assertNotIn("token=", line)
        # The indirect leak: the module prints the token into the ring buffer and
        # ir_dump_kernel_log() copies the tail into the world-readable provider log.
        dump = definition(self.text, "ir_dump_kernel_log")
        self.assertIsNotNone(dump)
        self.assertIn("klog_line_contains_token(", dump)
        self.assertIn("<redacted: L3 su token>", dump)
        filter_body = definition(self.text, "klog_line_contains_token")
        self.assertIsNotNone(filter_body)
        self.assertIn(r'"suToken="', filter_body)

    def test_07_the_abi_numbers_are_the_frozen_ones(self):
        # ABI v2: the private option number is gone. The option is the kernel's own
        # PR_SET_DUMPABLE (4), the magic is a non-zero token in arg3/arg4, and arg2
        # selects the op (0 = ARM, 1 = SU).
        self.assertEqual("4", c_define(self.text, "MAPLESU_L3_PR_SET_DUMPABLE"))
        self.assertEqual("0", c_define(self.text, "MAPLESU_L3_OP_ARM"))
        self.assertEqual("1", c_define(self.text, "MAPLESU_L3_OP_SU"))
        self.assertNotIn("0x4D535503", self.text,
                         "the ABI v1 private option must not survive anywhere")
        self.assertIn("#define MAPLESU_NR_PRCTL 167", self.text)
        self.assertIn("_Static_assert(SYS_prctl == MAPLESU_NR_PRCTL", self.text)
        arm = definition(self.text, "hook_arm_l3")
        for needle in ("SYS_prctl", "hook_l3_arm_arguments", "arguments[0]",
                       "arguments[1]", "arguments[2]", "arguments[3]", "arguments[4]",
                       "state->dir_uid"):
            self.assertIn(needle, arm)
        # The tuple itself lives in exactly one function, so the host can assert the
        # parameter order without a kernel (see test_y2_l3_abi_v2.py).
        builder = definition(self.text, "hook_l3_arm_arguments")
        self.assertIsNotNone(builder)
        for needle in ("MAPLESU_L3_PR_SET_DUMPABLE", "MAPLESU_L3_OP_ARM",
                       "token & 0xffffffffULL", "token >> 32", "owner_uid"):
            self.assertIn(needle, builder)

    def test_11_arm_needs_the_modules_acknowledgement(self):
        arm = definition(self.text, "hook_arm_l3")
        self.assertIsNotNone(arm)
        # Two samples around the call: the baseline before syscall(), the second one
        # inside the rc == 0 branch. Existence alone (a single read) would accept a
        # stale line from an earlier attempt in the same boot.
        first = arm.find("hook_l3_count_marker(marker, &before)")
        call = arm.find("syscall(SYS_prctl")
        second = arm.find("hook_l3_count_marker(marker, &after)")
        self.assertGreaterEqual(first, 0, "no baseline ring-buffer sample")
        self.assertGreater(call, first, "the baseline is not taken before prctl()")
        self.assertGreater(second, call, "no second ring-buffer sample after prctl()")
        decision = arm.find("hook_l3_arm_confirm(readable, before, after)")
        self.assertGreater(decision, second, "the decision does not use both samples")
        # The gate word flips only on a positive decision (NULL), and a negative one
        # publishes the reason the decision returned.
        armed_at = arm.find("MAPLESU_L3_GATE_ARMED")
        self.assertGreater(armed_at, decision, "ARMED is set without the confirmation")
        self.assertIn("const char *unconfirmed", arm)
        self.assertIn("if (unconfirmed == NULL)", arm)
        self.assertIn("hook_set_state(state->su_gate_reason", arm[decision:],
                      "the unconfirmed reason is never published")
        # A confirmation failure never publishes a token: the only success-path write
        # of su_token_hex is inside the confirmed branch.
        success = arm[arm.find("if (rc == 0)"):decision]
        self.assertNotIn("hook_l3_token_hex", success,
                         "the token is published before the confirmation")
        self.assertIn("state->su_token_hex[0] = '\\0'",
                      arm[arm.find("unconfirmed"):],
                      "the failure path does not clear the token")

    def test_08_attest_worker_receives_the_token_in_its_environment(self):
        daemon = definition(self.text, "hook_daemon")
        self.assertIn("MAPLESU_L3_ENV_TOKEN", daemon)
        self.assertIn("state->su_token_hex", daemon)
        self.assertIn("setenv(", daemon,
                      "the token must cross the exec boundary through the environment")
        self.assertIn("MAPLESU_L3_ENV_REASON", daemon,
                      "an unarmed gate must carry its reason to the worker too")
        attest = definition(self.text, "attest_main")
        self.assertIn("getenv(MAPLESU_L3_ENV_TOKEN)", attest)
        self.assertIn("hook_l3_token_arg_ok", attest)
        self.assertIn("hook_l3_reason_ok", attest)
        self.assertIn("same_binary", daemon,
                      "a custom --daemon must not receive a token it may not know")
        # B1: the token is not an argv value anywhere in the helper (its argv is
        # /proc/<pid>/cmdline, mode 0444). The source-level assertion is the gate.
        self.assertNotIn("--su-token", self.text)
        self.assertNotIn('"--su-token"', daemon)
        self.assertNotIn('"--su-token"', attest)

    def test_09_unload_is_still_maplesu_root_only(self):
        unload = definition(self.text, "hook_unload_child")
        self.assertIn("MAPLESU_HOOK_MODULE_NAME", unload)
        self.assertNotIn("maplesu_l3", unload,
                         "L3 is left resident; only maplesu_root is unloaded")
        self.assertEqual(1, self.text.count("syscall(MAPLESU_NR_DELETE_MODULE"))

    def test_10_attestation_field_gate_still_passes(self):
        if not ATTESTATION_GATE.is_file():
            self.skipTest("tools/check_attestation_fields.py is absent")
        result = subprocess.run([sys.executable, str(ATTESTATION_GATE)],
                                cwd=str(REPO), capture_output=True, text=True)
        self.assertEqual(0, result.returncode,
                         result.stdout + result.stderr)
        self.assertIn("RESULT:", result.stdout)


HARNESS_MAIN = r"""
static void verdict_line(const char *label, struct hook_state *state) {
    printf("VERDICT|%s|%s\n", label, hook_verdict(state));
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "token") == 0) {
        char out[24];
        for (int i = 2; i < argc; ++i) {
            const unsigned long long value = strtoull(argv[i], NULL, 0);
            hook_l3_token_hex(value, out, sizeof(out));
            printf("TOKEN|%s|%s\n", argv[i], out);
        }
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "arg") == 0) {
        printf("ARG|%d|%s\n", hook_l3_token_arg_ok(argv[2]), argv[2]);
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "json") == 0) {
        char out[128];
        hook_l3_su_json(out, sizeof(out), argv[2], argv[3], argv[4]);
        printf("JSON|%s\n", out);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "verdict") == 0) {
        struct hook_state state;
        memset(&state, 0, sizeof(state));
        state.want_final = '1';
        state.readback_final = 1;
        strcpy(state.stage2_state, "NOT_EXERCISED");
        strcpy(state.daemon_state, "STARTED");
        state.unload_state = "DONE";
        state.enforce_before = 0;
        verdict_line("base", &state);
        state.su_arm_errno = 13;                 /* EACCES: a denied ARM */
        strcpy(state.su_gate, MAPLESU_L3_GATE_UNAVAILABLE);
        verdict_line("arm_failed", &state);
        strcpy(state.su_gate, MAPLESU_L3_GATE_ARMED);
        strcpy(state.su_token_hex, "0123456789abcdef");
        verdict_line("armed", &state);
        state.readback_final = 0;                /* a genuinely broken restore */
        verdict_line("restore_failed", &state);
        state.want_final = '0';
        state.readback_final = 1;
        verdict_line("target_zero_failed", &state);
        return 0;
    }
    return 2;
}
"""


@unittest.skipUnless(HOST_CC is not None,
                     "no host C compiler (llvm-mingw, clang, gcc or cc) found")
class L3HostExecutionTest(unittest.TestCase):
    """Compile the real token/JSON/verdict functions and drive them on the host."""

    @classmethod
    def setUpClass(cls):
        cls.text = SOURCE.read_text(encoding="utf-8")
        struct = re.search(r"(?ms)^struct hook_state \{.*?^\};", cls.text)
        if struct is None:
            raise AssertionError("struct hook_state is missing")
        pieces = [
            "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n",
            "#ifndef PATH_MAX\n#define PATH_MAX 4096\n#endif\n"
            "#ifndef MAPLESU_HOOK_SMALL_MAX\n#define MAPLESU_HOOK_SMALL_MAX 96\n#endif\n",
        ]
        for name in ("MAPLESU_L3_TOKEN_DIGITS", "MAPLESU_L3_GATE_ARMED",
                     "MAPLESU_L3_GATE_UNAVAILABLE"):
            value = c_define(cls.text, name)
            if value is None:
                raise AssertionError("missing #define " + name)
            pieces.append("#define %s %s\n" % (name, value))
        pieces.append(struct.group(0))
        for name in ("hook_l3_token_arg_ok", "hook_l3_token_hex",
                     "hook_l3_su_json", "hook_verdict"):
            body = definition(cls.text, name)
            if body is None:
                raise AssertionError("missing function " + name)
            pieces.append(body)
        pieces.append(HARNESS_MAIN)
        cls.scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.scratch.cleanup)
        directory = Path(cls.scratch.name)
        source = directory / "l3_harness.c"
        cls.binary = directory / ("l3_harness.exe" if os.name == "nt" else "l3_harness")
        source.write_text("\n\n".join(pieces), encoding="utf-8")
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O1",
                                str(source), "-o", str(cls.binary)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            raise AssertionError("host harness did not compile:\n%s\n%s"
                                 % (build.stdout, build.stderr))

    @classmethod
    def run_harness(cls, *arguments: str) -> list[str]:
        result = subprocess.run([str(cls.binary), *arguments],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError("harness rc=%d: %s%s"
                                 % (result.returncode, result.stdout, result.stderr))
        return [line for line in result.stdout.splitlines() if line]

    def test_01_token_is_always_16_lowercase_hex(self):
        values = ["0", "1", "42", "0x0123456789abcdef", "18446744073709551615"]
        lines = self.run_harness("token", *values)
        self.assertEqual(len(values), len(lines))
        for line, value in zip(lines, values):
            _tag, shown, token = line.split("|", 2)
            self.assertEqual(value, shown)
            self.assertRegex(token, r"^[0-9a-f]{16}$",
                             "token %r is not 16 lowercase hex digits" % token)
            self.assertEqual(format(int(value, 0), "016x"), token)

    def test_02_arg_validation_is_exact(self):
        accepted = ["0123456789abcdef", "0000000000000000", "ffffffffffffffff"]
        rejected = ["", "1234567890abcde", "1234567890abcdef0",
                    "0123456789ABCDEF", "0123456789abcdeg", " 1234567890abcde",
                    "0x123456789abcde", "1234567890abcde "]
        for value in accepted:
            _tag, ok, shown = self.run_harness("arg", value)[0].split("|", 2)
            self.assertEqual("1", ok, "rejected valid token %r" % value)
            self.assertEqual(value, shown)
        for value in rejected:
            _tag, ok, shown = self.run_harness("arg", value)[0].split("|", 2)
            self.assertEqual("0", ok, "accepted invalid token %r" % shown)

    def test_03_json_is_valid_and_token_only_when_armed(self):
        import json

        def document(gate: str, token: str, reason: str = "") -> dict:
            fragment = self.run_harness("json", gate, token, reason)[0][len("JSON|"):]
            return json.loads("{" + fragment + "}")

        armed = document("ARMED", "0123456789abcdef")
        self.assertEqual({"suToken": "0123456789abcdef", "suGate": "ARMED"}, armed)
        unavailable = document("UNAVAILABLE", "")
        self.assertEqual({"suGate": "UNAVAILABLE"}, unavailable)
        # B1: an unarmed gate names why, and only on the UNAVAILABLE form.
        self.assertEqual({"suGate": "UNAVAILABLE", "suGateReason": "STAGE2_LOAD_FAILED"},
                         document("UNAVAILABLE", "", "STAGE2_LOAD_FAILED"))
        self.assertEqual({"suToken": "0123456789abcdef", "suGate": "ARMED"},
                         document("ARMED", "0123456789abcdef", "STAGE2_LOAD_FAILED"))
        # Fail closed: neither half of the pair alone may look ARMED.
        self.assertEqual({"suGate": "UNAVAILABLE"}, document("ARMED", ""))
        self.assertEqual({"suGate": "UNAVAILABLE"},
                         document("UNAVAILABLE", "0123456789abcdef"))

    def test_04_arm_failure_does_not_change_the_verdict(self):
        verdicts = {}
        for line in self.run_harness("verdict"):
            _tag, label, verdict = line.split("|", 2)
            verdicts[label] = verdict
        self.assertEqual("OK", verdicts["base"])
        self.assertEqual(verdicts["base"], verdicts["arm_failed"],
                         "a denied ARM changed the verdict")
        self.assertEqual(verdicts["base"], verdicts["armed"],
                         "a successful ARM changed the verdict")
        self.assertEqual("FAILED", verdicts["restore_failed"])
        self.assertEqual("FAILED", verdicts["target_zero_failed"])


if __name__ == "__main__":
    unittest.main()
