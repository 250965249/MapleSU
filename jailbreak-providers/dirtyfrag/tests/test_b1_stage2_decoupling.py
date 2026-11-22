"""Host tests for B1: the stage-2/L3 leg is decoupled from the handover verdict, and
the su token never travels through argv.

B1 (controller decision, 2026-10-31) is a bootstrap-only change:

  * ``hook_stage2()``'s LOAD_FAILED branch used to call ``hook_fail()``. That turned a
    handover which had already verified its restore into ``verdict=FAILED`` and a
    non-zero exit. L3 is an *optional* capability: the kernel refusing the module must
    leave DAEMON_READY exactly as it was, record ``stage2.state=LOAD_FAILED`` with the
    kernel's rc/errno, and publish ``suGate=UNAVAILABLE`` plus ``suGateReason``.
  * the token used to reach the attest worker as ``--su-token <hex>`` in argv, i.e.
    ``/proc/<pid>/cmdline`` (0444, world-readable for the worker's whole life). It now
    travels as ``MAPLESU_SU_TOKEN`` in the worker's environment (0400, root-owned, and
    gated by the kernel's ptrace check), and its companion ``MAPLESU_SU_GATE_REASON``
    carries the UNAVAILABLE reason.

What is *structural* (the C is bionic-only and cannot be linked on the host):

  * the LOAD_FAILED branch has no ``hook_fail()``, never touches ``state->failures`` or
    ``state->token``, and records the reason + UNAVAILABLE gate instead;
  * ``hook_verdict()`` no longer reads LOAD_FAILED, while INVALID stays fatal - a staged
    file that is not a loadable image is a stager defect, not "the module did not
    load", and it must not be reported as a working L3;
  * both evidence writers still emit the fields through the single fragment helper;
  * no argv string named ``--su-token`` exists anywhere in the helper; the daemon child
    sets the environment entry with ``putenv()`` and the worker reads it with
    ``getenv()``;
  * no ``log_line`` carries the token.

What is *dynamic* (a host C harness compiled from the real extracted functions):

  * ``hook_verdict`` still returns OK for ``stage2=LOAD_FAILED`` (the B1 acceptance
    criterion) and FAILED for ``stage2=INVALID``;
  * the unarmed-gate JSON is exactly
    ``{"suGate":"UNAVAILABLE","suGateReason":"<code>"}`` and the armed form carries no
    reason;
  * ``hook_l3_reason_ok`` accepts exactly the helper's fixed codes.

HOST_ONLY: the prctl call, the exec'd worker and the bytes written on a device are NOT
verified here. Until a real run this is a host gate, not closure.

Run: python -m unittest discover -s jailbreak-providers/dirtyfrag/tests
"""

from __future__ import annotations

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

REASONS = ("STAGE2_NOT_EXERCISED", "STAGE2_INVALID", "STAGE2_LOAD_FAILED",
           "ARM_REJECTED", "WINDOW_CLOSED",
           # Y2/ABI v2 (2026-10-31): the ARM second confirmation's two fail-closed
           # codes. Adding them here keeps the worker's accepted set in step with the
           # helper's published set: the worker re-validates whatever it is handed.
           "ARM_NOT_OBSERVED", "KLOG_UNAVAILABLE")


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


class B1SourceShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise unittest.SkipTest("bootstrap.c is missing")
        cls.text = SOURCE.read_text(encoding="utf-8")
        for name in ("hook_stage2", "hook_verdict", "hook_daemon", "attest_main",
                     "hook_l3_su_json", "hook_l3_reason_ok", "hook_write_main_json",
                     "attest_write_final"):
            if definition(cls.text, name) is None:
                raise AssertionError("missing function " + name)

    def test_01_load_failed_raises_no_failure_token(self):
        body = definition(self.text, "hook_stage2")
        self.assertNotIn('hook_fail(state, "MA_HOOK_STAGE2_LOAD_FAILED")', body,
                         "a refused L3 module still adds a handover failure token")
        self.assertNotIn("state->failures", body,
                         "the LOAD_FAILED branch must not move the failure count")
        self.assertNotIn("state->token", body,
                         "the LOAD_FAILED branch must not set the verdict token")
        # Every hook_fail() that remains in this function is an INVALID one (the
        # procedural tokens are matched exactly, so a comment cannot satisfy or trip it).
        tokens = set(re.findall(r'hook_fail\(state, "([A-Z0-9_]+)"\)', body))
        self.assertEqual({"MA_HOOK_STAGE2_INVALID"}, tokens,
                         "hook_stage2 still raises a non-INVALID failure token")
        self.assertEqual(3, body.count('hook_fail(state, "MA_HOOK_STAGE2_INVALID")'),
                         "the three INVALID branches changed")
        # ... and the load-failure branch names the cause and the gate instead.
        at = body.find('"LOAD_FAILED"')
        self.assertGreaterEqual(at, 0)
        tail = body[at:at + 900]
        self.assertIn("MAPLESU_L3_REASON_LOAD_FAILED", tail,
                      "the LOAD_FAILED branch does not publish suGateReason")
        self.assertIn("MAPLESU_L3_GATE_UNAVAILABLE", tail,
                      "the LOAD_FAILED branch does not leave suGate UNAVAILABLE")
        self.assertIsNone(re.search(r"hook_fail\(state", tail),
                          "the LOAD_FAILED branch still calls hook_fail")
        self.assertIn("ir_dump_kernel_log(" + '"hook-stage2"', tail,
                      "the kernel's own reason is no longer dumped")

    def test_02_verdict_ignores_load_failed_but_not_invalid(self):
        verdict = definition(self.text, "hook_verdict")
        self.assertNotIn('strcmp(state->stage2_state, "LOAD_FAILED")', verdict,
                         "the verdict still fails on an optional L3 load failure")
        self.assertIn('strcmp(state->stage2_state, "INVALID")', verdict,
                      "a staged file that is not a module image must still fail")
        self.assertNotIn("su_", verdict,
                         "the verdict must not read any L3 field")
        # The exit code is the other half of "unchanged": it depends only on the
        # restore target and the unload, never on the stage-2 slot.
        umh = definition(self.text, "umh_main")
        self.assertIn("return (want >= 0 && state.readback_final == want &&", umh)
        self.assertIn('!strcmp(state.unload_state, "DONE")', umh)
        exit_expression = umh[umh.find("return (want >= 0"):]
        self.assertNotIn("stage2", exit_expression,
                         "the exit code reads the stage-2 slot")

    def test_03_defaults_name_the_unavailable_reason(self):
        umh = definition(self.text, "umh_main")
        self.assertIn("MAPLESU_L3_GATE_UNAVAILABLE", umh)
        self.assertIn("MAPLESU_L3_REASON_NOT_EXERCISED", umh,
                      "the default gate has no default reason")
        self.assertIn("hook_stage2(&state);", umh)
        self.assertIn("hook_daemon(&state);", umh)
        self.assertLess(umh.find("hook_stage2(&state);"),
                        umh.find("hook_daemon(&state);"),
                        "the reason must exist before the worker is spawned")

    def test_04_token_transport_is_the_environment(self):
        self.assertNotIn("--su-token", self.text,
                         "the token is still an argv value somewhere")
        self.assertEqual('"MAPLESU_SU_TOKEN"', c_define(self.text,
                                                        "MAPLESU_L3_ENV_TOKEN"))
        self.assertEqual('"MAPLESU_SU_GATE_REASON"',
                         c_define(self.text, "MAPLESU_L3_ENV_REASON"))
        daemon = definition(self.text, "hook_daemon")
        self.assertIn("setenv(variable, value, 1)", daemon,
                      "the helper does not publish the token through the environment")
        self.assertIn("MAPLESU_L3_ENV_TOKEN", daemon)
        self.assertIn("state->su_token_hex", daemon)
        self.assertIn("same_binary", daemon,
                      "a custom --daemon must not receive a token it may not know")
        attest = definition(self.text, "attest_main")
        self.assertIn("getenv(MAPLESU_L3_ENV_TOKEN)", attest)
        self.assertIn("getenv(MAPLESU_L3_ENV_REASON)", attest)
        self.assertIn("hook_l3_token_arg_ok", attest,
                      "the worker must re-validate the environment value")
        self.assertIn("hook_l3_reason_ok", attest)

    def test_05_both_records_still_carry_the_fields(self):
        for name, reason_field in (("hook_write_main_json", "state->su_gate_reason"),
                                   ("attest_write_final", "state->su_reason"),
                                   ("attest_main", "state.su_reason")):
            body = definition(self.text, name)
            self.assertIn("hook_l3_su_json(", body,
                          "%s does not emit the L3 fields" % name)
            self.assertIn(reason_field, body,
                          "%s drops the suGateReason" % name)
        main = definition(self.text, "hook_write_main_json")
        self.assertIn(r'\"token\":%s,%s,\"ts\":%ld}', main,
                      "the fragment is no longer spliced into the record")

    def test_06_no_log_line_carries_the_token(self):
        for number, line in enumerate(self.text.splitlines(), start=1):
            if "log_line(" not in line:
                continue
            self.assertNotIn("su_token", line,
                             "line %d logs the token: %s" % (number, line.strip()))
            self.assertNotIn("suToken", line,
                             "line %d logs the token: %s" % (number, line.strip()))
        # The worker reads the token from the environment; make sure it never logs the
        # variable's value. The only mention may be the getenv() lookup itself.
        for number, line in enumerate(self.text.splitlines(), start=1):
            if "MAPLESU_L3_ENV_TOKEN" not in line:
                continue
            self.assertNotIn("log_line", line,
                             "line %d logs the token variable name: %s"
                             % (number, line.strip()))

    def test_07_reason_codes_are_the_frozen_ones(self):
        for reason in REASONS:
            self.assertIn('"%s"' % reason, self.text)
        for name, reason in (("MAPLESU_L3_REASON_NOT_EXERCISED", "STAGE2_NOT_EXERCISED"),
                             ("MAPLESU_L3_REASON_INVALID", "STAGE2_INVALID"),
                             ("MAPLESU_L3_REASON_LOAD_FAILED", "STAGE2_LOAD_FAILED"),
                             ("MAPLESU_L3_REASON_ARM_REJECTED", "ARM_REJECTED"),
                             ("MAPLESU_L3_REASON_WINDOW_CLOSED", "WINDOW_CLOSED"),
                             ("MAPLESU_L3_REASON_NOT_ARMED", "NOT_ARMED")):
            self.assertEqual('"%s"' % reason, c_define(self.text, name))
        reason_ok = definition(self.text, "hook_l3_reason_ok")
        for name in ("MAPLESU_L3_REASON_NOT_EXERCISED", "MAPLESU_L3_REASON_INVALID",
                     "MAPLESU_L3_REASON_LOAD_FAILED", "MAPLESU_L3_REASON_ARM_REJECTED",
                     "MAPLESU_L3_REASON_WINDOW_CLOSED"):
            self.assertIn(name, reason_ok,
                          "hook_l3_reason_ok does not list " + name)


HARNESS_MAIN = r"""
static void line(const char *label, struct hook_state *state) {
    printf("VERDICT|%s|%s\n", label, hook_verdict(state));
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "reason") == 0) {
        for (int i = 2; i < argc; ++i)
            printf("REASON|%s|%d\n", argv[i], hook_l3_reason_ok(argv[i]));
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
        line("base", &state);
        strcpy(state.stage2_state, "LOAD_FAILED");
        line("stage2_load_failed", &state);
        strcpy(state.stage2_state, "INVALID");
        line("stage2_invalid", &state);
        strcpy(state.stage2_state, "NOT_EXERCISED");
        state.readback_final = 0;
        line("restore_failed", &state);
        state.readback_final = 1;
        strcpy(state.daemon_state, "EXEC_FAILED");
        line("daemon_failed", &state);
        return 0;
    }
    return 2;
}
"""


@unittest.skipUnless(HOST_CC is not None,
                     "no host C compiler (llvm-mingw, clang, gcc or cc) found")
class B1HostExecutionTest(unittest.TestCase):
    """Compile the real verdict/JSON/reason functions and drive them on the host."""

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
                     "MAPLESU_L3_GATE_UNAVAILABLE", "MAPLESU_L3_REASON_NOT_EXERCISED",
                     "MAPLESU_L3_REASON_INVALID", "MAPLESU_L3_REASON_LOAD_FAILED",
                     "MAPLESU_L3_REASON_ARM_REJECTED", "MAPLESU_L3_REASON_WINDOW_CLOSED",
                     "MAPLESU_L3_REASON_ARM_NOT_OBSERVED",
                     "MAPLESU_L3_REASON_KLOG_UNAVAILABLE",
                     "MAPLESU_L3_REASON_NOT_ARMED"):
            value = c_define(cls.text, name)
            if value is None:
                raise AssertionError("missing #define " + name)
            pieces.append("#define %s %s\n" % (name, value))
        pieces.append(struct.group(0))
        for name in ("hook_l3_token_arg_ok", "hook_l3_reason_ok", "hook_l3_su_json",
                     "hook_verdict"):
            body = definition(cls.text, name)
            if body is None:
                raise AssertionError("missing function " + name)
            pieces.append(body)
        pieces.append(HARNESS_MAIN)
        cls.scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.scratch.cleanup)
        directory = Path(cls.scratch.name)
        source = directory / "b1_harness.c"
        cls.binary = directory / ("b1_harness.exe" if os.name == "nt" else "b1_harness")
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

    def test_01_a_refused_l3_module_keeps_the_handover_ok(self):
        verdicts = {}
        for line in self.run_harness("verdict"):
            _tag, label, verdict = line.split("|", 2)
            verdicts[label] = verdict
        self.assertEqual("OK", verdicts["base"])
        self.assertEqual("OK", verdicts["stage2_load_failed"],
                         "a refused L3 module turned a good handover into %s"
                         % verdicts["stage2_load_failed"])
        self.assertEqual("FAILED", verdicts["stage2_invalid"],
                         "a staged non-image must still fail the handover")
        self.assertEqual("FAILED", verdicts["restore_failed"])
        self.assertEqual("DEGRADED", verdicts["daemon_failed"])

    def test_02_the_unarmed_gate_names_its_reason(self):
        def document(gate: str, token: str, reason: str) -> dict:
            fragment = self.run_harness("json", gate, token, reason)[0][len("JSON|"):]
            return json.loads("{" + fragment + "}")

        self.assertEqual({"suGate": "UNAVAILABLE", "suGateReason": "STAGE2_LOAD_FAILED"},
                         document("UNAVAILABLE", "", "STAGE2_LOAD_FAILED"))
        self.assertEqual({"suGate": "UNAVAILABLE", "suGateReason": "STAGE2_INVALID"},
                         document("UNAVAILABLE", "", "STAGE2_INVALID"))
        # The armed form keeps exactly the two frozen fields, whatever reason is around.
        self.assertEqual({"suToken": "0123456789abcdef", "suGate": "ARMED"},
                         document("ARMED", "0123456789abcdef", "STAGE2_LOAD_FAILED"))
        # No reason and no token: the step-4-era spelling, still valid JSON.
        self.assertEqual({"suGate": "UNAVAILABLE"}, document("UNAVAILABLE", "", ""))

    def test_03_only_the_fixed_reason_codes_are_accepted(self):
        accepted = list(REASONS)
        rejected = ["", "STAGE2", "stage2_load_failed", "NOT_ARMed", "STAGE2_LOAD_FAILED ",
                    "ARM_REJECTED;", "STAGE2_LOAD_FAILEDGARBAGE"]
        lines = self.run_harness("reason", *accepted, *rejected)
        self.assertEqual(len(accepted) + len(rejected), len(lines))
        for value, line in zip(accepted + rejected, lines):
            _tag, shown, ok = line.split("|", 2)
            self.assertEqual(value, shown)
            expected = "1" if value in accepted else "0"
            self.assertEqual(expected, ok, "hook_l3_reason_ok(%r) == %s" % (value, ok))


if __name__ == "__main__":
    unittest.main()
