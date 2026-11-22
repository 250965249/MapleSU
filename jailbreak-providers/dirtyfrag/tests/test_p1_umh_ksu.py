"""Host tests for P1: the marker-gated KernelSU route inside UMH mode.

The device evidence in ``.analysis/ksu-acceptance-20261031-055807/`` pinned the
failure: the module execs ``<CE>/bs --umh --entry-enforcing <0|1>``, and ``main()``
returns into ``umh_main()`` before stage-1's attempt document is opened. The
``use-ksu`` branch lived only on the attempt-document path, so with the marker
present and the App's daemon staged (``/data/user/0/dev.maplesu.manager/ksud``,
6,641,192 B, 0700) nothing ever called ``ksu_handoff()``; the provider log ended at
``daemon skipped (no attempt binding)`` / ``unload name=maplesu_root``.

P1 puts the marked handoff in ``umh_main`` itself:

  * after argv parsing (the ``--entry-enforcing`` value is the entry field) and the
    in-memory defaults, before the first hook descriptor, log line or ARM;
  * ``MAPLESU_USE_KSU`` + an executable ``MAPLESU_CE_KSUD`` -> return
    ``ksu_handoff()``'s status directly (it soft-reboots on success, fails through
    its own ``fail_with()``/teardown otherwise, so no hook restore is added here);
  * marker present without an executable daemon -> the stage-1 diagnostic and the
    original hook path; marker absent -> one ``access()`` and the pre-P1 code.

What is *dynamic* (a host C harness compiled from the real extracted branch):
the marker-absent no-op (no log, no handoff, one access), the invalid-argv
short-circuit, the missing-daemon fallthrough with the exact log line, and the
handoff's arguments/return value for entry ``0``/``1`` and a failure status.

What is *structural*: the branch sits before every hook descriptor/log/ARM; the
daemon constant is the App's CE staging target (``stageKernelSuDaemon()`` uses
``getFilesDir().getParentFile()/ksud``); the entry value is argv's, never
``getenforce``; and ``ksu_handoff(`` has exactly one call site in ``umh_main``.

HOST_ONLY: no adb, no device, no module. The real handoff still has to be proven by
the controller's P1 run.

Run: python -m unittest discover -s jailbreak-providers/dirtyfrag/tests
"""

from __future__ import annotations

import hashlib
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
APP = (REPO / "jailbreak-providers" / "android" / "src" / "main" / "java"
       / "dev" / "maplesu" / "manager" / "jailbreak" / "DirtyfragAttempt.java")

MARKER = "if (parsed == 0 && access(MAPLESU_USE_KSU, F_OK) == 0) {"
CE_KSUD = "/data/user/0/dev.maplesu.manager/ksud"
FALLBACK_LOG = "maplesu-dirtyfrag: use-ksu requested without a staged daemon\n"


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


def p1_branch(body: str) -> str | None:
    """The marker-gated KernelSU block inside umh_main, brace-matched."""
    start = body.find(MARKER)
    if start < 0:
        return None
    brace = body.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(body)):
        if body[index] == "{":
            depth += 1
        elif body[index] == "}":
            depth -= 1
            if depth == 0:
                return body[start:index + 1]
    return None


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


HARNESS = r'''
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define F_OK 0
#define X_OK 1
#define MAPLESU_USE_KSU "/maplesu-test/use-ksu"
#define MAPLESU_CE_KSUD @@DAEMON@@

struct p1_request { char entry; };

static int g_marker;
static int g_executable;
static int g_handoff_rc;
static int g_handoff_calls;
static int g_log_calls;
static int g_access_calls;
static int g_other_access;
static char g_daemon[256];
static char g_entry[8];
static char g_log[256];

static int access(const char *path, int mode) {
    ++g_access_calls;
    if (!strcmp(path, MAPLESU_USE_KSU)) {
        if (mode != F_OK) g_other_access = 1;
        return g_marker ? 0 : -1;
    }
    if (!strcmp(path, MAPLESU_CE_KSUD)) {
        if (mode != X_OK) g_other_access = 1;
        return g_executable ? 0 : -1;
    }
    g_other_access = 1;
    return -1;
}

static void log_line(const char *format, ...) {
    va_list args;
    ++g_log_calls;
    va_start(args, format);
    vsnprintf(g_log, sizeof(g_log), format, args);
    va_end(args);
}

static int ksu_handoff(const char *daemon, const char *entry) {
    ++g_handoff_calls;
    snprintf(g_daemon, sizeof(g_daemon), "%s", daemon);
    snprintf(g_entry, sizeof(g_entry), "%s", entry);
    return g_handoff_rc;
}

static int run_branch(int parsed, char entry) {
    struct p1_request request;
    request.entry = entry;
@@BRANCH@@
    return 4242;
}

static void print_escaped(const char *text) {
    for (; *text != '\0'; ++text) {
        if (*text == '\n') fputs("\\n", stdout);
        else if (*text == '\t') fputs("\\t", stdout);
        else putchar(*text);
    }
}

int main(int argc, char **argv) {
    if (argc != 7) return 2;
    const char *name = argv[1];
    int parsed = atoi(argv[2]);
    g_marker = atoi(argv[3]);
    g_executable = atoi(argv[4]);
    g_handoff_rc = atoi(argv[5]);
    char entry = argv[6][0];
    g_handoff_calls = g_log_calls = g_access_calls = g_other_access = 0;
    g_daemon[0] = g_entry[0] = g_log[0] = '\0';
    int rc = run_branch(parsed, entry);
    printf("%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t", name, rc, g_handoff_calls,
           g_log_calls, g_access_calls, g_other_access, g_daemon, g_entry);
    print_escaped(g_log);
    printf("\n");
    return 0;
}
'''


class P1SourceShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SOURCE.is_file():
            raise unittest.SkipTest("bootstrap.c is missing")
        cls.text = SOURCE.read_text(encoding="utf-8")
        cls.sha_before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        cls.umh = definition(cls.text, "umh_main")
        if cls.umh is None:
            raise AssertionError("umh_main is missing")
        cls.branch = p1_branch(cls.umh)
        if cls.branch is None:
            raise AssertionError("the P1 marker-gated KSU branch is missing from umh_main")

    @classmethod
    def tearDownClass(cls):
        if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != cls.sha_before:
            raise AssertionError("a test modified the real bootstrap.c")

    def test_01_the_branch_is_the_only_handoff_in_umh_main(self):
        self.assertEqual(1, self.umh.count(MARKER),
                         "the P1 marker check is not unique in umh_main")
        self.assertEqual(1, self.umh.count("ksu_handoff("),
                         "umh_main has more than one handoff call site")
        self.assertEqual(1,
                         self.branch.count("return ksu_handoff(MAPLESU_CE_KSUD, "
                                           "ksu_entry);"),
                         "the handoff return is not the expected shape")
        self.assertIn("access(MAPLESU_CE_KSUD, X_OK) == 0", self.branch,
                      "the branch does not require an executable staged daemon")
        self.assertIn("const char ksu_entry[2] = {request.entry, '\\0'};",
                      self.branch,
                      "the entry value is not the argv observation, NUL-terminated")

    def test_02_the_daemon_path_is_the_apps_ce_staging_target(self):
        self.assertEqual('"%s"' % CE_KSUD, c_define(self.text, "MAPLESU_CE_KSUD"),
                         "MAPLESU_CE_KSUD is not the App's CE staging path")
        self.assertNotIn("MAPLESU_ATTEMPT_DIRECTORY", c_define(self.text,
                                                              "MAPLESU_CE_KSUD"),
                         "the CE daemon path was derived from the DE directory")
        app = APP.read_text(encoding="utf-8")
        self.assertIn("getFilesDir().getParentFile()", app,
                      "DirtyfragAttempt no longer stages next to getFilesDir()")
        self.assertIn('new File(home, "ksud")', app,
                      "DirtyfragAttempt no longer names the staged daemon 'ksud'")
        self.assertIn("KSU_DAEMON_LIBRARY", app,
                      "the staged daemon source constant is missing")
        self.assertTrue(CE_KSUD.startswith("/data/user/0/"),
                        "the CE path is not in the credential-protected data root")
        self.assertTrue(CE_KSUD.endswith("/dev.maplesu.manager/ksud"),
                        "the CE path does not sit in this App's data directory")

    def test_03_the_branch_precedes_all_hook_work(self):
        check_at = self.umh.find(MARKER)
        self.assertGreaterEqual(check_at, 0)
        # After argv parsing and the state defaults ...
        self.assertLess(self.umh.find("hook_parse_argv(argc, argv, &request)"),
                        check_at, "the branch runs before argv parsing")
        self.assertLess(self.umh.find("memset(&state, 0, sizeof(state));"),
                        check_at, "the branch runs before the state defaults")
        # ... and before every descriptor, log line, stage-2/ARM and the restore fork.
        for anchor in ("state.dirfd = open(", "state.write_fd = open(",
                       "state.kmsg_fd = open(", "state.ev_fd = open(",
                       'log_line("maplesu-hook: mode=umh', "hook_read_env(",
                       "hook_stage2(&state);", "fork()"):
            position = self.umh.find(anchor)
            self.assertGreaterEqual(position, 0,
                                    "cannot locate %r in umh_main" % anchor)
            self.assertLess(check_at, position,
                            "the KSU branch runs after %r" % anchor)
        # ARM lives in hook_stage2 (which is after the branch); umh_main has none.
        self.assertNotIn("hook_arm_l3(state)", self.umh,
                         "ARM moved into umh_main")
        self.assertNotIn("hook_arm_l3(&state)", self.umh,
                         "ARM moved into umh_main")

    def test_04_the_entry_comes_from_argv_not_getenforce(self):
        self.assertIn("request.entry", self.branch)
        self.assertNotIn("getenforce", self.text,
                         "the helper now infers enforcing through getenforce")
        self.assertNotIn('"/sys/fs/selinux/enforce"', self.branch,
                         "the branch reads the enforcing byte itself")
        parse = definition(self.text, "hook_parse_argv") or ""
        self.assertIn("request->entry = value[0];", parse,
                      "hook_parse_argv no longer records --entry-enforcing")

    def test_05_the_handoff_return_has_no_hook_restore_after_it(self):
        tail = self.branch[self.branch.find("return ksu_handoff("):]
        self.assertNotIn("hook_", tail,
                         "hook work happens after the handoff return")
        self.assertNotIn("state.", tail,
                         "hook state is touched after the handoff return")
        self.assertNotIn("write_fd", self.branch)
        self.assertNotIn("read_byte", self.branch)
        self.assertNotIn("write_byte", self.branch)
        self.assertNotIn("emergency_teardown", self.branch)
        self.assertNotIn("arm", self.branch.lower(),
                         "the branch arms something after the handoff")

    def test_06_marker_absent_has_no_side_effect_in_the_source(self):
        condition = self.branch[:self.branch.find("{") + 1]
        self.assertIn("parsed == 0", condition,
                      "an invalid argv could reach the handoff")
        self.assertTrue(condition.strip().startswith("if (parsed == 0"),
                        "the marker check is not the first guard")
        self.assertEqual(1, self.branch.count("log_line("),
                         "the branch has more than one diagnostic")
        inner = self.branch[self.branch.find("if (access(MAPLESU_CE_KSUD"):]
        diagnostic = re.search(r"}\n\s+log_line\(", inner)
        inner_end = diagnostic.start() if diagnostic else -1
        self.assertGreater(inner_end, 0,
                           "the missing-daemon diagnostic is not after the X_OK block")
        self.assertNotIn("log_line(", inner[:inner_end],
                         "the diagnostic is inside the executable-daemon block")

    def test_07_the_branch_carries_no_other_stage1_step(self):
        for needle in ("touch(", "unlink(", "emergency_teardown",
                       "set_current_domain", "soft_reboot", "setprop",
                       "finit_module", "execv("):
            self.assertNotIn(needle, self.branch,
                             "the P1 branch smuggles %r into UMH mode" % needle)


@unittest.skipUnless(HOST_CC is not None,
                     "no host C compiler (llvm-mingw, clang, gcc or cc) found")
class P1HostExecutionTest(unittest.TestCase):
    """Compile the real extracted branch and drive it with mocked kernel effects."""

    @classmethod
    def setUpClass(cls):
        cls.text = SOURCE.read_text(encoding="utf-8")
        body = definition(cls.text, "umh_main")
        branch = p1_branch(body or "")
        if branch is None:
            raise AssertionError("the P1 branch is missing from umh_main")
        daemon = c_define(cls.text, "MAPLESU_CE_KSUD")
        if daemon is None:
            raise AssertionError("MAPLESU_CE_KSUD is missing")
        source = HARNESS.replace("@@DAEMON@@", daemon).replace("@@BRANCH@@", branch)
        cls.scratch = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.scratch.cleanup)
        directory = Path(cls.scratch.name)
        harness = directory / "p1_harness.c"
        cls.binary = directory / ("p1_harness.exe" if os.name == "nt" else "p1_harness")
        harness.write_text(source, encoding="utf-8")
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O1", "-Wall", "-Wextra",
                                "-fsyntax-only", str(harness)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            raise AssertionError("the P1 harness did not pass -fsyntax-only:\n%s\n%s"
                                 % (build.stdout, build.stderr))
        build = subprocess.run([str(HOST_CC), "-std=c11", "-O1",
                                str(harness), "-o", str(cls.binary)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            raise AssertionError("the P1 harness did not compile:\n%s\n%s"
                                 % (build.stdout, build.stderr))

    def run_case(self, name: str, parsed: int, marker: int, executable: int,
                 handoff_rc: int, entry: str) -> dict:
        result = subprocess.run([str(self.binary), name, str(parsed), str(marker),
                                 str(executable), str(handoff_rc), entry],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode,
                         "harness rc=%d stderr=%s" % (result.returncode, result.stderr))
        fields = result.stdout.strip("\n").split("\t")
        self.assertEqual(9, len(fields), "unexpected harness output: %r" % result.stdout)
        return {"name": fields[0], "rc": int(fields[1]),
                "handoff": int(fields[2]), "logs": int(fields[3]),
                "accesses": int(fields[4]), "other": int(fields[5]),
                "daemon": fields[6], "entry": fields[7], "log": fields[8]}

    def test_01_marker_absent_is_a_noop(self):
        row = self.run_case("absent", 0, marker=0, executable=1,
                            handoff_rc=0, entry="1")
        self.assertEqual(4242, row["rc"], "the pre-P1 path did not continue")
        self.assertEqual(0, row["handoff"], "a handoff happened without the marker")
        self.assertEqual(0, row["logs"], "the branch logged without the marker")
        self.assertEqual(1, row["accesses"], "more than the marker check was touched")
        self.assertEqual(0, row["other"], "an unexpected path reached access()")
        self.assertEqual("", row["log"])

    def test_02_invalid_argv_never_handoffs(self):
        row = self.run_case("badargv", parsed=1, marker=1, executable=1,
                            handoff_rc=0, entry="1")
        self.assertEqual(4242, row["rc"])
        self.assertEqual(0, row["handoff"])
        self.assertEqual(0, row["logs"])
        self.assertEqual(0, row["accesses"],
                         "invalid argv evaluated the marker before failing closed")
        self.assertEqual(0, row["other"])

    def test_03_marker_without_a_daemon_logs_and_falls_through(self):
        row = self.run_case("noexec", 0, marker=1, executable=0,
                            handoff_rc=0, entry="0")
        self.assertEqual(4242, row["rc"], "the branch returned without a handoff")
        self.assertEqual(0, row["handoff"])
        self.assertEqual(1, row["logs"])
        self.assertEqual(2, row["accesses"])
        self.assertEqual(0, row["other"])
        self.assertEqual(FALLBACK_LOG.replace("\n", "\\n"), row["log"],
                         "the fallthrough diagnostic is not the stage-1 line")

    def test_04_handoff_receives_the_ce_daemon_and_entry_zero(self):
        row = self.run_case("zero", 0, marker=1, executable=1,
                            handoff_rc=0, entry="0")
        self.assertEqual(0, row["rc"], "the handoff's success status was not returned")
        self.assertEqual(1, row["handoff"])
        self.assertEqual(0, row["logs"])
        self.assertEqual(2, row["accesses"])
        self.assertEqual(0, row["other"])
        self.assertEqual(CE_KSUD, row["daemon"])
        self.assertEqual("0", row["entry"])

    def test_05_handoff_receives_entry_one(self):
        row = self.run_case("one", 0, marker=1, executable=1,
                            handoff_rc=0, entry="1")
        self.assertEqual(0, row["rc"])
        self.assertEqual(CE_KSUD, row["daemon"])
        self.assertEqual("1", row["entry"])
        self.assertEqual(0, row["logs"])

    def test_06_a_failure_status_is_returned_unchanged(self):
        row = self.run_case("fail76", 0, marker=1, executable=1,
                            handoff_rc=76, entry="0")
        self.assertEqual(76, row["rc"],
                         "umh_main did not return ksu_handoff()'s failure status")
        self.assertEqual(1, row["handoff"])
        self.assertEqual(0, row["logs"])
        self.assertEqual(CE_KSUD, row["daemon"])


if __name__ == "__main__":
    unittest.main()
