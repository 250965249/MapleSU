"""T8 host tests: `bs --handover` argv/env/evidence contract (design §6.3).

Static shape checks keep pre free of reboot and direct root-module loading,
and the pure block between the handover markers is compiled on the host and
driven directly for argv parsing, env parsing, sha256, JSON and module verification.
"""

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

BEGIN = "/* --- handover host-testable block begin --- */"
END = "/* --- handover host-testable block end --- */"


def definition(text: str, name: str) -> str | None:
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


def host_compiler() -> Path | None:
    explicit = os.environ.get("MAPLESU_HOST_CC")
    if explicit and Path(explicit).is_file():
        return Path(explicit)
    toolchains = REPO / ".research" / "toolchains"
    if toolchains.is_dir():
        candidates = sorted(toolchains.glob("llvm-mingw-*/bin/x86_64-w64-mingw32-clang.exe"))
        if candidates:
            return candidates[-1]
    for name in ("clang", "gcc", "cc"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


HOST_CC = host_compiler() if os.name == "nt" else None

HARNESS_PREAMBLE = r'''
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifdef _WIN32
static int host_openat(int ignored, const char *name, int flags) {
    (void)ignored;
    if (!strcmp(name, "/fixture/ksud")) name = "ksud";
    return open(name, flags);
}
#define openat host_openat
#endif
'''

HARNESS_MAIN = r'''
static void read_stdin(char *buffer, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        const size_t got = fread(buffer + used, 1, capacity - used - 1, stdin);
        if (got == 0) break;
        used += got;
    }
    buffer[used] = '\0';
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "argv")) {
        char *sub[64];
        int count = 0;
        sub[count++] = (char *)"/system/bin/bs";
        for (int i = 2; i < argc && count < 63; ++i) sub[count++] = argv[i];
        sub[count] = NULL;
        struct handover_request request;
        const int rc = handover_parse_argv(count, sub, &request);
        printf("%d|%d|%d|%d|%d|%s|%s|%s|%s|%s|%d\n", rc, request.valid, request.pre,
               request.ultra, request.entry_enforcing,
               request.attempt ? request.attempt : "",
               request.boot ? request.boot : "",
               request.root_module ? request.root_module : "",
               request.stage2 ? request.stage2 : "",
               request.ksud ? request.ksud : "", request.soft_reboot);
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "env")) {
        char text[HANDOVER_ENV_MAX];
        read_stdin(text, sizeof(text));
        struct handover_env env;
        const int rc = handover_env_parse(text, &env);
        printf("%d|%d|%s|%s|%s|%s|%s\n", rc, env.valid, env.boot, env.attempt, env.target,
               env.root_sha256, env.stage2_sha256);
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "sha")) {
        char text[HANDOVER_ENV_MAX * 4];
        read_stdin(text, sizeof(text));
        unsigned char digest[32];
        char hex[HANDOVER_HEX + 1];
        handover_sha256((const unsigned char *)text, strlen(text), digest);
        handover_sha256_hex(digest, hex);
        printf("%s\n", hex);
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "json")) {
        struct handover_result result;
        memset(&result, 0, sizeof(result));
        result.target = "ultra";
        result.kind = "l3-gate";
        result.gate = "ARMED";
        result.stage2 = "LOADED";
        result.ksu = "";
        result.token = "";
        result.detail = "quote\"inside";
        result.enforcing_before = 0;
        result.enforcing_final = 1;
        result.restore_failures = 0;
        char json[2048];
        if (handover_format_json(json, sizeof(json), &result, "attempt-1", "boot-1") < 0) {
            printf("FORMAT_FAILED\n");
            return 1;
        }
        printf("%s", json);
        return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "verify")) {
        struct handover_file file;
        const int rc = handover_verify_file(-1, argv[2], argc >= 4 ? argv[3] : NULL, &file);
        printf("%d|%d|%ld|%d\n", rc, file.error, file.size, file.ok);
        return 0;
    }
    printf("unknown mode\n");
    return 2;
}
'''


def read_block() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    begin = text.find(BEGIN)
    end = text.find(END)
    if begin < 0 or end < 0:
        raise AssertionError("handover host-testable markers are missing")
    return text[begin + len(BEGIN):end]


class SourceShapeTest(unittest.TestCase):
    def setUp(self):
        self.text = SOURCE.read_text(encoding="utf-8")

    def test_handover_is_dispatched_before_umh(self):
        body = definition(self.text, "main")
        self.assertIsNotNone(body)
        handover = body.index("handover_mode_requested")
        umh = body.index("umh_mode_requested")
        self.assertLess(handover, umh, "--handover must be dispatched before UMH")

    def test_pre_never_unloads_reboots_or_loads_a_root_module(self):
        body = definition(self.text, "handover_main")
        self.assertIsNotNone(body)
        pre = body[body.index("if (request.pre)"):body.index("/* post: the restore")]
        for forbidden in ("ksu_finish", "MAPLESU_NR_DELETE_MODULE", "emergency_teardown",
                          "MAPLESU_NR_FINIT_MODULE", "soft-reboot", "soft_reboot\""):
            self.assertNotIn(forbidden, pre, f"pre must not contain {forbidden}")

    def test_pre_performs_the_two_target_handovers(self):
        body = definition(self.text, "handover_main")
        pre = body[body.index("if (request.pre)"):body.index("/* post: the restore")]
        self.assertIn("umh_main(4, helper_argv, 1, &observed)", pre)
        self.assertIn("env.stage2_sha256", pre)
        self.assertIn("late-load", pre)
        self.assertIn("--package-name", pre)
        self.assertIn("set_current_domain(\"u:r:init:s0\")", pre)

    def test_post_owns_the_optional_soft_reboot(self):
        body = definition(self.text, "handover_main")
        post = body[body.index("/* post: the restore"):]
        self.assertIn("soft_reboot", post)
        self.assertIn("setprop sys.powerctl reboot,soft_reboot", post)

    def test_evidence_is_root_owned_and_single_schema(self):
        write = definition(self.text, "handover_write_evidence")
        self.assertIsNotNone(write)
        self.assertIn("0644", write)
        self.assertIn("O_NOFOLLOW", write)
        self.assertIn('"schema\\":\\"maplesu.handover.v1', definition(self.text, "handover_format_json"))


@unittest.skipUnless(HOST_CC is not None, "no host C compiler")
class HostBlockTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = Path(tempfile.mkdtemp(prefix="maplesu-handover-"))
        source = cls.directory / "harness.c"
        source.write_text(HARNESS_PREAMBLE + read_block() + HARNESS_MAIN, encoding="utf-8")
        cls.exe = cls.directory / ("harness.exe" if os.name == "nt" else "harness")
        built = subprocess.run([str(HOST_CC), "-std=c11", "-O0", "-o", str(cls.exe), str(source)],
                               capture_output=True, text=True)
        if built.returncode != 0:
            raise AssertionError("harness build failed:\n" + built.stderr)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory, ignore_errors=True)

    def run_mode(self, *args, stdin: bytes | None = None) -> str:
        done = subprocess.run([str(self.exe), *args], input=stdin, capture_output=True)
        self.assertEqual(0, done.returncode, done.stderr.decode("utf-8", "replace"))
        return done.stdout.decode("utf-8", "replace").strip()

    def test_valid_ultra_pre(self):
        out = self.run_mode("argv", "--handover", "--target", "ultra", "--phase", "pre",
                            "--attempt", "attempt-1", "--boot", "boot-1",
                            "--entry-enforcing", "0", "--root-module", "/x/maplesu_root.ko")
        self.assertEqual("0|1|1|1|0|attempt-1|boot-1|/x/maplesu_root.ko|||0", out)

    def test_valid_normal_post(self):
        out = self.run_mode("argv", "--handover", "--target", "normal", "--phase", "post",
                            "--attempt", "att-1", "--boot", "boot-1", "--entry-enforcing", "1",
                            "--soft-reboot")
        self.assertEqual("0|1|0|0|1|att-1|boot-1||||1", out)

    def test_unknown_and_duplicate_tokens_are_refused(self):
        base = ["--handover", "--target", "ultra", "--phase", "pre",
                "--attempt", "att-1", "--boot", "boot-1", "--entry-enforcing", "0"]
        self.assertTrue(self.run_mode("argv", *base, "--bogus").startswith("-1|0"))
        self.assertTrue(self.run_mode("argv", *base, "--phase", "post").startswith("-1|0"))
        self.assertTrue(self.run_mode("argv", *base[:-2]).startswith("-1|0"))

    def test_post_cannot_carry_load_paths(self):
        out = self.run_mode("argv", "--handover", "--target", "ultra", "--phase", "post",
                            "--attempt", "att-1", "--boot", "boot-1", "--entry-enforcing", "0",
                            "--root-module", "/x/maplesu_root.ko")
        self.assertTrue(out.startswith("-1|0"))

    def test_env_document(self):
        digest = "a" * 64
        text = ("schema=maplesu.handover.env.v1 boot=boot-1 attempt=attempt-1 target=ultra "
                "root_sha256=" + digest + "\n")
        self.assertEqual("0|1|boot-1|attempt-1|ultra|" + digest + "|",
                         self.run_mode("env", stdin=text.encode()))
        self.assertTrue(self.run_mode("env", stdin=b"boot=boot-1").startswith("-1|0"))
        bad = text.replace("maplesu.handover.env.v1", "other.v1")
        self.assertTrue(self.run_mode("env", stdin=bad.encode()).startswith("-1|0"))

    def test_sha256_matches_the_standard(self):
        for payload in (b"", b"abc", b"x" * 1000):
            self.assertEqual(hashlib.sha256(payload).hexdigest(),
                             self.run_mode("sha", stdin=payload))

    def test_provider_is_explicit_valid_and_unambiguous(self):
        base = ("schema=maplesu.handover.env.v1 boot=boot-1 attempt=attempt-1 "
                "target=normal root_sha256=" + "a" * 64)
        self.assertTrue(self.run_mode("env", stdin=(base + " provider=maplesu_93260").encode()).startswith("0|1"))
        for suffix in (" provider=other", " provider=maplesu_93260 provider=ghostlock",
                       " provider=maplesu_93260 provider=maplesu_93260"):
            self.assertTrue(self.run_mode("env", stdin=(base + suffix).encode()).startswith("-1|0"))

    def test_evidence_json_shape_and_escaping(self):
        out = self.run_mode("json")
        self.assertIn('"schema":"maplesu.handover.v1"', out)
        self.assertIn('"verdict":"OK"', out)
        self.assertIn('"kind":"l3-gate"', out)
        self.assertIn('quote\\"inside', out)
        self.assertTrue(out.endswith("}"))

    def test_module_verification(self):
        payload = b"\x7fELF" + b"\x02" * 60
        staged = self.directory / "maplesu_root.ko"
        staged.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual("0|0|64|1", self.run_mode("verify", str(staged), digest))
        self.assertEqual("5", self.run_mode("verify", str(staged), "b" * 64).split("|")[1])
        not_elf = self.directory / "not-elf.ko"
        not_elf.write_bytes(b"nope" * 16)
        self.assertEqual("4", self.run_mode("verify", str(not_elf), "").split("|")[1])


if __name__ == "__main__":
    unittest.main()
