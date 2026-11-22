"""Run the production successful-Normal restore function with SELinux I/O fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class KsuSelinuxFinishTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ksu-selinux-finish-")
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        if os.name == "nt":
            candidates = sorted((ROOT / ".research/toolchains").glob(
                "llvm-mingw-*/bin/x86_64-w64-mingw32-clang.exe"))
            compiler = candidates[-1] if candidates else None
        else:
            compiler = shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("host C compiler is required")
        text = (ROOT / "jailbreak-providers/dirtyfrag/adapter/bootstrap.c").read_text(encoding="utf-8")
        function = text[text.index("static int ksu_finish("):text.index("static int ksu_handoff(")]
        source = r'''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define MAPLESU_ATTEMPT_DIRECTORY "."
#define MAPLESU_TEARDOWN "teardown"
static int enforcing, denied, ineffective, writes;
static int read_byte(const char *path) { return enforcing; }
static int write_byte(const char *path, char value) {
    ++writes;
    if (denied) return -1;
    if (!ineffective) enforcing = value - '0';
    return 0;
}
#define log_line(...) ((void)0)
''' + function + r'''
int main(int argc, char **argv) {
    if (argc != 4) return 64;
    enforcing = atoi(argv[1]); denied = atoi(argv[2]); ineffective = atoi(argv[3]);
    const int result = ksu_finish();
    printf("%d:%d:%d\n", result, enforcing, writes);
    return 0;
}
'''
        file = directory / "fixture.c"
        file.write_text(source, encoding="utf-8", newline="\n")
        cls.exe = directory / ("fixture.exe" if os.name == "nt" else "fixture")
        build = subprocess.run([str(compiler), "-std=c11", "-static", "-DO_CLOEXEC=0",
                                str(file), "-o", str(cls.exe)],
                               capture_output=True, text=True)
        if build.returncode:
            raise AssertionError(build.stderr)

    def run_case(self, enforcing, denied=0, ineffective=0):
        result = subprocess.run([str(self.exe), str(enforcing), str(denied), str(ineffective)],
                                cwd=self.temp.name, capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def test_successful_normal_restores_enforcing(self):
        self.assertEqual("0:1:1", self.run_case(0))

    def test_already_enforcing_needs_no_write(self):
        self.assertEqual("0:1:0", self.run_case(1, denied=1))

    def test_failed_or_ineffective_write_is_reported(self):
        self.assertEqual("1:0:1", self.run_case(0, denied=1))
        self.assertEqual("1:0:1", self.run_case(0, ineffective=1))


if __name__ == "__main__":
    unittest.main()
