"""Exercise the real stage-2 dispatch, replacing only OS/kernel boundaries.

Ghostlock Normal reaches init_module with a verified memory buffer. Keep that
transport for Ghostlock Ultra, then use the same L3 ARM/restore contract. This
host fixture verifies dispatch and errors, not an OPPO kernel hang or panic.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_handover_mode import HOST_CC, HARNESS_PREAMBLE, SOURCE, definition

FIXTURE = r'''
#include <stdarg.h>
#define MAPLESU_IR_MODULE_LIMIT 4096
#define MAPLESU_STAGE2_NAME "maplesu_stage2.ko"
#define MAPLESU_HOOK_MODULE_NAME "maplesu_root"
#define MAPLESU_NR_INIT_MODULE 105
#define MAPLESU_NR_FINIT_MODULE 273
#define MAPLESU_L3_REASON_WINDOW_CLOSED "WINDOW_CLOSED"
#define MAPLESU_L3_REASON_INVALID "STAGE2_INVALID"
#define MAPLESU_L3_REASON_LOAD_FAILED "STAGE2_LOAD_FAILED"
#define MAPLESU_L3_GATE_UNAVAILABLE "UNAVAILABLE"
struct hook_state {
    int enforce_before, dirfd, from_ghostlock, stage2_rc, stage2_errno;
    char stage2_state[32], su_gate_reason[32], su_gate[32], stage2_name[64];
};
static const unsigned char payload[] = "verified-L3-image";
static const char *scenario;
static int calls, arms, failures, dumps, watch_starts, watch_stops;
static pid_t hook_stage2_watch_start(int *stop) {
    watch_starts++; *stop = 12; return 23;
}
static void hook_stage2_watch_stop(pid_t child, int stop) {
    if (child < 0) return;
    if (child != 23 || stop != 12) abort();
    watch_stops++; errno = 127;
}
static void log_line(const char *format, ...) {
    va_list args; va_start(args, format); vprintf(format, args); va_end(args);
}
static void hook_set_state(char *out, size_t capacity, const char *value) {
    snprintf(out, capacity, "%s", value);
}
static void hook_fail(struct hook_state *state, const char *token) {
    (void)state; (void)token; failures++;
}
static int fixture_read_staged(int dirfd, const char *name, unsigned char *out,
                          size_t capacity, size_t *size, int *verified_fd, ...) {
    (void)dirfd; (void)name; (void)capacity;
    memcpy(out, payload, sizeof(payload)); *size = sizeof(payload);
    if (verified_fd) *verified_fd = 7;
    return 0;
}
/* Accept the old five-argument reader too, so the regression runs before the fix. */
#define ir_read_staged(...) fixture_read_staged(__VA_ARGS__, NULL)
static int ir_elf_precheck(const unsigned char *out, size_t size) {
    return !strcmp(scenario, "invalid") || size != sizeof(payload) ||
           memcmp(out, payload, size) ? -1 : 0;
}
static int fixture_openat(int dirfd, const char *name, int flags) {
    (void)dirfd; (void)name; (void)flags;
    static int opens;
    opens++;
    if (!strcmp(scenario, "missing")) return -1;
    if (!strcmp(scenario, "replacement")) return opens == 1 ? 6 : 8;
    return 7;
}
#define openat fixture_openat
static int fixture_fstat(int fd, struct stat *st) {
    (void)fd; memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0600; st->st_size = sizeof(payload); return 0;
}
#define fstat fixture_fstat
#define close(fd) ((void)(fd), 0)
#define open(path, flags) ((void)(path), (void)(flags), -1)
static long fixture_syscall(long nr, ...) {
    va_list args; va_start(args, nr); calls++;
    if (nr == MAPLESU_NR_INIT_MODULE) {
        const void *image = va_arg(args, const void *);
        size_t bytes = va_arg(args, size_t);
        const char *params = va_arg(args, const char *);
        if (bytes != sizeof(payload) || memcmp(image, payload, bytes) || *params) abort();
        puts("CALL=buffer verified=1 params=empty");
    } else if (nr == MAPLESU_NR_FINIT_MODULE) {
        int fd = va_arg(args, int);
        const char *params = va_arg(args, const char *);
        int flags = va_arg(args, int);
        if ((fd != 7 && strcmp(scenario, "replacement")) || *params || flags) abort();
        printf("CALL=file fd=%d flags=0 verified=%d\n", fd, fd == 7);
    } else abort();
    va_end(args);
    if (!strcmp(scenario, "duplicate")) { errno = 17; return -1; }
    if (!strcmp(scenario, "rejected")) { errno = 8; return -1; }
    // Inject a file-only error to verify source isolation. This does not
    // reproduce the captured device hang or identify its kernel-side cause.
    if (!strcmp(scenario, "file-error") && nr == MAPLESU_NR_FINIT_MODULE) {
        errno = 5; return -1;
    }
    return 0;
}
#define syscall fixture_syscall
static void hook_arm_l3(struct hook_state *state) {
    arms++; strcpy(state->su_gate, "ARMED");
}
static void ir_dump_kernel_log(const char *label) { (void)label; dumps++; }
'''
MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    scenario = argv[2];
    struct hook_state state; memset(&state, 0, sizeof(state));
    state.from_ghostlock = atoi(argv[1]);
    state.enforce_before = !strcmp(scenario, "closed") ? 1 : 0;
    strcpy(state.su_gate, "UNAVAILABLE");
    hook_stage2(&state);
    printf("RESULT state=%s gate=%s reason=%s rc=%d errno=%d calls=%d arms=%d failures=%d watches=%d/%d\n",
        state.stage2_state, state.su_gate, state.su_gate_reason, state.stage2_rc,
        state.stage2_errno, calls, arms, failures, watch_starts, watch_stops);
    return 0;
}
'''


@unittest.skipUnless(HOST_CC is not None, "no host C compiler")
class GhostlockStage2TransportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ghostlock-stage2-transport-")
        cls.path = Path(cls.temp.name)
        source = cls.path / "fixture.c"
        source.write_text(HARNESS_PREAMBLE + FIXTURE +
                          definition(SOURCE.read_text(encoding="utf-8"), "hook_stage2") + MAIN,
                          encoding="utf-8")
        cls.exe = cls.path / ("fixture.exe" if os.name == "nt" else "fixture")
        result = subprocess.run([str(HOST_CC), "-std=c11", "-O0", str(source), "-o", str(cls.exe)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_stage2(self, provider=1, scenario="ok"):
        result = subprocess.run([str(self.exe), str(provider), scenario],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def test_ghostlock_uses_normal_memory_transport_and_shared_arm(self):
        text = self.run_stage2()
        self.assertIn("CALL=buffer verified=1 params=empty", text)
        self.assertNotIn("CALL=file", text)
        self.assertIn("state=LOADED gate=ARMED", text)
        self.assertIn("calls=1 arms=1 failures=0", text)
        self.assertIn("watches=1/1", text)

    def test_file_transport_keeps_the_verified_descriptor_after_path_replacement(self):
        for provider in (0, 2):
            with self.subTest(provider=provider):
                text = self.run_stage2(provider, "replacement")
                self.assertIn("CALL=file fd=7 flags=0 verified=1", text)
                self.assertIn("state=LOADED gate=ARMED", text)

    def test_file_only_loader_error_is_isolated_to_file_sources(self):
        text = self.run_stage2(scenario="file-error")
        self.assertIn("state=LOADED gate=ARMED", text)
        self.assertIn("calls=1 arms=1 failures=0", text)
        for provider in (0, 2):
            with self.subTest(provider=provider):
                text = self.run_stage2(provider, "file-error")
                self.assertIn("state=LOAD_FAILED gate=UNAVAILABLE", text)
                self.assertIn("rc=-1 errno=5 calls=1 arms=0 failures=0", text)

    def test_dirtyfrag_and_93260_keep_their_working_file_transport(self):
        for provider in (0, 2):
            with self.subTest(provider=provider):
                text = self.run_stage2(provider)
                self.assertIn("CALL=file fd=7 flags=0", text)
                self.assertNotIn("CALL=buffer", text)
                self.assertIn("state=LOADED gate=ARMED", text)
                self.assertIn("watches=0/0", text)

    def test_load_error_does_not_retry_or_arm_or_hide_errno(self):
        for provider in (0, 1, 2):
            with self.subTest(provider=provider):
                text = self.run_stage2(provider, "rejected")
                self.assertIn("state=LOAD_FAILED gate=UNAVAILABLE reason=STAGE2_LOAD_FAILED rc=-1 errno=8", text)
                self.assertIn("calls=1 arms=0 failures=0", text)

    def test_already_resident_still_requires_the_shared_arm(self):
        for provider in (0, 1, 2):
            with self.subTest(provider=provider):
                text = self.run_stage2(provider, "duplicate")
                self.assertIn("state=ALREADY_RESIDENT gate=ARMED", text)
                self.assertIn("calls=1 arms=1 failures=0", text)

    def test_closed_window_missing_or_invalid_image_never_loads(self):
        for scenario, state in (("closed", "NOT_EXERCISED"), ("missing", "NOT_EXERCISED"),
                                ("invalid", "INVALID")):
            with self.subTest(scenario=scenario):
                text = self.run_stage2(scenario=scenario)
                self.assertIn("state=" + state + " gate=UNAVAILABLE", text)
                self.assertIn("calls=0 arms=0", text)
                self.assertIn("watches=0/0", text)


if __name__ == "__main__":
    unittest.main()
