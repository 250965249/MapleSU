"""Run the production bounded kmsg reader with injected OS boundaries.

This verifies diagnostic persistence/lifetime only, not the device panic.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_handover_mode import HOST_CC, SOURCE, definition

FIXTURE = r'''
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
struct pollfd { int fd; short events, revents; };
#define O_RDONLY 0
#define O_NONBLOCK 0x800
#define O_CLOEXEC 0x80000
#define SEEK_END 2
#define POLLIN 1
#define CLOCK_MONOTONIC 1
#define WNOHANG 1
#define SIGTERM 15
static const char *scenario;
static int records, polls, waits, closed, returned, ended, overrun;
static unsigned written;
static long parent_pid = 99;
static int scenario_is(const char *value) { return !strcmp(scenario, value); }
static void log_line(const char *format, ...) {
    va_list args; va_start(args, format); vprintf(format, args); va_end(args);
}
static int fixture_open(const char *path, int flags) {
    if (strcmp(path, "/dev/kmsg") || !(flags & O_NONBLOCK) || !(flags & O_CLOEXEC)) abort();
    if (scenario_is("open")) { errno = EACCES; return -1; }
    return 10;
}
static int fixture_pipe2(int pipefd[2], int flags) {
    if (!(flags & O_CLOEXEC) || !(flags & O_NONBLOCK)) abort();
    if (scenario_is("pipe")) { errno = EMFILE; return -1; }
    pipefd[0] = 11; pipefd[1] = 12; return 0;
}
static long fixture_lseek(int fd, long offset, int whence) {
    if (fd != 10 || offset || whence != SEEK_END) abort();
    if (scenario_is("seek")) { errno = ESPIPE; return -1; }
    return 0;
}
static int fixture_clock_gettime(int clock, struct timespec *time) {
    if (clock != CLOCK_MONOTONIC) abort();
    time->tv_sec = scenario_is("timeout") ? polls * 200 : polls / 10;
    time->tv_nsec = 0; return 0;
}
static int fixture_poll(struct pollfd *fds, unsigned count, int timeout) {
    if (count != 2 || timeout > 250 || timeout <= 0) abort();
    polls++;
    if (scenario_is("parent")) parent_pid = 1;
    if (scenario_is("timeout") || scenario_is("parent") || scenario_is("flood")) return 0;
    if (polls == 1) { fds[0].revents = POLLIN; return 1; }
    fds[1].revents = POLLIN; ended = 1; return 1;
}
static ssize_t fixture_read(int fd, void *buffer, size_t capacity) {
    if (fd != 10) abort();
    if (scenario_is("overflow") && !overrun++) { errno = EPIPE; return -1; }
    const char *message;
    if (scenario_is("flood")) {
        memset(buffer, 'a', capacity);
        written += capacity;
        return capacity;
    }
    switch (records++) {
    case 0: message = "6,1,1,-;maplesu_l3: init stage=entry\n"; break;
    case 1: message = "6,2,2,-;maplesu_l3: legacy suToken=0011223344556677\n"; break;
    case 2: message = "4,3,3,-;unrelated driver\n"; break;
    case 3: message = "0,4,4,-;Kernel panic - not syncing: fixture\n"; break;
    default: errno = EAGAIN; return -1;
    }
    size_t size = strlen(message); if (size > capacity) abort();
    memcpy(buffer, message, size); return size;
}
static int fixture_close(int fd) { if (fd < 0) abort(); closed++; return 0; }
static long fixture_fork(void) {
    if (scenario_is("fork")) { errno = EAGAIN; return -1; }
    return scenario_is("parent-branch") ? 23 : 0;
}
static long fixture_getpid(void) { return 99; }
static long fixture_getppid(void) { return parent_pid; }
static void fixture_exit(int code) {
    if (code) abort();
    printf("EXIT polls=%d close=%d written=%u ended=%d\n", polls, closed, written, ended);
    exit(0);
}
static ssize_t fixture_write(int fd, const void *value, size_t size) {
    if (fd != 12 || !size || !value) abort();
    return size;
}
static long fixture_waitpid(long pid, int *status, int options) {
    (void)status; if (pid != 23 || options != WNOHANG) abort();
    waits++; return 23;
}
static void fixture_usleep(unsigned value) { if (value > 50000) abort(); }
static int klog_line_contains_token(const char *line, size_t size) {
    return size >= 8 && strstr(line, "suToken=") != NULL;
}
#define open fixture_open
#define pipe2 fixture_pipe2
#define lseek fixture_lseek
#define clock_gettime fixture_clock_gettime
#define poll fixture_poll
#define read fixture_read
#define write fixture_write
#define close fixture_close
#define fork fixture_fork
#define getpid fixture_getpid
#define getppid fixture_getppid
#define _exit fixture_exit
#define waitpid fixture_waitpid
#define usleep fixture_usleep
'''
MAIN = r'''
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    scenario = argv[1];
    int stop = -1;
    pid_t pid = hook_stage2_watch_start(&stop);
    returned++;
    hook_stage2_watch_stop(pid, stop);
    printf("RESULT pid=%ld stop=%d closes=%d waits=%d returned=%d\n",
           (long)pid, stop, closed, waits, returned);
    return 0;
}
'''


@unittest.skipUnless(HOST_CC is not None, "no host C compiler")
class GhostlockStage2DiagnosticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = SOURCE.read_text(encoding="utf-8")
        cls.functions = [definition(text, name) for name in
                         ("hook_stage2_watch_start", "hook_stage2_watch_stop")]
        if not all(cls.functions):
            return
        cls.temp = tempfile.TemporaryDirectory(prefix="ghostlock-load-watch-")
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        source = path / "fixture.c"
        source.write_text(FIXTURE + "\n".join(cls.functions) + MAIN, encoding="utf-8")
        cls.binary = path / ("fixture.exe" if os.name == "nt" else "fixture")
        result = subprocess.run([str(HOST_CC), "-std=c11", str(source), "-o", str(cls.binary)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_watch(self, scenario):
        self.assertTrue(all(self.functions), "stage2 has no independent kernel log reader")
        result = subprocess.run([str(self.binary), scenario], capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def test_records_reach_durable_log_before_loader_returns(self):
        text = self.run_watch("ok")
        self.assertIn("maplesu_l3: init stage=entry", text)
        self.assertIn("Kernel panic", text)
        self.assertNotIn("unrelated driver", text)
        self.assertNotIn("0011223344556677", text)
        self.assertIn("EXIT polls=2", text)
        self.assertNotIn("RESULT", text)

    def test_ring_overrun_continues_reading(self):
        text = self.run_watch("overflow")
        self.assertIn("Kernel panic", text)
        self.assertIn("EXIT", text)

    def test_parent_exit_and_deadline_end_reader(self):
        for scenario in ("parent", "timeout"):
            with self.subTest(scenario=scenario):
                text = self.run_watch(scenario)
                self.assertIn("EXIT", text)
                self.assertNotIn("RESULT", text)

    def test_flood_is_bounded(self):
        text = self.run_watch("flood")
        self.assertIn("EXIT", text)

    def test_unavailable_diagnostics_leave_no_open_descriptors(self):
        for scenario, closed in (("open", 0), ("seek", 1), ("pipe", 1), ("fork", 3)):
            with self.subTest(scenario=scenario):
                text = self.run_watch(scenario)
                self.assertIn(f"RESULT pid=-1 stop=-1 closes={closed} waits=0 returned=1", text)

    def test_successful_parent_signals_reader_without_blocking_wait(self):
        text = self.run_watch("parent-branch")
        self.assertIn("RESULT pid=23 stop=12 closes=3 waits=1 returned=1", text)


if __name__ == "__main__":
    unittest.main()
