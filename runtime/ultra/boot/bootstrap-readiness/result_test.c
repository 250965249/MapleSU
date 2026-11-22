#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

long maplesu_installer_result_open(int, int[2]);
long maplesu_installer_result_parent(pid_t, int, int[2]);
void maplesu_installer_result_worker(int[2]);
int maplesu_installer_result_complete(int[2], const char*, int);
int maplesu_installer_bootstrap_ready(const char*);

static char helper[256], safe_path[300], completed_path[300], boot[37];
static int poll_mode, pipe_failure, poll_calls;
int __real_poll(struct pollfd*, nfds_t, int);
int __wrap_poll(struct pollfd* fds, nfds_t count, int timeout) {
    ++poll_calls;
    assert(timeout == 120000);
    if (poll_mode == 1) return 0;
    if (poll_mode == 2) { errno = EIO; return -1; }
    if (poll_mode == 3 && poll_calls == 1) { errno = EINTR; return -1; }
    return __real_poll(fds, count, timeout);
}
int __real_pipe2(int[2], int);
int __wrap_pipe2(int pair[2], int flags) {
    assert(flags == O_CLOEXEC);
    if (pipe_failure) { errno = EMFILE; return -1; }
    return __real_pipe2(pair, flags);
}

static void put(const char* path, const void* bytes, size_t count) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && write(fd, bytes, count) == (ssize_t)count && close(fd) == 0);
}
static void valid_files(void) {
    (void)unlink(safe_path); (void)unlink(completed_path);
    put(safe_path, "2", 1); put(completed_path, boot, sizeof(boot));
}
static void reset_poll(void) { poll_mode = pipe_failure = poll_calls = 0; }

static void run_worker(int launched, int expected) {
    int pair[2];
    assert(maplesu_installer_result_open(1, pair) == 0);
    assert((fcntl(pair[0], F_GETFD) & FD_CLOEXEC) && (fcntl(pair[1], F_GETFD) & FD_CLOEXEC));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        maplesu_installer_result_worker(pair);
        int result = maplesu_installer_result_complete(pair, helper, launched);
        _exit(result ? 0 : 17);
    }
    long result = maplesu_installer_result_parent(child, 1, pair);
    assert(result == expected && pair[0] == -1 && pair[1] == -1);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == (expected == 0 ? 0 : 17));
}

static void raw_reply(const void* data, size_t length, int expected) {
    int pair[2];
    assert(maplesu_installer_result_open(1, pair) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        maplesu_installer_result_worker(pair);
        if (length) assert(write(pair[1], data, length) == (ssize_t)length);
        close(pair[1]); _exit(0);
    }
    assert(maplesu_installer_result_parent(child, 1, pair) == expected);
    int status; assert(waitpid(child, &status, 0) == child);
}

int main(void) {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    assert(fd >= 0 && read(fd, boot, sizeof(boot)) == sizeof(boot) && close(fd) == 0);
    assert(snprintf(helper, sizeof(helper), "/tmp/maplesu-result-%ld", (long)getpid()) > 0);
    assert(snprintf(safe_path, sizeof(safe_path), "%s.safe_flag", helper) > 0);
    assert(snprintf(completed_path, sizeof(completed_path), "%s.boot_session.completed", helper) > 0);
    valid_files(); reset_poll();
    assert(maplesu_installer_bootstrap_ready(helper) == 1);
    run_worker(1, 0);
    run_worker(0, -21002);

    assert(unlink(completed_path) == 0); run_worker(1, -21002);
    valid_files(); put(completed_path, boot, 36); run_worker(1, -21002);
    valid_files(); char stale[37]; memcpy(stale, boot, 37); stale[0] = stale[0] == 'a' ? 'b' : 'a';
    put(completed_path, stale, 37); run_worker(1, -21002);
    valid_files(); put(safe_path, "1", 1); run_worker(1, -21002);
    // ensure-05: helper process exits 0 after ERR_MODULE_PARAM, with safe=1 and
    // no completion receipt. A successful process exit must still reject it.
    valid_files(); put(safe_path, "1", 1); assert(unlink(completed_path) == 0);
    run_worker(1, -21002);
    valid_files(); put(safe_path, "", 0); run_worker(1, -21002);
    valid_files(); put(safe_path, "2\n", 2); run_worker(1, -21002);
    valid_files(); assert(unlink(safe_path) == 0); run_worker(1, -21002);
    valid_files(); assert(unlink(completed_path) == 0 && symlink(safe_path, completed_path) == 0); run_worker(1, -21002);
    valid_files(); char hard[320]; snprintf(hard, sizeof(hard), "%s.hard", completed_path);
    assert(link(completed_path, hard) == 0); run_worker(1, -21002); assert(unlink(hard) == 0);
    valid_files(); assert(chown(completed_path, 12345, 12345) == 0); run_worker(1, -21002);

    valid_files(); reset_poll(); poll_mode = 3; run_worker(1, 0); assert(poll_calls == 2);
    reset_poll(); raw_reply("", 0, -21002);
    raw_reply("bad", 3, -21002);
    int32_t bad_magic[2] = {0, 0}; raw_reply(bad_magic, sizeof(bad_magic), -21002);
    int32_t error_reply[2] = {0x4d535552, -21002}; raw_reply(error_reply, sizeof(error_reply), -21002);

    int pair[2]; reset_poll(); assert(maplesu_installer_result_open(1, pair) == 0);
    poll_mode = 1; assert(maplesu_installer_result_parent(222, 1, pair) == -21002);
    reset_poll(); assert(maplesu_installer_result_open(1, pair) == 0);
    poll_mode = 2; assert(maplesu_installer_result_parent(222, 1, pair) == -21002);
    reset_poll(); pipe_failure = 1; assert(maplesu_installer_result_open(1, pair) == -21002);
    assert(pair[0] == -1 && pair[1] == -1);
    reset_poll(); assert(maplesu_installer_result_open(1, pair) == 0);
    assert(maplesu_installer_result_parent(-1, 1, pair) == -21002 && pair[0] == -1 && pair[1] == -1);
    assert(maplesu_installer_result_open(0, pair) == 0 && pair[0] == -1 && pair[1] == -1);
    assert(maplesu_installer_result_parent(222, 0, pair) == 0);
    unlink(safe_path); unlink(completed_path);
    puts("PASS: 23 result-channel/readiness cases including ensure-05 safe=1/completed-missing; real fork/pipe");
    return 0;
}
