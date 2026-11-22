#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LAUNCH_ERROR (-21002L)
#define RESULT_MAGIC UINT32_C(0x4d535552)
struct launch_result { uint32_t magic; int32_t error; };

static void close_pair(int pair[2]) {
    if (pair[0] >= 0) (void)close(pair[0]);
    if (pair[1] >= 0) (void)close(pair[1]);
    pair[0] = pair[1] = -1;
}

__attribute__((visibility("hidden")))
long maplesu_installer_result_open(int mode, int pair[2]) {
    pair[0] = pair[1] = -1;
    if (mode != 1) return 0;
    return pipe2(pair, O_CLOEXEC) == 0 ? 0 : LAUNCH_ERROR;
}

__attribute__((visibility("hidden")))
void maplesu_installer_result_worker(int pair[2]) {
    if (pair[0] >= 0) (void)close(pair[0]);
    pair[0] = -1;
}

__attribute__((visibility("hidden")))
long maplesu_installer_result_parent(pid_t child, int mode, int pair[2]) {
    if (child <= 0) { close_pair(pair); return LAUNCH_ERROR; }
    if (mode != 1) { close_pair(pair); return 0; }
    (void)close(pair[1]); pair[1] = -1;
    struct pollfd ready = { pair[0], POLLIN, 0 };
    int result;
    do { result = poll(&ready, 1, 120000); } while (result < 0 && errno == EINTR);
    struct launch_result reply = {0, 0};
    ssize_t count = -1;
    if (result > 0 && (ready.revents & (POLLIN | POLLHUP))) {
        do { count = read(pair[0], &reply, sizeof(reply)); } while (count < 0 && errno == EINTR);
    }
    close_pair(pair);
    if (count != sizeof(reply) || reply.magic != RESULT_MAGIC || reply.error != 0) return LAUNCH_ERROR;
    return 0;
}

static int read_exact_file(const char* path, char* bytes, size_t expected, int receipt) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st;
    int valid = fstat(fd, &st) == 0;
    if (receipt) valid = valid && S_ISREG(st.st_mode) && st.st_uid == 0 && st.st_nlink == 1 && st.st_size == (off_t)expected;
    char extra[38];
    size_t size = 0;
    while (valid && size < expected + 1) {
        ssize_t count = read(fd, extra + size, expected + 1 - size);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { valid = 0; break; }
        if (count == 0) break;
        size += (size_t)count;
    }
    if (close(fd) != 0) valid = 0;
    valid = valid && size == expected;
    if (valid) memcpy(bytes, extra, expected);
    return valid;
}

__attribute__((visibility("hidden")))
int maplesu_installer_bootstrap_ready(const char* helper) {
    char path[4096], boot[37], receipt[37], safe;
    if (!helper || !*helper || !read_exact_file("/proc/sys/kernel/random/boot_id", boot, sizeof(boot), 0) || boot[36] != '\n') return 0;
    for (size_t i = 0; i < 36; ++i) {
        const char c = boot[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c == '-') continue; }
        else if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) continue;
        return 0;
    }
    int n = snprintf(path, sizeof(path), "%s.boot_session.completed", helper);
    if (n <= 0 || (size_t)n >= sizeof(path) || !read_exact_file(path, receipt, sizeof(receipt), 1) || memcmp(boot, receipt, sizeof(boot))) return 0;
    n = snprintf(path, sizeof(path), "%s.safe_flag", helper);
    return n > 0 && (size_t)n < sizeof(path) && read_exact_file(path, &safe, 1, 1) && safe == '2';
}

__attribute__((visibility("hidden")))
int maplesu_installer_result_complete(int pair[2], const char* helper, int launch_ok) {
    const int valid = launch_ok && maplesu_installer_bootstrap_ready(helper);
    struct launch_result reply = { RESULT_MAGIC, valid ? 0 : (int32_t)LAUNCH_ERROR };
    ssize_t count;
    do { count = write(pair[1], &reply, sizeof(reply)); } while (count < 0 && errno == EINTR);
    close_pair(pair);
    return valid && count == sizeof(reply);
}
