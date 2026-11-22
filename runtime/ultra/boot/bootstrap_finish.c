/* Commit the SDK bootstrap result in the process that performed initialization. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int failed(const char *step) {
    printf("MapleSU bootstrap completion failed: %s errno=%d; Running not published\n", step, errno);
    return 1;
}

/* Module install/uninstall intentionally reset safe_flag. Keep proof of the
 * successful bootstrap separately; neither operation publishes this receipt.
 */
static int complete_receipt(const char *flag_path) {
    char path[4096], boot[38];
    const char suffix[] = ".safe_flag", receipt[] = ".boot_session.completed";
    size_t length = strlen(flag_path);
    if (length < sizeof(suffix) - 1 || length + sizeof(receipt) >= sizeof(path) ||
        strcmp(flag_path + length - sizeof(suffix) + 1, suffix)) return failed("receipt path");
    size_t prefix = length - sizeof(suffix) + 1;
    memcpy(path, flag_path, prefix);
    memcpy(path + prefix, receipt, sizeof(receipt));
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/sys/kernel/random/boot_id",
                         O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0) return failed("read boot ID");
    long count;
    do { count = syscall(SYS_read, fd, boot, sizeof(boot)); } while (count < 0 && errno == EINTR);
    int closed = (int)syscall(SYS_close, fd);
    if (count != 37 || boot[36] != '\n' || closed) return failed("validate boot ID");
    for (size_t i = 0; i < 36; ++i) {
        char c = boot[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (c == '-') continue; }
        else if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) continue;
        return failed("validate boot ID");
    }
    fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                      O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0) return failed("open completion receipt");
    struct stat st;
    int result = 1;
    if (syscall(SYS_fstat, fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_nlink != 1 || (st.st_size != 0 && st.st_size != 37)) {
        failed("validate completion receipt");
        goto done;
    }
    do { count = syscall(SYS_pwrite64, fd, boot, 37, 0); } while (count < 0 && errno == EINTR);
    if (count != 37) { failed("write completion receipt"); goto done; }
    do { count = syscall(SYS_fsync, fd); } while (count < 0 && errno == EINTR);
    if (count) { failed("sync completion receipt"); goto done; }
    result = 0;
done:
    if (syscall(SYS_close, fd) && !result) return failed("close completion receipt");
    return result;
}

int maplesu_bootstrap_finish(const char *path, int64_t initialization_error) {
    if (initialization_error) {
        printf("load_module_main -> rc=%lld; bootstrap protection retained\n", (long long)initialization_error);
        return 1;
    }

    /* The original pre-load path has already created the one-byte '1' marker.
     * Update that inode without truncation: a failed write retains protection.
     */
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
                         O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0) return failed("open safe flag");
    struct stat st;
    int result = 1;
    if (syscall(SYS_fstat, fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_nlink != 1 || st.st_size != 1) {
        failed("validate safe flag");
        goto done;
    }
    if (complete_receipt(path)) goto done;
    long count;
    do { count = syscall(SYS_pwrite64, fd, "2", 1, 0); } while (count < 0 && errno == EINTR);
    if (count != 1) {
        failed("write safe flag");
        goto done;
    }
    do { count = syscall(SYS_fsync, fd); } while (count < 0 && errno == EINTR);
    if (count) {
        failed("sync safe flag");
        goto done;
    }
    result = 0;
done:
    if (syscall(SYS_close, fd) && !result) return failed("close safe flag");
    return result;
}
