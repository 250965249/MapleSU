/* The SDK owns these paths; never follow a substituted symlink or adopt a
 * foreign inode while migrating an existing installation's DAC permissions. */
#include "private_dac.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int owned(int fd, struct stat *st) {
    return syscall(SYS_fstat, fd, st) == 0 && st->st_uid == 0 && st->st_gid == 0 &&
        (S_ISDIR(st->st_mode) || (S_ISREG(st->st_mode) && st->st_nlink == 1));
}

int maplesu_private_chmod(const char *path, unsigned mode) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct stat st;
    int result = -1;
    if (owned(fd, &st)) {
        if (!mode) mode = S_ISDIR(st.st_mode) ? 0700 : 0600;
        if ((S_ISDIR(st.st_mode) && (mode == 0700 || mode == 0711)) ||
            (S_ISREG(st.st_mode) && mode == 0600))
            result = (int)syscall(SYS_fchmod, fd, mode);
    }
    if (syscall(SYS_close, fd) && !result) result = -1;
    return result;
}

int maplesu_private_file_open(const char *path, int exclusive) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path,
        O_WRONLY | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC |
        (exclusive ? O_EXCL : 0), 0600);
    if (fd < 0) return -1;
    struct stat st;
    static const char context[] = "u:object_r:system_file:s0";
    if (!owned(fd, &st) || !S_ISREG(st.st_mode) ||
        syscall(SYS_fchmod, fd, 0600) ||
        syscall(SYS_fsetxattr, fd, "security.selinux", context, sizeof(context), 0)) {
        syscall(SYS_close, fd);
        return -1;
    }
    return fd;
}

int maplesu_private_allowlist_create(const char *path) {
    int fd = maplesu_private_file_open(path, 1);
    return fd >= 0 && syscall(SYS_close, fd) == 0;
}
