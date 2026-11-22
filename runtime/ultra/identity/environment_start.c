/* Called by the environment bootstrap after default initialization, before user modules. */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MAPLESU_IDENTITY_SHELL
#define MAPLESU_IDENTITY_SHELL "/system/bin/sh"
#endif

static int open_script(void) {
    int dir = open("/data", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return -1;
    const char *parts[] = {"adb", "maplesu", "ultra-identity"};
    struct stat st;
    for (unsigned i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        int next = openat(dir, parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dir);
        if (next < 0) return -1;
        if (fstat(next, &st) || st.st_uid != 0 || (st.st_mode & 0022)) {
            close(next);
            return -1;
        }
        dir = next;
    }
    if (fstatat(dir, "disabled", &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        close(dir);
        return -1;
    }
    /* Retain the validated inode across fork/exec; sh receives its descriptor path. */
    int fd = openat(dir, "start.sh", O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 07777) != 0700 || st.st_nlink != 1) {
        close(fd);
        return -1;
    }
    if (fd <= 2) {
        int next = fcntl(fd, F_DUPFD, 3);
        close(fd);
        return next;
    }
    return fd;
}

/* Do not let the daemon retain the bootstrap's locks, pipes or module descriptors. */
static int close_inherited(int script) {
    int dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return -1;
    char bytes[1024];
    long count;
    while ((count = syscall(SYS_getdents64, dir, bytes, sizeof(bytes))) > 0) {
        for (long at = 0; at < count;) {
            struct entry { uint64_t ino; int64_t off; unsigned short size; unsigned char type; char name[]; };
            const struct entry *e = (const struct entry *)(bytes + at);
            if (e->size < offsetof(struct entry, name) + 2 || at + e->size > count) {
                close(dir);
                return -1;
            }
            int fd = 0;
            const char *name = e->name;
            while (*name >= '0' && *name <= '9' && fd < 10000000) fd = fd * 10 + (*name++ - '0');
            if (!*name && fd > 2 && fd != script && fd != dir) close(fd);
            at += e->size;
        }
    }
    close(dir);
    return count < 0 ? -1 : 0;
}

int maplesu_environment_identity_start(void) {
    if (getuid() != 0) return 1;
    int script = open_script();
    if (script < 0) return 2;
    pid_t child = fork();
    if (child < 0) { close(script); return 3; }
    if (child > 0) {
        close(script);
        /* Reap only the short-lived intermediate, never wait for Android or the broker. */
        int status;
        while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) return 4; }
        return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 4;
    }
    if (setsid() < 0) _exit(5);
    child = fork();
    if (child < 0) _exit(6);
    if (child > 0) _exit(0);
    if (close_inherited(script)) _exit(7);
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0) _exit(8);
    for (int fd = 0; fd <= 2; ++fd) if (dup2(null_fd, fd) < 0) _exit(8);
    if (null_fd > 2) close(null_fd);
    char path[48];
    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", script) <= 0) _exit(9);
    execl(MAPLESU_IDENTITY_SHELL, "sh", path, (char *)0);
    _exit(10);
}
