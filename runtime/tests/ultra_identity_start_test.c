#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int maplesu_environment_identity_start(void);
static int nonroot;
uid_t __real_getuid(void);
uid_t __wrap_getuid(void) { return nonroot ? 10000 : __real_getuid(); }

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *which = argv[1];
    const char *dir = "/data/adb/maplesu/ultra-identity";
    const char *script = "/data/adb/maplesu/ultra-identity/start.sh";
    assert(mkdir("/data", 0755) == 0);
    assert(mkdir("/data/adb", 0700) == 0);
    assert(mkdir("/data/adb/maplesu", 0700) == 0);
    assert(mkdir(dir, 0700) == 0);
    int fd = open(script, O_WRONLY | O_CREAT | O_EXCL, 0700);
    assert(fd >= 0);
    const char text[] = "#!/bin/sh\nprintf ready > /data/ready\nsleep 2\n";
    assert(write(fd, text, sizeof(text) - 1) == sizeof(text) - 1);
    close(fd);
    int lock = open("/data/inherited-lock", O_RDWR | O_CREAT, 0600);
    assert(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0);
    if (!strcmp(which, "missing")) assert(unlink(script) == 0);
    if (!strcmp(which, "mode")) assert(chmod(script, 0777) == 0);
    if (!strcmp(which, "owner")) assert(chown(script, 10000, 10000) == 0);
    if (!strcmp(which, "directory-mode")) assert(chmod(dir, 0777) == 0);
    if (!strcmp(which, "directory-owner")) assert(chown(dir, 10000, 10000) == 0);
    if (!strcmp(which, "disabled")) { fd = open("/data/adb/maplesu/ultra-identity/disabled", O_CREAT, 0600); assert(fd >= 0); close(fd); }
    if (!strcmp(which, "disabled-symlink")) assert(symlink("/absent", "/data/adb/maplesu/ultra-identity/disabled") == 0);
    if (!strcmp(which, "script-symlink")) { assert(rename(script, "/data/original") == 0); assert(symlink("/data/original", script) == 0); }
    if (!strcmp(which, "directory-symlink")) { assert(rename(dir, "/data/original") == 0); assert(symlink("/data/original", dir) == 0); }
    if (!strcmp(which, "hardlink")) assert(link(script, "/data/link") == 0);
    if (!strcmp(which, "fifo")) { assert(unlink(script) == 0); assert(mkfifo(script, 0700) == 0); }
    if (!strcmp(which, "nonroot")) nonroot = 1;
    const int valid = !strcmp(which, "valid") || !strcmp(which, "closed-stdio");
    if (!strcmp(which, "closed-stdio")) { close(0); close(1); close(2); }
    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    int result = maplesu_environment_identity_start();
    clock_gettime(CLOCK_MONOTONIC, &after);
    long ms = (after.tv_sec - before.tv_sec) * 1000 + (after.tv_nsec - before.tv_nsec) / 1000000;
    assert(ms < 500); /* Waiting for Android/broker here would stall all user modules. */
    assert((result == 0) == valid);
    close(lock);
    if (valid) {
        for (int i = 0; access("/data/ready", F_OK) && i < 100; ++i) usleep(10000);
        assert(access("/data/ready", F_OK) == 0);
        lock = open("/data/inherited-lock", O_RDWR);
        assert(lock >= 0 && flock(lock, LOCK_EX | LOCK_NB) == 0);
        close(lock);
    } else {
        usleep(20000);
        assert(access("/data/ready", F_OK) != 0);
    }
    printf("PASS identity launcher %s %ldms\n", which, ms);
    return 0;
}
