#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int maplesu_bootstrap_finish(const char *, int64_t);

static void marker(const char *path, const char *value) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    assert(fd >= 0);
    assert(write(fd, value, strlen(value)) == (ssize_t)strlen(value));
    assert(close(fd) == 0);
}

static char contents(const char *path) {
    int fd = open(path, O_RDONLY);
    char byte;
    assert(fd >= 0 && read(fd, &byte, 1) == 1);
    assert(close(fd) == 0);
    return byte;
}

int main(void) {
    char dir[] = "/tmp/maplesu-boot-XXXXXX";
    assert(mkdtemp(dir));
    char path[128], other[128], completed[128];
    assert(snprintf(path, sizeof(path), "%s/init.safe_flag", dir) > 0);
    assert(snprintf(other, sizeof(other), "%s/other", dir) > 0);
    assert(snprintf(completed, sizeof(completed), "%s/init.boot_session.completed", dir) > 0);

    marker(path, "1");
    assert(maplesu_bootstrap_finish(path, 0) == 0 && contents(path) == '2');
    puts("PASS durable-success");

    marker(path, "1");
    assert(maplesu_bootstrap_finish(path, -19999) != 0 && contents(path) == '1');
    puts("PASS initialization-failure-retains-marker");

    assert(unlink(path) == 0);
    assert(maplesu_bootstrap_finish(path, 0) != 0 && access(path, F_OK) != 0);
    puts("PASS missing-marker");

    marker(other, "1");
    assert(symlink(other, path) == 0);
    assert(maplesu_bootstrap_finish(path, 0) != 0 && contents(other) == '1');
    assert(unlink(path) == 0);
    puts("PASS symlink");

    assert(link(other, path) == 0);
    assert(maplesu_bootstrap_finish(path, 0) != 0 && contents(other) == '1');
    assert(unlink(path) == 0 && unlink(other) == 0);
    puts("PASS hardlink");

    assert(mkfifo(path, 0600) == 0);
    assert(maplesu_bootstrap_finish(path, 0) != 0);
    assert(unlink(path) == 0);
    puts("PASS fifo-does-not-block");

    marker(path, "13");
    assert(maplesu_bootstrap_finish(path, 0) != 0 && contents(path) == '1');
    puts("PASS malformed-marker");

    marker(path, "1");
    assert(chown(path, 10000, 10000) == 0);
    assert(maplesu_bootstrap_finish(path, 0) != 0 && contents(path) == '1');
    assert(unlink(path) == 0 && unlink(completed) == 0 && rmdir(dir) == 0);
    puts("PASS marker-owner");
    return 0;
}
