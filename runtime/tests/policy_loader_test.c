#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "environment_backend_identity.h"

int maplesu_environment_policy_load(const char*);
uid_t __real_getuid(void);
uid_t __wrap_getuid(void) { return getenv("FIXTURE_NONROOT") ? 2000 : __real_getuid(); }
void* __real_dlopen(const char*, int);
ssize_t __real_read(int, void*, size_t);
ssize_t __wrap_read(int fd, void* buffer, size_t count) {
    static int interrupted;
    if (getenv("FIXTURE_READ_EINTR") && !interrupted++) { errno = EINTR; return -1; }
    if (getenv("FIXTURE_READ_EOF")) return 0;
    if (getenv("FIXTURE_SHORT_READ") && count > 7) count = 7;
    return __real_read(fd, buffer, count);
}
void* __wrap_dlopen(const char* path, int flags) {
    if (getenv("FIXTURE_REPLACE")) {
        if (rename("/tmp/maplesu-policy-loader/replacement.so",
                   "/tmp/maplesu-policy-loader/adb/maplesu/bin/" MAPLESU_POLICY_BACKEND_FILE)) _exit(90);
    }
    return __real_dlopen(path, flags);
}
int main(int count, char** argv) {
    if (count != 2) return 99;
    int result = maplesu_environment_policy_load(getenv("FIXTURE_NULL_KEY") ? NULL : "fixture-key");
    if (result == atoi(argv[1])) return 0;
    fprintf(stderr, "loader result %d expected %s\n", result, argv[1]);
    return 98;
}
