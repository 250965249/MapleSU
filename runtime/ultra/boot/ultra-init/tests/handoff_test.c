// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "handoff.h"
#include "../../../identity/kernel/manager_deployment_namespace.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifdef MAPLESU_ULTRA_INIT_OS_FIXTURE
#include "os_fixture.h"
#else
#include <sys/syscall.h>
#endif
#include <sys/types.h>

static jmp_buf handed_off;
static char trace[64];
static char diagnostic[512];
static size_t steps, diagnostic_size;
static pid_t pid;
static int rename_error, open_error, load_error, close_error, exec_error, exec_interrupt;
static const char *credential;
static size_t credential_size, credential_at, read_piece;
static int credential_open_error, read_error, read_interrupt, credential_close_error, unlink_error;
static const unsigned char *deployment;
static size_t deployment_size, deployment_at, deployment_piece;
static int deployment_open_error, deployment_read_error, deployment_interrupt, deployment_close_error, deployment_unlink_error;
static const char *loaded_parameters;
static char **expected_argv, **expected_envp;

static void note(char step) {
    assert(steps + 1 < sizeof(trace));
    trace[steps++] = step;
    trace[steps] = 0;
}

pid_t __wrap_getpid(void) { return pid; }

int __wrap_rename(const char *from, const char *to) {
    note('R');
    assert(strcmp(from, "/init.maplesu.orig") == 0 && strcmp(to, "/init") == 0);
    errno = rename_error;
    return rename_error ? -1 : 0;
}

int __wrap_open(const char *path, int flags, ...) {
    if (strcmp(path, "/.maplesu_ultra/deployment") == 0) {
        assert(flags == (O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
        if (!deployment && !deployment_open_error) { errno = ENOENT; return -1; }
        note('N');
        errno = deployment_open_error;
        return deployment_open_error ? -1 : 9;
    }
    if (strcmp(path, "/.maplesu_ultra/credential") == 0) {
        assert(flags == (O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
        if (!credential && !credential_open_error) { errno = ENOENT; return -1; }
        note('K');
        errno = credential_open_error;
        return credential_open_error ? -1 : 8;
    }
    note('O');
    assert(strcmp(path, "/.maplesu_ultra/bridge.ko") == 0);
    assert(flags == (O_RDONLY | O_CLOEXEC));
    errno = open_error;
    return open_error ? -1 : 7;
}

#ifdef MAPLESU_ULTRA_INIT_OS_FIXTURE
int __wrap_read(int fd, void *buffer, unsigned int bytes) {
#else
ssize_t __wrap_read(int fd, void *buffer, size_t bytes) {
#endif
    if (fd == 9) {
        note('d');
        if (deployment_interrupt) { deployment_interrupt = 0; errno = EINTR; return -1; }
        if (deployment_read_error) { errno = deployment_read_error; return -1; }
        size_t count = deployment_size - deployment_at;
        if (count > bytes) count = bytes;
        if (count > deployment_piece) count = deployment_piece;
        memcpy(buffer, deployment + deployment_at, count);
        deployment_at += count;
        return count;
    }
    assert(fd == 8);
    note('D');
    if (read_interrupt) { read_interrupt = 0; errno = EINTR; return -1; }
    if (read_error) { errno = read_error; return -1; }
    size_t count = credential_size - credential_at;
    if (count > bytes) count = bytes;
    if (count > read_piece) count = read_piece;
    memcpy(buffer, credential + credential_at, count);
    credential_at += count;
    return count;
}

int __wrap_unlink(const char *path) {
    if (strcmp(path, "/.maplesu_ultra/deployment") == 0) {
        note('u');
        errno = deployment_unlink_error;
        return deployment_unlink_error ? -1 : 0;
    }
    assert(strcmp(path, "/.maplesu_ultra/credential") == 0);
    note('U');
    errno = unlink_error;
    return unlink_error ? -1 : 0;
}

long __wrap_syscall(long number, ...) {
    note('L');
    assert(number == SYS_finit_module);
    va_list args;
    va_start(args, number);
    assert(va_arg(args, int) == 7);
    loaded_parameters = va_arg(args, const char *);
    char expected[128] = {0};
    if (credential) {
        memcpy(expected, "credential=", 11);
        memcpy(expected + 11, credential, 48);
    }
    if (deployment) {
        const size_t used = strlen(expected);
        snprintf(expected + used, sizeof(expected) - used, "%sdeployment_namespace=%.*s",
            used ? " " : "", 16, (const char *)deployment + 8);
    }
    assert(strcmp(loaded_parameters, expected) == 0);
    assert(va_arg(args, int) == 0);
    va_end(args);
    errno = load_error;
    return load_error ? -1 : 0;
}

int __wrap_close(int fd) {
    if (fd == 9) {
        note('n');
        errno = deployment_close_error;
        return deployment_close_error ? -1 : 0;
    }
    if (fd == 8) {
        note('k');
        errno = credential_close_error;
        return credential_close_error ? -1 : 0;
    }
    note('C');
    assert(fd == 7);
    if (loaded_parameters) {
        for (size_t index = 0; index < 128; ++index) assert(loaded_parameters[index] == 0);
    }
    errno = close_error;
    return close_error ? -1 : 0;
}

int __wrap_execve(const char *path, char *const argv[], char *const envp[]) {
    note('E');
    assert(strcmp(path, rename_error ? "/init.maplesu.orig" : "/init") == 0);
    assert(argv == expected_argv && envp == expected_envp);
    assert(strcmp(argv[0], "/init") == 0 && strcmp(argv[1], "first_stage") == 0 && argv[2] == NULL);
    assert(strcmp(envp[0], "INIT_ENV=kept value") == 0 && envp[1] == NULL);
    if (exec_interrupt) {
        exec_interrupt = 0;
        errno = EINTR;
        return -1;
    }
    if (exec_error) {
        errno = exec_error;
        return -1;
    }
    longjmp(handed_off, 1);
}

#ifdef MAPLESU_ULTRA_INIT_OS_FIXTURE
int __wrap_write(int fd, const void *bytes, unsigned int size) {
#else
ssize_t __wrap_write(int fd, const void *bytes, size_t size) {
#endif
    note('W');
    assert(fd == 2 && diagnostic_size + size < sizeof(diagnostic));
    memcpy(diagnostic + diagnostic_size, bytes, size);
    diagnostic_size += size;
    diagnostic[diagnostic_size] = 0;
    return size;
}

static void reset(void) {
    memset(trace, 0, sizeof(trace));
    memset(diagnostic, 0, sizeof(diagnostic));
    steps = diagnostic_size = 0;
    pid = 1;
    rename_error = open_error = load_error = close_error = exec_error = exec_interrupt = 0;
    credential = loaded_parameters = NULL;
    credential_size = credential_at = 0;
    read_piece = 49;
    credential_open_error = read_error = read_interrupt = credential_close_error = unlink_error = 0;
    deployment = NULL;
    deployment_size = deployment_at = 0;
    deployment_piece = 25;
    deployment_open_error = deployment_read_error = deployment_interrupt = deployment_close_error = deployment_unlink_error = 0;
}

static void expect_handoff(const char *sequence) {
    if (setjmp(handed_off) == 0) {
        (void)maplesu_ultra_first_stage(expected_argv, expected_envp);
        assert(!"original init was not executed");
    }
    assert(strcmp(trace, sequence) == 0);
}

int main(void) {
    char name[] = "/init", argument[] = "first_stage", environment[] = "INIT_ENV=kept value";
    char *argv[] = {name, argument, NULL};
    char *envp[] = {environment, NULL};
    expected_argv = argv;
    expected_envp = envp;

    reset();
    expect_handoff("ROLCE");
    reset(); open_error = ENOENT;
    expect_handoff("ROWE");
    assert(strstr(diagnostic, "open /.maplesu_ultra/bridge.ko failed errno=2") != NULL);
    reset(); load_error = ENOEXEC;
    expect_handoff("ROLCWE");
    assert(strstr(diagnostic, "finit_module /.maplesu_ultra/bridge.ko failed errno=8") != NULL);
    reset(); close_error = EIO;
    expect_handoff("ROLCWE");
    assert(strstr(diagnostic, "close /.maplesu_ultra/bridge.ko failed errno=5") != NULL);
    reset(); load_error = ENOEXEC; close_error = EIO;
    expect_handoff("ROLCWWE");
    const char *load_message = strstr(diagnostic, "finit_module /.maplesu_ultra/bridge.ko failed errno=8");
    const char *close_message = strstr(diagnostic, "close /.maplesu_ultra/bridge.ko failed errno=5");
    assert(load_message && close_message && load_message < close_message);
    reset(); rename_error = EROFS;
    expect_handoff("RWOLCE");
    assert(strstr(diagnostic, "rename /init.maplesu.orig failed errno=30") != NULL);
    reset(); rename_error = EROFS; load_error = ENOEXEC; close_error = EIO;
    expect_handoff("RWOLCWWE");
    const char *rename_message = strstr(diagnostic, "rename /init.maplesu.orig failed errno=30");
    load_message = strstr(diagnostic, "finit_module /.maplesu_ultra/bridge.ko failed errno=8");
    close_message = strstr(diagnostic, "close /.maplesu_ultra/bridge.ko failed errno=5");
    assert(rename_message && load_message && close_message &&
           rename_message < load_message && load_message < close_message);
    reset(); exec_interrupt = 1;
    expect_handoff("ROLCEE");
    reset(); exec_error = EACCES;
    assert(maplesu_ultra_first_stage(argv, envp) == 126 && strcmp(trace, "ROLCEW") == 0);
    assert(strstr(diagnostic, "execve /init failed errno=13") != NULL);
    reset(); rename_error = EROFS; exec_error = ENOENT;
    assert(maplesu_ultra_first_stage(argv, envp) == 126 && strcmp(trace, "RWOLCEW") == 0);
    assert(strstr(diagnostic, "execve /init.maplesu.orig failed errno=2") != NULL);
    reset(); pid = 123;
    assert(maplesu_ultra_first_stage(argv, envp) == 64 && steps == 0);
    assert(strcmp(name, "/init") == 0 && strcmp(argument, "first_stage") == 0);
    assert(strcmp(environment, "INIT_ENV=kept value") == 0);

    const char key[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL";
    assert(sizeof(key) == 49);
    reset(); credential = key; credential_size = 48;
    expect_handoff("ROKDDkULCE");
    assert(diagnostic_size == 0);
    reset(); credential = key; credential_size = 48; read_piece = 17; read_interrupt = 1;
    expect_handoff("ROKDDDDDkULCE");
    reset(); credential = key; credential_size = 47;
    expect_handoff("ROKDDWkUCE");
    assert(strstr(diagnostic, "read /.maplesu_ultra/credential failed errno=22"));
    reset(); credential = key; credential_size = 49;
    expect_handoff("ROKDWkUCE");
    reset(); credential = "bad\n"; credential_size = 4;
    expect_handoff("ROKDDWkUCE");
    reset(); credential = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJK/"; credential_size = 48;
    expect_handoff("ROKDDWkUCE");
    reset(); credential = "";
    expect_handoff("ROKDWkUCE");
    reset(); credential = key; credential_size = 48; read_error = EIO;
    expect_handoff("ROKDWkUCE");
    assert(strstr(diagnostic, "read /.maplesu_ultra/credential failed errno=5"));
    reset(); credential = key; credential_size = 48; credential_close_error = EIO;
    expect_handoff("ROKDDkWUCE");
    reset(); credential_open_error = ELOOP;
    expect_handoff("ROKWCE");
    reset(); credential = key; credential_size = 48; unlink_error = EROFS;
    expect_handoff("ROKDDkUWLCE");
    assert(strstr(diagnostic, "unlink /.maplesu_ultra/credential failed errno=30"));
    reset(); credential = key; credential_size = 48; load_error = ENOEXEC;
    expect_handoff("ROKDDkULCWE");
    assert(strstr(diagnostic, key) == NULL);
    reset(); credential = key; credential_size = 48; open_error = ENOENT;
    expect_handoff("ROWKDDkUE");
    assert(credential_at == 48 && strstr(diagnostic, key) == NULL);

    struct msu_deployment_namespace_record record = {
        .magic = MSU_DEPLOYMENT_NAMESPACE_MAGIC,
        .schema = MSU_DEPLOYMENT_NAMESPACE_SCHEMA,
        .bytes = sizeof(record),
    };
    memcpy(record.name, "ABCD2345EFGH6789", sizeof(record.name));
    unsigned char namespace_bytes[sizeof(record) + 1] = {0};
    memcpy(namespace_bytes, &record, sizeof(record));
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record);
    expect_handoff("RONddnuLCE");
    assert(diagnostic_size == 0);
    reset(); credential = key; credential_size = 48; deployment = namespace_bytes; deployment_size = sizeof(record);
    expect_handoff("ROKDDkUNddnuLCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); deployment_piece = 7; deployment_interrupt = 1;
    expect_handoff("RONddddddnuLCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record) - 1;
    expect_handoff("RONddWnuCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(namespace_bytes);
    expect_handoff("RONdWnuCE");
    namespace_bytes[0] ^= 1;
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record);
    expect_handoff("RONddWnuCE");
    namespace_bytes[0] ^= 1;
    namespace_bytes[8] = '/';
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record);
    expect_handoff("RONddWnuCE");
    memcpy(namespace_bytes, &record, sizeof(record));
    reset(); deployment_open_error = ELOOP;
    expect_handoff("RONWCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); deployment_read_error = EIO;
    expect_handoff("RONdWnuCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); deployment_close_error = EIO;
    expect_handoff("RONddnWuCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); deployment_unlink_error = EROFS;
    expect_handoff("RONddnuWLCE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); open_error = ENOENT;
    expect_handoff("ROWNddnuE");
    assert(deployment_at == sizeof(record));
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); credential = key; credential_size = 47;
    expect_handoff("ROKDDWkUNddnuCE");
    assert(deployment_at == sizeof(record));
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); load_error = ENOEXEC;
    expect_handoff("RONddnuLCWE");
    reset(); deployment = namespace_bytes; deployment_size = sizeof(record); rename_error = EROFS;
    expect_handoff("RWONddnuLCE");
    puts("PASS isolated first-stage handoff seam");
    return 0;
}
