/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef MAPLESU_ULTRA_INIT_OS_FIXTURE_H
#define MAPLESU_ULTRA_INIT_OS_FIXTURE_H
/* Compile only with the all-OS-wrapped host fixture, never an Android target.
 * These tokens model Android-only flags/syscall identity without making calls. */
#if !defined(MAPLESU_ULTRA_INIT_OS_FIXTURE) || defined(__ANDROID__)
#error "Host OS fixture only"
#endif
#include <sys/types.h>
#include <unistd.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0x80000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0x20000
#endif
#define SYS_finit_module 273
pid_t __wrap_getpid(void);
int __wrap_rename(const char *, const char *);
int __wrap_open(const char *, int, ...);
int __wrap_read(int, void *, unsigned int);
int __wrap_unlink(const char *);
long __wrap_syscall(long, ...);
int __wrap_close(int);
int __wrap_execve(const char *, char *const [], char *const []);
int __wrap_write(int, const void *, unsigned int);
/* Explicit redirects prevent the host CRT's aliases from reaching an OS call. */
#undef getpid
#undef rename
#undef open
#undef read
#undef unlink
#undef syscall
#undef close
#undef execve
#undef write
#define getpid __wrap_getpid
#define rename __wrap_rename
#define open __wrap_open
#define read __wrap_read
#define unlink __wrap_unlink
#define syscall __wrap_syscall
#define close __wrap_close
#define execve __wrap_execve
#define write __wrap_write
#endif
