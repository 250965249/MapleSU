// SPDX-License-Identifier: GPL-3.0-only
/* Same one-shot shmem lifetime and fallback as pinned KSU preinit/preinit.c.
 * Runs in the existing SDK execve continuation, after the kprobe returned. */
#include <linux/err.h>
#include <linux/init.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/ptrace.h>
#include "manager_dynamic_layout.h"
#include "native_lookup.h"
#include "preinit.h"
#define INIT_PATH "/system/bin/init"
extern const char msu_preinit_runner_start[], msu_preinit_runner_end[];
static struct file *runner;
static typeof(&shmem_file_setup) make_shmem;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
static noinline struct file *reference_shmem(const char *name, loff_t bytes, vma_flags_t flags)
#else
static noinline struct file *reference_shmem(const char *name, loff_t bytes, unsigned long flags)
#endif
{ return make_shmem(name, bytes, flags); }
_Static_assert(__builtin_types_compatible_p(typeof(&reference_shmem), typeof(&shmem_file_setup)),
    "target shmem_file_setup prototype");

static typeof(&kernel_write) write_runner;
static noinline ssize_t reference_write(struct file *file, const void *buffer, size_t count, loff_t *position)
{ return write_runner(file, buffer, count, position); }
_Static_assert(__builtin_types_compatible_p(typeof(&reference_write), typeof(&kernel_write)),
    "target kernel_write prototype");

int __init msu_preinit_start(void)
{
    size_t bytes = msu_preinit_runner_end - msu_preinit_runner_start;
    struct file *file;
    loff_t position = 0;
    ssize_t written;
    unsigned long address;
    int error;
    if (READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) != 1) return -EPERM;
    if (READ_ONCE(runner)) return -EALREADY;
    error = msu_init_bridge_resolve_cfi("shmem_file_setup", (void *)reference_shmem, &address);
    if (error) return error;
    make_shmem = (typeof(make_shmem))address;
    error = msu_init_bridge_resolve_cfi("kernel_write", (void *)reference_write, &address);
    if (error) return error;
    write_runner = (typeof(write_runner))address;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
    file = make_shmem("maplesu_preinit", bytes, EMPTY_VMA_FLAGS);
#else
    file = make_shmem("maplesu_preinit", bytes, 0);
#endif
    if (IS_ERR(file)) return PTR_ERR(file);
    written = write_runner(file, msu_preinit_runner_start, bytes, &position);
    if (written < 0 || (size_t)written != bytes) { fput(file); return written < 0 ? (int)written : -EIO; }
    WRITE_ONCE(runner, file);
    return 0;
}

static void runner_close_fd(unsigned int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    close_fd(fd);
#else
    __close_fd(MSU_DYN_FIELD(current, task_struct, files), fd);
#endif
}

void msu_preinit_release(void)
{
    struct file *file = xchg(&runner, NULL);
    if (file) fput(file);
}

bool msu_preinit_execve(const void *args, long (*original)(const void *), long *result)
{
    const struct pt_regs *native = args;
    struct pt_regs redirect;
    const char __user *arg;
    char path[sizeof(INIT_PATH) + 1], stage[sizeof("selinux_setup") + 1], fd_path[32];
    struct file *file;
    struct path resolved;
    unsigned long stack;
    int fd, length;
    if (!READ_ONCE(runner) || READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) != 1 || !args) return false;
    memset(path, 0, sizeof path); memset(stage, 0, sizeof stage);
    if (strncpy_from_user(path, (void __user *)untagged_addr(native->regs[0]), sizeof(path)-1) < 0 ||
        strcmp(path, INIT_PATH) || !native->regs[1] ||
        get_user(arg, (const char __user *const __user *)untagged_addr(native->regs[1]) + 1) || !arg ||
        strncpy_from_user(stage, arg, sizeof(stage)-1) < 0 || strcmp(stage, "selinux_setup")) return false;
    /* The runner's own original-init exec passes through unmodified. */
    file = xchg(&runner, NULL);
    if (!file) return false;
    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) { fput(file); pr_warn("MapleSU preinit fd: %d\n", fd); return false; }
    fd_install(fd, file);
    length = snprintf(fd_path, sizeof fd_path, "/proc/self/fd/%d", fd);
    if (kern_path(fd_path, LOOKUP_FOLLOW, &resolved)) goto close;
    path_put(&resolved);
    stack = (unsigned long)untagged_addr(native->sp) - ALIGN(length + 1, 16);
    if (copy_to_user((void __user *)stack, fd_path, length + 1)) goto close;
    redirect = *native;
    redirect.regs[0] = stack;
    *result = original(&redirect);
    if (*result < 0) {
        pr_warn("MapleSU preinit exec: %ld; continuing original init\n", *result);
        runner_close_fd(fd);
        *result = original(args);
    }
    return true;
close:
    runner_close_fd(fd);
    return false;
}
