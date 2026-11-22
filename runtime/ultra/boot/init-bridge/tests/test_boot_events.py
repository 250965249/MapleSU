"""Unexecuted boot-event unit fixture; real product C, mock VFS/kernel only.

No rc file/helper is installed or run. Reset models a new boot, not a production
restart. Mock refcounts check ownership order, not real target RCU/CFI behavior.
Only Aristotle/evidence executes the host compiler and fixture.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
REPO = BRIDGE.parents[6]
SELECTION = REPO / ".tmp/p2-host-final-20261118/core-builder/deployment54/HOST-DEPLOYMENT-SOURCE-SELECTION.json"
SELECTION_SHA256 = "34058fd92ddd84a1a7f6d678fae4239f142c028fdc583dd56b78df2b38b671a1"
CC = os.environ.get("BRIDGE_FIXTURE_CC", "C:/msys64/ucrt64/bin/gcc.exe")
DEFINITIONS = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
#ifndef ENODATA
#define ENODATA 61
#endif
#define EIOCBQUEUED 529
#define CONFIG_ARM64 1
#define __user
#define S64_MAX INT64_MAX
#define FMODE_READ 1
#define FMODE_WRITE 2
#define S_ISREG(x) (((x) & 0170000) == 0100000)
#define S_IWGRP 0020
#define S_IWOTH 0002
#define GLOBAL_ROOT_UID 0
#define uid_eq(x, y) ((x) == (y))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) (*(p) = (v))
#define smp_load_acquire(p) (*(p))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define cmpxchg(p, from, to) ({ int old_value = *(p); if (old_value == (from)) *(p) = (to); old_value; })
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
typedef int64_t loff_t;
struct task_struct { int pid, refs; } init_task = {1, 1}, other_task = {2, 1};
struct task_struct *fixture_current = &init_task;
#define current fixture_current
int task_pid_nr(struct task_struct *task) { return task->pid; }
struct task_struct *get_task_struct(struct task_struct *task) { ++task->refs; return task; }
void put_task_struct(struct task_struct *task) { assert(task && task->refs > 1); --task->refs; }
struct module { int refs; } bridge_module, fs_module;
#define THIS_MODULE (&bridge_module)
int deny_file_ref, module_get_calls;
bool try_module_get(struct module *module) {
    ++module_get_calls;
    if (deny_file_ref && module_get_calls == 2) return false;
    ++module->refs; return true;
}
void module_put(struct module *module) { assert(module->refs > 0); --module->refs; }
struct mutex { int held; };
#define DEFINE_MUTEX(name) struct mutex name = {0}
void mutex_lock(struct mutex *lock) { assert(!lock->held); lock->held = 1; }
void mutex_unlock(struct mutex *lock) { assert(lock->held); lock->held = 0; }
struct cred { int euid; } file_cred;
struct inode { unsigned int i_mode; int i_uid; loff_t size; } rc_inode;
struct path { const char *name; };
struct file;
struct kiocb;
struct iov_iter { char *buffer; size_t count, used; };
struct file_operations {
    struct module *owner;
    ssize_t (*read)(struct file *, char *, size_t, loff_t *);
    ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
    int (*release)(struct inode *, struct file *);
};
struct file {
    unsigned int f_mode;
    int refs;
    const struct cred *f_cred;
    struct path f_path;
    const struct file_operations *f_op;
    struct inode *inode;
} rc_file;
struct kiocb { struct file *ki_filp; loff_t ki_pos; void (*ki_complete)(void); int ki_flags; };
#define IOCB_NOWAIT 1
bool is_sync_kiocb(struct kiocb *request) { return !request->ki_complete; }
struct inode *file_inode(struct file *file) { return file->inode; }
int file_count(struct file *file) { return file->refs; }
loff_t i_size_read(struct inode *inode) { return inode->size; }
const struct file_operations *fops_get(const struct file_operations *ops) {
    return try_module_get(ops->owner) ? ops : NULL;
}
void fops_put(const struct file_operations *ops) { module_put(ops->owner); }
int path_error;
char *d_path(const struct path *path, char *buffer, int bytes) {
    if (path_error) return (char *)(intptr_t)-EIO;
    int length = snprintf(buffer, (size_t)bytes, "%s", path->name);
    assert(length >= 0 && length < bytes); return buffer;
}
size_t copy_limit = SIZE_MAX;
size_t copy_to_user(char *to, const char *from, size_t bytes) {
    size_t copied = min(bytes, copy_limit); memcpy(to, from, copied); return bytes - copied;
}
size_t iov_iter_count(struct iov_iter *to) { return to->count; }
size_t copy_to_iter(const char *from, size_t bytes, struct iov_iter *to) {
    size_t copied = min(min(bytes, to->count), copy_limit);
    memcpy(to->buffer + to->used, from, copied); to->used += copied; to->count -= copied; return copied;
}
void memzero_explicit(void *value, size_t bytes) {
    volatile unsigned char *p = value; while (bytes--) *p++ = 0;
}
struct pt_regs { uintptr_t args[4]; };
uintptr_t regs_get_kernel_argument(struct pt_regs *regs, unsigned int n) { return regs->args[n]; }
struct kprobe { const char *symbol_name; int (*pre_handler)(struct kprobe *, struct pt_regs *); };
int probe_error, registrations, removals, atomic_context, irq_off;
bool in_task(void) { return true; }
int in_atomic(void) { return atomic_context; }
int irqs_disabled(void) { return irq_off; }
int register_kprobe(struct kprobe *probe) {
    assert(bridge_module.refs == 1 && !strcmp(probe->symbol_name, "vfs_read"));
    ++registrations; return probe_error;
}
void unregister_kprobe(struct kprobe *probe) {
    (void)probe; assert(bridge_module.refs >= 1); ++removals;
}
"""
CASES = r"""
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "boot events fixture line %d\n", __LINE__); return 1; } } while (0)
static const char original_bytes[] = "ORIGINAL-RC\n";
struct file_operations native_ops;
loff_t position;
ssize_t native_error;
int release_calls, native_calls, use_nested_iter;
size_t native_chunk;
int native_release(struct inode *inode, struct file *file) {
    (void)inode; (void)file; assert(fs_module.refs == 1); ++release_calls; return -EIO;
}
ssize_t native_iter(struct kiocb *request, struct iov_iter *to) {
    ++native_calls;
    if (!is_sync_kiocb(request) || (request->ki_flags & IOCB_NOWAIT)) assert(!event_io.held);
    if (native_error) return native_error;
    if (request->ki_pos < 0) return -EINVAL;
    if (request->ki_pos >= (loff_t)(sizeof original_bytes - 1)) return 0;
    size_t bytes = min(to->count, (sizeof original_bytes - 1) - (size_t)request->ki_pos);
    bytes = min(bytes, native_chunk);
    memcpy(to->buffer + to->used, original_bytes + request->ki_pos, bytes);
    to->used += bytes; to->count -= bytes; request->ki_pos += bytes; return (ssize_t)bytes;
}
ssize_t native_read(struct file *file, char *buffer, size_t count, loff_t *offset) {
    if (use_nested_iter) {
        struct kiocb request = {file, *offset, NULL, 0}; struct iov_iter to = {buffer, count, 0};
        ssize_t result = file->f_op->read_iter(&request, &to); *offset = request.ki_pos; return result;
    }
    ++native_calls;
    if (native_error) return native_error;
    if (*offset < 0) return -EINVAL;
    if (*offset >= (loff_t)(sizeof original_bytes - 1)) return 0;
    size_t bytes = min(count, (sizeof original_bytes - 1) - (size_t)*offset);
    bytes = min(bytes, native_chunk); memcpy(buffer, original_bytes + *offset, bytes);
    *offset += bytes; return (ssize_t)bytes;
}
static void reset_boot(bool iter) {
    memset(&events, 0, sizeof events);
    events.probe.symbol_name = "vfs_read"; events.probe.pre_handler = boot_read_pre;
    event_lifecycle.held = event_io.held = 0;
    bridge_module.refs = 0; fs_module.refs = 1; init_task.refs = other_task.refs = 1;
    fixture_current = &init_task; deny_file_ref = module_get_calls = 0;
    probe_error = registrations = removals = atomic_context = irq_off = path_error = 0;
    release_calls = native_calls = use_nested_iter = 0;
    copy_limit = native_chunk = SIZE_MAX; native_error = 0; position = 0;
    rc_inode.i_mode = 0100644; rc_inode.i_uid = file_cred.euid = 0;
    rc_inode.size = sizeof original_bytes - 1;
    native_ops = (struct file_operations){&fs_module, iter ? NULL : native_read, native_iter, native_release};
    rc_file = (struct file){FMODE_READ, 1, &file_cred, {"/system/etc/init/hw/init.rc"}, &native_ops, &rc_inode};
}
static struct msu_deployment_namespace_record deployment(void) {
    struct msu_deployment_namespace_record record = {
        .magic = MSU_DEPLOYMENT_NAMESPACE_MAGIC, .schema = MSU_DEPLOYMENT_NAMESPACE_SCHEMA,
        .bytes = sizeof(struct msu_deployment_namespace_record),
    };
    memcpy(record.name, "aB3dE6gH9jK2mN5p", 16); return record;
}
static int arm(void) {
    struct msu_deployment_namespace_record record = deployment();
    return msu_boot_events_start(&record);
}
static int bind_file(void) {
    struct pt_regs regs = {{(uintptr_t)&rc_file, 0, 0, (uintptr_t)&position}};
    return events.probe.pre_handler(&events.probe, &regs);
}
static ssize_t read_file(char *buffer, size_t count) {
    if (rc_file.f_op->read) return rc_file.f_op->read(&rc_file, buffer, count, &position);
    struct kiocb request = {&rc_file, position, NULL, 0}; struct iov_iter to = {buffer, count, 0};
    ssize_t result = rc_file.f_op->read_iter(&request, &to); position = request.ki_pos; return result;
}
static int close_file(bool stop_before_fops_put) {
    CHECK(rc_file.f_op == &events.proxy && bridge_module.refs >= 1);
    CHECK(rc_file.f_op->release(&rc_inode, &rc_file) == -EIO);
    CHECK(fs_module.refs == 0 && init_task.refs == 1 && release_calls == 1);
    if (stop_before_fops_put) {
        CHECK(msu_boot_events_stop() == 0 && bridge_module.refs == 1);
        CHECK(rc_file.f_op->owner == THIS_MODULE);
    }
    fops_put(rc_file.f_op); /* The actual VFS does this after release returns. */
    CHECK(msu_boot_events_stop() == 0 && bridge_module.refs == 0);
    CHECK(removals == 1 && !events.owner && !events.rc_bytes);
    return 0;
}
static int check_stream(bool iter) {
    reset_boot(iter); CHECK(arm() == 0 && registrations == 1 && init_task.refs == 2);
    char suffix[MSU_BOOT_RC_BYTES], output[MSU_BOOT_RC_BYTES + sizeof original_bytes + 1];
    size_t suffix_bytes = events.rc_bytes, used = 0; memcpy(suffix, events.rc, suffix_bytes);
    CHECK(events.rc[0] == '\n' && strstr(events.rc, "exec -- /data/aB3dE6gH9jK2mN5p/init --boot-event post-fs-data"));
    CHECK(strstr(events.rc, "on nonencrypted") && strstr(events.rc, "vold.decrypt=trigger_restart_framework"));
    CHECK(strstr(events.rc, "sys.boot_completed=1") && !strstr(events.rc, "--boot-event post-mount"));
    CHECK(!strstr(events.rc, "setenforce") && !strstr(events.rc, "setprop ") && !strstr(events.rc, "daemon"));
    CHECK(bind_file() == 0 && rc_file.f_op == &events.proxy && bridge_module.refs == 2 && fs_module.refs == 1);
    CHECK(msu_boot_events_stop() == -EBUSY && removals == 1 && bridge_module.refs == 2);
    native_chunk = 3;
    for (;;) {
        ssize_t got = read_file(output + used, 5);
        CHECK(got >= 0 && got <= 5);
        if (!got) break;
        used += (size_t)got; CHECK(used <= sizeof output);
    }
    CHECK(used == sizeof original_bytes - 1 + suffix_bytes);
    CHECK(!memcmp(output, original_bytes, sizeof original_bytes - 1));
    CHECK(!memcmp(output + sizeof original_bytes - 1, suffix, suffix_bytes));
    CHECK(position == (loff_t)used && events.emitted == suffix_bytes);
    CHECK(read_file(output, sizeof output) == 0);
    CHECK(close_file(iter) == 0);
    CHECK(arm() == -EALREADY); /* A published proxy is never reused. */
    return 0;
}
static int check_failures(bool iter) {
    reset_boot(iter); CHECK(arm() == 0 && bind_file() == 0);
    char bytes[MSU_BOOT_RC_BYTES]; ssize_t got = read_file(bytes, sizeof bytes);
    CHECK(got == (ssize_t)(sizeof original_bytes - 1) && events.emitted == 0);
    native_error = -EIO;
    CHECK(read_file(bytes, sizeof bytes) == -EIO && !events.emitted);
    native_error = 0;
    CHECK(read_file(bytes, 0) == 0 && !events.emitted);
    copy_limit = 3; CHECK(read_file(bytes, 9) == 3 && events.emitted == 3);
    CHECK(!memcmp(bytes, events.rc, 3));
    copy_limit = 0; CHECK(read_file(bytes, 9) == -EFAULT && events.emitted == 3);
    copy_limit = SIZE_MAX; CHECK(read_file(bytes, 9) == 9 && events.emitted == 12);
    CHECK(!memcmp(bytes, events.rc + 3, 9));
    position = 0; CHECK(read_file(bytes, 2) == 2 && !events.linear);
    CHECK(close_file(false) == 0);
    reset_boot(iter); CHECK(arm() == 0 && bind_file() == 0);
    fixture_current = &other_task;
    CHECK(read_file(bytes, sizeof bytes) == (ssize_t)(sizeof original_bytes - 1) && !events.linear && !events.emitted);
    fixture_current = &init_task; CHECK(read_file(bytes, sizeof bytes) == 0);
    CHECK(close_file(false) == 0);
    return 0;
}
static void completed(void) {}
int main(void) {
    CHECK(check_stream(false) == 0 && check_stream(true) == 0);
    CHECK(check_failures(false) == 0 && check_failures(true) == 0);
    for (int which = 0; which < 8; ++which) {
        reset_boot(false); CHECK(arm() == 0);
        switch (which) {
        case 0: rc_file.f_path.name = "/system/etc/init/hw/init.rc.extra"; break;
        case 1: rc_inode.i_uid = 1000; break;
        case 2: rc_inode.i_mode |= S_IWGRP; break;
        case 3: file_cred.euid = 1000; break;
        case 4: rc_file.refs = 2; break;
        case 5: position = 1; break;
        case 6: path_error = 1; break;
        case 7: fixture_current = &other_task; break;
        }
        CHECK(bind_file() == 0 && rc_file.f_op == &native_ops && events.state == EVENTS_ARMED);
        fixture_current = &init_task; CHECK(msu_boot_events_stop() == 0 && bridge_module.refs == 0);
    }
    reset_boot(false); struct msu_deployment_namespace_record record = deployment();
    CHECK(msu_boot_events_start(NULL) == -EINVAL && !registrations);
    record.bytes = 0; CHECK(msu_boot_events_start(&record) == -EINVAL && !registrations);
    record = deployment(); record.name[0] = '/';
    CHECK(msu_boot_events_start(&record) == -EINVAL && !registrations);
    reset_boot(false); probe_error = -EPERM;
    CHECK(arm() == -EPERM && !events.owner && !events.rc_bytes && bridge_module.refs == 0 && init_task.refs == 1);
    reset_boot(false); CHECK(arm() == 0); deny_file_ref = 1;
    CHECK(bind_file() == 0 && rc_file.f_op == &native_ops && bridge_module.refs == 1 && fs_module.refs == 1);
    CHECK(msu_boot_events_stop() == 0 && bridge_module.refs == 0);
    reset_boot(false); CHECK(arm() == 0 && bind_file() == 0); use_nested_iter = 1;
    char output[64]; CHECK(rc_file.f_op->read_iter == native_iter);
    CHECK(read_file(output, sizeof output) == (ssize_t)(sizeof original_bytes - 1));
    CHECK(close_file(false) == 0);
    reset_boot(true); CHECK(arm() == 0 && bind_file() == 0);
    struct kiocb request = {&rc_file, 0, completed, 0}; struct iov_iter to = {output, sizeof output, 0};
    native_error = -EIOCBQUEUED; CHECK(rc_file.f_op->read_iter(&request, &to) == -EIOCBQUEUED);
    CHECK(!events.linear && !events.emitted);
    native_error = -EAGAIN; request.ki_complete = NULL; request.ki_flags = IOCB_NOWAIT;
    CHECK(rc_file.f_op->read_iter(&request, &to) == -EAGAIN && !events.emitted);
    CHECK(close_file(true) == 0);
    return 0;
}
"""


class BootEventsChecks(unittest.TestCase):
    def test_native_stream_and_lifetime_fixture(self):
        selection_data = SELECTION.read_bytes()
        self.assertEqual(hashlib.sha256(selection_data).hexdigest(), SELECTION_SHA256)
        rows = {row["logicalPath"]: row["after"] for row in json.loads(selection_data)["files"]}
        originals = {BRIDGE / name: (BRIDGE / name).read_bytes() for name in ("boot_events.c", "boot_events.h")}
        originals[SELECTION] = selection_data
        headers = {}
        for name in ("manager_deployment_namespace.h", "manager_claim_loader.h"):
            reference = rows["runtime/ultra/identity/kernel/" + name]
            path = Path(reference["path"])
            data = path.read_bytes()
            self.assertEqual(len(data), reference["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), reference["sha256"])
            headers[name] = data
            originals[path] = data
        with tempfile.TemporaryDirectory(prefix="bridge-boot-events-") as directory:
            output = Path(directory)
            for header in ("cred", "dcache", "err", "fs", "irqflags", "kernel", "kprobes", "limits", "module",
                           "mutex", "pid", "preempt", "sched", "sched/task", "string", "uaccess", "uio"):
                path = output / "linux" / (header + ".h")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("/* kernel mock declarations preincluded */\n")
            path = output / "asm/ptrace.h"
            path.parent.mkdir(exist_ok=True)
            path.write_text("/* ARM64 argument registers mocked */\n")
            for name in ("boot_events.c", "boot_events.h"):
                (output / name).write_bytes(originals[BRIDGE / name])
            for name, data in headers.items():
                (output / name).write_bytes(data)
            source = output / "fixture.c"
            source.write_text(DEFINITIONS + '\n#include "boot_events.c"\n' + CASES)
            binary = output / "fixture.exe"
            subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-UNDEBUG",
                            "-I" + str(output), str(source), "-o", str(binary)], check=True, timeout=25)
            subprocess.run([str(binary)], check=True, timeout=5)
        for path, data in originals.items():
            self.assertEqual(path.read_bytes(), data, "input changed: " + str(path))


if __name__ == "__main__":
    unittest.main()
