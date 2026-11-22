// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <asm/ptrace.h>
#include "manager_dynamic_layout.h"
#include "boot_events.h"
#include "preinit.h"

#ifndef CONFIG_ARM64
#error "Ultra init boot events require the target ARM64 calling convention"
#endif

#define MSU_BOOT_RC_BYTES 512
#define MSU_BOOT_HELPER_BYTES 28
#define MSU_MODULE_RC_BYTES (1024U * 1024U)

static long msu_init_bridge_file_count(const struct file *file)
{
#ifdef FILE_REF_ONEREF
    return file_ref_read(&MSU_DYN_FIELD(file, file, f_ref));
#else
    return atomic_long_read(&MSU_DYN_FIELD(file, file, f_count));
#endif
}

enum boot_event_state { EVENTS_OFF, EVENTS_ARMED, EVENTS_BINDING, EVENTS_BOUND, EVENTS_CLOSED, EVENTS_STOPPED };
static int boot_read_pre(struct kprobe *probe, struct pt_regs *regs);
static ssize_t boot_read(struct file *file, char __user *buffer, size_t count, loff_t *position);
static ssize_t boot_read_iter(struct kiocb *request, struct iov_iter *to);
static int boot_release(struct inode *inode, struct file *file);

static struct {
    struct kprobe probe;
    struct file_operations proxy;
    const struct file_operations *original;
    struct task_struct *owner;
    struct file *file;
    loff_t native_size, next;
    size_t emitted, rc_bytes, module_rc_bytes;
    char *module_rc;
    int module_rc_error;
    bool module_rc_loaded;
    char rc[MSU_BOOT_RC_BYTES];
    int state;
    bool linear, registered, registration_ref, started;
} events = { .probe = { .symbol_name = "vfs_read", .pre_handler = boot_read_pre } };
static DEFINE_MUTEX(event_lifecycle);
static DEFINE_MUTEX(event_io);

_Static_assert(__builtin_types_compatible_p(typeof(&boot_read),
    typeof(((struct file_operations *)0)->read)), "native read callback");
_Static_assert(__builtin_types_compatible_p(typeof(&boot_read_iter),
    typeof(((struct file_operations *)0)->read_iter)), "native read_iter callback");
_Static_assert(__builtin_types_compatible_p(typeof(&boot_release),
    typeof(((struct file_operations *)0)->release)), "native release callback");
_Static_assert(__builtin_types_compatible_p(typeof(&boot_read_pre),
    typeof(((struct kprobe *)0)->pre_handler)), "native kprobe pre-handler");

/* The trusted root-only producer publishes one complete next-boot snapshot.
 * Read it only in the sleepable native read path, never in the kprobe. The
 * preferred metadata parent is shared with module-tools module-initrc; a new
 * parent does not resurrect a stale file from a lower-priority location. */
static struct file *module_rc_open(const char *path, bool directory)
{
    struct file *file = filp_open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
        (directory ? O_DIRECTORY : 0), 0);
    struct inode *inode;
    if (IS_ERR(file)) return file;
    inode = msu_dynamic_file_inode(file);
    if (!uid_eq(MSU_DYN_FIELD(inode, inode, i_uid), GLOBAL_ROOT_UID) || (MSU_DYN_FIELD(inode, inode, i_mode) & (S_IWGRP | S_IWOTH)) ||
        (directory ? !S_ISDIR(MSU_DYN_FIELD(inode, inode, i_mode)) : (!S_ISREG(MSU_DYN_FIELD(inode, inode, i_mode)) || MSU_DYN_FIELD(inode, inode, i_nlink) != 1))) {
        fput(file);
        return ERR_PTR(-EACCES);
    }
    return file;
}

static int load_module_rc(void)
{
    struct file *file;
    const char *base = "/metadata/maplesu", *path = "/metadata/maplesu/modules.rc";
    char *buffer = NULL;
    loff_t size, position = 0;
    ssize_t count;
    int error = 0;
    if (events.module_rc_loaded) return events.module_rc_error;
    events.module_rc_loaded = true;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    file = module_rc_open("/metadata", true);
    if (IS_ERR(file)) return PTR_ERR(file) == -ENOENT ? 0 : PTR_ERR(file);
    fput(file);
    file = module_rc_open("/metadata/vold", true);
    if (!IS_ERR(file)) {
        base = "/metadata/vold/maplesu"; path = "/metadata/vold/maplesu/modules.rc";
        fput(file);
    } else {
        if (PTR_ERR(file) != -ENOENT) return PTR_ERR(file);
        file = module_rc_open("/metadata/watchdog", true);
        if (!IS_ERR(file)) {
            base = "/metadata/watchdog/maplesu"; path = "/metadata/watchdog/maplesu/modules.rc";
            fput(file);
        } else if (PTR_ERR(file) != -ENOENT) return PTR_ERR(file);
    }
    file = module_rc_open(base, true);
    if (IS_ERR(file)) return PTR_ERR(file) == -ENOENT ? 0 : PTR_ERR(file);
    fput(file);
    file = module_rc_open(path, false);
    if (IS_ERR(file)) return PTR_ERR(file) == -ENOENT ? 0 : PTR_ERR(file);
    size = READ_ONCE(MSU_DYN_FIELD(msu_dynamic_file_inode(file), inode, i_size));
    if (size < 0 || size > MSU_MODULE_RC_BYTES) { error = -EFBIG; goto out; }
    if (!size) goto out;
    buffer = kvmalloc((size_t)size, GFP_KERNEL);
    if (!buffer) { error = -ENOMEM; goto out; }
    while (position < size) {
        count = kernel_read(file, buffer + (size_t)position, (size_t)(size - position), &position);
        if (count < 0) { error = (int)count; goto out; }
        if (!count) { error = -EIO; goto out; }
    }
    if (READ_ONCE(MSU_DYN_FIELD(msu_dynamic_file_inode(file), inode, i_size)) != size) { error = -ESTALE; goto out; }
    events.module_rc = buffer;
    events.module_rc_bytes = (size_t)size;
    buffer = NULL;
out:
    kvfree(buffer);
    fput(file);
    return error;
}

static void prepare_module_rc(void)
{
    int error;
    if (events.module_rc_loaded) return;
    error = load_module_rc();
    events.module_rc_error = error;
    /* KernelSU skips a broken custom rc after diagnostics. Failing the base
     * init.rc read would also discard unrelated Android boot actions. */
    if (error) pr_warn("MapleSU module initrc skipped: %d\n", error);
}

static const char *append_source(size_t *bytes)
{
    if (events.emitted < events.rc_bytes) {
        *bytes = events.rc_bytes - events.emitted;
        return events.rc + events.emitted;
    }
    *bytes = events.rc_bytes + events.module_rc_bytes - events.emitted;
    return events.module_rc + (events.emitted - events.rc_bytes);
}

static void free_consumed_module_rc(void)
{
    if (events.emitted == events.rc_bytes + events.module_rc_bytes) {
        kvfree(events.module_rc);
        events.module_rc = NULL;
    }
}

static bool event_reader(struct file *file, loff_t position)
{
    return READ_ONCE(events.linear) && current == events.owner && READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) == 1 &&
        file == events.file && position == events.next &&
        READ_ONCE(MSU_DYN_FIELD(msu_dynamic_file_inode(file), inode, i_size)) == events.native_size;
}

static bool append_at_eof(struct file *file, loff_t before, loff_t after, bool eligible)
{
    if (!eligible || before != after || !event_reader(file, before) ||
        before != events.native_size + (loff_t)events.emitted) {
        WRITE_ONCE(events.linear, false);
        return false;
    }
    return events.emitted < events.rc_bytes + events.module_rc_bytes;
}

static ssize_t boot_read(struct file *file, char __user *buffer, size_t count, loff_t *position)
{
    loff_t before = *position;
    ssize_t result;
    bool eligible;
    size_t amount, copied, available;
    const char *source;

    if (current != events.owner || file != events.file) {
        WRITE_ONCE(events.linear, false);
        return events.original->read(file, buffer, count, position);
    }
    mutex_lock(&event_io);
    eligible = event_reader(file, before);
    if (!eligible) WRITE_ONCE(events.linear, false);
    result = events.original->read(file, buffer, count, position);
    if (result) {
        if (eligible && result > 0) events.next = *position;
        goto out;
    }
    if (!count) goto out;
    if (eligible) prepare_module_rc();
    if (!append_at_eof(file, before, *position, eligible)) goto out;
    source = append_source(&available);
    amount = min(count, available);
    copied = amount - copy_to_user(buffer, source, amount);
    events.emitted += copied;
    *position += (loff_t)copied;
    events.next = *position;
    result = copied ? (ssize_t)copied : -EFAULT;
    free_consumed_module_rc();
out:
    mutex_unlock(&event_io);
    return result;
}

static ssize_t boot_read_iter(struct kiocb *request, struct iov_iter *to)
{
    loff_t before = request->ki_pos;
    ssize_t result;
    bool eligible;
    size_t copied, available;
    const char *source;

    if (!is_sync_kiocb(request) || (request->ki_flags & IOCB_NOWAIT) ||
        current != events.owner || request->ki_filp != events.file) {
        WRITE_ONCE(events.linear, false);
        return events.original->read_iter(request, to);
    }
    mutex_lock(&event_io);
    eligible = event_reader(request->ki_filp, before);
    if (!eligible) WRITE_ONCE(events.linear, false);
    result = events.original->read_iter(request, to);
    if (result) {
        if (eligible && result > 0) events.next = request->ki_pos;
        goto out;
    }
    if (!iov_iter_count(to)) goto out;
    if (eligible) prepare_module_rc();
    if (!append_at_eof(request->ki_filp, before, request->ki_pos, eligible)) goto out;
    source = append_source(&available);
    copied = copy_to_iter(source, available, to);
    events.emitted += copied;
    request->ki_pos += (loff_t)copied;
    events.next = request->ki_pos;
    result = copied ? (ssize_t)copied : -EFAULT;
    free_consumed_module_rc();
out:
    mutex_unlock(&event_io);
    return result;
}

static int boot_release(struct inode *inode, struct file *file)
{
    int result = 0;

    /* VFS invokes release only after the last file reference: no read can still
     * be entered or waiting to branch into this proxy. Keep proxy.owner intact;
     * normal __fput drops its module reference AFTER this callback returns. */
    mutex_lock(&event_io);
    if (events.original->release) result = events.original->release(inode, file);
    kvfree(events.module_rc);
    events.module_rc = NULL;
    fops_put(events.original);
    msu_dynamic_put_task_struct(events.owner);
    events.owner = NULL;
    events.file = NULL;
    smp_store_release(&events.state, EVENTS_CLOSED);
    mutex_unlock(&event_io);
    return result;
}

static int boot_read_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct file *file;
    struct inode *inode;
    loff_t *position, size;
    char path[128], *resolved;
    const struct file_operations *original;

    (void)probe;
    if (current != events.owner || READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) != 1 ||
        smp_load_acquire(&events.state) != EVENTS_ARMED) return 0;
    file = (struct file *)regs_get_kernel_argument(regs, 0);
    position = (loff_t *)regs_get_kernel_argument(regs, 3);
    if (!file || !position || *position || msu_init_bridge_file_count(file) != 1 ||
        !(MSU_DYN_FIELD(file, file, f_mode) & FMODE_READ) || (MSU_DYN_FIELD(file, file, f_mode) & FMODE_WRITE)) return 0;
    inode = msu_dynamic_file_inode(file);
    if (!S_ISREG(MSU_DYN_FIELD(inode, inode, i_mode)) || !uid_eq(MSU_DYN_FIELD(inode, inode, i_uid), GLOBAL_ROOT_UID) ||
        (MSU_DYN_FIELD(inode, inode, i_mode) & (S_IWGRP | S_IWOTH)) ||
        !uid_eq(MSU_DYN_FIELD(MSU_DYN_FIELD(file, file, f_cred), cred, euid), GLOBAL_ROOT_UID)) return 0;
    resolved = d_path(&MSU_DYN_FIELD(file, file, f_path), path, sizeof(path));
    if (IS_ERR(resolved) || strcmp(resolved, "/system/etc/init/hw/init.rc")) return 0;
    /* Init has reached rc parsing: no later exec may consume an unused blob. */
    msu_preinit_release();
    size = READ_ONCE(MSU_DYN_FIELD(inode, inode, i_size));
    original = READ_ONCE(MSU_DYN_FIELD(file, file, f_op));
    if (size < 0 || size > S64_MAX - MSU_BOOT_RC_BYTES - MSU_MODULE_RC_BYTES || !original ||
        (!original->read && !original->read_iter)) return 0;
    if (cmpxchg(&events.state, EVENTS_ARMED, EVENTS_BINDING) != EVENTS_ARMED) return 0;

    /* No allocation/sleep in the probe. The native file's existing original
     * fops reference is transferred to events.original until proxy release. */
    events.proxy = *original;
    events.proxy.owner = THIS_MODULE;
    /* vfs_read selects read first, otherwise its synchronous read_iter path.
     * Intercept only that choice: an original read may call read_iter itself. */
    if (original->read) events.proxy.read = boot_read;
    else events.proxy.read_iter = boot_read_iter;
    events.proxy.release = boot_release;
    if (!fops_get(&events.proxy)) {
        smp_store_release(&events.state, EVENTS_ARMED);
        return 0;
    }
    events.original = original;
    events.file = file;
    events.native_size = size;
    events.next = 0;
    events.emitted = 0;
    WRITE_ONCE(events.linear, true);
    /* The newly acquired file-owned module ref precedes callback publication.
     * Original owner refs and all copied native operations remain valid. */
    smp_store_release(&events.state, EVENTS_BOUND);
    WRITE_ONCE(MSU_DYN_FIELD(file, file, f_op), &events.proxy);
    return 0;
}

int msu_boot_events_start(const struct msu_deployment_namespace_record *deployment)
{
    char helper[MSU_BOOT_HELPER_BYTES];
    int bytes, error;

    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    if (READ_ONCE(MSU_DYN_FIELD(current, task_struct, pid)) != 1) return -EPERM;
    if (!msu_deployment_namespace_valid(deployment)) return -EINVAL;
    bytes = snprintf(helper, sizeof(helper), "/data/%.*s/init",
        (int)sizeof(deployment->name), (const char *)deployment->name);
    if (bytes != (int)sizeof(helper) - 1) return -EOVERFLOW;
    mutex_lock(&event_lifecycle);
    if (events.started) { error = -EALREADY; goto out; }
    /* post-mount is already synchronous inside the real post-fs-data consumer,
     * after properties_and_mount. Do not run it early or run it twice here. */
    bytes = snprintf(events.rc, sizeof(events.rc),
        "\non post-fs-data\n    exec -- %s --boot-event post-fs-data\n"
        "\non nonencrypted\n    exec -- %s --boot-event service\n"
        "\non property:vold.decrypt=trigger_restart_framework\n    exec -- %s --boot-event service\n"
        "\non property:sys.boot_completed=1\n    exec -- %s --boot-event boot-completed\n\n",
        helper, helper, helper, helper);
    if (bytes < 0 || (size_t)bytes >= sizeof(events.rc)) { error = -EOVERFLOW; goto clear; }
    events.rc_bytes = bytes;
    msu_dynamic_get_task_struct(current);
    events.owner = current;
    if (!try_module_get(THIS_MODULE)) { error = -ENODEV; goto owner; }
    events.registration_ref = true;
    smp_store_release(&events.state, EVENTS_ARMED);
    events.started = true;
    error = register_kprobe(&events.probe);
    if (error) {
        smp_store_release(&events.state, EVENTS_OFF);
        events.registration_ref = false;
        module_put(THIS_MODULE);
        goto owner;
    }
    events.registered = true;
    goto out;
owner:
    msu_dynamic_put_task_struct(events.owner);
    events.owner = NULL;
clear:
    memzero_explicit(events.rc, sizeof(events.rc));
    events.rc_bytes = 0;
out:
    mutex_unlock(&event_lifecycle);
    memzero_explicit(helper, sizeof(helper));
    return error;
}

int msu_boot_events_stop(void)
{
    int error = 0;

    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    msu_preinit_release();
    mutex_lock(&event_lifecycle);
    if (events.registered) {
        unregister_kprobe(&events.probe);
        events.registered = false;
    }
    if (smp_load_acquire(&events.state) == EVENTS_BOUND) {
        error = -EBUSY;
        goto out;
    }
    /* Never change/free proxy fops, even when release has reported CLOSED:
     * __fput may still be about to read its owner for the final fops_put. */
    mutex_lock(&event_io);
    if (events.owner) { msu_dynamic_put_task_struct(events.owner); events.owner = NULL; }
    kvfree(events.module_rc);
    events.module_rc = NULL;
    events.module_rc_bytes = 0;
    memzero_explicit(events.rc, sizeof(events.rc));
    events.rc_bytes = 0;
    smp_store_release(&events.state, EVENTS_STOPPED);
    mutex_unlock(&event_io);
    if (events.registration_ref) {
        events.registration_ref = false;
        module_put(THIS_MODULE);
    }
out:
    mutex_unlock(&event_lifecycle);
    return error;
}
