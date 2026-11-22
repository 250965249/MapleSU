// SPDX-License-Identifier: GPL-3.0-only
#include <linux/anon_inodes.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/nospec.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/refcount.h>
#include <linux/sched/task.h>
#include <linux/security.h>
#include <linux/securebits.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#include "su_install_registry.h"
#include "su_profile_execution.h"
#include "su_exec_session.h"
#include "manager_dynamic_layout.h"

#ifndef MSU_SU_EXEC_SESSION_RAW_RESIDENT
#define MSU_SU_EXEC_SESSION_RAW_RESIDENT 0
#endif
#if MSU_SU_EXEC_SESSION_RAW_RESIDENT != 0 && MSU_SU_EXEC_SESSION_RAW_RESIDENT != 1
#error "MSU_SU_EXEC_SESSION_RAW_RESIDENT must be 0 or 1"
#endif
#if MSU_SU_EXEC_SESSION_RAW_RESIDENT
#include "manager_resident_abi.h"
#else
#include <linux/module.h>
#endif
#include "../../../payload/su/su_session_receipt.h"

struct msu_su_exec_session {
    refcount_t refs;
    struct mutex lock;
    struct hlist_node exit_link;
    struct rcu_head rcu;
    struct callback_head resume;
    struct work_struct exit_work;
    struct msu_su_lease lease;
    struct task_struct *task;
    struct file *executable, *receipt_file, *executed_file;
    const struct cred *expected_cred, *executed_cred;
    struct nsproxy *expected_ns;
    struct mm_struct *executed_mm;
    struct msu_su_session_receipt receipt;
    int executable_fd, receipt_fd;
    u32 expected_secid;
    u64 original_exec_id;
    bool write_denied, apply_attempted, published, ready, identity_valid;
    bool consumed, exited;
};

#define MSU_SU_SESSION_HASH_BITS 8
#define MSU_SU_SESSION_BUCKET_LIMIT 16U
static DEFINE_HASHTABLE(msu_su_sessions, MSU_SU_SESSION_HASH_BITS);
static u32 msu_su_session_buckets[1U << MSU_SU_SESSION_HASH_BITS];
static u32 msu_su_session_count;
static DEFINE_SPINLOCK(msu_su_sessions_lock);

#if MSU_SU_EXEC_SESSION_RAW_RESIDENT
static DEFINE_SPINLOCK(msu_su_session_owner_lock);
static struct {
    const struct msu_resident_slot *slot;
    const void *memory;
    u64 allocation_bytes;
    u32 users;
} msu_su_session_boot;
#endif

int msu_su_exec_session_bind_boot_resident(const struct msu_resident_slot *slot,
    const void *memory, u64 allocation_bytes)
{
#if MSU_SU_EXEC_SESSION_RAW_RESIDENT
    unsigned long irq, start = (unsigned long)memory, end;
    unsigned long code = (unsigned long)msu_su_exec_session_bind_boot_resident;
    unsigned long data = (unsigned long)&msu_su_session_boot;
    int error = 0;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!slot || ((unsigned long)slot & 63U) || !memory ||
        allocation_bytes < sizeof(msu_su_session_boot) ||
        allocation_bytes > ~0UL - start) return -EINVAL;
    end = start + allocation_bytes;
    if (code < start || code >= end || data < start ||
        data > end - sizeof(msu_su_session_boot) ||
        ((unsigned long)slot >= start && (unsigned long)slot < end)) return -EINVAL;
    if (smp_load_acquire(&slot->boot_magic) != MSU_RESIDENT_BOOT_MAGIC ||
        smp_load_acquire(&slot->state) != MSU_RESIDENT_INITIALIZING ||
        READ_ONCE(slot->memory) || READ_ONCE(slot->allocation_bytes)) return -ESTALE;
    spin_lock_irqsave(&msu_su_session_owner_lock, irq);
    if (msu_su_session_boot.slot) {
        if (msu_su_session_boot.slot != slot || msu_su_session_boot.memory != memory ||
            msu_su_session_boot.allocation_bytes != allocation_bytes) error = -ESTALE;
    } else if (msu_su_session_boot.users) error = -EBUSY;
    else {
        msu_su_session_boot.slot = slot;
        msu_su_session_boot.memory = memory;
        msu_su_session_boot.allocation_bytes = allocation_bytes;
    }
    spin_unlock_irqrestore(&msu_su_session_owner_lock, irq);
    return error;
#else
    (void)slot;
    (void)memory;
    (void)allocation_bytes;
    return -EOPNOTSUPP;
#endif
}

static int msu_su_session_owner_get(void)
{
    if (!msu_runtime_layout_ready()) return -EAGAIN;
#if MSU_SU_EXEC_SESSION_RAW_RESIDENT
    unsigned long irq;
    int error = 0;
    spin_lock_irqsave(&msu_su_session_owner_lock, irq);
    if (!msu_su_session_boot.slot ||
        smp_load_acquire(&msu_su_session_boot.slot->boot_magic) != MSU_RESIDENT_BOOT_MAGIC ||
        smp_load_acquire(&msu_su_session_boot.slot->state) != MSU_RESIDENT_READY ||
        READ_ONCE(msu_su_session_boot.slot->memory) != (unsigned long)msu_su_session_boot.memory ||
        READ_ONCE(msu_su_session_boot.slot->allocation_bytes) != msu_su_session_boot.allocation_bytes)
        error = -ENODEV;
    else if (msu_su_session_boot.users == ~0U) error = -EAGAIN;
    else ++msu_su_session_boot.users;
    spin_unlock_irqrestore(&msu_su_session_owner_lock, irq);
    return error;
#else
    return THIS_MODULE && try_module_get(THIS_MODULE) ? 0 : -ENODEV;
#endif
}

static void msu_su_session_owner_put(void)
{
#if MSU_SU_EXEC_SESSION_RAW_RESIDENT
    unsigned long irq;
    spin_lock_irqsave(&msu_su_session_owner_lock, irq);
    --msu_su_session_boot.users;
    spin_unlock_irqrestore(&msu_su_session_owner_lock, irq);
    /* A successfully published READY allocation stays owned by its non-init
     * Image slot for this boot. Zero users does not retire this callback or
     * its return path; only failed initialization uses staged retirement. */
#else
    module_put(THIS_MODULE);
#endif
}

static void msu_su_session_free_rcu(struct rcu_head *rcu)
{
    struct msu_su_exec_session *session = container_of(rcu,
        struct msu_su_exec_session, rcu);
    kfree(session);
    msu_su_session_owner_put();
}

static void msu_su_session_put(struct msu_su_exec_session *session)
{
    if (!refcount_dec_and_test(&session->refs)) return;
    msu_su_lease_end(&session->lease);
    if (session->executed_mm) msu_dynamic_mmdrop(session->executed_mm);
    if (session->executed_cred) msu_dynamic_put_cred(session->executed_cred);
    if (session->expected_cred) msu_dynamic_put_cred(session->expected_cred);
    if (session->expected_ns) msu_dynamic_put_nsproxy(session->expected_ns);
    if (session->executed_file) fput(session->executed_file);
    if (session->write_denied) msu_dynamic_allow_write_access(session->executable);
    if (session->executable) fput(session->executable);
    msu_dynamic_put_task_struct(session->task);
    /* task_exit may still be examining this retired hash node. Only the node
     * memory/module pin wait for RCU; the actual lease and native pins end now. */
    call_rcu(&session->rcu, msu_su_session_free_rcu);
}

static void msu_su_session_untrack(struct msu_su_exec_session *session)
{
    unsigned long irq;
    bool removed = false;
    spin_lock_irqsave(&msu_su_sessions_lock, irq);
    if (!hlist_unhashed(&session->exit_link)) {
        hlist_del_init_rcu(&session->exit_link);
        --msu_su_session_buckets[hash_min((unsigned long)session->task,
            MSU_SU_SESSION_HASH_BITS)];
        --msu_su_session_count;
        removed = true;
    }
    spin_unlock_irqrestore(&msu_su_sessions_lock, irq);
    if (removed) msu_su_session_put(session);
}

static int msu_su_session_track(struct msu_su_exec_session *session)
{
    struct msu_su_exec_session *other;
    unsigned long irq;
    u32 bucket = hash_min((unsigned long)session->task, MSU_SU_SESSION_HASH_BITS);
    int error = 0;
    spin_lock_irqsave(&msu_su_sessions_lock, irq);
    if (msu_su_session_buckets[bucket] >= MSU_SU_SESSION_BUCKET_LIMIT) {
        error = -ENOSPC;
        goto out;
    }
    hash_for_each_possible(msu_su_sessions, other, exit_link,
        (unsigned long)session->task) {
        if (other->task == session->task) { error = -EALREADY; goto out; }
    }
    refcount_inc(&session->refs);
    hash_add_rcu(msu_su_sessions, &session->exit_link, (unsigned long)session->task);
    ++msu_su_session_buckets[bucket];
    ++msu_su_session_count;
out:
    spin_unlock_irqrestore(&msu_su_sessions_lock, irq);
    return error;
}

static struct file *msu_su_session_lookup_fd_locked(struct fdtable *table, unsigned int fd)
{
    unsigned int max_fds = MSU_DYN_FIELD(table, fdtable, max_fds);
    if (fd >= max_fds) return NULL;
    return rcu_dereference_raw(MSU_DYN_FIELD(table, fdtable, fd)[array_index_nospec(fd, max_fds)]);
}

/* Native 6.6/6.18 close_fd() has no compare-and-close primitive and pick_file()
 * is private to fs/file.c. Perform its locked detach only on the exact owned
 * file. A separate fget/close_fd sequence would race dup2/CLONE_FILES. Never
 * dereference an old files pointer or close an fd just because its number fits.
 * These are regular/anon files, with no dma-buf accounting side effects. */
static void msu_su_session_close_owned(int fd, struct file *owned)
{
    struct files_struct *files = MSU_DYN_FIELD(current, task_struct, files);
    struct fdtable *table;
    struct file *detached = NULL;
    if (!files || fd < 0 || !owned) return;
    spin_lock(&MSU_DYN_FIELD(files, files_struct, file_lock));
    table = rcu_dereference_protected(MSU_DYN_FIELD(files, files_struct, fdt), 1);
    if ((unsigned int)fd < MSU_DYN_FIELD(table, fdtable, max_fds) &&
        msu_su_session_lookup_fd_locked(table, fd) == owned) {
        detached = owned;
        rcu_assign_pointer(MSU_DYN_FIELD(table, fdtable, fd)[fd], NULL);
        __clear_bit(fd, MSU_DYN_FIELD(table, fdtable, open_fds));
        __clear_bit(fd / BITS_PER_LONG, MSU_DYN_FIELD(table, fdtable, full_fds_bits));
        __clear_bit(fd, MSU_DYN_FIELD(table, fdtable, close_on_exec));
        if ((unsigned int)fd < MSU_DYN_FIELD(files, files_struct, next_fd)) MSU_DYN_FIELD(files, files_struct, next_fd) = fd;
    }
    spin_unlock(&MSU_DYN_FIELD(files, files_struct, file_lock));
    if (detached) filp_close(detached, files);
}

static bool msu_su_session_fds_match(struct msu_su_exec_session *session)
{
    struct files_struct *files = MSU_DYN_FIELD(current, task_struct, files);
    struct fdtable *table;
    bool matches;
    if (!files || atomic_read(&MSU_DYN_FIELD(files, files_struct, count)) != 1) return false;
    spin_lock(&MSU_DYN_FIELD(files, files_struct, file_lock));
    table = rcu_dereference_protected(MSU_DYN_FIELD(files, files_struct, fdt), 1);
    matches = msu_su_session_lookup_fd_locked(table, session->executable_fd) == session->executable &&
        msu_su_session_lookup_fd_locked(table, session->receipt_fd) == session->receipt_file &&
        test_bit(session->executable_fd, MSU_DYN_FIELD(table, fdtable, close_on_exec)) &&
        !test_bit(session->receipt_fd, MSU_DYN_FIELD(table, fdtable, close_on_exec));
    spin_unlock(&MSU_DYN_FIELD(files, files_struct, file_lock));
    return matches;
}

static int msu_su_session_executable_check(struct file *file)
{
    struct inode *inode = msu_dynamic_file_inode(file);
    umode_t mode = READ_ONCE(MSU_DYN_FIELD(inode, inode, i_mode));
    ssize_t caps;
    if (!S_ISREG(mode) || (mode & (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID)) ||
        !uid_eq(MSU_DYN_FIELD(inode, inode, i_uid), GLOBAL_ROOT_UID)) return -EACCES;
    /* Same internal xattr read as get_vfs_caps_from_disk: inspect the pinned
     * file, without impersonation, userspace path lookup or a new root call. */
#ifdef XATTR_NOSECURITY
    caps = __vfs_getxattr(MSU_DYN_FIELD(file, file, f_path).dentry, inode,
        XATTR_NAME_CAPS, NULL, 0, XATTR_NOSECURITY);
#else
    caps = __vfs_getxattr(MSU_DYN_FIELD(file, file, f_path).dentry, inode,
        XATTR_NAME_CAPS, NULL, 0);
#endif
    if (caps >= 0) return -EPERM;
    return caps == -ENODATA || caps == -EOPNOTSUPP ? 0 : (int)caps;
}

static bool msu_su_session_caps_equal(kernel_cap_t left, kernel_cap_t right)
{
    return cap_issubset(left, right) && cap_issubset(right, left);
}

static bool msu_su_session_profile_matches(struct msu_su_exec_session *session)
{
    const struct cred *expected = session->expected_cred, *actual = msu_dynamic_current_cred();
    kernel_cap_t permitted, effective;
    u32 secid = 0;
    int i;
    if (actual != msu_dynamic_current_real_cred() || MSU_DYN_FIELD(actual, cred, user_ns) != MSU_DYN_FIELD(expected, cred, user_ns) ||
        !uid_eq(MSU_DYN_FIELD(actual, cred, uid), MSU_DYN_FIELD(expected, cred, uid)) || !uid_eq(MSU_DYN_FIELD(actual, cred, euid), MSU_DYN_FIELD(expected, cred, euid)) ||
        !uid_eq(MSU_DYN_FIELD(actual, cred, suid), MSU_DYN_FIELD(expected, cred, suid)) || !uid_eq(MSU_DYN_FIELD(actual, cred, fsuid), MSU_DYN_FIELD(expected, cred, fsuid)) ||
        !gid_eq(MSU_DYN_FIELD(actual, cred, gid), MSU_DYN_FIELD(expected, cred, gid)) || !gid_eq(MSU_DYN_FIELD(actual, cred, egid), MSU_DYN_FIELD(expected, cred, egid)) ||
        !gid_eq(MSU_DYN_FIELD(actual, cred, sgid), MSU_DYN_FIELD(expected, cred, sgid)) || !gid_eq(MSU_DYN_FIELD(actual, cred, fsgid), MSU_DYN_FIELD(expected, cred, fsgid)) ||
        MSU_DYN_FIELD(actual, cred, securebits) != (MSU_DYN_FIELD(expected, cred, securebits) & ~SECBIT_KEEP_CAPS) ||
        MSU_DYN_FIELD(actual, cred, group_info)->ngroups != MSU_DYN_FIELD(expected, cred, group_info)->ngroups) return false;
    for (i = 0; i < MSU_DYN_FIELD(expected, cred, group_info)->ngroups; ++i)
        if (!gid_eq(MSU_DYN_FIELD(actual, cred, group_info)->gid[i], MSU_DYN_FIELD(expected, cred, group_info)->gid[i])) return false;
    /* No setid/filecaps payload is admitted. commoncap preserves I/A/B. For
     * nonzero KSU targets, I=A=the selected effective mask, so P'=E'=A.
     * For UID0 with cleared securebits, P'=E'=B|I|A; NNP may only reduce P'
     * to the applied permitted mask. Do not require exec's new cred pointer
     * to equal CORE's pre-exec pointer, or accept arbitrary nonzero IDs. */
    permitted = MSU_DYN_FIELD(expected, cred, cap_ambient);
    effective = MSU_DYN_FIELD(expected, cred, cap_ambient);
    if (uid_eq(MSU_DYN_FIELD(expected, cred, uid), GLOBAL_ROOT_UID)) {
        permitted = cap_combine(cap_combine(MSU_DYN_FIELD(expected, cred, cap_bset),
            MSU_DYN_FIELD(expected, cred, cap_inheritable)), MSU_DYN_FIELD(expected, cred, cap_ambient));
        if (test_bit(PFA_NO_NEW_PRIVS, &MSU_DYN_FIELD(current, task_struct, atomic_flags)))
            permitted = cap_intersect(permitted, MSU_DYN_FIELD(expected, cred, cap_permitted));
        effective = permitted;
    }
    if (!msu_su_session_caps_equal(MSU_DYN_FIELD(actual, cred, cap_permitted), permitted) ||
        !msu_su_session_caps_equal(MSU_DYN_FIELD(actual, cred, cap_effective), effective) ||
        !msu_su_session_caps_equal(MSU_DYN_FIELD(actual, cred, cap_inheritable), MSU_DYN_FIELD(expected, cred, cap_inheritable)) ||
        !msu_su_session_caps_equal(MSU_DYN_FIELD(actual, cred, cap_ambient), MSU_DYN_FIELD(expected, cred, cap_ambient)) ||
        !msu_su_session_caps_equal(MSU_DYN_FIELD(actual, cred, cap_bset), MSU_DYN_FIELD(expected, cred, cap_bset))) return false;
    security_cred_getsecid(actual, &secid);
    return secid == session->expected_secid && MSU_DYN_FIELD(current, task_struct, nsproxy) == session->expected_ns;
}

static void msu_su_session_end_locked(struct msu_su_exec_session *session)
{
    msu_su_lease_end(&session->lease);
    msu_su_session_untrack(session);
}

static long msu_su_session_ioctl(struct file *file, unsigned int command,
    unsigned long argument)
{
    struct msu_su_exec_session *session = MSU_DYN_FIELD(file, file, private_data);
    struct msu_su_session_receipt receipt;
    struct file *executable;
    int error;
    if (command != MSU_SU_SESSION_CONSUME) return -ENOTTY;
    if (current != session->task) return -EPERM;
    mutex_lock(&session->lock);
    if (session->consumed) { error = -EALREADY; goto out; }
    if (!session->ready) { error = -EAGAIN; goto out; }
    if (!session->identity_valid || session->exited) {
        error = session->receipt.error ? session->receipt.error : -ESTALE;
        goto out;
    }
    executable = MSU_DYN_FIELD(current, task_struct, mm) ? get_mm_exe_file(MSU_DYN_FIELD(current, task_struct, mm)) : NULL;
    error = READ_ONCE(MSU_DYN_FIELD(current, task_struct, mm)) != session->executed_mm ||
        READ_ONCE(MSU_DYN_FIELD(current, task_struct, self_exec_id)) != session->receipt.exec_id ||
        msu_dynamic_current_cred() != session->executed_cred ||
        msu_dynamic_current_real_cred() != session->executed_cred ||
        MSU_DYN_FIELD(current, task_struct, nsproxy) != session->expected_ns ||
        executable != session->executed_file ? -ESTALE : 0;
    if (executable) fput(executable);
    if (error) {
        session->identity_valid = false;
        session->receipt.error = error;
        msu_su_session_end_locked(session);
        goto out;
    }
    if (!session->receipt.error)
        session->receipt.error = msu_su_lease_validate_after_exec(&session->lease);
    receipt = session->receipt;
    receipt.state |= MSU_SU_SESSION_CONSUMED;
    if (copy_to_user((void __user *)argument, &receipt, sizeof(receipt))) {
        error = -EFAULT;
        goto out;
    }
    session->consumed = true;
    session->receipt = receipt;
    error = receipt.error;
    msu_su_session_end_locked(session);
out:
    mutex_unlock(&session->lock);
    return error;
}

#ifdef CONFIG_COMPAT
static long msu_su_session_compat_ioctl(struct file *file, unsigned int command,
    unsigned long argument)
{
    return msu_su_session_ioctl(file, command, (unsigned long)compat_ptr(argument));
}
#endif

static int msu_su_session_flush(struct file *file, fl_owner_t owner)
{
    struct msu_su_exec_session *session = MSU_DYN_FIELD(file, file, private_data);
    if (current != session->task) return 0;
    mutex_lock(&session->lock);
    if (!session->consumed) {
        if (!session->receipt.error) session->receipt.error = -ECANCELED;
        session->identity_valid = false;
        msu_su_session_end_locked(session);
    }
    mutex_unlock(&session->lock);
    return 0;
}

static int msu_su_session_release(struct inode *inode, struct file *file)
{
    struct msu_su_exec_session *session = MSU_DYN_FIELD(file, file, private_data);
    mutex_lock(&session->lock);
    msu_su_session_end_locked(session);
    mutex_unlock(&session->lock);
    msu_su_session_put(session);
    return 0;
}

static const struct file_operations msu_su_session_fops = {
#if !MSU_SU_EXEC_SESSION_RAW_RESIDENT
    .owner = THIS_MODULE,
#endif
    .unlocked_ioctl = msu_su_session_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = msu_su_session_compat_ioctl,
#endif
    .flush = msu_su_session_flush,
    .release = msu_su_session_release,
};

/* Same-TU facts for the fixed group_info flexible tail and local fops.
 * The carrier checks target BTF/type/CFI before exposing this implementation. */
const u32 msu_su_session_abi_words[24] __used
__attribute__((section(".msu.session.abi"))) = {
    0x4d535553U, 1U, 24U * sizeof(u32),
    sizeof(struct group_info), __alignof__(struct group_info),
    __builtin_offsetof(struct group_info, usage), sizeof(((struct group_info *)0)->usage),
    __builtin_offsetof(struct group_info, ngroups), sizeof(((struct group_info *)0)->ngroups),
    __builtin_offsetof(struct group_info, gid), sizeof(((struct group_info *)0)->gid[0]),
    __alignof__(((struct group_info *)0)->gid[0]),
    sizeof(struct file_operations), __alignof__(struct file_operations),
    __builtin_offsetof(struct file_operations, owner), sizeof(((struct file_operations *)0)->owner),
    __builtin_offsetof(struct file_operations, unlocked_ioctl), sizeof(((struct file_operations *)0)->unlocked_ioctl),
#ifdef CONFIG_COMPAT
    __builtin_offsetof(struct file_operations, compat_ioctl), sizeof(((struct file_operations *)0)->compat_ioctl),
#else
    ~0U, 0U,
#endif
    __builtin_offsetof(struct file_operations, flush), sizeof(((struct file_operations *)0)->flush),
    __builtin_offsetof(struct file_operations, release), sizeof(((struct file_operations *)0)->release),
};

static void msu_su_session_resume(struct callback_head *work)
{
    struct msu_su_exec_session *session = container_of(work,
        struct msu_su_exec_session, resume);
    struct file *receipt_file;
    bool executed;
    int error = 0;
    mutex_lock(&session->lock);
    executed = current == session->task && !(MSU_DYN_FIELD(current, task_struct, flags) & PF_EXITING) &&
        MSU_DYN_FIELD(current, task_struct, mm) && MSU_DYN_FIELD(current, task_struct, mm) != session->lease.mm &&
        READ_ONCE(MSU_DYN_FIELD(current, task_struct, self_exec_id)) == session->original_exec_id + 1;
    receipt_file = session->receipt_file;
    session->receipt_file = NULL;
    if (executed) {
        session->executed_mm = MSU_DYN_FIELD(current, task_struct, mm);
        msu_dynamic_mmgrab(session->executed_mm);
        session->executed_cred = msu_dynamic_get_current_cred();
        session->executed_file = get_mm_exe_file(session->executed_mm);
        /* execveat(AT_EMPTY_PATH) reopens a file; exe_file need not be the
         * struct file passed to prepare. It must be the held inode AND the
         * held mount/dentry, then the exact post-exec file is pinned below. */
        if (!session->executed_file ||
            msu_dynamic_file_inode(session->executed_file) != msu_dynamic_file_inode(session->executable) ||
            !path_equal(&MSU_DYN_FIELD(session->executed_file, file, f_path), &MSU_DYN_FIELD(session->executable, file, f_path)) ||
            !msu_su_session_profile_matches(session)) error = -ESTALE;
        session->identity_valid = !error;
        if (!error) error = msu_su_lease_validate_after_exec(&session->lease);
        session->receipt.error = error;
        session->receipt.exec_id = READ_ONCE(MSU_DYN_FIELD(current, task_struct, self_exec_id));
        session->receipt.state |= MSU_SU_SESSION_EXECUTED;
        session->ready = true;
        if (!session->identity_valid) msu_su_session_end_locked(session);
    } else {
        session->receipt.error = -ESTALE;
        msu_su_session_end_locked(session);
    }
    mutex_unlock(&session->lock);
    msu_su_session_close_owned(session->executable_fd, session->executable);
    if (!executed) msu_su_session_close_owned(session->receipt_fd, receipt_file);
    /* Even revoked successful exec keeps its denying receipt in the fd table.
     * Dropping the construction ref must never erase that failure marker. */
    fput(receipt_file);
    msu_su_session_put(session);
}

static void msu_su_session_exit_work(struct work_struct *work)
{
    struct msu_su_exec_session *session = container_of(work,
        struct msu_su_exec_session, exit_work);
    mutex_lock(&session->lock);
    if (!session->receipt.error) session->receipt.error = -ESRCH;
    session->identity_valid = false;
    msu_su_lease_end(&session->lease);
    mutex_unlock(&session->lock);
    msu_su_session_put(session);
}

void msu_su_exec_session_task_exit(struct task_struct *task)
{
    struct msu_su_exec_session *session, *found = NULL;
    unsigned long irq;
    u32 examined = 0;
    if (!READ_ONCE(msu_su_session_count)) return;
    rcu_read_lock();
    hash_for_each_possible_rcu(msu_su_sessions, session, exit_link, (unsigned long)task) {
        if (++examined > MSU_SU_SESSION_BUCKET_LIMIT) break;
        if (session->task == task) {
            spin_lock_irqsave(&msu_su_sessions_lock, irq);
            if (!hlist_unhashed(&session->exit_link)) {
                hlist_del_init_rcu(&session->exit_link);
                --msu_su_session_buckets[hash_min((unsigned long)task,
                    MSU_SU_SESSION_HASH_BITS)];
                --msu_su_session_count;
                WRITE_ONCE(session->exited, true);
                found = session;
            }
            spin_unlock_irqrestore(&msu_su_sessions_lock, irq);
            break;
        }
    }
    rcu_read_unlock();
    /* The detached hash's reference becomes this worker's reference. Ordinary
     * exits never lock or queue work; both lookup and admission are bounded. */
    if (found) schedule_work(&found->exit_work);
}

int msu_su_exec_session_prepare(const void *registry, struct file *executable,
    struct msu_su_exec_session **out)
{
    struct msu_su_exec_session *session;
    struct file *receipt_file;
    int error;
    if (!out) return -EINVAL;
    *out = NULL;
    if (!registry || IS_ERR_OR_NULL(executable)) return -EINVAL;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!MSU_DYN_FIELD(current, task_struct, files) ||
        atomic_read(&MSU_DYN_FIELD(MSU_DYN_FIELD(current, task_struct, files), files_struct, count)) != 1)
        return -EBUSY;
    error = msu_su_session_owner_get();
    if (error) return error;
    session = kzalloc(sizeof(*session), GFP_KERNEL);
    if (!session) { msu_su_session_owner_put(); return -ENOMEM; }
    refcount_set(&session->refs, 1);
    mutex_init(&session->lock);
    INIT_HLIST_NODE(&session->exit_link);
    init_task_work(&session->resume, msu_su_session_resume);
    INIT_WORK(&session->exit_work, msu_su_session_exit_work);
    session->task = current;
    msu_dynamic_get_task_struct(session->task);
    session->executable_fd = session->receipt_fd = -1;
    error = msu_su_lease_begin(registry, &session->lease);
    if (error) goto fail;
    session->original_exec_id = session->lease.exec_id;
    if (session->original_exec_id == ~0ULL) { error = -EOVERFLOW; goto fail; }
    session->executable = msu_dynamic_get_file(executable);
    error = msu_dynamic_deny_write_access(executable);
    if (error) goto fail;
    session->write_denied = true;
    error = msu_su_session_executable_check(executable);
    if (error) goto fail;
    session->receipt.magic = MSU_SU_SESSION_MAGIC;
    session->receipt.version = MSU_SU_SESSION_VERSION;
    session->receipt.bytes = sizeof(session->receipt);
    session->receipt.subject_uid = __kuid_val(MSU_DYN_FIELD(session->lease.cred, cred, uid));
    session->receipt.generation = session->lease.generation;
    session->executable_fd = get_unused_fd_flags(O_CLOEXEC);
    if (session->executable_fd < 0) { error = session->executable_fd; goto fail; }
    session->receipt_fd = get_unused_fd_flags(0);
    if (session->receipt_fd < 0) {
        error = session->receipt_fd;
        put_unused_fd(session->executable_fd);
        goto fail;
    }
    receipt_file = anon_inode_getfile(MSU_SU_SESSION_NAME, &msu_su_session_fops,
        session, O_RDONLY);
    if (IS_ERR(receipt_file)) {
        error = PTR_ERR(receipt_file);
        put_unused_fd(session->receipt_fd);
        put_unused_fd(session->executable_fd);
        goto fail;
    }
    refcount_inc(&session->refs); /* fops.release */
    session->receipt_file = receipt_file;
    fd_install(session->executable_fd, msu_dynamic_get_file(executable));
    fd_install(session->receipt_fd, msu_dynamic_get_file(receipt_file));
    *out = session;
    return 0;
fail:
    msu_su_session_put(session);
    return error;
}

int msu_su_exec_session_apply(struct msu_su_exec_session *session,
    struct msu_su_execution_receipt *receipt)
{
    const struct msu_su_profile *profile;
    int error;
    if (!session || !receipt) return -EINVAL;
    if (current != session->task) return -EPERM;
    mutex_lock(&session->lock);
    if (session->published || session->apply_attempted) { error = -EALREADY; goto out; }
    session->apply_attempted = true;
    error = msu_su_apply_held_detailed(&session->lease, receipt);
    session->receipt.phase = receipt->phase;
    session->receipt.credential_effects = receipt->credential_effects;
    session->receipt.task_effects = receipt->task_effects;
    if (error) goto out;
    if (!receipt->completed) { error = -EIO; goto out; }
    profile = msu_su_lease_profile(&session->lease);
    if (!profile || !MSU_DYN_FIELD(current, task_struct, nsproxy)) { error = -ESTALE; goto out; }
    session->expected_cred = msu_dynamic_get_current_cred();
    if (session->expected_cred != msu_dynamic_current_real_cred() ||
        __kuid_val(MSU_DYN_FIELD(session->expected_cred, cred, uid)) != profile->uid ||
        __kuid_val(MSU_DYN_FIELD(session->expected_cred, cred, euid)) != profile->uid ||
        __kuid_val(MSU_DYN_FIELD(session->expected_cred, cred, suid)) != profile->uid ||
        __kuid_val(MSU_DYN_FIELD(session->expected_cred, cred, fsuid)) != profile->uid ||
        __kgid_val(MSU_DYN_FIELD(session->expected_cred, cred, gid)) != profile->gid ||
        __kgid_val(MSU_DYN_FIELD(session->expected_cred, cred, egid)) != profile->gid ||
        __kgid_val(MSU_DYN_FIELD(session->expected_cred, cred, sgid)) != profile->gid ||
        __kgid_val(MSU_DYN_FIELD(session->expected_cred, cred, fsgid)) != profile->gid ||
        MSU_DYN_FIELD(session->expected_cred, cred, securebits)) { error = -ESTALE; goto out; }
    session->expected_ns = MSU_DYN_FIELD(current, task_struct, nsproxy);
    msu_dynamic_get_nsproxy(session->expected_ns);
    security_cred_getsecid(session->expected_cred, &session->expected_secid);
    session->receipt.target_uid = profile->uid;
    session->receipt.target_gid = profile->gid;
    session->receipt.state = MSU_SU_SESSION_APPLIED;
out:
    session->receipt.error = error;
    mutex_unlock(&session->lock);
    return error;
}

int msu_su_exec_session_exec_fd(const struct msu_su_exec_session *session)
{
    return session && current == session->task ? session->executable_fd : -EINVAL;
}

int msu_su_exec_session_publish(struct msu_su_exec_session *session)
{
    int error;
    if (!session) return -EINVAL;
    if (current != session->task) return -EPERM;
    mutex_lock(&session->lock);
    if (session->published) { error = -EALREADY; goto out; }
    if (session->receipt.state != MSU_SU_SESSION_APPLIED ||
        !session->expected_cred || session->receipt.error) { error = -EINVAL; goto out; }
    error = msu_su_lease_validate(&session->lease);
    if (error) goto out;
    if (MSU_DYN_FIELD(current, task_struct, nsproxy) != session->expected_ns ||
        !msu_su_session_fds_match(session)) { error = -ESTALE; goto out; }
    error = msu_su_session_track(session);
    if (error) goto out;
    error = task_work_add(current, &session->resume, TWA_RESUME);
    if (error) {
        msu_su_session_untrack(session);
        goto out;
    }
    session->published = true; /* caller ref becomes task_work ref */
out:
    mutex_unlock(&session->lock);
    return error;
}

void msu_su_exec_session_abort(struct msu_su_exec_session *session)
{
    struct file *receipt_file;
    if (!session || current != session->task) return;
    mutex_lock(&session->lock);
    if (session->published) { mutex_unlock(&session->lock); return; }
    receipt_file = session->receipt_file;
    session->receipt_file = NULL;
    msu_su_lease_end(&session->lease);
    mutex_unlock(&session->lock);
    msu_su_session_close_owned(session->executable_fd, session->executable);
    msu_su_session_close_owned(session->receipt_fd, receipt_file);
    if (receipt_file) fput(receipt_file);
    msu_su_session_put(session);
}
