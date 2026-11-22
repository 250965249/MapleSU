// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/task_work.h>
#include <asm/ptrace.h>
#include "su_nonroot_transition.h"
#include "su_nonroot_transition_work.h"
#include "manager_dynamic_layout.h"

#ifndef MSU_SU_NONROOT_WORK_RAW_RESIDENT
#define MSU_SU_NONROOT_WORK_RAW_RESIDENT 0
#endif
#if MSU_SU_NONROOT_WORK_RAW_RESIDENT != 0 && MSU_SU_NONROOT_WORK_RAW_RESIDENT != 1
#error "MSU_SU_NONROOT_WORK_RAW_RESIDENT must be 0 or 1"
#endif
#if MSU_SU_NONROOT_WORK_RAW_RESIDENT
#include "manager_resident_abi.h"
#else
#include <linux/module.h>
#endif

struct msu_su_nonroot_work {
    struct callback_head resume;
    struct task_struct *task;
    struct mm_struct *mm;
    const struct pt_regs *regs;
    u64 exec_id;
    u32 old_uid;
};

static DEFINE_SPINLOCK(msu_nonroot_work_lock);
static enum { MSU_WORK_NEW, MSU_WORK_OPEN, MSU_WORK_CLOSED } msu_work_state;
static unsigned int msu_work_count;

#if MSU_SU_NONROOT_WORK_RAW_RESIDENT
static struct {
    const struct msu_resident_slot *slot;
    const void *memory;
    u64 allocation_bytes;
} msu_nonroot_boot;
#endif

int msu_su_nonroot_work_bind_boot_resident(const struct msu_resident_slot *slot,
    const void *memory, u64 allocation_bytes)
{
#if MSU_SU_NONROOT_WORK_RAW_RESIDENT
    unsigned long irq, start = (unsigned long)memory, end;
    unsigned long code = (unsigned long)msu_su_nonroot_work_bind_boot_resident;
    unsigned long data = (unsigned long)&msu_nonroot_boot;
    int error = 0;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!slot || ((unsigned long)slot & 63U) || !memory ||
        allocation_bytes < sizeof(msu_nonroot_boot) ||
        allocation_bytes > ~0UL - start) return -EINVAL;
    end = start + allocation_bytes;
    if (code < start || code >= end || data < start ||
        data > end - sizeof(msu_nonroot_boot) ||
        ((unsigned long)slot >= start && (unsigned long)slot < end)) return -EINVAL;
    /* The real v3 constructor runs before bootstrap publishes this mapping.
     * Only its non-init Image slot may later admit work from READY. */
    if (smp_load_acquire(&slot->boot_magic) != MSU_RESIDENT_BOOT_MAGIC ||
        smp_load_acquire(&slot->state) != MSU_RESIDENT_INITIALIZING ||
        READ_ONCE(slot->memory) || READ_ONCE(slot->allocation_bytes)) return -ESTALE;
    spin_lock_irqsave(&msu_nonroot_work_lock, irq);
    if (msu_work_state == MSU_WORK_CLOSED) error = -ESHUTDOWN;
    else if (msu_nonroot_boot.slot) {
        if (msu_nonroot_boot.slot != slot || msu_nonroot_boot.memory != memory ||
            msu_nonroot_boot.allocation_bytes != allocation_bytes) error = -ESTALE;
    } else if (msu_work_state != MSU_WORK_NEW || msu_work_count) error = -EBUSY;
    else {
        msu_nonroot_boot.slot = slot;
        msu_nonroot_boot.memory = memory;
        msu_nonroot_boot.allocation_bytes = allocation_bytes;
    }
    spin_unlock_irqrestore(&msu_nonroot_work_lock, irq);
    return error;
#else
    (void)slot;
    (void)memory;
    (void)allocation_bytes;
    return -EOPNOTSUPP;
#endif
}

int msu_su_nonroot_work_open(void)
{
    unsigned long irq;
    int error = 0;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    spin_lock_irqsave(&msu_nonroot_work_lock, irq);
    if (msu_work_state == MSU_WORK_CLOSED) error = -ESHUTDOWN;
#if MSU_SU_NONROOT_WORK_RAW_RESIDENT
    else if (!msu_nonroot_boot.slot) error = -ENODEV;
#endif
    else msu_work_state = MSU_WORK_OPEN;
    spin_unlock_irqrestore(&msu_nonroot_work_lock, irq);
    return error;
}

int msu_su_nonroot_work_close(void)
{
    unsigned long irq;
    int error;
    spin_lock_irqsave(&msu_nonroot_work_lock, irq);
    msu_work_state = MSU_WORK_CLOSED;
    error = msu_work_count ? -EINPROGRESS : 0;
    spin_unlock_irqrestore(&msu_nonroot_work_lock, irq);
    return error;
}

static int msu_nonroot_work_admit(void)
{
    unsigned long irq;
    int error = 0;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    spin_lock_irqsave(&msu_nonroot_work_lock, irq);
    if (msu_work_state != MSU_WORK_OPEN) error = -ESHUTDOWN;
#if MSU_SU_NONROOT_WORK_RAW_RESIDENT
    else if (!msu_nonroot_boot.slot ||
        smp_load_acquire(&msu_nonroot_boot.slot->boot_magic) != MSU_RESIDENT_BOOT_MAGIC ||
        smp_load_acquire(&msu_nonroot_boot.slot->state) != MSU_RESIDENT_READY ||
        READ_ONCE(msu_nonroot_boot.slot->memory) != (unsigned long)msu_nonroot_boot.memory ||
        READ_ONCE(msu_nonroot_boot.slot->allocation_bytes) != msu_nonroot_boot.allocation_bytes)
        error = -ENODEV;
#endif
    else if (msu_work_count == MSU_SU_NONROOT_WORK_LIMIT) error = -EAGAIN;
    else ++msu_work_count;
    spin_unlock_irqrestore(&msu_nonroot_work_lock, irq);
    return error;
}

static void msu_nonroot_work_unadmit(void)
{
    unsigned long irq;
    spin_lock_irqsave(&msu_nonroot_work_lock, irq);
    --msu_work_count;
    spin_unlock_irqrestore(&msu_nonroot_work_lock, irq);
}

static void msu_nonroot_work_put(struct msu_su_nonroot_work *work)
{
    msu_dynamic_mmdrop(work->mm);
    msu_dynamic_put_task_struct(work->task);
    kfree(work);
#if !MSU_SU_NONROOT_WORK_RAW_RESIDENT
    module_put(THIS_MODULE);
#endif
    /* Release the reservation last, including on native exit. LKM boot pin or
     * the raw READY allocation's permanent Image ownership protects this tail. */
    msu_nonroot_work_unadmit();
}

static bool msu_nonroot_native_frame(const struct pt_regs *regs)
{
    /* Never dereference an unrecognized before pointer. */
    return regs && msu_runtime_layout_ready() &&
        regs == msu_dynamic_task_pt_regs(current) && user_mode(regs);
}

static void msu_nonroot_work_resume(struct callback_head *head)
{
    struct msu_su_nonroot_work *work = container_of(head,
        struct msu_su_nonroot_work, resume);
    struct msu_su_nonroot_receipt receipt = {0};
    const struct pt_regs *regs;
    long result;

    /* exit_task_work runs even after exit_mm. Retain mm_count, not mm_users,
     * so neither exit nor an exec is held hostage by a queued notification. */
    if (!in_task() || in_atomic() || irqs_disabled() || current != work->task ||
        (READ_ONCE(MSU_DYN_FIELD(current, task_struct, flags)) & PF_EXITING) ||
        READ_ONCE(MSU_DYN_FIELD(current, task_struct, mm)) != work->mm ||
        READ_ONCE(MSU_DYN_FIELD(current, task_struct, self_exec_id)) != work->exec_id)
        goto out;
    regs = msu_dynamic_task_pt_regs(current);
    if (regs != work->regs || !msu_nonroot_native_frame(regs)) goto out;
    result = (long)READ_ONCE(regs->regs[0]);
    if (result || __kuid_val(msu_dynamic_current_uid()) == work->old_uid) goto out;
    /* Synchronous side action only. The real endpoint reacquires runtime and
     * current policy/source; its error never replaces the syscall result. */
    msu_su_runtime_nonroot_complete(work->old_uid, result, &receipt);
out:
    msu_nonroot_work_put(work);
}

int msu_su_nonroot_work_prepare(u32 old_uid, const struct pt_regs *regs)
{
    struct msu_su_nonroot_work *work;
    int error;
    if (!in_task() || in_atomic() || irqs_disabled()) return -EWOULDBLOCK;
    if (!msu_runtime_layout_ready()) return -EAGAIN;
    if (!msu_nonroot_native_frame(regs)) return -EINVAL;
    if ((READ_ONCE(MSU_DYN_FIELD(current, task_struct, flags)) & PF_EXITING) || !MSU_DYN_FIELD(current, task_struct, mm)) return -ESRCH;
    if (__kuid_val(msu_dynamic_current_uid()) != old_uid) return -ESTALE;
    error = msu_nonroot_work_admit();
    if (error) return error;
#if !MSU_SU_NONROOT_WORK_RAW_RESIDENT
    if (!THIS_MODULE || !try_module_get(THIS_MODULE)) {
        error = -ENODEV;
        goto unadmit;
    }
#endif
    work = kzalloc(sizeof(*work), GFP_KERNEL);
    if (!work) {
#if !MSU_SU_NONROOT_WORK_RAW_RESIDENT
        module_put(THIS_MODULE);
#endif
        error = -ENOMEM;
        goto unadmit;
    }
    work->task = current;
    msu_dynamic_get_task_struct(work->task);
    work->mm = MSU_DYN_FIELD(current, task_struct, mm);
    msu_dynamic_mmgrab(work->mm);
    work->regs = regs;
    work->exec_id = READ_ONCE(MSU_DYN_FIELD(current, task_struct, self_exec_id));
    work->old_uid = old_uid;
    init_task_work(&work->resume, msu_nonroot_work_resume);
    error = task_work_add(current, &work->resume, TWA_RESUME);
    if (error) msu_nonroot_work_put(work);
    return error;
unadmit:
    msu_nonroot_work_unadmit();
    return error;
}
