// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_NONROOT_TRANSITION_WORK_H
#define MAPLESU_SU_NONROOT_TRANSITION_WORK_H
#include <linux/types.h>

struct pt_regs;
struct msu_su_nonroot_receipt;
struct msu_resident_slot;
#define MSU_SU_NONROOT_WORK_LIMIT 64U

/* Raw claim only, compiled with MSU_SU_NONROOT_WORK_RAW_RESIDENT=1. The real
 * validated v3 constructor binds its Image slot and allocated resident by
 * value while INITIALIZING, before work_open. The allocation must contain
 * this implementation and its static owner. Only matching READY admits work;
 * failed/quarantined startup never does. READY is boot-owned and never retired
 * by the paired Image bootstrap. No config-stack pointer or module is stored.
 * Binding is immutable; close retains the identity and permanently closes
 * admission. A real LKM build returns -EOPNOTSUPP from this raw-only API. */
int msu_su_nonroot_work_bind_boot_resident(const struct msu_resident_slot *slot,
    const void *memory, u64 allocation_bytes);

/* Boot-only: open after native imports. Idempotent while open; ANY close
 * permanently prevents reopening (-ESHUTDOWN). Raw open requires the v3 bind;
 * admission still waits for matching READY. The real bridge LKM init lifetime,
 * then its published boot pin, covers callback tail after module_put. The raw
 * READY mapping's permanent Image ownership covers its callback return tail. */
int msu_su_nonroot_work_open(void);

/* Called ONCE at the actual ARM64 setresuid/setresuid16 before gate, only
 * after the parent's in-memory Enabled-only registry hint. regs must be the
 * actual task_pt_regs(current), not the wrapper's own or a user-supplied frame.
 * Parent verifies the selected native/compat syscall entry; compat users may
 * reach the same native wrapper, so no native-only syscall number is assumed.
 * The hint is not authorization; no registry/runtime reference crosses syscall.
 * Reserve one bounded slot before allocation. 0 transfers ownership to native
 * TWA_RESUME; errors preserve task_work_add errno and release every reference.
 * Parent ALWAYS executes the original syscall and preserves its return value,
 * including prepare errors. No retry or replay is implied.
 * -ESHUTDOWN: not open/closed; -EAGAIN: 64 in flight; -EINVAL: wrong frame;
 * -ESTALE: wrong old UID; -ESRCH: exiting/no mm; -EWOULDBLOCK: atomic context;
 * -ENODEV: no native module reference or matching raw READY allocation;
 * -ENOMEM: allocation failure. */
int msu_su_nonroot_work_prepare(u32 old_uid, const struct pt_regs *regs);

/* Nonblocking, monotonic admission close. -EINPROGRESS includes preparing,
 * queued, running and reference cleanup. Parent retains runtime.close PENDING
 * on nonzero; work drains at native resume/exit, without cancellation or waits.
 * No callback reenters close; a later external close may observe drain as 0. */
int msu_su_nonroot_work_close(void);

/* Parent supplies the real synchronous endpoint. Reacquire the published
 * runtime and MODULE source and validate actual current snapshot policy here.
 * Called only for same-task/mm/exec setresuid success with changed UID.
 * Local receipt/return describe side action only, never the syscall return. */
extern int msu_su_runtime_nonroot_complete(u32 old_uid, long syscall_result,
    struct msu_su_nonroot_receipt *receipt);
#endif
