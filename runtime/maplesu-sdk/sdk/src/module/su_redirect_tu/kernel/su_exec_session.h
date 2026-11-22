// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_EXEC_SESSION_H
#define MAPLESU_SU_EXEC_SESSION_H
#include <linux/types.h>

struct file;
struct msu_resident_slot;
struct task_struct;
struct msu_su_execution_receipt;
struct msu_su_exec_session;

/* Raw resident v3 constructor only, before actual READY publication. The
 * successful allocation remains owned by its Image slot for the whole boot. */
int msu_su_exec_session_bind_boot_resident(const struct msu_resident_slot *slot,
    const void *memory, u64 allocation_bytes);

/* Current, sleepable exec caller only. Borrows executable; holds its own file,
 * task, original lease/mm/cred and module references. A shared files table is
 * rejected before allocating descriptors or applying the Profile. */
int msu_su_exec_session_prepare(const void *registry, struct file *executable,
    struct msu_su_exec_session **out);
int msu_su_exec_session_apply(struct msu_su_exec_session *session,
    struct msu_su_execution_receipt *receipt);
int msu_su_exec_session_exec_fd(const struct msu_su_exec_session *session);
/* Success transfers caller ownership to TWA_RESUME. The caller may read exec_fd
 * before it returns from this same kernel invocation, but must not abort or
 * otherwise retain the object after task_work can run. Failure retains caller
 * ownership and its original errno; caller must abort exactly once. */
int msu_su_exec_session_publish(struct msu_su_exec_session *session);
void msu_su_exec_session_abort(struct msu_su_exec_session *session);

/* Required existing HOST/CORE process-exit notification; no new observer.
 * Call for the actual exiting task, even when its files are shared/exported.
 * Atomic-context safe: detaches records and defers sleeping cleanup. */
void msu_su_exec_session_task_exit(struct task_struct *task);

#endif
