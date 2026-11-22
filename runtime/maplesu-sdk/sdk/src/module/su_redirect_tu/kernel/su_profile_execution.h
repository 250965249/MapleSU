// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_PROFILE_EXECUTION_H
#define MAPLESU_SU_PROFILE_EXECUTION_H
#include <linux/types.h>
#include "su_profile_namespace.h"
#include "manager_task_state.h"

struct msu_su_profile;
struct msu_su_lease;

enum msu_su_execution_phase {
    MSU_SU_EXECUTION_ADMISSION = 1,
    MSU_SU_EXECUTION_SUPPORT,
    MSU_SU_EXECUTION_CREDENTIALS,
    MSU_SU_EXECUTION_TASK,
    MSU_SU_EXECUTION_NAMESPACE,
    MSU_SU_EXECUTION_FINAL_VALIDATE,
    MSU_SU_EXECUTION_PROFILE_FLAGS,
};

/* Kernel-private result, not a second request wire. A failed later stage never
 * erases committed credentials or completed task/namespace changes. */
struct msu_su_execution_receipt {
    u32 phase, credential_effects, task_effects;
    u64 previous_seccomp_mode;
    struct msu_su_namespace_receipt mount_namespace;
    int error;
    bool completed;
    struct msu_task_profile_receipt task_profile;
};

/* The actual source.validate_profile callback can use this combined admission
 * check before publishing a grant. Qualification comes from the sole CORE and
 * native namespace implementation; default/template/non-root policy must have
 * real business consumers, not just populated fields. */
int msu_su_profile_check_execution(const struct msu_su_profile *profile);

/* Uses an already-held lease and never begins or ends it. The caller retains
 * the authority across its operation and owns the final release. */
int msu_su_apply_held_detailed(struct msu_su_lease *lease,
    struct msu_su_execution_receipt *receipt);

/* Holds the original installation/Profile and active task/mm/exec/cred lease
 * through every stage, including all post-commit cleanup. No mutation replay,
 * second credential transaction, Manager lookup, disk I/O or fallback route. */
int msu_su_apply_current_detailed(const void *context,
    struct msu_su_execution_receipt *receipt);
#endif
