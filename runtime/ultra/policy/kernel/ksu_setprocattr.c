// SPDX-License-Identifier: GPL-3.0-only
/* Credential transition checks follow KernelSU selinux_hide.c. */
#include "policy_view_internal.h"

static inline u32 view_cred_sid(const struct cred *cred)
{
    const struct maplesu_cred_security *tsec;

    tsec = pv_selinux_cred(cred);
    return PV_FIELD(tsec, maplesu_cred_security, sid);
}

/*
 * get the objective security ID of a task
 */
static inline u32 view_task_sid_obj(const struct task_struct *task)
{
    u32 sid;

    rcu_read_lock();
    sid = view_cred_sid(pv_task_cred(task));
    rcu_read_unlock();
    return sid;
}

static u32 view_ptrace_parent_sid(void)
{
    u32 sid = 0;
    struct task_struct *tracer;

    rcu_read_lock();
    tracer = pv_ptrace_parent(current);
    if (tracer)
        sid = view_task_sid_obj(tracer);
    rcu_read_unlock();

    return sid;
}

typedef int (*setprocattr_fn)(const char *name, void *value, size_t size);
static int view_setprocattr(const char *name, void *value, size_t size)
{
    struct maplesu_cred_security *tsec;
    struct cred *new;
    u32 mysid = pv_current_sid(), sid = 0, ptsid;
    int error;
    char *str = value;
    (void)name; // The SDK bridge applies the operation/UID predicate first.

    error = maplesu_avc_has_perm(mysid, mysid, SECCLASS_PROCESS, PROCESS__SETCURRENT, NULL);
    if (error)
        return error;

    /* Obtain a SID for the context, if one was specified. */
    if (size && str[0] && str[0] != '\n') {
        if (str[size - 1] == '\n') {
            str[size - 1] = 0;
            size--;
        }
        error = maplesu_context_to_sid_live(value, size, &sid);
        if (error)
            return error;
    }

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    /* Permission checking based on the specified context is
	   performed during the actual operation (execve,
	   open/mkdir/...), when we know the full context of the
	   operation.  See selinux_bprm_creds_for_exec for the execve
	   checks and may_create for the file creation checks. The
	   operation will then fail if the context is not permitted. */
    tsec = pv_selinux_cred(new);
    error = -EINVAL;
    if (sid == 0)
        goto abort_change;

    if (!current_is_single_threaded()) {
        error = maplesu_bounded_transition(PV_FIELD(tsec, maplesu_cred_security, sid), sid);
        if (error)
            goto abort_change;
    }

    /* Check permissions for the transition. */
    error = maplesu_avc_has_perm(PV_FIELD(tsec, maplesu_cred_security, sid), sid, SECCLASS_PROCESS, PROCESS__DYNTRANSITION, NULL);
    if (error)
        goto abort_change;

    /* Check for ptracing, and update the task SID if ok.
        Otherwise, leave SID unchanged and fail. */
    ptsid = view_ptrace_parent_sid();
    if (ptsid != 0) {
        error = maplesu_avc_has_perm(ptsid, sid, SECCLASS_PROCESS, PROCESS__PTRACE, NULL);
        if (error)
            goto abort_change;
    }

    PV_FIELD(tsec, maplesu_cred_security, sid) = sid;

    commit_creds(new);
    return size;

abort_change:
    abort_creds(new);
    return error;
}

int maplesu_policy_view_setprocattr(const char *name, void *value, size_t size)
{
    int result;

    maplesu_policy_query_begin();
    result = view_setprocattr(name, value, size);
    maplesu_policy_query_end();
    return result;
}

