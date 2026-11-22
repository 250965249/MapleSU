// SPDX-License-Identifier: GPL-3.0-only
/* Derived from KernelSU 730f644615969cfd4a84b45d7f62a667b7b95a50,
 * kernel/feature/selinux_hide.c. Retries are bounded for Ultra's independent reloaders. */
#include "policy_view_internal.h"

int maplesu_context_to_sid(const char *scontext, u32 scontext_len, u32 *sid, u32 *orig_sid_p, int *orig_rc_p)
{
    struct selinux_policy *policy = maplesu_view.policy, *orig_policy;
    unsigned int retries = 0;
    struct policydb *policydb, *orig_policydb;
    struct sidtab *sidtab, *orig_sidtab;
    char *scontext2;
    struct context context, orig_context;
    int rc = 0, orig_rc = -EINVAL;
    u32 orig_sid;

    /* An empty security context is never valid. */
    if (!scontext_len)
        return -EINVAL;

    /* Copy the string to allow changes and ensure a NUL terminator */
    scontext2 = kmemdup_nul(scontext, scontext_len, GFP_KERNEL);
    if (!scontext2)
        return -ENOMEM;

    // removed: if (!selinux_initialized())
    *sid = SECSID_NULL;
    if (orig_sid_p)
        *orig_sid_p = SECSID_NULL;

    // removed: if (force)
retry:
    rcu_read_lock();
    policydb = &PV_FIELD(policy, selinux_policy, policydb);
    sidtab = PV_FIELD(policy, selinux_policy, sidtab);
    orig_policy = rcu_dereference(PV_FIELD(&selinux_state, selinux_state, policy));
    if (!orig_policy) {
        rc = orig_rc = -EAGAIN;
        goto out_unlock;
    }
    orig_policydb = &PV_FIELD(orig_policy, selinux_policy, policydb);
    orig_sidtab = PV_FIELD(orig_policy, selinux_policy, sidtab);

    // parse both policies together
    orig_rc = -EINVAL;
    rc = maplesu_context_parse(policydb, orig_policydb, sidtab, orig_sidtab, scontext2, scontext, scontext_len,
                                  &context, &orig_context, PV_FIELD(orig_policy, selinux_policy, latest_granting), SECSID_NULL, &orig_rc);
    if (rc)
        goto out_unlock;

    // update backup sidtab first
    rc = sidtab_context_to_sid(sidtab, &context, sid);
    context_destroy(&context);
    if (rc) {
        if (!orig_rc)
            context_destroy(&orig_context);
        // backup sidtab is not reloaded
        orig_rc = rc;
        goto out_unlock;
    }

    if (orig_rc)
        goto out_unlock;

    // only sync valid contexts
    // sync to live sidtab
    orig_rc = sidtab_context_to_sid(orig_sidtab, &orig_context, &orig_sid);
    context_destroy(&orig_context);
    if (!orig_rc && orig_sid_p)
        *orig_sid_p = orig_sid;
    if (orig_rc == -ESTALE && ++retries < 4) {
        // retry after live policy reload
        rcu_read_unlock();
        memcpy(scontext2, scontext, scontext_len);
        scontext2[scontext_len] = '\0';
        goto retry;
    }
out_unlock:
    rcu_read_unlock();
    if (orig_rc_p)
        *orig_rc_p = orig_rc;
    kfree(scontext2);
    return rc;
}

int maplesu_context_to_sid_live(const char *text, u32 length, u32 *sid)
{
    struct selinux_policy *policy = maplesu_view.policy, *live;
    struct context context;
    char *copy;
    unsigned int retries = 0;
    u32 backup_sid;
    int rc;
    bool fallback = false;

    if (!length)
        return -EINVAL;
    copy = kmemdup_nul(text, length, GFP_KERNEL);
    if (!copy)
        return -ENOMEM;
    *sid = SECSID_NULL;
retry:
    rcu_read_lock();
    live = rcu_dereference(PV_FIELD(&selinux_state, selinux_state, policy));
    if (!live) {
        rc = -EAGAIN;
        goto out_unlock;
    }
    rc = maplesu_context_parse_live(&PV_FIELD(policy, selinux_policy, policydb),
        &PV_FIELD(live, selinux_policy, policydb), PV_FIELD(policy, selinux_policy, sidtab),
        copy, &context, PV_FIELD(live, selinux_policy, latest_granting));
    fallback = rc == -EAGAIN;
    if (rc)
        goto out_unlock;
    rc = sidtab_context_to_sid(PV_FIELD(policy, selinux_policy, sidtab), &context, &backup_sid);
    if (!rc)
        rc = sidtab_context_to_sid(PV_FIELD(live, selinux_policy, sidtab), &context, sid);
    context_destroy(&context);
    if (rc == -ESTALE && ++retries < 4) {
        rcu_read_unlock();
        memcpy(copy, text, length);
        copy[length] = '\0';
        goto retry;
    }
out_unlock:
    rcu_read_unlock();
    kfree(copy);
    if (fallback) {
        int live_rc;

        rc = maplesu_context_to_sid(text, length, &backup_sid, sid, &live_rc);
        return rc ?: live_rc;
    }
    return rc;
}


