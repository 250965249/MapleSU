// SPDX-License-Identifier: GPL-3.0-only
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include "su_profile_apply.h"
#include "su_profile_namespace.h"
#include "su_install_registry.h"
#include "manager_credential_profile.h"
#include "manager_task_state.h"
#include "manager_dynamic_layout.h"

struct msu_su_profile_execution {
    struct msu_su_lease *lease;
    const struct cred *before;
    u32 *effects;
    bool adopted;
};

static int msu_su_profile_normalize(const struct msu_su_profile *profile,
    struct msu_credential_profile *normalized)
{
    size_t domain_bytes;
    int error;
    if (!profile) return -EINVAL;
    if (profile->use_default ||
        profile->template_name[0] || profile->non_root || profile->umount_modules)
        return -EOPNOTSUPP;
    error = msu_task_profile_flags_supported(profile->flags);
    if (error) return error;
    error = msu_su_profile_namespace_supported(profile->namespace_mode);
    if (error) return error;
    if (profile->groups_count > MSU_SU_PROFILE_GROUPS ||
        profile->groups_count > MSU_CRED_PROFILE_MAX_GROUPS) return -EINVAL;
    domain_bytes = strnlen(profile->selinux_domain, sizeof(profile->selinux_domain));
    if (domain_bytes == sizeof(profile->selinux_domain) ||
        domain_bytes >= sizeof(normalized->selinux_domain)) return -EINVAL;
    memset(normalized, 0, sizeof(*normalized));
    normalized->uid = profile->uid;
    normalized->gid = profile->gid;
    /* KSU's {0} singleton selects its root supplementary group set.  Keep
     * the sentinel in the shared credential input; collapsing it to an empty
     * list changes the committed group_info semantics. */
    normalized->groups_count = profile->groups_count;
    memcpy(normalized->groups, profile->groups,
        (size_t)normalized->groups_count * sizeof(profile->groups[0]));
    memcpy(normalized->selinux_domain, profile->selinux_domain, domain_bytes + 1);
    normalized->replace_ids = normalized->replace_groups = normalized->clear_securebits = true;
    normalized->caps.effective = normalized->caps.permitted =
        normalized->caps.bounding = profile->effective;
    normalized->cap_write_mask = MSU_CRED_CAP_EFFECTIVE |
        MSU_CRED_CAP_PERMITTED | MSU_CRED_CAP_BOUNDING;
    if (profile->uid) {
        normalized->caps.inheritable = normalized->caps.ambient = profile->effective;
        normalized->cap_write_mask |= MSU_CRED_CAP_INHERITABLE | MSU_CRED_CAP_AMBIENT;
    }
    return 0;
}

int msu_su_profile_check(const struct msu_su_profile *profile)
{
    struct msu_credential_profile normalized;
    int error = msu_su_profile_normalize(profile, &normalized);
    return error ? error : msu_credential_profile_validate(&normalized);
}

static int msu_su_profile_validate_held(void *context)
{
    struct msu_su_profile_execution *execution = context;
    return msu_task_profile_check_current(msu_su_lease_validate, execution->lease);
}

static int msu_su_profile_adopt(void *context,
    const struct cred *before, const struct cred *after)
{
    struct msu_su_profile_execution *execution = context;
    struct msu_su_lease *lease = execution->lease;
    if (execution->adopted || lease->invalidated || !before || !after || before == after ||
        current != lease->task || READ_ONCE(MSU_DYN_FIELD(current, task_struct, mm)) != lease->mm ||
        READ_ONCE(MSU_DYN_FIELD(current, task_struct, self_exec_id)) != lease->exec_id ||
        before != execution->before || before != lease->cred ||
        after != msu_dynamic_current_cred() || after != msu_dynamic_current_real_cred() ||
        !(*execution->effects & MAPLESU_EFFECT_COMMITTED)) return -ESTALE;
    lease->cred = msu_dynamic_get_cred(after);
    execution->adopted = true;
    msu_dynamic_put_cred(before);
    return 0;
}

int msu_su_profile_apply_held(struct msu_su_lease *lease, u32 *effects)
{
    struct msu_credential_profile normalized;
    struct msu_su_profile_execution execution = {0};
    int error;
    if (!effects) return -EINVAL;
    *effects = 0;
    error = msu_su_lease_validate(lease);
    if (error) return error;
    error = msu_su_profile_normalize(msu_su_lease_profile(lease), &normalized);
    if (error) return error;
    execution.lease = lease;
    execution.before = lease->cred;
    execution.effects = effects;
    error = msu_credential_replace_profile_current(&normalized,
        msu_su_profile_validate_held, msu_su_profile_adopt, &execution, effects);
    if (!execution.adopted) {
        if (*effects & MAPLESU_EFFECT_COMMITTED) lease->invalidated = true;
        if (!error) error = -ESTALE;
    }
    return error;
}
