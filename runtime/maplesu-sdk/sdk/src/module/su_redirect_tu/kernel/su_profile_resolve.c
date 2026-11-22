// SPDX-License-Identifier: GPL-3.0-only
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/string.h>
#include "su_install_registry.h"
#include "su_profile_resolve.h"

int msu_su_profile_resolve_root(const struct msu_su_profile *saved,
    struct msu_su_profile *effective)
{
    struct msu_su_profile selected;
    if (!saved || !effective) return -EINVAL;
    if (saved->non_root) return -EOPNOTSUPP;
    if (!memchr(saved->template_name, 0, sizeof(saved->template_name))) return -EINVAL;
    if (saved->use_default) {
        memset(&selected, 0, sizeof(selected));
        selected.groups_count = 1;
        selected.groups[0] = 0;
#if CAP_LAST_CAP < 63
        selected.effective = (1ULL << (CAP_LAST_CAP + 1)) - 1;
#else
        selected.effective = ~0ULL;
#endif
        memcpy(selected.selinux_domain, "u:r:ksu:s0", sizeof("u:r:ksu:s0"));
    } else {
        selected = *saved;
        /* The pinned KSU Manager already copied a chosen template's concrete
         * values. Its name is metadata, not a deferred execution instruction. */
        memset(selected.template_name, 0, sizeof(selected.template_name));
        selected.use_default = false;
        /* The non-root union is dormant for an allowed root Profile. */
        selected.umount_modules = false;
    }
    *effective = selected;
    return 0;
}
