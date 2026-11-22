// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_PROFILE_NAMESPACE_H
#define MAPLESU_SU_PROFILE_NAMESPACE_H

#include <linux/types.h>

struct msu_su_lease;

#define MSU_SU_NS_NATIVE_LAYOUT_WORDS 31U
extern const unsigned long msu_su_namespace_native_layout[MSU_SU_NS_NATIVE_LAYOUT_WORDS];

/* Kernel-private receipt; no wire bits or credential effects are redefined.
 * APPLIED means the native setns/unshare succeeded, even for the same namespace.
 * CHANGED compares held mount namespace objects, independently of later errors. */
#define MSU_SU_NS_APPLIED       (1U << 0)
#define MSU_SU_NS_CHANGED       (1U << 1)
#define MSU_SU_NS_CWD_RESTORED  (1U << 2)
#define MSU_SU_NS_ROOT_PRIVATE  (1U << 3)
#define MSU_SU_NS_COMPLETED     (1U << 4)

struct msu_su_namespace_receipt {
    int mode;
    u32 effects;
    int error;
    int operation_error;
    int close_error;
    int cwd_error;
    int validation_error;
};

/* Mode 0 needs no native namespace qualification. Modes 1/2 default to
 * -EOPNOTSUPP. P2 must prove this target's imports, data objects, native
 * layouts/CFI and sleeping current-task context before setting
 * MSU_SU_NAMESPACE_NATIVE_VERIFIED. A macro or reference compile is not proof. */
int msu_su_profile_namespace_supported(int mode);

/* Consume only the Profile pinned by this already admitted/adopted lease.
 * Call after CORE credential/task stages, on the same current task. Validate
 * immediately before native override_creds(&init_cred), and after revert.
 * Mode 1 needs a private FD table; shared CLONE_FILES returns -EBUSY before
 * mutation. Native setns enforces the fs_struct sharing restrictions itself.
 * All native errors survive; the first error wins, later errors remain in the
 * receipt. Namespace effects are never rolled back or erased by failure.
 * No prepare/commit, lease begin/end, credential adoption or automatic retry.
 * The parent retains its credential effects and ends the lease only after all
 * post-stages/cleanup have returned. This receipt is not an authorization. */
int msu_su_profile_namespace_apply_held(struct msu_su_lease *lease,
    struct msu_su_namespace_receipt *receipt);

#endif
