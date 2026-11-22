// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_PROFILE_APPLY_H
#define MAPLESU_SU_PROFILE_APPLY_H
#include <linux/types.h>

struct msu_su_profile;
struct msu_su_lease;

/* Input is KSU business fields with default/template selection already
 * resolved. effective is authoritative; the four other compatibility caps
 * fields do not select five independent writes. KSU's singleton group {0}
 * selects its root supplementary group set and is passed unchanged; other
 * groups pass to CORE's sort.
 * This structure/target-support check grants no authority. Non-credential
 * stages are admitted only through their actual support checks. Unsupported
 * flags/non-root/umount and unqualified namespaces fail before commit. */
int msu_su_profile_check(const struct msu_su_profile *profile);

/* Apply only the immutable Profile owned by this already admitted lease via
 * CORE's one credential transaction. KSU f4603d14 uses effective for Prm/Eff/
 * Bset; target UID != 0 also writes Inh/Amb, while UID 0 retains them.
 * Adoption replaces only the held active cred reference after CORE's real
 * commit; the original fullUID/install/Profile authority remains unchanged.
 * COMMITTED survives all later errors. This function never ends the lease:
 * the caller holds it through its post-credential stages and then lease_end.
 * This is not a full task/seccomp/namespace/umount Profile implementation. */
int msu_su_profile_apply_held(struct msu_su_lease *lease, u32 *effects);
#endif
