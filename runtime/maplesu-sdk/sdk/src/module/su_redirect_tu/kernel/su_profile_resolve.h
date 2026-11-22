// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_PROFILE_RESOLVE_H
#define MAPLESU_SU_PROFILE_RESOLVE_H
struct msu_su_profile;

/* Pure selection of the pinned KSU f4603d14 root semantics. The input is an
 * authenticated durable policy, not a caller grant. Output may alias input.
 * The saved default/template metadata stays in the existing authority; this
 * output is only the immutable effective execution object. A template name
 * never causes a kernel JSON lookup or supplies missing concrete settings.
 * Default domain existence/support is still checked by the unique CORE. */
int msu_su_profile_resolve_root(const struct msu_su_profile *saved,
    struct msu_su_profile *effective);
#endif
