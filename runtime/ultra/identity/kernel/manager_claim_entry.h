// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_CLAIM_ENTRY_H
#define MAPLESU_MANAGER_CLAIM_ENTRY_H

#include "manager_claim_abi.h"
#include "manager_apk_identity.h"

#define MSU_MANAGER_CLAIM_BOOT_VERSION 1U

/* Retained read-only boot state, supplied only by the bound kernel entry.
 * The request never contains this object or a pointer to it. */
struct msu_manager_claim_boot_policy {
    msu_apk_u32 version;
    msu_apk_u32 reserved;
    const char *credential;
};

_Static_assert(sizeof(struct msu_manager_claim_boot_policy) == 16,
               "claim boot policy layout");

/* Must run synchronously as the real app caller. name is the kernel-owned
 * struct filename name, not a userspace pointer. Returns 1 only after delivery;
 * the exec hook continues its original path regardless of this result. */
int msu_manager_claim_entry(const struct msu_manager_claim_boot_policy *boot,
                            const char *name);

#endif
