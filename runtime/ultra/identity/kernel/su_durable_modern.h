// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_DURABLE_MODERN_H
#define MAPLESU_SU_DURABLE_MODERN_H
#include "su_observed_install_source.h"
int msu_su_modern_authority_list(u32 *uids, u32 capacity, u32 *count);
/* ENODATA alone permits legacy SDK selection when the modern root is absent. */
int msu_su_modern_authority_grant(const struct msu_su_verified_install *installation,
    struct msu_su_saved_grant *grant);
#endif
