// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_DURABLE_AUTHORITY_H
#define MAPLESU_SU_DURABLE_AUTHORITY_H
#include "su_observed_install_source.h"
/* Consumes no disk state at early boot. Successful creation returns one actual
 * source reference; observed_create consumes it only on success. */
int msu_su_durable_authority_create(const unsigned char name[16],
    struct msu_su_observed_authority *authority);
/* Reads existing protected bin/journal authority or the historical SDK format.
 * Errors leave outputs unchanged. No I/O occurs in the native SU read path. */
int msu_su_durable_authority_load(const struct msu_su_observed_authority *authority,
    u32 *uids, u32 capacity, u32 *count);
#endif
