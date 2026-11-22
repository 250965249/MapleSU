// SPDX-License-Identifier: GPL-2.0-only
#ifndef MAPLESU_MANAGER_EARLY_OEM_H
#define MAPLESU_MANAGER_EARLY_OEM_H

#include <linux/types.h>
#include "request_protocol.h"
#include "manager_early_fixed.h"

/* The provider is a HOST-owned fixed business domain.  It is deliberately
 * separate from EARLY_HELPER's task-only service and never accepts a pointer
 * or a generic helper command. */
int msu_early_oem_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *));
int msu_early_oem_init(const maplesu_host_instance *host, const void *deployment,
    const unsigned char generation[16]);
int msu_early_oem_operation(u32 operation, u32 mode, u32 exploit, u64 value,
    struct msu_early_fixed_result *result);
int msu_early_oem_revoke(void *context, const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects);
int msu_early_oem_close(u32 *effects);
int msu_early_oem_discarded(void);

#endif
