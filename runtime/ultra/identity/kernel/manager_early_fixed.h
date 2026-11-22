// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_FIXED_H
#define MAPLESU_MANAGER_EARLY_FIXED_H

#include <linux/types.h>
#include "request_protocol.h"

/* Fixed EarlyHelper business operations. This is a private kernel/SDK seam;
 * command31 below carries only these bounded scalars and never a pointer. */
enum msu_early_fixed_operation {
    MSU_EARLY_FIXED_OEM_MTK = 1,
    MSU_EARLY_FIXED_OEM_OPLUS_GUARD = 2,
    MSU_EARLY_FIXED_OEM_OPLUS_INTE = 3,
    MSU_EARLY_FIXED_ROOT_ENV = 4,
    MSU_EARLY_FIXED_SELINUX_PREPARE = 5,
    MSU_EARLY_FIXED_SELINUX_ENABLE = 6,
    MSU_EARLY_FIXED_SELINUX_READ_STATUS = 7,
    MSU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE = 8,
};

#define MSU_EARLY_FIXED_RESULT_SCHEMA 1U
#define MSU_EARLY_FIXED_EFFECT_ATTEMPTED MAPLESU_EARLY_FIXED_EFFECT_ATTEMPTED
#define MSU_EARLY_FIXED_EFFECT_APPLIED MAPLESU_EARLY_FIXED_EFFECT_APPLIED
#define MSU_EARLY_FIXED_EFFECT_READBACK MAPLESU_EARLY_FIXED_EFFECT_READBACK
#define MSU_EARLY_FIXED_EFFECT_PENDING MAPLESU_EARLY_FIXED_EFFECT_PENDING
#define MSU_EARLY_FIXED_EFFECT_RELEASED MAPLESU_EARLY_FIXED_EFFECT_RELEASED
#define MSU_EARLY_FIXED_EFFECT_QUARANTINED MAPLESU_EARLY_FIXED_EFFECT_QUARANTINED
#define MSU_EARLY_FIXED_MAX_VALUES 3U

struct msu_early_fixed_result {
    s64 code;                 /* original module/KModErr code, not transport */
    s32 native_errno;         /* raw host/provider errno, 0 when none */
    u32 effects;              /* observed effects only; never inferred success */
    u64 values[MSU_EARLY_FIXED_MAX_VALUES];
};

struct msu_early_fixed_provider {
    maplesu_host_instance host;
    unsigned char generation[16];
    bool generation_valid;
    const void *owner;
    const void *deployment;
    bool (*validate)(const struct msu_early_fixed_provider *provider);
    int (*operation)(struct msu_early_fixed_provider *provider, u32 operation,
                     u32 mode, u32 exploit, u64 value,
                     struct msu_early_fixed_result *result);
    int (*revoke)(struct msu_early_fixed_provider *provider,
                  const unsigned char generation[16], u32 *effects);
    int (*close)(struct msu_early_fixed_provider *provider, u32 *effects);
};

/* HOST installs one provider per domain after the authenticated installation
 * lease exists. A provider is never a generic helper service or an EXEC grant.
 * Registration rejects duplicate owners and stale host/deployment bindings. */
int msu_early_fixed_provider_register(u32 operation_first, u32 operation_last,
                                      struct msu_early_fixed_provider *provider);
int msu_early_fixed_provider_unregister(u32 operation_first, u32 operation_last,
                                        const void *owner, u32 *effects);
int msu_early_fixed_provider_call(const maplesu_host_instance *host, u32 operation,
                                  u32 mode, u32 exploit, u64 value,
                                  struct msu_early_fixed_result *result);
int msu_early_fixed_provider_revoke(const maplesu_host_instance *host,
                                    const unsigned char generation[16], u32 *effects);

/* Command31 uses management64 with operation in address, mode/exploit/value in
 * bounded fields; the authenticated helper service remains task-only. */
/* The included request_protocol.h owns command and scalar limits. */

#endif
