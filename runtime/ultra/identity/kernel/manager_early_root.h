// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_ROOT_H
#define MAPLESU_MANAGER_EARLY_ROOT_H

#include <linux/types.h>
#include <linux/mutex.h>
#include "manager_deployment_namespace.h"
#include "request_protocol.h"
#include "manager_early_fixed.h"

/* m070 fixed root-environment operation. This is a private HOST contract;
 * no request opcode or generic helper authority is added. */
#define MSU_EARLY_ROOT_OPERATION_ROOT_ENV 4U
#define MSU_EARLY_ROOT_MODE_MAX 3U
#define MSU_EARLY_ROOT_EFFECT_PRECHECK      (1U << 0)
#define MSU_EARLY_ROOT_EFFECT_AVC           (1U << 1)
#define MSU_EARLY_ROOT_EFFECT_FILLDIR       (1U << 2)
#define MSU_EARLY_ROOT_EFFECT_COMPAT       (1U << 3)
#define MSU_EARLY_ROOT_EFFECT_HBT           (1U << 4)
#define MSU_EARLY_ROOT_EFFECT_ITERATE      (1U << 5)
#define MSU_EARLY_ROOT_EFFECT_AUDIT         (1U << 6)
#define MSU_EARLY_ROOT_EFFECT_REVOKE        (1U << 7)
#define MSU_EARLY_ROOT_EFFECT_PENDING       (1U << 8)
#define MSU_EARLY_ROOT_EFFECT_QUARANTINED   (1U << 9)
#define MSU_EARLY_ROOT_EFFECT_CLOSED        (1U << 10)

#define MSU_EARLY_ROOT_TARGET_AVC       1U
#define MSU_EARLY_ROOT_TARGET_FILLDIR   2U
#define MSU_EARLY_ROOT_TARGET_COMPAT    3U
#define MSU_EARLY_ROOT_TARGET_HBT       4U
#define MSU_EARLY_ROOT_TARGET_ITERATE   5U
#define MSU_EARLY_ROOT_TARGET_AUDIT     6U

struct msu_early_root_result {
    s64 code;             /* stable KModErr / protocol code */
    s32 native_errno;     /* errno from the first failed native operation */
    u32 effects;          /* only observed effects; never inferred success */
    u64 value;            /* opaque publication/actor value, when supplied */
};

/* Callbacks are supplied by the boot-live native producer. They are not user
 * pointers and are held only for this installation generation. The provider
 * never obtains a generic read/write/execute primitive. */
struct msu_early_root_ops {
    void *context;
    int (*resolve)(void *context, const char *name, u32 match_mode, u64 *address);
    int (*read_word)(void *context, u64 address, u32 *word);
    int (*credential_precheck)(void *context, u32 mode, u32 exploit);
    int (*patch)(void *context, u32 target, const u64 *addresses,
                 u32 address_count, const char *const *hide_names, u32 hide_count,
                 u64 *value);
    int (*revoke)(void *context, u32 *effects);
    int (*discarded)(void *context);
};

struct msu_early_root_provider {
    struct mutex lock;
    maplesu_host_instance host;
    struct msu_deployment_namespace_record deployment;
    struct msu_early_root_ops ops;
    unsigned char generation[16];
    u32 generation_valid;
    u32 effects;
    u32 lifecycle_effects;
    int last_error;
    bool initialized;
    bool closed;
    bool active;
    bool revoked;
    bool quarantined;
};

int msu_early_root_provider_init(struct msu_early_root_provider *provider,
    const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16],
    const struct msu_early_root_ops *ops);
int msu_early_root_provider_bind(struct msu_early_root_provider *provider,
    const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16],
    const struct msu_early_root_ops *ops);
int msu_early_root_operation(struct msu_early_root_provider *provider,
    u32 operation, u32 mode, u32 exploit, u64 value,
    const unsigned char generation[16],
    const char *const *hide_names, u32 hide_count,
    struct msu_early_root_result *result);
/* Command-31 adapter: uses the generation captured at bind; external callers
 * cannot substitute another generation. */
int msu_early_root_operation_bound(struct msu_early_root_provider *provider,
    u32 operation, u32 mode, u32 exploit, u64 value,
    const char *const *hide_names, u32 hide_count,
    struct msu_early_root_result *result);
int msu_early_root_provider_revoke(struct msu_early_root_provider *provider,
    const maplesu_host_instance *host, const unsigned char generation[16],
    u32 *effects);
int msu_early_root_provider_close(struct msu_early_root_provider *provider,
    u32 *effects);
int msu_early_root_provider_discarded(struct msu_early_root_provider *provider);

#endif
