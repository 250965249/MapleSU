// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_SELINUX_H
#define MAPLESU_MANAGER_EARLY_SELINUX_H
#include <linux/types.h>
#include "request_protocol.h"
#include "manager_early_fixed.h"

struct msu_deployment_namespace_record;

/* Fixed EarlyHelper SELinux business, separate from generic management RW/EXEC. */
enum msu_early_selinux_operation {
    MSU_EARLY_SELINUX_PREPARE = 5,
    MSU_EARLY_SELINUX_ENABLE = 6,
    MSU_EARLY_SELINUX_READ_STATUS = 7,
    MSU_EARLY_SELINUX_WRITE_SEQUENCE = 8,
};
struct msu_early_selinux_result {
    s64 code;              /* original KModErr/business code, zero on success */
    s32 native_errno;      /* transport/native errno, zero when none */
    u32 effects;           /* real publication/store/readback effects */
    u64 values[3];         /* status: {version,sequence}, {enforcing,policyload}, deny_unknown */
};
struct msu_early_selinux_bind {
    unsigned long (*lookup)(const char *name);
    int (*resolve_cfi)(const char *name, const void *prototype, unsigned long *address);
};
struct msu_early_selinux_native {
    int (*prepare)(void *ctx, u32 mode, u32 exploit, struct msu_early_selinux_result *r);
    int (*enable)(void *ctx, struct msu_early_selinux_result *r);
    int (*read_status)(void *ctx, struct msu_early_selinux_result *r);
    int (*write_sequence)(void *ctx, u32 sequence, struct msu_early_selinux_result *r);
    int (*revoke)(void *ctx, u32 *effects);
    int (*close)(void *ctx);
    void *ctx;
    const unsigned char *generation;
};
int msu_early_selinux_host_backend(const maplesu_host_instance *,
    const struct msu_deployment_namespace_record *, struct msu_early_selinux_native *);
/* Boot-owned fixed target qualification. No user pointer or generic EXEC. */
int msu_early_selinux_target_bind(const struct msu_early_selinux_bind *bind);
int msu_early_selinux_init(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment);
/* mode is bounded exploit/install selector; value is only used by WRITE_SEQUENCE. */
int msu_early_selinux_operation(u32 operation, u32 mode, u32 exploit, u64 value,
    struct msu_early_selinux_result *result);
/* Revoke closes admission first and reports pending until publication readers and
 * target/actor callbacks have drained. It never clears a committed effect. */
int msu_early_selinux_revoke(const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects);
int msu_early_selinux_close(void);
int msu_early_selinux_discarded(void);
#endif
