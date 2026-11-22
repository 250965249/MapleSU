#ifndef MAPLESU_LEGACY_HOOK_PRIVATE_H
#define MAPLESU_LEGACY_HOOK_PRIVATE_H

#include "request_protocol.h"

/* Same-generation kernel-only bridge. Public v2 length and capabilities stay
 * unchanged. Only the real Key-authenticated EXEC producer opens a scope. */
#define MAPLESU_LEGACY_HOOK_MAGIC UINT64_C(0x314b484c55534d)
#define MAPLESU_LEGACY_HOOK_SCHEMA 1u
#define MAPLESU_LEGACY_HOOK_METADATA_MAGIC UINT32_C(0x35484c4d)
/* Optional Key/v2 QUERY selector. The immutable v2 descriptor keeps its original
 * capability set; only this response reports the real provider's P4 services. */
#define MAPLESU_KEY_CREDENTIAL_QUERY (MAPLESU_CAP_CREDENTIAL | MAPLESU_CAP_PROCATTR | MAPLESU_CAP_TASK_STATE)

struct maplesu_legacy_hook_provider {
    uint64_t magic;
    uint32_t schema;
    uint32_t length;
    maplesu_host_instance host;
    uint64_t capabilities;
    uint64_t bind_function;     /* u64 bind(u64 gateway_base, u64 gateway_bytes) */
    uint64_t begin_function;    /* u64 begin(u64 gateway_token) */
    uint64_t end_function;      /* int end(u64 scope) */
    uint64_t dispatch_function; /* int dispatch(u64 scope, u32 command,
                                * const management_v3 *, response_owner_v3 *) */
};

struct maplesu_legacy_hook_metadata_private {
    uint32_t magic;
    uint16_t schema;
    uint16_t length;
    int64_t provider_get_displacement;
    int64_t provider_put_displacement;
};

#ifdef __cplusplus
static_assert(sizeof(maplesu_legacy_hook_provider) == 72, "legacy provider ABI");
static_assert(sizeof(maplesu_legacy_hook_metadata_private) == 24, "legacy metadata ABI");
#else
_Static_assert(sizeof(struct maplesu_legacy_hook_provider) == 72, "legacy provider ABI");
_Static_assert(sizeof(struct maplesu_legacy_hook_metadata_private) == 24, "legacy metadata ABI");
#endif

#ifdef __KERNEL__
void maplesu_legacy_uid_rcu_lock(void);
void maplesu_legacy_uid_rcu_unlock(void);
int maplesu_legacy_uid_synchronize_rcu(void);
int maplesu_legacy_hook_provider_get(const struct maplesu_legacy_hook_provider **provider,
    void **lease);
void maplesu_legacy_hook_provider_put(void *lease);
int maplesu_legacy_hook_provider_register(const struct maplesu_legacy_hook_provider *provider,
    const void *owner);
int maplesu_legacy_hook_provider_unregister(const void *owner);
#endif

#endif
