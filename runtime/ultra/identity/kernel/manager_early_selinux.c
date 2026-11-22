// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include "manager_early_selinux.h"
#include "manager_deployment_namespace.h"

/* These callbacks are supplied by the same authenticated HOST factory. They are
 * intentionally narrow: no arbitrary address, caller pointer, or generic EXEC. */
/* HOST owns this registration; a null backend is a hard failure, never success. */
extern int msu_early_selinux_host_backend(const maplesu_host_instance *,
    const struct msu_deployment_namespace_record *, struct msu_early_selinux_native *);

static DEFINE_MUTEX(msu_early_selinux_lock);
static struct {
    maplesu_host_instance host;
    unsigned char generation[16];
    struct msu_early_selinux_native native;
    bool initialized, qualified, prepared, enabled, closed, discarded, retiring;
    u32 inflight;
    unsigned long selinux_state, setenforce, policyload;
} state;

static int invalid_result(struct msu_early_selinux_result *r, int e)
{
    if (r) { memset(r, 0, sizeof(*r)); r->native_errno = e < 0 ? -e : e; }
    return e < 0 ? e : -EIO;
}
static int check_status(const struct msu_early_selinux_result *r)
{
    if (!r || r->native_errno < 0 || r->native_errno > 4095 || r->code > 0 ||
        (r->effects & ~(MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_RELEASED |
            MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_QUARANTINED |
            MAPLESU_EFFECT_WRITTEN | MAPLESU_EFFECT_TEXT_ATTEMPTED |
            MAPLESU_EFFECT_PUBLICATION_PREPARED | MAPLESU_EFFECT_PUBLICATION_PUBLISHED |
            MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED |
            MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_REFERENCE_DROPPED |
            MAPLESU_EFFECT_SHARED_RETAINED))) return -EPROTO;
    return 0;
}
static u32 selinux_effects_to_fixed(u32 effects, u32 operation)
{
    u32 fixed = MSU_EARLY_FIXED_EFFECT_ATTEMPTED;
    if (effects & MAPLESU_EFFECT_ALLOCATED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_ALLOCATED;
    if (effects & MAPLESU_EFFECT_RELEASED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_RELEASED;
    if (effects & MAPLESU_EFFECT_EXECUTED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_EXECUTED;
    if (effects & MAPLESU_EFFECT_COMMITTED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_COMMITTED;
    if (effects & MAPLESU_EFFECT_QUARANTINED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_QUARANTINED;
    if (effects & MAPLESU_EFFECT_WRITTEN) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_WRITTEN;
    if (effects & MAPLESU_EFFECT_TEXT_ATTEMPTED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_TEXT_ATTEMPTED;
    if (effects & MAPLESU_EFFECT_PUBLICATION_PREPARED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_PUBLICATION_PREPARED;
    if (effects & MAPLESU_EFFECT_PUBLICATION_PUBLISHED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_PUBLICATION_PUBLISHED;
    if (effects & MAPLESU_EFFECT_PUBLICATION_RETAINED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_PUBLICATION_RETAINED;
    if (effects & MAPLESU_EFFECT_GATE_PINNED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_GATE_PINNED;
    if (effects & MAPLESU_EFFECT_PENDING) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_PENDING | MSU_EARLY_FIXED_EFFECT_PENDING;
    if (effects & MAPLESU_EFFECT_REFERENCE_DROPPED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_REFERENCE_DROPPED;
    if (effects & MAPLESU_EFFECT_SHARED_RETAINED) fixed |= MAPLESU_EARLY_FIXED_EFFECT_SELINUX_SHARED_RETAINED;
    if (effects & (MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_WRITTEN |
            MAPLESU_EFFECT_PUBLICATION_PUBLISHED)) fixed |= MSU_EARLY_FIXED_EFFECT_APPLIED;
    if (operation == MSU_EARLY_SELINUX_READ_STATUS) fixed |= MSU_EARLY_FIXED_EFFECT_READBACK;
    if (effects & MAPLESU_EFFECT_RELEASED) fixed |= MSU_EARLY_FIXED_EFFECT_RELEASED;
    if (effects & MAPLESU_EFFECT_QUARANTINED) fixed |= MSU_EARLY_FIXED_EFFECT_QUARANTINED;
    return fixed;
}
struct selinux_state;
static void fixed_setenforce_prototype(int value) { (void)value; }
static void fixed_policyload_prototype(u32 sequence) { (void)sequence; }
static void fixed_setenforce_state_prototype(struct selinux_state *s, int value) { (void)s; (void)value; }
static void fixed_policyload_state_prototype(struct selinux_state *s, u32 sequence) { (void)s; (void)sequence; }
static int qualify_status_target(const struct msu_early_selinux_bind *bind,
    const char *name, const void *global, const void *with_state, unsigned long target)
{
    unsigned long cfi = 0;
    int error = bind->resolve_cfi(name, global, &cfi);
    if (!error && cfi == target) return 0;
    cfi = 0;
    error = bind->resolve_cfi(name, with_state, &cfi);
    return error ? error : (!cfi || cfi != target ? -ESTALE : 0);
}
int msu_early_selinux_target_bind(const struct msu_early_selinux_bind *bind)
{
    unsigned long state_addr, set_addr, policy_addr;
    if (!bind || !bind->lookup || !bind->resolve_cfi) return -EINVAL;
    state_addr = bind->lookup("selinux_state");
    set_addr = bind->lookup("selinux_status_update_setenforce");
    policy_addr = bind->lookup("selinux_status_update_policyload");
    if (!state_addr || !set_addr || !policy_addr || (state_addr & 3) || (set_addr & 3) || (policy_addr & 3)) return -ENOENT;
    if (qualify_status_target(bind, "selinux_status_update_setenforce",
        (const void *)fixed_setenforce_prototype, (const void *)fixed_setenforce_state_prototype, set_addr) ||
        qualify_status_target(bind, "selinux_status_update_policyload",
        (const void *)fixed_policyload_prototype, (const void *)fixed_policyload_state_prototype, policy_addr)) return -ESTALE;
    mutex_lock(&msu_early_selinux_lock);
    if (state.initialized && !state.discarded) { mutex_unlock(&msu_early_selinux_lock); return -EALREADY; }
    state.selinux_state = state_addr; state.setenforce = set_addr; state.policyload = policy_addr;
    state.qualified = true;
    mutex_unlock(&msu_early_selinux_lock);
    return 0;
}
static bool selinux_fixed_validate(const struct msu_early_fixed_provider *provider)
{
    bool valid;
    if (!provider || !provider->generation_valid || provider->owner != &state) return false;
    mutex_lock(&msu_early_selinux_lock);
    valid = state.initialized && state.qualified && !state.closed &&
        !state.retiring && !state.discarded && state.selinux_state &&
        state.setenforce && state.policyload &&
        state.host.low == provider->host.low && state.host.high == provider->host.high &&
        !memcmp(state.generation, provider->generation, sizeof(state.generation));
    mutex_unlock(&msu_early_selinux_lock);
    return valid;
}
static int selinux_fixed_operation(struct msu_early_fixed_provider *provider, u32 operation,
    u32 mode, u32 exploit, u64 value, struct msu_early_fixed_result *result)
{
    struct msu_early_selinux_result r = {};
    int e;
    (void)provider;
    e = msu_early_selinux_operation(operation, mode, exploit, value, &r);
    if (result) {
        result->code = r.code;
        result->native_errno = r.native_errno;
        result->effects = selinux_effects_to_fixed(r.effects, operation);
        memcpy(result->values, r.values, sizeof(r.values));
    }
    return e;
}
static int selinux_fixed_revoke(struct msu_early_fixed_provider *provider,
    const unsigned char generation[16], u32 *effects)
{
    return msu_early_selinux_revoke(&provider->host, generation, effects);
}
static int selinux_fixed_close(struct msu_early_fixed_provider *provider, u32 *effects)
{
    int e = msu_early_selinux_close();
    if (effects) *effects |= e ? MAPLESU_EFFECT_PENDING : MAPLESU_EFFECT_RELEASED;
    return e;
}
static struct msu_early_fixed_provider selinux_fixed_provider;

int msu_early_selinux_init(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment)
{
    struct msu_early_selinux_native native = {0};
    int e;
    if (!host || !(host->low | host->high) || !msu_deployment_namespace_valid(deployment)) return -EINVAL;
    mutex_lock(&msu_early_selinux_lock);
    if (state.initialized && (!state.discarded || state.inflight)) { mutex_unlock(&msu_early_selinux_lock); return -EALREADY; }
    if (!state.qualified || !state.selinux_state || !state.setenforce || !state.policyload) { mutex_unlock(&msu_early_selinux_lock); return -EOPNOTSUPP; }
    mutex_unlock(&msu_early_selinux_lock);
    /* HOST backend construction may acquire registry/service locks; never call it
     * while holding this provider lock. */
    e = msu_early_selinux_host_backend(host, deployment, &native);
    if (e || !native.prepare || !native.enable || !native.read_status ||
        !native.write_sequence || !native.revoke || !native.close || !native.ctx ||
        !native.generation) return e ? e : -EOPNOTSUPP;
    { u32 i; bool any = false; for (i = 0; i < sizeof(state.generation); ++i) any |= native.generation[i] != 0;
      if (!any) return -ESTALE; }
    mutex_lock(&msu_early_selinux_lock);
    if (state.initialized && (!state.discarded || state.inflight)) { mutex_unlock(&msu_early_selinux_lock); return -EALREADY; }
    state.prepared = state.enabled = state.closed = state.discarded = state.retiring = false;
    state.host = *host; state.native = native;
    memcpy(state.generation, native.generation, sizeof(state.generation));
    state.initialized = true;
    mutex_unlock(&msu_early_selinux_lock);
    memset(&selinux_fixed_provider, 0, sizeof(selinux_fixed_provider));
    selinux_fixed_provider.host = *host;
    memcpy(selinux_fixed_provider.generation, state.generation, 16);
    selinux_fixed_provider.generation_valid = true;
    selinux_fixed_provider.owner = &state;
    selinux_fixed_provider.deployment = deployment;
    selinux_fixed_provider.validate = selinux_fixed_validate;
    selinux_fixed_provider.operation = selinux_fixed_operation;
    selinux_fixed_provider.revoke = selinux_fixed_revoke;
    selinux_fixed_provider.close = selinux_fixed_close;
    e = msu_early_fixed_provider_register(MSU_EARLY_FIXED_SELINUX_PREPARE,
        MSU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE, &selinux_fixed_provider);
    if (e) (void)msu_early_selinux_close();
    return e;
}
int msu_early_selinux_operation(u32 operation, u32 mode, u32 exploit, u64 value,
    struct msu_early_selinux_result *result)
{
    struct msu_early_selinux_native native;
    bool prepare = false;
    int e;
    if (!result) return -EINVAL;
    memset(result, 0, sizeof(*result));
    if (operation < MSU_EARLY_SELINUX_PREPARE || operation > MSU_EARLY_SELINUX_WRITE_SEQUENCE)
        return invalid_result(result, -EINVAL);
    if (mode > 3 || exploit > 0xffffU ||
        (operation == MSU_EARLY_SELINUX_WRITE_SEQUENCE && value > 0xffffffffULL))
        return invalid_result(result, -EINVAL);
    mutex_lock(&msu_early_selinux_lock);
    if (!state.initialized || !state.qualified) e = -EAGAIN;
    else if (state.closed || state.discarded) e = -ESHUTDOWN;
    else if (operation == MSU_EARLY_SELINUX_PREPARE && state.prepared) e = -EALREADY;
    else if (operation != MSU_EARLY_SELINUX_PREPARE && !state.prepared) e = -EPERM;
    else {
        native = state.native; ++state.inflight; prepare = operation == MSU_EARLY_SELINUX_PREPARE; e = 0;
    }
    mutex_unlock(&msu_early_selinux_lock);
    if (e) return invalid_result(result, e);
    /* No provider callback is executed under the registry/state mutex. */
    if (operation == MSU_EARLY_SELINUX_PREPARE)
        e = native.prepare(native.ctx, mode, exploit, result);
    else if (operation == MSU_EARLY_SELINUX_ENABLE)
        e = native.enable(native.ctx, result);
    else if (operation == MSU_EARLY_SELINUX_READ_STATUS)
        e = native.read_status(native.ctx, result);
    else
        e = native.write_sequence(native.ctx, (u32)value, result);
    if (e && !result->native_errno) result->native_errno = e < 0 ? -e : e;
    if (!e && check_status(result)) e = -EPROTO;
    if (e && !result->native_errno) result->native_errno = e < 0 ? -e : e;
    mutex_lock(&msu_early_selinux_lock);
    if (state.inflight) --state.inflight;
    if (!e && prepare) state.prepared = true;
    if (!e && operation == MSU_EARLY_SELINUX_ENABLE) state.enabled = true;
    mutex_unlock(&msu_early_selinux_lock);
    return e;
}
int msu_early_selinux_revoke(const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects)
{
    struct msu_early_selinux_native native;
    int e;
    if (!host || !generation || !effects) return -EINVAL;
    mutex_lock(&msu_early_selinux_lock);
    if (!state.initialized || state.host.low != host->low || state.host.high != host->high ||
        memcmp(state.generation, generation, 16)) { mutex_unlock(&msu_early_selinux_lock); return -ESTALE; }
    if (state.discarded) { mutex_unlock(&msu_early_selinux_lock); return 0; }
    state.closed = true; state.retiring = true; native = state.native;
    mutex_unlock(&msu_early_selinux_lock);
    e = native.revoke(native.ctx, effects);
    mutex_lock(&msu_early_selinux_lock);
    if (state.inflight && !e) e = -EINPROGRESS;
    if (!e && !(*effects & (MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED))) {
        state.retiring = false; state.discarded = true;
    } else if (!e) e = -EINPROGRESS;
    mutex_unlock(&msu_early_selinux_lock);
    return e;
}
int msu_early_selinux_close(void)
{
    struct msu_early_selinux_native native;
    int e;
    mutex_lock(&msu_early_selinux_lock);
    if (!state.initialized) { mutex_unlock(&msu_early_selinux_lock); return 0; }
    if (state.discarded) { mutex_unlock(&msu_early_selinux_lock); return 0; }
    state.closed = true; native = state.native;
    mutex_unlock(&msu_early_selinux_lock);
    e = native.close(native.ctx);
    mutex_lock(&msu_early_selinux_lock);
    if (state.inflight && !e) e = -EINPROGRESS;
    if (!e) { state.retiring = false; state.discarded = true; }
    mutex_unlock(&msu_early_selinux_lock);
    return e;
}
int msu_early_selinux_discarded(void)
{
    int e;
    mutex_lock(&msu_early_selinux_lock);
    e = !state.initialized || (state.discarded && !state.inflight) ? 0 : -EINPROGRESS;
    mutex_unlock(&msu_early_selinux_lock);
    return e;
}
