// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include "manager_early_root.h"

#define MSU_EARLY_ROOT_SYMBOL_EXACT 0U
#define MSU_EARLY_ROOT_SYMBOL_PREFIX 1U
#define MSU_EARLY_ROOT_SYMBOL_OPTIONAL 2U

static bool generation_nonzero(const unsigned char generation[16])
{
    unsigned int i;
    for (i = 0; i < 16; ++i) if (generation[i]) return true;
    return false;
}

static int root_result(struct msu_early_root_result *r, int code, int native_errno,
    u32 effects, u64 value)
{
    if (r) {
        r->code = code;
        r->native_errno = native_errno;
        r->effects = effects;
        r->value = value;
    }
    return code;
}

static int root_fail(struct msu_early_root_provider *p,
    struct msu_early_root_result *r, int code, int native_errno)
{
    p->last_error = code;
    return root_result(r, code, native_errno, p->effects, 0);
}

static int resolve_required(struct msu_early_root_provider *p, const char *name,
    u32 mode, u64 *address, struct msu_early_root_result *r)
{
    int e;
    *address = 0;
    e = p->ops.resolve(p->ops.context, name, mode, address);
    if (e) return root_fail(p, r, e, e > -4095 ? -e : 0);
    if (!*address) return root_fail(p, r, -EFAULT, EFAULT);
    return 0;
}

static int resolve_optional(struct msu_early_root_provider *p, const char *name,
    u64 *address, bool *present, struct msu_early_root_result *r)
{
    int e;
    *address = 0;
    *present = false;
    e = p->ops.resolve(p->ops.context, name, MSU_EARLY_ROOT_SYMBOL_OPTIONAL, address);
    if (e == -ENOENT) return 0;
    if (e) return root_fail(p, r, e, e > -4095 ? -e : 0);
    if (!*address) return root_fail(p, r, -EFAULT, EFAULT);
    *present = true;
    return 0;
}

static int patch_one(struct msu_early_root_provider *p, u32 target,
    const u64 *addresses, u32 count, const char *const *hide_names,
    u32 hide_count, struct msu_early_root_result *r)
{
    u64 value = 0;
    int e = p->ops.patch(p->ops.context, target, addresses, count,
        hide_names, hide_count, &value);
    if (e) return root_fail(p, r, e, e > -4095 ? -e : 0);
    switch (target) {
    case MSU_EARLY_ROOT_TARGET_AVC: p->effects |= MSU_EARLY_ROOT_EFFECT_AVC; break;
    case MSU_EARLY_ROOT_TARGET_FILLDIR: p->effects |= MSU_EARLY_ROOT_EFFECT_FILLDIR; break;
    case MSU_EARLY_ROOT_TARGET_COMPAT: p->effects |= MSU_EARLY_ROOT_EFFECT_COMPAT; break;
    case MSU_EARLY_ROOT_TARGET_HBT: p->effects |= MSU_EARLY_ROOT_EFFECT_HBT; break;
    case MSU_EARLY_ROOT_TARGET_ITERATE: p->effects |= MSU_EARLY_ROOT_EFFECT_ITERATE; break;
    case MSU_EARLY_ROOT_TARGET_AUDIT: p->effects |= MSU_EARLY_ROOT_EFFECT_AUDIT; break;
    default: return root_fail(p, r, -EINVAL, EINVAL);
    }
    if (r) r->value = value;
    return 0;
}

static int do_root_env(struct msu_early_root_provider *p, u32 mode, u32 exploit,
    bool only_print, const char *const *hide_names, u32 hide_count,
    struct msu_early_root_result *r)
{
    u64 avc, filldir, compat, hbt, iterate, audit, addresses[1];
    bool has_hbt, has_iterate;
    int e;
    if (mode > MSU_EARLY_ROOT_MODE_MAX || hide_count > 64U) return root_fail(p, r, -EINVAL, EINVAL);
    if ((hide_count && !hide_names) || !p->ops.resolve || !p->ops.read_word ||
        !p->ops.credential_precheck || !p->ops.patch) return root_fail(p, r, -ENOSYS, ENOSYS);
    e = p->ops.credential_precheck(p->ops.context, mode, exploit);
    if (e) return root_fail(p, r, e, e > -4095 ? -e : 0);
    p->effects |= MSU_EARLY_ROOT_EFFECT_PRECHECK;
    e = resolve_required(p, "avc_denied", MSU_EARLY_ROOT_SYMBOL_EXACT, &avc, r);
    if (e) return e;
    { u32 word = 0; e = p->ops.read_word(p->ops.context, avc, &word); if (e || !word) return root_fail(p, r, e ? e : -EFAULT, e ? -e : EFAULT); }
    e = resolve_required(p, "filldir64", MSU_EARLY_ROOT_SYMBOL_EXACT, &filldir, r);
    if (e) return e;
    { u32 word = 0; e = p->ops.read_word(p->ops.context, filldir, &word); if (e || !word) return root_fail(p, r, e ? e : -EFAULT, e ? -e : EFAULT); }
    e = resolve_required(p, "compat_filldir", MSU_EARLY_ROOT_SYMBOL_PREFIX, &compat, r);
    if (e) return e;
    { u32 word = 0; e = p->ops.read_word(p->ops.context, compat, &word); if (e || !word) return root_fail(p, r, e ? e : -EFAULT, e ? -e : EFAULT); }
    e = resolve_optional(p, "hbt:filldir64", &hbt, &has_hbt, r);
    if (e) return e;
    e = resolve_optional(p, "iterate_dir", &iterate, &has_iterate, r);
    if (e) return e;
    if (has_hbt) { u32 word = 0; e = p->ops.read_word(p->ops.context, hbt, &word); if (e || !word) return root_fail(p, r, e ? e : -EFAULT, e ? -e : EFAULT); }
    if (has_iterate) { u32 word = 0; e = p->ops.read_word(p->ops.context, iterate, &word); if (e || !word) return root_fail(p, r, e ? e : -EFAULT, e ? -e : EFAULT); }
    /* m070 enables its optional MTK path only when both symbols exist.
     * A normal kernel still has iterate_dir without the HBT module. */
    e = resolve_required(p, "audit_log_start", MSU_EARLY_ROOT_SYMBOL_EXACT, &audit, r);
    if (e) return e;
    { u32 word = 0; e = p->ops.read_word(p->ops.context, audit, &word); if (e || !word) return root_fail(p, r, e ? e : -EFAULT, e ? -e : EFAULT); }
    /* Inspection ends before any native publication or text allocation. */
    if (only_print) return 0;
    addresses[0] = avc;
    e = patch_one(p, MSU_EARLY_ROOT_TARGET_AVC, addresses, 1, hide_names, hide_count, r);
    if (e) return e;
    addresses[0] = filldir;
    e = patch_one(p, MSU_EARLY_ROOT_TARGET_FILLDIR, addresses, 1, hide_names, hide_count, r);
    if (e) return e;
    addresses[0] = compat;
    e = patch_one(p, MSU_EARLY_ROOT_TARGET_COMPAT, addresses, 1, hide_names, hide_count, r);
    if (e) return e;
    if (has_hbt && has_iterate) {
        /* The native backend gates the original HBT entry, preserving its CFI
         * identity and the caller's actor. No generated actor escapes through
         * iterate_dir and no separate iterate text mutation is claimed. */
        addresses[0] = hbt;
        e = patch_one(p, MSU_EARLY_ROOT_TARGET_HBT, addresses, 1, hide_names, hide_count, r);
        if (e) return e;
    }
    addresses[0] = audit;
    return patch_one(p, MSU_EARLY_ROOT_TARGET_AUDIT, addresses, 1, hide_names, hide_count, r);
}

static struct msu_early_root_provider *root_fixed_current;
static u32 root_effects_to_fixed(u32 effects)
{
    u32 fixed = MSU_EARLY_FIXED_EFFECT_ATTEMPTED;
    fixed |= (effects & 0x7ffU) << 6;
    if (effects & (MSU_EARLY_ROOT_EFFECT_AVC | MSU_EARLY_ROOT_EFFECT_FILLDIR |
            MSU_EARLY_ROOT_EFFECT_COMPAT | MSU_EARLY_ROOT_EFFECT_HBT |
            MSU_EARLY_ROOT_EFFECT_ITERATE | MSU_EARLY_ROOT_EFFECT_AUDIT))
        fixed |= MSU_EARLY_FIXED_EFFECT_APPLIED;
    if (effects & MSU_EARLY_ROOT_EFFECT_PENDING)
        fixed |= MSU_EARLY_FIXED_EFFECT_PENDING;
    if (effects & MSU_EARLY_ROOT_EFFECT_QUARANTINED)
        fixed |= MSU_EARLY_FIXED_EFFECT_QUARANTINED;
    if (effects & MSU_EARLY_ROOT_EFFECT_CLOSED)
        fixed |= MSU_EARLY_FIXED_EFFECT_RELEASED;
    return fixed;
}

static bool root_fixed_validate(const struct msu_early_fixed_provider *provider)
{
    struct msu_early_root_provider *p = root_fixed_current;
    return provider && p && provider->generation_valid && p->initialized && !p->closed && !p->revoked;
}
static int root_fixed_operation(struct msu_early_fixed_provider *provider, u32 operation,
    u32 mode, u32 exploit, u64 value, struct msu_early_fixed_result *result)
{
    struct msu_early_root_result r = {};
    int e;
    struct msu_early_root_provider *p = root_fixed_current;
    (void)provider;
    /* Command31 carries bounded scalars only; no caller-owned name list. */
    e = msu_early_root_operation_bound(p, operation, mode, exploit, value, NULL, 0, &r);
    if (result) {
        result->code = r.code;
        result->native_errno = r.native_errno;
        result->effects = root_effects_to_fixed(r.effects);
        result->values[0] = r.value;
    }
    return e;
}
static int root_fixed_revoke(struct msu_early_fixed_provider *provider,
    const unsigned char generation[16], u32 *effects)
{
    u32 domain_effects = 0;
    int error = msu_early_root_provider_revoke(root_fixed_current, &provider->host,
        generation, &domain_effects);
    if (effects) *effects |= domain_effects;
    return error;
}
static int root_fixed_close(struct msu_early_fixed_provider *provider, u32 *effects)
{
    u32 domain_effects = 0;
    int error;
    (void)provider;
    error = msu_early_root_provider_close(root_fixed_current, &domain_effects);
    if (effects) *effects |= domain_effects;
    return error;
}
static struct msu_early_fixed_provider root_fixed_provider;

int msu_early_root_provider_init(struct msu_early_root_provider *p,
    const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16],
    const struct msu_early_root_ops *ops)
{
    if (!p || !host || !(host->low | host->high) ||
        !msu_deployment_namespace_valid(deployment) || !generation || !generation_nonzero(generation) || !ops || !ops->resolve ||
        !ops->read_word || !ops->credential_precheck || !ops->patch || !ops->revoke)
        return -EINVAL;
    memset(p, 0, sizeof(*p));
    mutex_init(&p->lock);
    p->host = *host;
    p->deployment = *deployment;
    p->ops = *ops;
    memcpy(p->generation, generation, sizeof(p->generation));
    p->generation_valid = 1;
    p->initialized = true;
    root_fixed_current = p;
    memset(&root_fixed_provider, 0, sizeof(root_fixed_provider));
    root_fixed_provider.host = *host;
    memcpy(root_fixed_provider.generation, generation, 16);
    root_fixed_provider.generation_valid = true;
    root_fixed_provider.owner = p;
    root_fixed_provider.deployment = &p->deployment;
    root_fixed_provider.validate = root_fixed_validate;
    root_fixed_provider.operation = root_fixed_operation;
    root_fixed_provider.revoke = root_fixed_revoke;
    root_fixed_provider.close = root_fixed_close;
    return msu_early_fixed_provider_register(MSU_EARLY_FIXED_ROOT_ENV,
        MSU_EARLY_FIXED_ROOT_ENV, &root_fixed_provider);
}

int msu_early_root_provider_bind(struct msu_early_root_provider *p,
    const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment,
    const unsigned char generation[16],
    const struct msu_early_root_ops *ops)
{
    int e;
    if (!p) return -EINVAL;
    e = msu_early_root_provider_init(p, host, deployment, generation, ops);
    return e;
}

int msu_early_root_operation(struct msu_early_root_provider *p,
    u32 operation, u32 mode, u32 exploit, u64 value,
    const unsigned char generation[16],
    const char *const *hide_names, u32 hide_count,
    struct msu_early_root_result *r)
{
    int e;
    if (r) memset(r, 0, sizeof(*r));
    if (!p || !p->initialized) return root_result(r, -EINVAL, EINVAL, 0, value);
    if (operation != MSU_EARLY_ROOT_OPERATION_ROOT_ENV || value > 1U) return root_fail(p, r, -EINVAL, EINVAL);
    if (!generation) return root_result(r, -ESTALE, ESTALE, 0, value);
    mutex_lock(&p->lock);
    if (!p->generation_valid || memcmp(generation, p->generation, sizeof(p->generation))) { mutex_unlock(&p->lock); return root_result(r, -ESTALE, ESTALE, p->effects, value); }
    if (p->closed || p->revoked || p->quarantined) {
        e = root_fail(p, r, p->quarantined ? -EIO : -ESHUTDOWN,
            p->quarantined ? EIO : ESHUTDOWN);
        mutex_unlock(&p->lock);
        return e;
    }
    if (p->active) { mutex_unlock(&p->lock); return root_result(r, -EBUSY, EBUSY, p->effects, value); }
    p->active = true;
    mutex_unlock(&p->lock);
    e = do_root_env(p, mode, exploit, value == 1U, hide_names, hide_count, r);
    mutex_lock(&p->lock);
    if (e) p->quarantined = (p->effects & (MSU_EARLY_ROOT_EFFECT_AVC | MSU_EARLY_ROOT_EFFECT_FILLDIR | MSU_EARLY_ROOT_EFFECT_COMPAT | MSU_EARLY_ROOT_EFFECT_HBT | MSU_EARLY_ROOT_EFFECT_ITERATE | MSU_EARLY_ROOT_EFFECT_AUDIT)) != 0;
    p->active = false;
    if (r) r->effects = p->effects;
    mutex_unlock(&p->lock);
    return e;
}

int msu_early_root_operation_bound(struct msu_early_root_provider *p,
    u32 operation, u32 mode, u32 exploit, u64 value,
    const char *const *hide_names, u32 hide_count,
    struct msu_early_root_result *r)
{
    unsigned char generation[16];
    if (!p) return root_result(r, -EINVAL, EINVAL, 0, value);
    mutex_lock(&p->lock);
    if (!p->generation_valid) { mutex_unlock(&p->lock); return root_result(r, -ESTALE, ESTALE, 0, value); }
    memcpy(generation, p->generation, sizeof(generation));
    mutex_unlock(&p->lock);
    return msu_early_root_operation(p, operation, mode, exploit, value,
        generation, hide_names, hide_count, r);
}

int msu_early_root_provider_revoke(struct msu_early_root_provider *p,
    const maplesu_host_instance *host, const unsigned char generation[16], u32 *effects)
{
    int e;
    u32 local = 0;
    (void)generation;
    if (!p || !host || host->low != p->host.low || host->high != p->host.high) return -ESTALE;
    mutex_lock(&p->lock);
    if (generation && (!p->generation_valid || memcmp(generation, p->generation, sizeof(p->generation)))) { mutex_unlock(&p->lock); return -ESTALE; }
    if (p->closed) { if (effects) *effects = p->lifecycle_effects | MAPLESU_EFFECT_RELEASED; mutex_unlock(&p->lock); return 0; }
    if (p->active) { p->effects |= MSU_EARLY_ROOT_EFFECT_PENDING; if (effects) *effects = MAPLESU_EFFECT_PENDING; mutex_unlock(&p->lock); return -EINPROGRESS; }
    p->revoked = true;
    mutex_unlock(&p->lock);
    e = p->ops.revoke(p->ops.context, &local);
    mutex_lock(&p->lock);
    p->effects |= MSU_EARLY_ROOT_EFFECT_REVOKE;
    p->lifecycle_effects |= local;
    if (!e) {
        p->closed = true;
        p->effects = (p->effects & ~MSU_EARLY_ROOT_EFFECT_PENDING) | MSU_EARLY_ROOT_EFFECT_CLOSED;
        p->lifecycle_effects &= ~MAPLESU_EFFECT_PENDING;
    } else p->effects |= MSU_EARLY_ROOT_EFFECT_PENDING;
    if (effects) *effects = p->lifecycle_effects | (e ? MAPLESU_EFFECT_PENDING : MAPLESU_EFFECT_RELEASED);
    mutex_unlock(&p->lock);
    return e;
}

int msu_early_root_provider_close(struct msu_early_root_provider *p, u32 *effects)
{
    int e;
    u32 local = 0;
    if (!p) return -EINVAL;
    mutex_lock(&p->lock);
    if (p->closed) { if (effects) *effects = p->lifecycle_effects | MAPLESU_EFFECT_RELEASED; mutex_unlock(&p->lock); return 0; }
    if (p->active) { p->effects |= MSU_EARLY_ROOT_EFFECT_PENDING; if (effects) *effects = MAPLESU_EFFECT_PENDING; mutex_unlock(&p->lock); return -EINPROGRESS; }
    p->revoked = true;
    mutex_unlock(&p->lock);
    if (!p->ops.revoke) return -ENOSYS;
    e = p->ops.revoke(p->ops.context, &local);
    mutex_lock(&p->lock);
    p->lifecycle_effects |= local;
    if (!e) {
        p->closed = true;
        p->effects = (p->effects & ~MSU_EARLY_ROOT_EFFECT_PENDING) | MSU_EARLY_ROOT_EFFECT_CLOSED;
        p->lifecycle_effects &= ~MAPLESU_EFFECT_PENDING;
    } else p->effects |= MSU_EARLY_ROOT_EFFECT_PENDING;
    if (effects) *effects = p->lifecycle_effects | (e ? MAPLESU_EFFECT_PENDING : MAPLESU_EFFECT_RELEASED);
    mutex_unlock(&p->lock);
    return e;
}

int msu_early_root_provider_discarded(struct msu_early_root_provider *p)
{
    int e;
    if (!p) return -EINVAL;
    mutex_lock(&p->lock);
    if (!p->closed || p->effects & MSU_EARLY_ROOT_EFFECT_PENDING) { mutex_unlock(&p->lock); return -EINPROGRESS; }
    e = p->ops.discarded ? p->ops.discarded(p->ops.context) : 0;
    if (e) p->effects |= MSU_EARLY_ROOT_EFFECT_QUARANTINED;
    mutex_unlock(&p->lock);
    return e;
}
