// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/string.h>
#include "manager_early_fixed.h"

struct msu_early_fixed_slot {
    u32 first, last, users;
    struct msu_early_fixed_provider *provider;
    bool registered, closing, teardown;
};
static DEFINE_MUTEX(msu_early_fixed_lock);
static DECLARE_WAIT_QUEUE_HEAD(msu_early_fixed_wait);
static struct msu_early_fixed_slot msu_early_fixed_slots[3];
/* Retired operations stay stale without retaining a provider or its owner. */
static u32 msu_early_fixed_retired;

static bool host_matches(const maplesu_host_instance *a, const maplesu_host_instance *b)
{
    return a && b && a->low == b->low && a->high == b->high;
}
static struct msu_early_fixed_slot *find_slot(u32 operation)
{
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(msu_early_fixed_slots); ++i)
        if (msu_early_fixed_slots[i].registered && operation >= msu_early_fixed_slots[i].first &&
            operation <= msu_early_fixed_slots[i].last) return &msu_early_fixed_slots[i];
    return NULL;
}
int msu_early_fixed_provider_register(u32 first, u32 last,
    struct msu_early_fixed_provider *provider)
{
    unsigned int i;
    int error = 0;
    unsigned int g;
    bool generation = false;
    if (!provider || !provider->owner || !provider->validate || !provider->operation ||
        !provider->revoke || !provider->close || first > last || first < MSU_EARLY_FIXED_OEM_MTK ||
        last > MSU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE || !(provider->host.low | provider->host.high) ||
        !provider->generation_valid) return -EINVAL;
    for (g = 0; g < 16; ++g) generation |= provider->generation[g] != 0;
    if (!generation || !provider->validate(provider)) return -ESTALE;
    mutex_lock(&msu_early_fixed_lock);
    for (i = 0; i < ARRAY_SIZE(msu_early_fixed_slots); ++i)
        if (msu_early_fixed_slots[i].registered &&
            !(last < msu_early_fixed_slots[i].first || first > msu_early_fixed_slots[i].last)) { error = -EALREADY; break; }
    if (!error) {
        for (i = 0; i < ARRAY_SIZE(msu_early_fixed_slots); ++i)
            if (!msu_early_fixed_slots[i].registered) {
                msu_early_fixed_slots[i] = (struct msu_early_fixed_slot){
                    .first = first, .last = last, .users = 0,
                    .provider = provider, .registered = true,
                };
                break;
            }
        if (i == ARRAY_SIZE(msu_early_fixed_slots)) error = -ENOSPC;
    }
    mutex_unlock(&msu_early_fixed_lock);
    return error;
}
static int retire_slot(struct msu_early_fixed_slot *slot, u32 first, u32 last,
    const void *owner, const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects)
{
    struct msu_early_fixed_provider *provider;
    u32 provider_effects = 0;
    u32 close_effects = 0, operation;
    int error;

retry:
    mutex_lock(&msu_early_fixed_lock);
    if (!slot->registered || slot->first != first || slot->last != last ||
        (owner && slot->provider->owner != owner) ||
        (host && !host_matches(host, &slot->provider->host)) ||
        (generation && memcmp(generation, slot->provider->generation, 16))) {
        mutex_unlock(&msu_early_fixed_lock);
        return -ENOENT;
    }
    slot->closing = true;
    if (slot->teardown) {
        mutex_unlock(&msu_early_fixed_lock);
        wait_event(msu_early_fixed_wait, !READ_ONCE(slot->teardown) ||
            !READ_ONCE(slot->registered));
        goto retry;
    }
    slot->teardown = true;
    provider = slot->provider;
    mutex_unlock(&msu_early_fixed_lock);

    /* Closing the slot above fences every new call. Drain admitted operations
     * before touching provider state or allowing its owner to be released. */
    wait_event(msu_early_fixed_wait, !READ_ONCE(slot->users));
    error = provider->revoke(provider, provider->generation, &provider_effects);
    if (!error && ((provider_effects & (MAPLESU_EFFECT_PENDING | MAPLESU_EFFECT_QUARANTINED |
            MAPLESU_EFFECT_SHARED_RETAINED)) ||
            (!(provider_effects & MAPLESU_EFFECT_RELEASED) &&
             (provider_effects & (MAPLESU_EFFECT_PUBLICATION_RETAINED | MAPLESU_EFFECT_GATE_PINNED)))))
        error = -EINPROGRESS;
    if (!error) error = provider->close(provider, &close_effects);
    provider_effects |= close_effects;

    mutex_lock(&msu_early_fixed_lock);
    if (!error) {
        for (operation = first; operation <= last; ++operation)
            msu_early_fixed_retired |= 1U << operation;
        slot->registered = false;
        slot->provider = NULL;
        slot->closing = false;
        *effects |= MAPLESU_EFFECT_RELEASED;
    } else {
        *effects |= MAPLESU_EFFECT_PENDING;
    }
    *effects |= provider_effects;
    slot->teardown = false;
    mutex_unlock(&msu_early_fixed_lock);
    wake_up_all(&msu_early_fixed_wait);
    return error;
}

int msu_early_fixed_provider_unregister(u32 first, u32 last,
    const void *owner, u32 *effects)
{
    struct msu_early_fixed_slot *slot = NULL;
    unsigned int i;
    if (!owner || !effects) return -EINVAL;
    *effects = 0;
    mutex_lock(&msu_early_fixed_lock);
    for (i = 0; i < ARRAY_SIZE(msu_early_fixed_slots); ++i)
        if (msu_early_fixed_slots[i].registered &&
            msu_early_fixed_slots[i].first == first &&
            msu_early_fixed_slots[i].last == last &&
            msu_early_fixed_slots[i].provider->owner == owner) {
            slot = &msu_early_fixed_slots[i];
            break;
        }
    mutex_unlock(&msu_early_fixed_lock);
    return slot ? retire_slot(slot, first, last, owner, NULL, NULL, effects) : -ENOENT;
}
int msu_early_fixed_provider_call(const maplesu_host_instance *host, u32 operation,
    u32 mode, u32 exploit, u64 value, struct msu_early_fixed_result *result)
{
    struct msu_early_fixed_slot *slot;
    struct msu_early_fixed_provider *provider;
    int error;
    if (!host || !result || mode > MAPLESU_EARLY_FIXED_MODE_MAX || exploit > MAPLESU_EARLY_FIXED_EXPLOIT_MAX) return -EINVAL;
    memset(result, 0, sizeof(*result));
    mutex_lock(&msu_early_fixed_lock);
    slot = find_slot(operation);
    if (!slot) {
        error = operation <= MSU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE &&
            (msu_early_fixed_retired & (1U << operation)) ? -ESTALE : -EOPNOTSUPP;
        mutex_unlock(&msu_early_fixed_lock);
        return error;
    }
    if (slot->closing) { mutex_unlock(&msu_early_fixed_lock); return -ESTALE; }
    provider = slot->provider;
    if (!host_matches(host, &provider->host)) {
        mutex_unlock(&msu_early_fixed_lock); return -ESTALE;
    }
    ++slot->users;
    mutex_unlock(&msu_early_fixed_lock);
    if (!provider->validate(provider)) {
        mutex_lock(&msu_early_fixed_lock);
        --slot->users;
        mutex_unlock(&msu_early_fixed_lock);
        wake_up_all(&msu_early_fixed_wait);
        return -ESTALE;
    }
    result->effects |= MSU_EARLY_FIXED_EFFECT_ATTEMPTED;
    error = provider->operation(provider, operation, mode, exploit, value, result);
    mutex_lock(&msu_early_fixed_lock);
    --slot->users;
    mutex_unlock(&msu_early_fixed_lock);
    wake_up_all(&msu_early_fixed_wait);
    return error;
}
int msu_early_fixed_provider_revoke(const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects)
{
    struct msu_early_fixed_slot *slots[ARRAY_SIZE(msu_early_fixed_slots)];
    unsigned int count = 0, i;
    int first_error = 0;
    if (!host || !generation || !effects) return -EINVAL;
    *effects = 0;
    mutex_lock(&msu_early_fixed_lock);
    for (i = 0; i < ARRAY_SIZE(msu_early_fixed_slots); ++i) {
        if (!msu_early_fixed_slots[i].registered || !host_matches(host, &msu_early_fixed_slots[i].provider->host)) continue;
        if (memcmp(generation, msu_early_fixed_slots[i].provider->generation, 16)) {
            if (!first_error) first_error = -ESTALE;
            *effects |= MAPLESU_EFFECT_PENDING;
            continue;
        }
        msu_early_fixed_slots[i].closing = true;
        slots[count++] = &msu_early_fixed_slots[i];
    }
    mutex_unlock(&msu_early_fixed_lock);
    for (i = 0; i < count; ++i) {
        int error = retire_slot(slots[i], slots[i]->first, slots[i]->last,
            NULL, host, generation, effects);
        if (error == -ENOENT) error = 0; /* concurrent retirement completed it */
        if (!first_error) first_error = error;
    }
    return first_error;
}
