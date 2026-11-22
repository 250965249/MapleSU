// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "manager_uid_gateway.h"
#include "manager_uid_snapshot.h"

#define MSU_UID_GATEWAY_SLOTS 64U

struct msu_uid_controller_slot {
    struct msu_uid_snapshot_state __rcu *state;
    maplesu_host_instance host;
    struct msu_uid_reader_fence fence;
    void *quarantined_transaction;
    u64 id, revision;
    bool closed, shutdown_pending, shutdown_complete, fence_broken;
};

struct msu_uid_candidate_slot {
    struct msu_uid_snapshot *snapshot;
    struct msu_uid_controller_slot *controller;
    const void *kernel_owner;
    u64 id, session, expected_revision;
};

static DEFINE_MUTEX(msu_uid_gateway_lock);
static struct msu_uid_controller_slot msu_uid_controllers[MSU_UID_GATEWAY_SLOTS];
static struct msu_uid_candidate_slot msu_uid_candidates[MSU_UID_GATEWAY_SLOTS];
static u64 msu_uid_next_controller = 1, msu_uid_next_candidate = 1;
static bool msu_uid_gateway_retiring;

_Static_assert(sizeof(struct msu_uid_snapshot_record) == sizeof(maplesu_uid_record_v3),
    "UID record wire size");
_Static_assert(offsetof(struct msu_uid_snapshot_record, full_uid) == offsetof(maplesu_uid_record_v3, full_uid) &&
    offsetof(struct msu_uid_snapshot_record, decision) == offsetof(maplesu_uid_record_v3, decision) &&
    offsetof(struct msu_uid_snapshot_record, installation_generation) == offsetof(maplesu_uid_record_v3, installation_generation) &&
    offsetof(struct msu_uid_snapshot_record, profile_revision) == offsetof(maplesu_uid_record_v3, profile_revision) &&
    offsetof(struct msu_uid_snapshot_record, package) == offsetof(maplesu_uid_record_v3, package),
    "UID record wire fields");
_Static_assert(sizeof(struct msu_uid_snapshot_metadata) == sizeof(maplesu_uid_metadata_v3),
    "UID metadata wire size");
_Static_assert(offsetof(struct msu_uid_snapshot_metadata, schema) == offsetof(maplesu_uid_metadata_v3, schema) &&
    offsetof(struct msu_uid_snapshot_metadata, count) == offsetof(maplesu_uid_metadata_v3, count) &&
    offsetof(struct msu_uid_snapshot_metadata, record_bytes) == offsetof(maplesu_uid_metadata_v3, record_bytes) &&
    offsetof(struct msu_uid_snapshot_metadata, reserved) == offsetof(maplesu_uid_metadata_v3, reserved) &&
    offsetof(struct msu_uid_snapshot_metadata, content_revision) == offsetof(maplesu_uid_metadata_v3, content_revision) &&
    offsetof(struct msu_uid_snapshot_metadata, host) == offsetof(maplesu_uid_metadata_v3, host),
    "UID metadata wire fields");

static bool msu_uid_gateway_sleepable(void)
{
    return in_task() && !in_atomic() && !irqs_disabled();
}

static bool msu_uid_host_equal(maplesu_host_instance left, maplesu_host_instance right)
{
    return left.low == right.low && left.high == right.high;
}

static bool msu_uid_user_range(u64 address, size_t bytes)
{
    return address && bytes && address <= ~0ULL - (bytes - 1) &&
        !(address & (1ULL << 55));
}

static struct msu_uid_controller_slot *msu_uid_controller(u64 id,
    maplesu_host_instance host)
{
    unsigned int i;
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i)
        if (msu_uid_controllers[i].id == id &&
            msu_uid_host_equal(msu_uid_controllers[i].host, host))
            return &msu_uid_controllers[i];
    return NULL;
}

static struct msu_uid_snapshot_state *msu_uid_controller_state(
    struct msu_uid_controller_slot *controller)
{
    return rcu_dereference_protected(controller->state,
        lockdep_is_held(&msu_uid_gateway_lock));
}

static struct msu_uid_candidate_slot *msu_uid_candidate_owned(u64 id, u64 session,
    struct msu_uid_controller_slot *controller, const void *kernel_owner)
{
    unsigned int i;
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i)
        if (msu_uid_candidates[i].snapshot && msu_uid_candidates[i].id == id &&
            msu_uid_candidates[i].session == session &&
            msu_uid_candidates[i].kernel_owner == kernel_owner &&
            msu_uid_candidates[i].controller == controller)
            return &msu_uid_candidates[i];
    return NULL;
}

static struct msu_uid_candidate_slot *msu_uid_candidate(u64 id, u64 session,
    struct msu_uid_controller_slot *controller)
{
    return msu_uid_candidate_owned(id, session, controller, NULL);
}

static void msu_uid_candidate_drop(struct msu_uid_candidate_slot *candidate)
{
    msu_uid_snapshot_cancel(&candidate->snapshot);
    memset(candidate, 0, sizeof(*candidate));
}

static int msu_uid_create(const maplesu_management_v3 *operation,
    maplesu_response_owner_v3 *response, int (*validate)(void *), void *context)
{
    struct msu_uid_controller_slot *controller = NULL;
    struct msu_uid_snapshot *initial = NULL;
    struct msu_uid_snapshot_state *state = NULL;
    u64 revision, id;
    unsigned int i;
    int error;
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i)
        if (!msu_uid_controllers[i].id) { controller = &msu_uid_controllers[i]; break; }
    if (!controller || !msu_uid_next_controller) return -ENOSPC;
    error = msu_uid_snapshot_prepare(NULL, 0, &initial);
    if (error) return error;
    error = validate(context);
    if (!error) error = msu_uid_snapshot_state_create(&operation->host, &state);
    if (error) goto out;
    rcu_assign_pointer(controller->state, state);
    controller->host = operation->host;
    id = msu_uid_next_controller++;
    response->metadata_address = id;
    response->metadata_length |= MAPLESU_EFFECT_ALLOCATED;
    error = validate(context);
    if (!error) error = msu_uid_snapshot_commit(state, &initial, 0, &revision);
    if (error) {
        /* A created state is boot-owned even when initial publication failed. */
        msu_uid_snapshot_state_shutdown(state);
        controller->closed = true;
        smp_store_release(&controller->id, id);
        goto out;
    }
    response->result = revision;
    controller->revision = revision;
    response->metadata_length |= MAPLESU_EFFECT_COMMITTED;
    /* The boot-stable state and host are immutable before lockless visibility.
     * A failed initial publish similarly exposes only its closed tombstone. */
    smp_store_release(&controller->id, id);
out:
    msu_uid_snapshot_cancel(&initial);
    return error;
}

int msu_uid_gateway_create_kernel(const maplesu_host_instance *host,
    int (*validate)(void *context), void *context,
    u64 *controller_id, u64 *revision, u32 *effects)
{
    maplesu_management_v3 operation = {0};
    maplesu_response_owner_v3 response = {0};
    int error, post_error;
    if (!host || !controller_id || !revision || !effects) return -EINVAL;
    operation.host = *host;
    *controller_id = *revision = 0;
    *effects = 0;
    if (!msu_uid_gateway_sleepable()) return -EWOULDBLOCK;
    if (!validate || !(operation.host.low | operation.host.high)) return -EINVAL;
    error = validate(context);
    if (error) return error;
    mutex_lock(&msu_uid_gateway_lock);
    if (msu_uid_gateway_retiring) { error = -ESHUTDOWN; goto out; }
    error = validate(context);
    if (!error) {
        error = msu_uid_create(&operation, &response, validate, context);
        post_error = validate(context);
        if (!error) error = post_error;
    }
    *controller_id = response.metadata_address;
    *revision = response.result;
    *effects = response.metadata_length;
out:
    mutex_unlock(&msu_uid_gateway_lock);
    return error;
}

int msu_uid_gateway_bind_reader(const maplesu_host_instance *host, u64 controller_id,
    const struct msu_uid_reader_fence *fence)
{
    struct msu_uid_reader_fence binding;
    struct msu_uid_controller_slot *controller;
    struct msu_uid_snapshot *snapshot;
    struct msu_uid_snapshot_metadata metadata;
    maplesu_host_instance expected;
    int error;
    if (!host || !controller_id || !fence) return -EINVAL;
    expected = *host;
    binding = *fence;
    if (!(expected.low | expected.high) || !binding.owner ||
        !binding.check_closed || !binding.begin || !binding.revoke || !binding.finish || !binding.retire) return -EINVAL;
    if (!msu_uid_gateway_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&msu_uid_gateway_lock);
    if (msu_uid_gateway_retiring) { error = -ESHUTDOWN; goto out; }
    controller = msu_uid_controller(controller_id, expected);
    if (!controller) { error = -ESTALE; goto out; }
    if (controller->closed || controller->shutdown_pending) { error = -ESHUTDOWN; goto out; }
    if (controller->fence.owner) { error = -EALREADY; goto out; }
    snapshot = msu_uid_snapshot_acquire(msu_uid_controller_state(controller));
    if (!snapshot) { error = -ESTALE; goto out; }
    error = msu_uid_snapshot_metadata(snapshot, &metadata);
    msu_uid_snapshot_put(snapshot);
    if (error) goto out;
    if (metadata.count || metadata.content_revision != 1) { error = -EBUSY; goto out; }
    error = binding.check_closed(binding.owner);
    if (error > 0) error = -EIO;
    if (!error) controller->fence = binding;
out:
    mutex_unlock(&msu_uid_gateway_lock);
    return error;
}

/* Gateway mutex owns both snapshots' mutation exclusivity. Reader callbacks
 * take no snapshot locks, close admission and report drain without waiting. */
static int msu_uid_fence_update(struct msu_uid_controller_slot *controller,
    struct msu_uid_snapshot *next, u64 expected_revision,
    maplesu_response_owner_v3 *response, void **transaction)
{
    struct msu_uid_snapshot *previous;
    struct msu_uid_snapshot_metadata before = {0}, after = {0};
    struct msu_uid_snapshot_record old_row, new_row = {0};
    u32 i, j = 0;
    int error, first_error = 0;
    if (!controller->fence.owner) return 0;
    if (controller->fence_broken) {
        response->metadata_address = controller->id;
        response->metadata_length |= MAPLESU_EFFECT_PENDING;
        return -EUCLEAN;
    }
    if (controller->closed && controller->shutdown_complete) return 0;
    previous = controller->closed ? NULL :
        msu_uid_snapshot_acquire(msu_uid_controller_state(controller));
    if (!previous && !controller->closed) return -ESTALE;
    if (previous) {
        error = msu_uid_snapshot_metadata(previous, &before);
        if (error) goto out;
    } else before.content_revision = controller->revision;
    if (next) {
        error = msu_uid_snapshot_metadata(next, &after);
        if (error) goto out;
        if (after.content_revision || (after.host.low | after.host.high)) { error = -EBUSY; goto out; }
        if (before.content_revision != expected_revision) { error = -EAGAIN; goto out; }
        if (before.content_revision == ~0ULL) { error = -EOVERFLOW; goto out; }
    }
    response->result = 0;
    response->metadata_address = controller->id;
    response->metadata_length |= MAPLESU_EFFECT_PENDING;
    error = controller->fence.begin(controller->fence.owner, next,
        before.content_revision, !next, transaction);
    if (error > 0) error = -EIO;
    if (error) goto out;
    if (!*transaction) {
        controller->fence_broken = true;
        error = -EUCLEAN;
        goto out;
    }
    for (i = 0; i < before.count; ++i) {
        error = msu_uid_snapshot_record_at(previous, i, &old_row);
        if (error) goto out;
        if (!old_row.decision) continue;
        while (j < after.count) {
            error = msu_uid_snapshot_record_at(next, j, &new_row);
            if (error) goto out;
            if (new_row.full_uid >= old_row.full_uid) break;
            ++j;
        }
        if (j < after.count && new_row.full_uid == old_row.full_uid && new_row.decision &&
            new_row.installation_generation == old_row.installation_generation &&
            new_row.profile_revision == old_row.profile_revision) continue;
        error = controller->fence.revoke(controller->fence.owner, old_row.full_uid);
        if (error > 0) error = -EIO;
        if (!first_error) first_error = error;
    }
    error = first_error;
out:
    msu_uid_snapshot_put(previous);
    return error;
}

static int msu_uid_fence_finish(struct msu_uid_controller_slot *controller,
    void **transaction, int commit_error)
{
    int error;
    if (!*transaction) return 0;
    error = controller->fence.finish(controller->fence.owner, transaction, commit_error);
    if (error > 0) error = -EIO;
    if (*transaction) {
        controller->fence_broken = true;
        controller->quarantined_transaction = *transaction;
        *transaction = NULL;
        if (!error) error = -EUCLEAN;
    }
    return error;
}

static int msu_uid_stage(u64 session, const void *kernel_owner,
    struct msu_uid_controller_slot *controller,
    const struct msu_uid_snapshot_record *records, u32 count, u64 expected_revision,
    maplesu_response_owner_v3 *response, int (*validate)(void *), void *context)
{
    struct msu_uid_snapshot *snapshot = NULL;
    struct msu_uid_candidate_slot *candidate = NULL;
    unsigned int i;
    int error;
    if (!expected_revision) return -EINVAL;
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i)
        if (!msu_uid_candidates[i].snapshot) { candidate = &msu_uid_candidates[i]; break; }
    if (!candidate || !msu_uid_next_candidate) return -ENOSPC;
    error = validate(context);
    if (!error) error = msu_uid_snapshot_prepare(records, count, &snapshot);
    if (error) goto out;
    error = validate(context);
    if (error) goto out;
    candidate->snapshot = snapshot;
    snapshot = NULL;
    candidate->controller = controller;
    candidate->id = msu_uid_next_candidate++;
    candidate->session = session;
    candidate->kernel_owner = kernel_owner;
    candidate->expected_revision = expected_revision;
    response->result = candidate->id;
    response->metadata_address = controller->id;
    response->metadata_length |= MAPLESU_EFFECT_ALLOCATED;
out:
    msu_uid_snapshot_cancel(&snapshot);
    return error;
}

static int msu_uid_prepare(u64 session, struct msu_uid_controller_slot *controller,
    const maplesu_management_v3 *operation, maplesu_response_owner_v3 *response,
    int (*validate)(void *), void *context)
{
    maplesu_uid_prepare_v3 descriptor;
    struct msu_uid_snapshot_record *records = NULL;
    size_t bytes;
    int error;
    if (copy_from_user_nofault(&descriptor,
        (void __user *)(unsigned long)operation->data_user, sizeof(descriptor))) return -EFAULT;
    if (descriptor.schema != MSU_UID_SNAPSHOT_SCHEMA || descriptor.reserved || !descriptor.expected_revision ||
        descriptor.record_bytes != sizeof(*records) ||
        descriptor.count > MSU_UID_SNAPSHOT_MAX_RECORDS) return -EINVAL;
    bytes = (size_t)descriptor.count * sizeof(*records);
    if (bytes && !msu_uid_user_range(descriptor.records_user, bytes)) return -EINVAL;
    if (bytes) {
        records = kvmalloc(bytes, GFP_KERNEL);
        if (!records) return -ENOMEM;
        if (copy_from_user_nofault(records,
            (void __user *)(unsigned long)descriptor.records_user, bytes)) {
            error = -EFAULT;
            goto out;
        }
    }
    error = msu_uid_stage(session, NULL, controller, records, descriptor.count,
        descriptor.expected_revision, response, validate, context);
out:
    kvfree(records);
    return error;
}

static int msu_uid_commit(struct msu_uid_controller_slot *controller,
    struct msu_uid_candidate_slot *candidate, maplesu_response_owner_v3 *response,
    int (*validate)(void *), void *context)
{
    void *transaction = NULL;
    u64 revision;
    int error, finish_error;
    error = validate(context);
    if (error) return error;
    error = msu_uid_fence_update(controller, candidate->snapshot,
        candidate->expected_revision, response, &transaction);
    if (!error && controller->fence.owner) error = validate(context);
    if (!error) error = msu_uid_snapshot_commit(msu_uid_controller_state(controller),
        &candidate->snapshot, candidate->expected_revision, &revision);
    if (!error) {
        controller->revision = revision;
        memset(candidate, 0, sizeof(*candidate));
        response->result = revision;
        response->metadata_address = controller->id;
        response->metadata_length &= ~MAPLESU_EFFECT_PENDING;
        response->metadata_length |= MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_REFERENCE_DROPPED;
    }
    finish_error = msu_uid_fence_finish(controller, &transaction, error);
    if (finish_error) response->metadata_length |= MAPLESU_EFFECT_PENDING;
    if (controller->fence_broken) response->metadata_length |= MAPLESU_EFFECT_QUARANTINED;
    if (!error) error = finish_error;
    return error;
}

static int msu_uid_shutdown(struct msu_uid_controller_slot *controller,
    maplesu_response_owner_v3 *response, int (*validate)(void *), void *context)
{
    void *transaction = NULL;
    unsigned int i;
    int error, finish_error;
    if (controller->shutdown_complete) {
        response->metadata_address = controller->id;
        response->metadata_length |= MAPLESU_EFFECT_RELEASED;
        return 0;
    }
    response->result = 0;
    response->metadata_address = controller->id;
    controller->shutdown_pending = true;
    error = msu_uid_fence_update(controller, NULL, 0, response, &transaction);
    if (!error && validate) error = validate(context);
    if (!error) error = msu_uid_snapshot_state_shutdown(msu_uid_controller_state(controller));
    if (!error) {
        controller->closed = true;
        for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i)
            if (msu_uid_candidates[i].snapshot && msu_uid_candidates[i].controller == controller)
                msu_uid_candidate_drop(&msu_uid_candidates[i]);
        response->metadata_address = controller->id;
        response->metadata_length |= MAPLESU_EFFECT_RELEASED;
    }
    finish_error = msu_uid_fence_finish(controller, &transaction, error);
    if (!error) error = finish_error;
    if (!error) {
        controller->shutdown_complete = true;
        response->metadata_length &= ~MAPLESU_EFFECT_PENDING;
    } else response->metadata_length |= MAPLESU_EFFECT_PENDING;
    if (controller->fence_broken) response->metadata_length |= MAPLESU_EFFECT_QUARANTINED;
    return error;
}

static int msu_uid_readback(struct msu_uid_controller_slot *controller,
    const maplesu_management_v3 *operation, maplesu_response_owner_v3 *response,
    int (*validate)(void *), void *context)
{
    maplesu_uid_readback_v3 descriptor;
    struct msu_uid_snapshot_metadata metadata;
    struct msu_uid_snapshot *snapshot;
    struct msu_uid_snapshot_record *records;
    void *buffer = NULL;
    size_t bytes;
    int error;
    if (copy_from_user_nofault(&descriptor,
        (void __user *)(unsigned long)operation->data_user, sizeof(descriptor))) return -EFAULT;
    if (descriptor.reserved || descriptor.capacity > MSU_UID_SNAPSHOT_MAX_RECORDS ||
        !msu_uid_user_range(descriptor.destination_user, sizeof(maplesu_uid_metadata_v3) +
            (size_t)descriptor.capacity * sizeof(maplesu_uid_record_v3))) return -EINVAL;
    error = validate(context);
    if (error) return error;
    snapshot = msu_uid_snapshot_acquire(msu_uid_controller_state(controller));
    if (!snapshot) return -EAGAIN;
    error = msu_uid_snapshot_metadata(snapshot, &metadata);
    if (error) goto out;
    if (descriptor.expected_revision && descriptor.expected_revision != metadata.content_revision) {
        error = -ESTALE;
        goto out;
    }
    if (descriptor.capacity < metadata.count) { error = -ENOSPC; goto out; }
    bytes = sizeof(maplesu_uid_metadata_v3) + (size_t)metadata.count * sizeof(maplesu_uid_record_v3);
    buffer = kvmalloc(bytes, GFP_KERNEL);
    if (!buffer) { error = -ENOMEM; goto out; }
    records = (struct msu_uid_snapshot_record *)((char *)buffer + sizeof(maplesu_uid_metadata_v3));
    error = msu_uid_snapshot_readback(snapshot, &metadata, records, descriptor.capacity);
    if (error) goto out;
    memcpy(buffer, &metadata, sizeof(metadata));
    error = validate(context);
    if (error) goto out;
    /* Failure may have copied a user prefix. No successful completion or byte
     * count is inferred; the SDK publishes only its fully validated candidate. */
    if (copy_to_user_nofault((void __user *)(unsigned long)descriptor.destination_user, buffer, bytes)) {
        error = -EFAULT;
        goto out;
    }
    response->result = metadata.content_revision;
    response->metadata_address = controller->id;
out:
    kvfree(buffer);
    msu_uid_snapshot_put(snapshot);
    return error;
}

static int msu_uid_kernel_result(maplesu_response_owner_v3 *response, int error)
{
    response->status = error;
    return error;
}

int msu_uid_gateway_prepare_kernel(const maplesu_host_instance *host, u64 controller_id,
    const void *owner, const struct msu_uid_snapshot_record *records, u32 count,
    u64 expected_revision, maplesu_response_owner_v3 *response,
    int (*validate)(void *context), void *context)
{
    struct msu_uid_controller_slot *controller;
    maplesu_host_instance expected;
    int error, post_error;
    if (!response) return -EINVAL;
    memset(response, 0, sizeof(*response));
    if (!host || !controller_id || !owner || !validate || !expected_revision ||
        count > MSU_UID_SNAPSHOT_MAX_RECORDS || (count && !records))
        return msu_uid_kernel_result(response, -EINVAL);
    expected = *host;
    if (!(expected.low | expected.high)) return msu_uid_kernel_result(response, -EINVAL);
    if (!msu_uid_gateway_sleepable()) return msu_uid_kernel_result(response, -EWOULDBLOCK);
    error = validate(context);
    if (error) return msu_uid_kernel_result(response, error);
    mutex_lock(&msu_uid_gateway_lock);
    if (msu_uid_gateway_retiring) { error = -ESHUTDOWN; goto out; }
    error = validate(context);
    if (error) goto out;
    controller = msu_uid_controller(controller_id, expected);
    if (!controller) { error = -ESTALE; goto out; }
    if (controller->closed || controller->shutdown_pending) { error = -ESHUTDOWN; goto out; }
    if (controller->fence_broken) { error = -EUCLEAN; goto out; }
    error = msu_uid_stage(0, owner, controller, records, count, expected_revision,
        response, validate, context);
    post_error = validate(context);
    if (!error) error = post_error;
out:
    mutex_unlock(&msu_uid_gateway_lock);
    return msu_uid_kernel_result(response, error);
}

int msu_uid_gateway_commit_kernel(const maplesu_host_instance *host, u64 controller_id,
    const void *owner, u64 candidate_id, maplesu_response_owner_v3 *response,
    int (*validate)(void *context), void *context)
{
    struct msu_uid_controller_slot *controller;
    struct msu_uid_candidate_slot *candidate;
    maplesu_host_instance expected;
    int error, post_error;
    if (!response) return -EINVAL;
    memset(response, 0, sizeof(*response));
    if (!host || !controller_id || !owner || !candidate_id || !validate)
        return msu_uid_kernel_result(response, -EINVAL);
    expected = *host;
    if (!(expected.low | expected.high)) return msu_uid_kernel_result(response, -EINVAL);
    if (!msu_uid_gateway_sleepable()) return msu_uid_kernel_result(response, -EWOULDBLOCK);
    error = validate(context);
    if (error) return msu_uid_kernel_result(response, error);
    mutex_lock(&msu_uid_gateway_lock);
    if (msu_uid_gateway_retiring) { error = -ESHUTDOWN; goto out; }
    error = validate(context);
    if (error) goto out;
    controller = msu_uid_controller(controller_id, expected);
    if (!controller) { error = -ESTALE; goto out; }
    if (controller->closed || controller->shutdown_pending) { error = -ESHUTDOWN; goto out; }
    candidate = msu_uid_candidate_owned(candidate_id, 0, controller, owner);
    if (!candidate) { error = -ESTALE; goto out; }
    error = msu_uid_commit(controller, candidate, response, validate, context);
    post_error = validate(context);
    if (!error) error = post_error;
out:
    mutex_unlock(&msu_uid_gateway_lock);
    return msu_uid_kernel_result(response, error);
}

int msu_uid_gateway_cancel_kernel(const maplesu_host_instance *host, u64 controller_id,
    const void *owner, u64 candidate_id, maplesu_response_owner_v3 *response)
{
    struct msu_uid_controller_slot *controller;
    struct msu_uid_candidate_slot *candidate;
    maplesu_host_instance expected;
    int error = 0;
    if (!response) return -EINVAL;
    memset(response, 0, sizeof(*response));
    if (!host || !controller_id || !owner || !candidate_id)
        return msu_uid_kernel_result(response, -EINVAL);
    expected = *host;
    if (!(expected.low | expected.high)) return msu_uid_kernel_result(response, -EINVAL);
    if (!msu_uid_gateway_sleepable()) return msu_uid_kernel_result(response, -EWOULDBLOCK);
    mutex_lock(&msu_uid_gateway_lock);
    controller = msu_uid_controller(controller_id, expected);
    if (!controller) { error = -ESTALE; goto out; }
    candidate = msu_uid_candidate_owned(candidate_id, 0, controller, owner);
    if (!candidate) { error = -ESTALE; goto out; }
    msu_uid_candidate_drop(candidate);
    response->metadata_address = candidate_id;
    response->metadata_length = MAPLESU_EFFECT_REFERENCE_DROPPED;
out:
    mutex_unlock(&msu_uid_gateway_lock);
    return msu_uid_kernel_result(response, error);
}

int msu_uid_gateway_dispatch(u32 command, u64 session,
    const maplesu_management_v3 *operation, maplesu_response_owner_v3 *response,
    int (*validate)(void *context), void *context)
{
    struct msu_uid_controller_slot *controller;
    struct msu_uid_candidate_slot *candidate;
    int error, post_error;
    if (!session || !operation || !response || !validate ||
        !(operation->host.low | operation->host.high)) return -EINVAL;
    if (!msu_uid_gateway_sleepable()) return -EWOULDBLOCK;
    error = validate(context);
    if (error) return error;
    mutex_lock(&msu_uid_gateway_lock);
    error = validate(context);
    if (error) goto out;
    if (msu_uid_gateway_retiring && command != MAPLESU_REQUEST_UID_CANCEL) {
        error = -ESHUTDOWN;
        goto out;
    }
    if (command == MAPLESU_REQUEST_UID_CREATE) {
        error = msu_uid_create(operation, response, validate, context);
        goto post;
    }
    controller = msu_uid_controller(command == MAPLESU_REQUEST_UID_COMMIT ||
        command == MAPLESU_REQUEST_UID_CANCEL ? operation->address : operation->handle,
        operation->host);
    if (!controller) { error = -ESTALE; goto out; }
    if (command == MAPLESU_REQUEST_UID_SHUTDOWN) {
        error = msu_uid_shutdown(controller, response, validate, context);
        goto post;
    }
    if (controller->closed) { error = -ESHUTDOWN; goto out; }
    if (controller->fence_broken && command == MAPLESU_REQUEST_UID_PREPARE) {
        error = -EUCLEAN;
        goto out;
    }
    if (controller->shutdown_pending && command != MAPLESU_REQUEST_UID_CANCEL &&
        command != MAPLESU_REQUEST_UID_READBACK) { error = -ESHUTDOWN; goto out; }
    switch (command) {
    case MAPLESU_REQUEST_UID_PREPARE:
        error = msu_uid_prepare(session, controller, operation, response, validate, context);
        break;
    case MAPLESU_REQUEST_UID_COMMIT:
    case MAPLESU_REQUEST_UID_CANCEL:
        candidate = msu_uid_candidate(operation->handle, session, controller);
        if (!candidate) { error = -ESTALE; break; }
        if (command == MAPLESU_REQUEST_UID_CANCEL) {
            msu_uid_candidate_drop(candidate);
            response->metadata_address = operation->handle;
            response->metadata_length |= MAPLESU_EFFECT_REFERENCE_DROPPED;
            error = 0;
            break;
        }
        error = msu_uid_commit(controller, candidate, response, validate, context);
        break;
    case MAPLESU_REQUEST_UID_READBACK:
        error = msu_uid_readback(controller, operation, response, validate, context);
        break;
    default:
        error = -EOPNOTSUPP;
    }
post:
    post_error = validate(context);
    if (!error) error = post_error;
out:
    mutex_unlock(&msu_uid_gateway_lock);
    return error;
}

int msu_uid_gateway_close(u64 session, u32 *effects)
{
    unsigned int i;
    if (!session || !effects) return -EINVAL;
    if (!msu_uid_gateway_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&msu_uid_gateway_lock);
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i) {
        if (!msu_uid_candidates[i].snapshot || msu_uid_candidates[i].session != session) continue;
        msu_uid_candidate_drop(&msu_uid_candidates[i]);
        *effects |= MAPLESU_EFFECT_REFERENCE_DROPPED;
    }
    mutex_unlock(&msu_uid_gateway_lock);
    return 0;
}

int msu_uid_gateway_discard_host_unpublished(
    const maplesu_host_instance *host, u32 *effects)
{
    maplesu_host_instance expected;
    unsigned int i;
    int error, first_error = 0;
    if (!host || !effects) return -EINVAL;
    expected = *host;
    if (!(expected.low | expected.high)) return -EINVAL;
    if (!msu_uid_gateway_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&msu_uid_gateway_lock);
    /* The resident runtime is shared; do not retire another live host. */
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i) {
        struct msu_uid_controller_slot *controller = &msu_uid_controllers[i];
        if ((msu_uid_controller_state(controller) || controller->fence.owner) &&
            !msu_uid_host_equal(controller->host, expected)) {
            first_error = -EBUSY;
            goto pending;
        }
    }
    WRITE_ONCE(msu_uid_gateway_retiring, true);
    error = msu_uid_snapshot_runtime_discard();
    if (error && error != -EINPROGRESS) first_error = error;
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i) {
        struct msu_uid_candidate_slot *candidate = &msu_uid_candidates[i];
        if (!candidate->snapshot || !msu_uid_host_equal(candidate->controller->host, expected))
            continue;
        msu_uid_candidate_drop(candidate);
        *effects |= MAPLESU_EFFECT_REFERENCE_DROPPED;
    }
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i) {
        struct msu_uid_controller_slot *controller = &msu_uid_controllers[i];
        struct msu_uid_snapshot_state *state;
        maplesu_response_owner_v3 response = {0};
        if (!controller->id || !msu_uid_host_equal(controller->host, expected)) continue;
        state = msu_uid_controller_state(controller);
        if (!controller->shutdown_complete) {
            if (!state) {
                *effects |= MAPLESU_EFFECT_QUARANTINED;
                if (!first_error) first_error = -EUCLEAN;
                continue;
            }
            error = msu_uid_shutdown(controller, &response, NULL, NULL);
            *effects |= response.metadata_length;
            if (error) {
                if (!first_error) first_error = error;
                continue;
            }
        }
        if (state) {
            rcu_assign_pointer(controller->state, NULL);
            /* Covers lookup through state dereference and snapshot ref take. */
            synchronize_rcu();
            error = msu_uid_snapshot_state_destroy_quiesced(state);
            if (error) {
                rcu_assign_pointer(controller->state, state);
                if (!first_error) first_error = error;
                continue;
            }
        }
        if (controller->fence.owner) {
            error = controller->fence.retire(controller->fence.owner);
            if (error > 0) error = -EIO;
            if (error) {
                if (!first_error) first_error = error;
                continue;
            }
            /* Successful retire may have freed owner and callback storage. */
            memset(&controller->fence, 0, sizeof(controller->fence));
        }
    }
    error = msu_uid_snapshot_runtime_discard();
    if (!first_error) first_error = error;
    if (first_error) goto pending;
    *effects |= MAPLESU_EFFECT_RELEASED;
    mutex_unlock(&msu_uid_gateway_lock);
    return 0;
pending:
    *effects |= MAPLESU_EFFECT_PENDING;
    mutex_unlock(&msu_uid_gateway_lock);
    return first_error;
}

struct msu_uid_snapshot *msu_uid_gateway_acquire(const maplesu_host_instance *host,
    u64 controller_id)
{
    struct msu_uid_snapshot *snapshot = NULL;
    maplesu_host_instance expected;
    unsigned int i;
    if (!host || !controller_id) return NULL;
    expected = *host;
    if (!(expected.low | expected.high)) return NULL;
    rcu_read_lock();
    if (READ_ONCE(msu_uid_gateway_retiring)) goto out;
    for (i = 0; i < MSU_UID_GATEWAY_SLOTS; ++i) {
        struct msu_uid_controller_slot *controller = &msu_uid_controllers[i];
        struct msu_uid_snapshot_state *state;
        if (smp_load_acquire(&controller->id) != controller_id) continue;
        if (!msu_uid_host_equal(controller->host, expected)) break;
        state = rcu_dereference(controller->state);
        snapshot = msu_uid_snapshot_acquire(state);
        break;
    }
out:
    rcu_read_unlock();
    return snapshot;
}
