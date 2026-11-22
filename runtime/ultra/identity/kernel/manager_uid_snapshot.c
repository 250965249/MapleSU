// SPDX-License-Identifier: GPL-3.0-only
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include "manager_uid_snapshot.h"

struct msu_uid_snapshot_state {
    struct mutex mutation;
    struct msu_uid_snapshot __rcu *published_snapshot;
    maplesu_host_instance host;
    u64 revision;
    bool closed;
};

struct msu_uid_snapshot {
    struct mutex publication;
    refcount_t references;
    struct rcu_head reclaim_rcu;
    struct work_struct reclaim_work;
    struct msu_uid_snapshot_metadata metadata;
    bool published;
    struct msu_uid_snapshot_record records[];
};

static atomic_t msu_uid_snapshot_states = ATOMIC_INIT(0);
static atomic_t msu_uid_snapshots_live = ATOMIC_INIT(0);
static DEFINE_MUTEX(msu_uid_snapshot_runtime_lock);
static struct workqueue_struct *msu_uid_snapshot_reclaim_queue;
static bool msu_uid_snapshot_runtime_closed;

/* Native callback signatures; actual target KCFI identities require compiled evidence. */
void msu_uid_snapshot_reclaim_work(struct work_struct *work);
void msu_uid_snapshot_reclaim_rcu(struct rcu_head *head);
_Static_assert(__builtin_types_compatible_p(typeof(&msu_uid_snapshot_reclaim_work),
    void (*)(struct work_struct *)), "UID snapshot work callback type");
_Static_assert(__builtin_types_compatible_p(typeof(&msu_uid_snapshot_reclaim_rcu),
    rcu_callback_t), "UID snapshot RCU callback type");
_Static_assert(sizeof(struct msu_uid_snapshot_record) == 280, "UID snapshot record layout");

static bool msu_uid_snapshot_sleepable(void)
{
    return in_task() && !in_atomic() && !irqs_disabled();
}

void msu_uid_snapshot_reclaim_work(struct work_struct *work)
{
    struct msu_uid_snapshot *snapshot = container_of(work,
        struct msu_uid_snapshot, reclaim_work);
    kvfree(snapshot);
    atomic_dec(&msu_uid_snapshots_live);
}

void msu_uid_snapshot_reclaim_rcu(struct rcu_head *head)
{
    struct msu_uid_snapshot *snapshot = container_of(head,
        struct msu_uid_snapshot, reclaim_rcu);
    /* kvfree may release vmalloc memory; keep it out of the RCU callback. */
    queue_work(READ_ONCE(msu_uid_snapshot_reclaim_queue), &snapshot->reclaim_work);
}

void msu_uid_snapshot_put(struct msu_uid_snapshot *snapshot)
{
    if (snapshot && refcount_dec_and_test(&snapshot->references))
        call_rcu(&snapshot->reclaim_rcu, msu_uid_snapshot_reclaim_rcu);
}

void msu_uid_snapshot_cancel(struct msu_uid_snapshot **candidate)
{
    struct msu_uid_snapshot *snapshot;
    if (!candidate) return;
    snapshot = *candidate;
    *candidate = NULL;
    msu_uid_snapshot_put(snapshot);
}

int msu_uid_snapshot_state_create(const maplesu_host_instance *host,
    struct msu_uid_snapshot_state **output)
{
    struct msu_uid_snapshot_state *state;
    int error = 0;
    if (!host || !output || !(host->low | host->high)) return -EINVAL;
    if (!msu_uid_snapshot_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&msu_uid_snapshot_runtime_lock);
    if (msu_uid_snapshot_runtime_closed) error = -ESHUTDOWN;
    else if (!atomic_add_unless(&msu_uid_snapshot_states, 1, MSU_UID_SNAPSHOT_MAX_STATES))
        error = -ENOSPC;
    mutex_unlock(&msu_uid_snapshot_runtime_lock);
    if (error) return error;
    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state) {
        atomic_dec(&msu_uid_snapshot_states);
        return -ENOMEM;
    }
    mutex_init(&state->mutation);
    state->host = *host;
    *output = state;
    return 0;
}

static int msu_uid_snapshot_validate(const struct msu_uid_snapshot_record *records, u32 count)
{
    u32 i;
    if (count > MSU_UID_SNAPSHOT_MAX_RECORDS || (count && !records)) return -EINVAL;
    for (i = 0; i < count; ++i) {
        if (records[i].full_uid == ~0U || records[i].decision > 1 ||
            !records[i].installation_generation || !records[i].profile_revision ||
            (i && records[i - 1].full_uid >= records[i].full_uid) ||
            !memchr(records[i].package, 0, sizeof(records[i].package))) return -EINVAL;
    }
    return 0;
}

int msu_uid_snapshot_prepare(const struct msu_uid_snapshot_record *records, u32 count,
    struct msu_uid_snapshot **output)
{
    struct msu_uid_snapshot *snapshot;
    size_t bytes;
    u32 i;
    int error;
    if (!output) return -EINVAL;
    if (!msu_uid_snapshot_sleepable()) return -EWOULDBLOCK;
    error = msu_uid_snapshot_validate(records, count);
    if (error) return error;
    mutex_lock(&msu_uid_snapshot_runtime_lock);
    if (msu_uid_snapshot_runtime_closed) error = -ESHUTDOWN;
    else if (!msu_uid_snapshot_reclaim_queue) {
        msu_uid_snapshot_reclaim_queue = alloc_workqueue("maplesu_uid_reclaim",
            WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
        if (!msu_uid_snapshot_reclaim_queue) error = -ENOMEM;
    }
    /* This reservation also covers an allocation still in flight at close. */
    if (!error) atomic_inc(&msu_uid_snapshots_live);
    mutex_unlock(&msu_uid_snapshot_runtime_lock);
    if (error) return error;
    bytes = sizeof(*snapshot) + (size_t)count * sizeof(*records);
    snapshot = kvmalloc(bytes, GFP_KERNEL);
    if (!snapshot) { atomic_dec(&msu_uid_snapshots_live); return -ENOMEM; }
    memset(snapshot, 0, sizeof(*snapshot));
    if (count) memcpy(snapshot->records, records, (size_t)count * sizeof(*records));
    error = msu_uid_snapshot_validate(snapshot->records, count);
    if (error) { kvfree(snapshot); atomic_dec(&msu_uid_snapshots_live); return error; }
    for (i = 0; i < count; ++i) {
        char *end = memchr(snapshot->records[i].package, 0, sizeof(snapshot->records[i].package));
        memset(end + 1, 0, sizeof(snapshot->records[i].package) -
            (size_t)(end - snapshot->records[i].package) - 1);
    }
    mutex_init(&snapshot->publication);
    refcount_set(&snapshot->references, 1);
    INIT_WORK(&snapshot->reclaim_work, msu_uid_snapshot_reclaim_work);
    snapshot->metadata.schema = MSU_UID_SNAPSHOT_SCHEMA;
    snapshot->metadata.count = count;
    snapshot->metadata.record_bytes = sizeof(*records);
    *output = snapshot;
    return 0;
}

int msu_uid_snapshot_commit(struct msu_uid_snapshot_state *state,
    struct msu_uid_snapshot **candidate, u64 expected_revision, u64 *new_revision)
{
    struct msu_uid_snapshot *snapshot, *old = NULL;
    u64 revision;
    int error = 0;
    if (!state || !candidate || !*candidate || !new_revision) return -EINVAL;
    if (!msu_uid_snapshot_sleepable()) return -EWOULDBLOCK;
    snapshot = *candidate;
    /* Each commit holds one state and one candidate; no reverse lock path. */
    mutex_lock(&state->mutation);
    mutex_lock(&snapshot->publication);
    if (state->closed) { error = -ESHUTDOWN; goto out; }
    if (state->revision != expected_revision) { error = -EAGAIN; goto out; }
    if (state->revision == ~0ULL) { error = -EOVERFLOW; goto out; }
    if (snapshot->published) { error = -EBUSY; goto out; }
    revision = state->revision + 1;
    snapshot->metadata.host = state->host;
    snapshot->metadata.content_revision = revision;
    snapshot->published = true;
    old = rcu_dereference_protected(state->published_snapshot, lockdep_is_held(&state->mutation));
    rcu_assign_pointer(state->published_snapshot, snapshot);
    state->revision = revision;
    *candidate = NULL;
    *new_revision = revision;
out:
    mutex_unlock(&snapshot->publication);
    mutex_unlock(&state->mutation);
    msu_uid_snapshot_put(old);
    return error;
}

struct msu_uid_snapshot *msu_uid_snapshot_acquire(struct msu_uid_snapshot_state *state)
{
    struct msu_uid_snapshot *snapshot;
    if (!state) return NULL;
    rcu_read_lock();
    snapshot = rcu_dereference(state->published_snapshot);
    if (snapshot && !refcount_inc_not_zero(&snapshot->references)) snapshot = NULL;
    rcu_read_unlock();
    return snapshot;
}

int msu_uid_snapshot_metadata(const struct msu_uid_snapshot *snapshot,
    struct msu_uid_snapshot_metadata *output)
{
    if (!snapshot || !output) return -EINVAL;
    *output = snapshot->metadata;
    return 0;
}

int msu_uid_snapshot_readback(const struct msu_uid_snapshot *snapshot,
    struct msu_uid_snapshot_metadata *metadata, struct msu_uid_snapshot_record *records,
    u32 capacity)
{
    if (!snapshot || !metadata || (snapshot->metadata.count && !records)) return -EINVAL;
    if (capacity < snapshot->metadata.count) return -ENOSPC;
    if (snapshot->metadata.count)
        memcpy(records, snapshot->records, (size_t)snapshot->metadata.count * sizeof(*records));
    *metadata = snapshot->metadata;
    return 0;
}

int msu_uid_snapshot_record_at(const struct msu_uid_snapshot *snapshot, u32 index,
    struct msu_uid_snapshot_record *output)
{
    if (!snapshot || !output) return -EINVAL;
    if (index >= snapshot->metadata.count) return -ENOENT;
    *output = snapshot->records[index];
    return 0;
}

int msu_uid_snapshot_lookup(const struct msu_uid_snapshot *snapshot, u32 full_uid,
    u64 trusted_current_installation_generation, struct msu_uid_snapshot_record *output)
{
    u32 low = 0, high, middle;
    const struct msu_uid_snapshot_record *record;
    if (!snapshot || !output || full_uid == ~0U || !trusted_current_installation_generation)
        return -EINVAL;
    high = snapshot->metadata.count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (snapshot->records[middle].full_uid < full_uid) low = middle + 1;
        else high = middle;
    }
    if (low == snapshot->metadata.count || snapshot->records[low].full_uid != full_uid)
        return -ENOENT;
    record = &snapshot->records[low];
    if (record->installation_generation != trusted_current_installation_generation) return -ESTALE;
    *output = *record;
    return 0;
}

int msu_uid_snapshot_state_shutdown(struct msu_uid_snapshot_state *state)
{
    struct msu_uid_snapshot *old;
    if (!state) return -EINVAL;
    if (!msu_uid_snapshot_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&state->mutation);
    state->closed = true;
    old = rcu_dereference_protected(state->published_snapshot, lockdep_is_held(&state->mutation));
    rcu_assign_pointer(state->published_snapshot, NULL);
    mutex_unlock(&state->mutation);
    msu_uid_snapshot_put(old);
    return 0;
}

/* The owner has already removed every external state pointer and waited for
 * its complete reader window. Snapshot refs do not dereference their state. */
int msu_uid_snapshot_state_destroy_quiesced(struct msu_uid_snapshot_state *state)
{
    bool busy;
    if (!state) return -EINVAL;
    if (!msu_uid_snapshot_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&state->mutation);
    busy = !state->closed || rcu_access_pointer(state->published_snapshot);
    mutex_unlock(&state->mutation);
    if (busy) return -EBUSY;
    kfree(state);
    atomic_dec(&msu_uid_snapshot_states);
    return 0;
}

/* Closing admission is irreversible for this resident. A nonzero live count
 * includes held refs, queued RCU and work; it is never reset to manufacture a
 * drain. Queue destruction waits past the last callback's return instruction. */
int msu_uid_snapshot_runtime_discard(void)
{
    int error = 0;
    if (!msu_uid_snapshot_sleepable()) return -EWOULDBLOCK;
    mutex_lock(&msu_uid_snapshot_runtime_lock);
    msu_uid_snapshot_runtime_closed = true;
    /* Reclaim already-put objects now; only real held/in-flight refs remain. */
    rcu_barrier();
    if (msu_uid_snapshot_reclaim_queue)
        flush_workqueue(msu_uid_snapshot_reclaim_queue);
    if (atomic_read(&msu_uid_snapshot_states) || atomic_read(&msu_uid_snapshots_live)) {
        error = -EINPROGRESS;
        goto out;
    }
    rcu_barrier();
    if (msu_uid_snapshot_reclaim_queue) {
        destroy_workqueue(msu_uid_snapshot_reclaim_queue);
        msu_uid_snapshot_reclaim_queue = NULL;
    }
out:
    mutex_unlock(&msu_uid_snapshot_runtime_lock);
    return error;
}
