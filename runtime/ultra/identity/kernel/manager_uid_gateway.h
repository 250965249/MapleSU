// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_UID_GATEWAY_H
#define MAPLESU_MANAGER_UID_GATEWAY_H

#include <linux/types.h>
#include "request_protocol.h"

struct msu_uid_snapshot;
struct msu_uid_snapshot_record;

/* Kernel-only factory binding. The owner and callback code stay live through
 * successful retire, including all error/pending continuations.
 * check_closed proves the real reader's initial admission is closed and old
 * leases are drained; the factory keeps it unexposed through bind. Only the
 * initial empty revision 1 can bind, once, with no replacement/unbind bypass.
 * begin validates the exact prepared kernel snapshot against real installation
 * and Profile pins, and reserves its producer so refresh cannot reopen old
 * admission before finish. Success returns a non-NULL owned transaction. The
 * candidate is NULL only for shutdown, whose expected revision is the actual
 * last committed revision, retained after unpublish. Every shutdown begin must
 * close/check all real provider gates and leases, including explicit continuation
 * after a consumed finish token returned an error; an absent old snapshot is
 * never proof of drain. begin failure may return a token for error-only finish.
 * revoke closes this fullUID's real admission before returning. Zero proves
 * its old credential leases drained; -EINPROGRESS retains the staged update.
 * finish consumes its token exactly once after commit/shutdown or a pre-error;
 * commit_error is that primitive's result, never a later request/delivery error.
 * It releases producer exclusion while keeping failed grants closed. No unknown
 * commit is retried or rolled back. A missing/leaked token quarantines this
 * binding; retained provider state is never reported as drained or discarded.
 * retire is mandatory. Only after shutdown/finish succeed, controller state is
 * withdrawn and its outer RCU readers finish may it destroy the real registry,
 * installation/source refs and entry/context gates. Zero proves no current or
 * future provider entry and all its callbacks have returned, not merely users=0.
 * An error retains a live owner and supports explicit drain continuation. On
 * zero the binding is cleared immediately without another owner/callback read.
 * Callbacks run under gateway mutex (and a Manager session mutex for dispatch),
 * without snapshot mutation/publication locks. Slow producer work may sleep,
 * but no callback waits for leases, enters gateway/session, or takes a reverse
 * lock. retire also must not enter host discard, whose outer mutex may be held.
 * No user callback or non-NULL owner pointer grants SU authority. */
struct msu_uid_reader_fence {
    const void *owner;
    int (*check_closed)(const void *owner);
    int (*begin)(const void *owner, const struct msu_uid_snapshot *candidate,
        u64 expected_revision, bool shutdown, void **transaction);
    int (*revoke)(const void *owner, u32 full_uid);
    int (*finish)(const void *owner, void **transaction, int commit_error);
    int (*retire)(const void *owner);
};

/* Same private controller construction as UID_CREATE, with the factory's own
 * actual validator and no Manager session. Outputs start at zero and retain
 * ALLOCATED/COMMITTED facts on later errors; created controllers are boot-owned.
 * This creates storage, not a reader binding or installation qualification. */
int msu_uid_gateway_create_kernel(const maplesu_host_instance *host,
    int (*validate)(void *context), void *context,
    u64 *controller_id, u64 *revision, u32 *effects);
int msu_uid_gateway_bind_reader(const maplesu_host_instance *host, u64 controller_id,
    const struct msu_uid_reader_fence *fence);

/* Kernel-only producers share the exact staged table and commit/fence path.
 * owner identifies a real retained producer object, remains live and unreused
 * until its candidates are consumed/cancelled or host discard returns zero,
 * and is not itself a qualification. Stable records and the actual validator
 * remain mandatory. A non-NULL response starts at zero and its status always
 * equals the returned native result; completed effects survive later errors.
 * PENDING without COMMITTED/REFERENCE_DROPPED retains the
 * candidate for explicit continuation; no unknown commit is replayed.
 * Cancel drops only this owner's staged ref and
 * remains available during retirement. No Manager session or Key is required. */
int msu_uid_gateway_prepare_kernel(const maplesu_host_instance *host, u64 controller_id,
    const void *owner, const struct msu_uid_snapshot_record *records, u32 count,
    u64 expected_revision, maplesu_response_owner_v3 *response,
    int (*validate)(void *context), void *context);
int msu_uid_gateway_commit_kernel(const maplesu_host_instance *host, u64 controller_id,
    const void *owner, u64 candidate_id, maplesu_response_owner_v3 *response,
    int (*validate)(void *context), void *context);
int msu_uid_gateway_cancel_kernel(const maplesu_host_instance *host, u64 controller_id,
    const void *owner, u64 candidate_id, maplesu_response_owner_v3 *response);

/* Called only by the same authenticated management gateway, while its current
 * session operation mutex is held. The actual validator is mandatory and must
 * retain the current task/mm/exec/active-cred/owner checks. Neither a session ID
 * nor stored scalar installation/Profile revisions confer a qualification.
 * Sleepable lock order: session -> gateway -> snapshot state -> candidate.
 * Bound reader revocation precedes a grant's deny/removal/installation or
 * Profile-revision replacement, and every granted row before SHUTDOWN. A
 * pre-primitive pending/error leaves the old snapshot and candidate unchanged;
 * result=0, metadata_address=controller ID and PENDING report the real fence
 * attempt. Only explicit re-invocation continues, with no automatic retry.
 * SHUTDOWN also blocks new PREPARE/COMMIT while its drain remains pending.
 * Unbound controllers remain generic storage with no SU drain promise.
 * Response effects/result survive a post-operation validation/finish error,
 * including a completed commit and its consumed candidate. A failed finish
 * keeps PENDING, plus QUARANTINED for broken token ownership. No error permits
 * an automatic mutation retry. */
int msu_uid_gateway_dispatch(u32 command, u64 session,
    const maplesu_management_v3 *operation, maplesu_response_owner_v3 *response,
    int (*validate)(void *context), void *context);

/* Trusted CLOSE/exec/revoke cleanup drops this session's staged candidates.
 * Committed controllers/snapshots retain their independent boot ownership.
 * This releases references, not an RCU/work or SU credential drain. */
int msu_uid_gateway_close(u64 session, u32 *effects);

/* Only the unpublished host owner may call this after closing its own entry
 * paths and releasing management/session/service locks. It irreversibly closes
 * resident UID admission, drops staged refs, performs the same real shutdown,
 * withdraws/free states after an outer RCU grace period, and retires providers.
 * Held snapshots or provider/token errors retain the host with PENDING (and
 * QUARANTINED for broken ownership). Explicit re-invocation continues draining.
 * Zero additionally proves final snapshot RCU/work callbacks have returned and
 * no future caller can enter this resident. effects accumulates actual facts. */
int msu_uid_gateway_discard_host_unpublished(
    const maplesu_host_instance *host, u32 *effects);

/* Kernel-only memory lookup for a real P7 consumer in RCU-watching context.
 * The caller supplies stable kernel host storage. This bounded lookup neither
 * sleeps nor consults a Manager/session or performs I/O. It returns one held
 * immutable snapshot ref; release it with msu_uid_snapshot_put(). NULL includes
 * unknown ID/host, closed state or a raced retirement and means unknown, not a
 * cached denial. This is not installation/Profile verification or SU authority;
 * the consumer must still hold/check its actual trusted providers and refs. */
struct msu_uid_snapshot *msu_uid_gateway_acquire(const maplesu_host_instance *host,
    u64 controller_id);

#endif
