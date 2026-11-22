// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_UID_SNAPSHOT_H
#define MAPLESU_MANAGER_UID_SNAPSHOT_H

#include <linux/types.h>
#include "request_protocol.h"

#define MSU_UID_SNAPSHOT_SCHEMA 1U
#define MSU_UID_SNAPSHOT_MAX_RECORDS 4095U
#define MSU_UID_SNAPSHOT_MAX_STATES 64U

struct msu_uid_snapshot_state;
struct msu_uid_snapshot;

/* Kernel-private data, not a grant or a complete KSU Profile. Generation and
 * profile_revision are scalar identifiers supplied by real P7 providers; this
 * module neither authenticates nor pins the external installation/Profile
 * objects. P7 must later hold actual object refs until snapshot reclamation,
 * or provide a boot-stable, nonreused registry lifetime contract. Package is
 * display text only. Records are strictly ordered by full_uid, including denials. */
struct msu_uid_snapshot_record {
    u32 full_uid, decision;
    u64 installation_generation, profile_revision;
    char package[256];
};

struct msu_uid_snapshot_metadata {
    u32 schema, count, record_bytes, reserved;
    u64 content_revision;
    maplesu_host_instance host;
};

/* All pointer inputs/outputs are stable kernel memory. Out parameters remain
 * unchanged on errors. The owner guarantees state lifetime through every raw
 * reader/writer and closes all such entry paths before quiesced destruction.
 * A successful create occupies one of 64 concurrent state reservations;
 * allocation failure/destruction returns it, shutdown does not recycle it.
 * Create/prepare/commit/shutdown require sleepable task context. No Manager
 * epoch, user role, Key or SU qualification enters the stored state. */
int msu_uid_snapshot_state_create(const maplesu_host_instance *host,
    struct msu_uid_snapshot_state **output);

/* Validate the complete stable input before allocation, copy then revalidate,
 * and clear bytes after each package's first NUL. The caller prevents concurrent
 * input mutation; revalidation does not repair a kernel data race or ABA.
 * Count zero prepares an empty snapshot. The candidate owns one independent ref. */
int msu_uid_snapshot_prepare(const struct msu_uid_snapshot_record *records, u32 count,
    struct msu_uid_snapshot **output);

/* Content revision starts at zero. One successful publish per snapshot, even
 * across controllers. Success transfers the candidate ref to current, consumes
 * *candidate and publishes the new revision; failure preserves both outputs.
 * Each candidate variable must own a live ref and be exclusive to its caller. */
int msu_uid_snapshot_commit(struct msu_uid_snapshot_state *state,
    struct msu_uid_snapshot **candidate, u64 expected_revision, u64 *new_revision);

/* Normal RCU-watching caller context only. Takes a ref inside the RCU section,
 * exits RCU before returning, and never sleeps. NULL means no snapshot was
 * acquired, including close or a raced retirement; it is not an authorization
 * decision. P7 must treat it as unknown/reacquire under its reader contract,
 * never as a cached deny. Held snapshots remain immutable and readable after
 * replacement or shutdown. Release every successful acquire once. */
struct msu_uid_snapshot *msu_uid_snapshot_acquire(struct msu_uid_snapshot_state *state);
void msu_uid_snapshot_put(struct msu_uid_snapshot *snapshot);
void msu_uid_snapshot_cancel(struct msu_uid_snapshot **candidate);

/* Caller owns a snapshot ref and separate output storage. Metadata reports
 * that held snapshot's revision, which need not remain the controller's latest.
 * Prepared metadata has revision/host zero. Readback copies the complete table
 * only when capacity suffices; no partial successful output is reported. */
int msu_uid_snapshot_metadata(const struct msu_uid_snapshot *snapshot,
    struct msu_uid_snapshot_metadata *output);
int msu_uid_snapshot_readback(const struct msu_uid_snapshot *snapshot,
    struct msu_uid_snapshot_metadata *metadata, struct msu_uid_snapshot_record *records,
    u32 capacity);

/* One immutable row from the caller's held snapshot, including a prepared
 * candidate. No allocation, lookup qualification or partial output on error. */
int msu_uid_snapshot_record_at(const struct msu_uid_snapshot *snapshot, u32 index,
    struct msu_uid_snapshot_record *output);

/* Bounded binary lookup and generation equality only. The generation must come
 * from P7's trusted current-installation provider; a caller-supplied integer is
 * not proof. Returns denial rows too. Grant/cred validation belongs to P7. */
int msu_uid_snapshot_lookup(const struct msu_uid_snapshot *snapshot, u32 full_uid,
    u64 trusted_current_installation_generation, struct msu_uid_snapshot_record *output);

/* Idempotently close commits and unpublish current. Acquires already observing
 * the old pointer may finish with a held ref. Snapshot callbacks/held readers
 * and SU credential transactions are not drained by this return. */
int msu_uid_snapshot_state_shutdown(struct msu_uid_snapshot_state *state);

/* Caller has closed every raw state entry, withdrawn every external pointer,
 * and waited through the complete RCU lookup-to-ref window. Only a shutdown,
 * unpublished state is freed; held snapshots no longer dereference the state. */
int msu_uid_snapshot_state_destroy_quiesced(struct msu_uid_snapshot_state *state);

/* Irreversibly close create/prepare admission for this resident. Zero proves
 * all state/snapshot allocations are physically freed, all queued RCU callbacks
 * returned and the private reclaim queue is destroyed. Live refs/allocation
 * reservations return -EINPROGRESS without clearing counters. The owner must
 * separately close every future raw caller before unloading resident code. */
int msu_uid_snapshot_runtime_discard(void);

#endif
