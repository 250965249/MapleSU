// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_NONROOT_MOUNT_SOURCE_H
#define MAPLESU_SU_NONROOT_MOUNT_SOURCE_H
#include "su_nonroot_transition.h"

struct msu_su_nonroot_mount_source;
#define MSU_SU_NONROOT_MOUNT_MAX_ENTRIES 1024U
#define MSU_SU_NONROOT_MOUNT_MAX_BYTES (256U * 1024U)

/* Factory-only construction. boot_cred is the factory's real held native
 * credential, borrowed here; success takes its OWN reference. No init_cred,
 * new grant or per-app disk read. Initially publishes an empty idle snapshot.
 * Factory retains this owner through every external call and successful destroy. */
int msu_su_nonroot_mount_source_create(const maplesu_host_instance *host,
    const struct cred *boot_cred, struct msu_su_nonroot_mount_source **output);
/* Slow post-fs-data/manual event producer. Native fsnotify also refreshes on
 * ledger/boot/ancestor events using the existing system workqueue, never polling.
 * A concurrent producer returns EINPROGRESS; errors invalidate old admission. */
int msu_su_nonroot_mount_source_refresh(struct msu_su_nonroot_mount_source *source);
/* Same sleepable task, AFTER original setresuid. Reads current fullUID/policy.
 * 0 + NULL means no action (default/Disabled/granted, Manager skip, empty list).
 * No disk here. Publishes layer fingerprints only after Enabled; action resolves
 * each actual child top immediately before consuming that layer.
 * Caller already holds the real factory runtime.users/registry reference. */
int msu_su_nonroot_mount_source_take(struct msu_su_nonroot_mount_source *source,
    struct msu_su_registry *registry, struct msu_su_nonroot_mounts **output);
/* Always after action, also on error. Drops only non-consumed paths plus all
 * snapshot/cred/namespace/source execution refs. NULL is an idle no-op. */
void msu_su_nonroot_mount_source_put(struct msu_su_nonroot_mount_source *source,
    struct msu_su_nonroot_mounts *mounts);
/* Close is nonblocking/monotonic and invalidates old action generations.
 * Quiesce is sleepable, does not wait on readers/producer locks; EINPROGRESS
 * retains the owner. destroy consumes *source only on actual successful drain.
 * Close external factory admission before destroy; no automatic retry thread. */
void msu_su_nonroot_mount_source_close(struct msu_su_nonroot_mount_source *source);
int msu_su_nonroot_mount_source_quiesce(struct msu_su_nonroot_mount_source *source);
int msu_su_nonroot_mount_source_destroy(struct msu_su_nonroot_mount_source **source);

/* Small SU proposal, implemented in the exact registry before/after evidence.
 * Protected known Manager member names cause only conservative no-action.
 * No signature Root identity, grant, claim or new startup qualification. */
int msu_su_registry_non_root_skip_manager(struct msu_su_registry *registry, bool *skip);
#endif
