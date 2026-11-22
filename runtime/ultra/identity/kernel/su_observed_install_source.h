// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_OBSERVED_INSTALL_SOURCE_H
#define MAPLESU_SU_OBSERVED_INSTALL_SOURCE_H
#include "su_install_registry.h"
struct msu_su_observed_provider;
/* Complete kernel-private producer facts; CORE projects them through its one
 * existing typed protocol. No controller/candidate here is a user capability. */
struct msu_su_observed_publication_receipt {
    maplesu_response_owner_v3 prepare, commit, cancel;
    u64 candidate_before, candidate_after;
    int status, cleanup_error;
    bool prepare_attempted, commit_attempted, cancel_attempted, uncertain;
};
struct msu_su_observed_sync_receipt {
    u32 full_uid, effects;
    int status, revoke_status, refresh_status;
    bool revoke_attempted, refresh_attempted, unchanged;
    struct msu_su_revoke_receipt revoke;
    maplesu_uid_record_v3 refreshed;
    struct msu_su_observed_publication_receipt previous, publication;
    u64 committed_revision;
    u32 scanned_uids, failed_uid;
};
/* Existing authenticated durable authority adapter, never a new grant store.
 * Caller owns one reference; create consumes it only on success. */
struct msu_su_observed_authority {
    const void *owner;
    int (*read_grant)(const void *owner,
        const struct msu_su_verified_install *installation,
        struct msu_su_saved_grant *grant);
    void (*put_owner)(const void *owner);
    int (*list_uids)(const void *owner, u32 *uids, u32 capacity, u32 *count);
    char directory[24];
    char filename[32];
};
int msu_su_observed_create(const maplesu_host_instance *host, u64 controller,
    const struct msu_su_observed_authority *authority,
    struct msu_su_observed_provider **provider, struct msu_su_registry **registry);
/* Actual post-fs-data producer supplies fullUIDs from the same durable store.
 * May return PENDING while old credential leases drain; never replays an
 * unknown snapshot commit. Repeated explicit refresh retries only known refs. */
int msu_su_observed_start(struct msu_su_observed_provider *provider,
    const u32 *full_uids, u32 count);
int msu_su_observed_refresh(struct msu_su_observed_provider *provider, u32 full_uid);
/* Authenticated slow path after the sole durable transaction. The caller's
 * validator is synchronous, kernel-only and mandatory; never called under
 * provider.operation. A retained known candidate is explicitly cancelled on
 * this new call before scanning current authority. Unknown completion is not
 * retried. full_uid=0 reloads the complete sole authority, then scans its union
 * with tracked tombstones; individual publications are not a table-wide atomic
 * transaction. The first error, earlier committed revision and all actual
 * effects survive. Every negative result keeps all earlier effects. */
int msu_su_observed_sync(struct msu_su_observed_provider *provider, u32 full_uid,
    int (*validate)(void *), void *context,
    struct msu_su_observed_sync_receipt *receipt);
/* Factory closes external entry/API admission first. Nonblocking and monotonic;
 * source.quiesce returns PENDING until queued/running workers have returned. */
void msu_su_observed_close(struct msu_su_observed_provider *provider);
int msu_su_observed_match_saved_member(const struct msu_su_verified_install *installation,
    const char *package,u64 first_install_ms,const u8 (*signers)[32],u32 signer_count);
#endif
