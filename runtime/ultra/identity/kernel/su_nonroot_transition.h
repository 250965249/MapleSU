// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_SU_NONROOT_TRANSITION_H
#define MAPLESU_SU_NONROOT_TRANSITION_H
#include <linux/atomic.h>
#include <linux/path.h>
#include "request_protocol.h"

struct cred;
struct mnt_namespace;
struct msu_su_registry;

enum msu_su_nonroot_class {
    MSU_SU_NONROOT_UNKNOWN, MSU_SU_NONROOT_APP, MSU_SU_NONROOT_MANAGER,
};

struct msu_su_nonroot_mount {
    const char *name;
    /* Only the single currently resolved child layer owns a transient path.
     * Source publishes fingerprints, never duplicated top-layer references. */
    struct path path;
    int flags;
    u64 device, inode;
    u32 inode_generation;
};

/* Kernel-private input from su_nonroot_mount_source.c. Caller retains the
 * real runtime.users/registry, immutable source snapshot, boot cred and child,
 * actual parent and PID1 namespace facts until action + put finish.
 * Filesystem events/refresh invalidate nonreused generations; this does not
 * claim an atomic shell mount/PMS transaction or pre-mutation observation.
 * Entries retain reverse ledger order, including distinct IDs at one name.
 * Global IDs are provenance only. Each child layer is resolved immediately
 * before its operation and checked against that layer's source fingerprint.
 * path_umount consumes its argument on ALL native results; action clears the
 * transient slot before handing it over. put drops any remaining owned slot.
 * Native target/import qualification and device effects are separate facts. */
struct msu_su_nonroot_mounts {
    struct msu_su_registry *registry;
    maplesu_installation_state_v3 installation;
    const atomic64_t *live_generation;
    u64 generation;
    u32 full_uid;
    enum msu_su_nonroot_class classification;
    struct mnt_namespace *mnt_ns, *zygote_ns, *global_ns;
    const struct cred *cred;
    struct msu_su_nonroot_mount *entries;
    u32 count;
};

enum msu_su_nonroot_effect {
    /* Native MS_PRIVATE|MS_REC completed; does not assert a new change. */
    MSU_SU_NONROOT_PRIVATE_COMPLETED = 1U << 0,
    MSU_SU_NONROOT_UNMOUNTED = 1U << 1,
    MSU_SU_NONROOT_COMPLETED = 1U << 2,
};
struct msu_su_nonroot_receipt {
    u32 full_uid, policy, effects, attempted, unmounted, index;
    int error, operation_error, validation_error;
};

/* Invoke ONLY after the original setresuid returns, in the same sleepable task.
 * Read the committed current UID; never classify from syscall input arguments.
 * A failed syscall, unchanged UID, non-app UID, DEFAULT, DISABLED, Manager or
 * granted path performs no mount/namespace/SELinux operation. DEFAULT stays
 * idle; this TU does not turn on KSU's global umount default or isolated bypass.
 * Explicit ENABLED without a real MODULE source returns ENODATA without effects.
 * The return value is the side action's status. HOST must always preserve the
 * original syscall result. All partial effects/native errno survive errors.
 * Read/check/native-call races are not an atomic PMS or mount transaction. */
int msu_su_nonroot_after_setresuid(struct msu_su_registry *registry,
    u32 old_uid, long syscall_result, struct msu_su_nonroot_mounts *mounts,
    struct msu_su_nonroot_receipt *receipt);
#endif
