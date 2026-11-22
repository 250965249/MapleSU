// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_SU_RUNTIME_FACTORY_H
#define MAPLESU_MANAGER_SU_RUNTIME_FACTORY_H
#include "manager_deployment_namespace.h"
#include "request_protocol.h"
struct msu_su_gate_frame;
struct msu_su_observed_sync_receipt;
struct msu_su_runtime_readback;
#define MSU_SU_RUNTIME_MAX_HOOKS MAPLESU_SU_RUNTIME_MAX_HOOKS
#define MSU_SU_RUNTIME_STATUS_SCHEMA 1U
#define MSU_SU_RUNTIME_INITIALIZED (1U << 0)
#define MSU_SU_RUNTIME_BOUND (1U << 1)
#define MSU_SU_RUNTIME_STARTED (1U << 2)
#define MSU_SU_RUNTIME_PUBLISHED (1U << 3)
#define MSU_SU_RUNTIME_CLOSED (1U << 4)
#define MSU_SU_RUNTIME_INSTALLATION_CLOSED (1U << 5)
struct msu_su_runtime_status {
    u32 schema, bytes;
    maplesu_host_instance host;
    unsigned char installation_generation[16], runtime_generation[16];
    u64 installation_fence;
    u32 flags, users, producers, hook_count;
    s32 status, target_error, cleanup_error, start_error;
    u32 target_qualified, installation_flags;
};
extern u32 msu_su_runtime_target_facts[9];
/* Boot-only normal LKM provider; no user addresses or generic helper authority. */
int msu_su_runtime_target_bind(unsigned long (*lookup)(const char *),
    int (*resolve_cfi)(const char *, const void *, unsigned long *));
/* Read-only diagnostics, not app authorization or SU/Ready. Requires sleepable
 * context and the actual host. Even a completed error retains actual facts.
 * No pointers, controller IDs, registry access, I/O or initialization occurs. */
int msu_su_runtime_status_get(const maplesu_host_instance *host,
    struct msu_su_runtime_status *output);
enum msu_su_hook_kind {
    MSU_SU_EXEC = 1, MSU_SU_STAT, MSU_SU_ACCESS,
    MSU_SU_SETRESUID, MSU_SU_SETRESUID16,
};
/* Built only from this target's actually selected native declarations and
 * instruction readback, not a Manager-created plan or an accepted user pointer. */
struct msu_su_runtime_hook {
    u64 entry;
    u32 kind, argument_register, result_register, filename_member;
    u32 fd_register, flags_register;
    bool syscall_frame, optional;
};
int msu_su_runtime_target_hooks(struct msu_su_runtime_hook *hooks, u32 *count);
int msu_su_runtime_init(const maplesu_host_instance *host,
    const struct msu_deployment_namespace_record *deployment);
/* Existing authenticated helper post-fs-data event, never a Manager resume.
 * The actual durable cache load and observed source return their raw errors. */
int msu_su_runtime_post_fs_data(void);
void msu_su_runtime_post_fs_data_event(void);
int msu_su_runtime_refresh(u32 full_uid, maplesu_response_owner_v3 *response);
/* Synchronize the sole durable authority after its transaction. The standalone
 * entry authorizes the current Manager; CORE's session-locked dispatch MUST
 * use _held and its existing validator instead of recursively authorizing.
 * All callbacks run without the runtime mutex or gateway/observation lock.
 * Completed effects/revision survive any later error; no grant is written. */
int msu_su_runtime_sync(u32 full_uid, maplesu_response_owner_v3 *response);
int msu_su_runtime_sync_held(u32 full_uid, maplesu_response_owner_v3 *response,
    int (*validate)(void *), void *context,
    struct msu_su_observed_sync_receipt *detail);
/* Kernel-only held immutable snapshot, not an SU qualification. validate/context
 * are borrowed for this request, never across requests. Release the view before
 * leaving that operation/session lock, including copy/error/delivery failures.
 * record validates the same task/mm/exec/cred, installation and caller again. */
int msu_su_runtime_readback_acquire(int (*validate)(void *), void *context,
    struct msu_su_runtime_readback **view, maplesu_uid_metadata_v3 *metadata,
    maplesu_response_owner_v3 *response);
int msu_su_runtime_readback_record(struct msu_su_runtime_readback *view,
    u32 index, maplesu_uid_record_v3 *record);
void msu_su_runtime_readback_put(struct msu_su_runtime_readback *view);
/* Nonblocking service retirement; installation mutex caller never reenters it. */
int msu_su_runtime_revoke_install(void *context, const maplesu_host_instance *host,
    const unsigned char generation[16], u32 *effects);
/* Close before host UID teardown; finish only after actual gateway retire. */
int msu_su_runtime_close(void);
int msu_su_runtime_discarded(void);
#endif
