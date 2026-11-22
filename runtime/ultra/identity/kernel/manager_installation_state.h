// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_INSTALLATION_STATE_H
#define MAPLESU_MANAGER_INSTALLATION_STATE_H
#include "request_protocol.h"
struct file;
struct msu_installation_helper_lease;
/* The worker must have completed genuine vendor READ/enrollment first. Acquire
 * does not enroll. It clears effects, then preserves actual observed source
 * invalidation/revoke effects with the original error. These are kernel-only
 * objects, not namespace/UID/path credentials.
 * CORE retains the lease with its exact task/mm/exec/credential session refs. */
int msu_installation_helper_acquire(const maplesu_host_instance *host,
    struct msu_installation_helper_lease **lease, u32 *epoch, u64 *service, u32 *effects);
/* Bounded current generation/admission validation, without disk I/O. Lock order
 * is session.operation -> installation mutex. Revoke never takes operation. */
int msu_installation_helper_validate(struct msu_installation_helper_lease *lease);
void msu_installation_helper_put(struct msu_installation_helper_lease *lease);
/* Host-only close, outside installation/gateway/session locks. */
int msu_installation_helper_close(const maplesu_host_instance *host, u32 *effects);
/* The bound factory callback closes its own admission and actually drains its
 * installation-owned execution refs. A nonzero result retains every live ref.
 * It may not reenter this installation mutex. Owner/context are boot-live. */
typedef int (*msu_installation_revoke_fn)(void *context,
    const maplesu_host_instance *host, const unsigned char generation[16], u32 *effects);
int msu_installation_init(const maplesu_host_instance *host,
    const unsigned char name[16]);
int msu_installation_bind_lifecycle(const maplesu_host_instance *host,
    const void *owner, msu_installation_revoke_fn revoke, void *context);
/* Only after external service/provider retirement is actually complete. */
int msu_installation_unbind_lifecycle(const maplesu_host_instance *host, const void *owner);
int msu_installation_discard_unpublished(void);
int msu_installation_read(maplesu_installation_state_v3 *output);
int msu_installation_management(u64 action, maplesu_installation_state_v3 *value,
    u32 *effects);
/* Only sessionless VENDOR_STATE uses this: real init-user-ns Root plus exact
 * retained current executable inode, never a package string or caller role. */
int msu_installation_vendor(u64 action, u64 index,
    maplesu_installation_state_v3 *value, u32 *effects);
#endif
