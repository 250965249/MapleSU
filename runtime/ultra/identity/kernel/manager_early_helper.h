// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_EARLY_HELPER_H
#define MAPLESU_MANAGER_EARLY_HELPER_H
#include "request_protocol.h"

struct msu_installation_helper_lease;
/* HOST owns these real installation/executable references. Acquire is called
 * without management locks; validate may run under session.operation. HOST
 * revoke may detach sessions under the table lock but never waits for cleanup
 * while holding its installation mutex. Put runs in sleepable cleanup context. */
int msu_installation_helper_acquire(const maplesu_host_instance *host,
    struct msu_installation_helper_lease **lease, u32 *epoch, u64 *service, u32 *effects);
int msu_installation_helper_validate(struct msu_installation_helper_lease *lease);
void msu_installation_helper_put(struct msu_installation_helper_lease *lease);
#endif
