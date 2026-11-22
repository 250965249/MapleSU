// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_MANAGER_OWNER_CLAIM_H
#define MAPLESU_MANAGER_OWNER_CLAIM_H

#include "manager_owner.h"

/* Only the retained host supplies owner and the internal output epoch.
 * The existing signed-install policy remains private to manager_claim_entry.c.
 * This entry has no legacy Key/name input and never copies a Key to a user address.
 * A successful return is not a user response: the shared gateway still validates
 * the epoch and publishes its own versioned response before returning. */
int msu_manager_owner_claim_entry(struct msu_manager_owner *owner, u32 *epoch);

#endif
