// SPDX-License-Identifier: GPL-3.0-only
/* A module write is scoped to the synchronous control ioctl. No task pointer
 * survives that call. Unmarked platform loads keep their native notifications
 * and replace the view only after the original sel_write_load has returned. */
#include "policy_view_internal.h"

static DECLARE_RWSEM(view_epoch_lock);

void maplesu_policy_query_begin(void) { down_read(&view_epoch_lock); }
void maplesu_policy_query_end(void) { up_read(&view_epoch_lock); }

int maplesu_policy_view_module_write(unsigned phase)
{
    if (phase > 1 || pv_current_uid().val != 0)
        return -EINVAL;
    if (!phase) {
        if (READ_ONCE(maplesu_view.module_writer))
            return -EBUSY;
        WRITE_ONCE(maplesu_view.module_writer, current);
    } else {
        if (READ_ONCE(maplesu_view.module_writer) != current)
            return -EPERM;
        WRITE_ONCE(maplesu_view.module_writer, NULL);
    }
    return 0;
}

int maplesu_policy_hidden_sequence(u32 sequence)
{
    struct hidden_policy_epoch *epoch;

    /* The boot SDK retains its existing notification contract. The temporary
     * backend opts into origin-aware delivery when its hot transition binds. */
    if (!smp_load_acquire(&maplesu_policy_hot_bound))
        return 1;
    for (epoch = smp_load_acquire(&maplesu_view.hidden_epochs); epoch;
         epoch = epoch->next)
        if (epoch->sequence == sequence)
            return 1;
    return 0;
}

int maplesu_policy_view_policyload(u32 sequence)
{
    struct hidden_policy_epoch *epoch;

    if (READ_ONCE(maplesu_view.module_writer) != current)
        return 0;
    if (maplesu_policy_hidden_sequence(sequence))
        return 0;
    /* Published nodes are immutable and remain resident with the payload, so
     * delivery/recv in atomic context takes no sleeping lock or allocation.
     * A bound prevents unlimited growth; exhaustion is an actual backend
     * failure and the sidecar restores the native view without failing writes. */
    if (maplesu_view.hidden_epoch_count == 4096)
        return -ENOSPC;
    epoch = kzalloc(sizeof(*epoch), GFP_KERNEL);
    if (!epoch)
        return -ENOMEM;
    epoch->sequence = sequence;
    epoch->next = maplesu_view.hidden_epochs;
    ++maplesu_view.hidden_epoch_count;
    smp_store_release(&maplesu_view.hidden_epochs, epoch);
    return 0;
}

int maplesu_policy_view_reload(unsigned phase, long result)
{
    int rc = 0;

    if (phase > 1)
        return -EINVAL;
    if (!phase) {
        down_write(&view_epoch_lock);
        return 0;
    }
    if (result >= 0 && READ_ONCE(maplesu_view.module_writer) != current)
        rc = maplesu_policy_refresh_snapshot();
    up_write(&view_epoch_lock);
    return rc;
}
