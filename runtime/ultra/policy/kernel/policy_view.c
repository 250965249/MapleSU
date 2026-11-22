// SPDX-License-Identifier: GPL-3.0-only
/* Policy serialization and initial SID-table construction follow KernelSU
 * sepolicy.c/rules.c. Do not retain aliases into the replaceable live policy. */
#include "policy_view_internal.h"
#ifndef MAPLESU_POLICY_BOOT_HOST_TEST
#include <linux/netlink.h>
#include <net/sock.h>
#endif

struct maplesu_policy_view maplesu_view;
static DEFINE_MUTEX(view_prepare_lock);

static struct selinux_policy *copy_policy(struct selinux_policy *live)
{
    struct selinux_policy *copy;
    struct policy_file *fp = NULL;
    struct policydb *live_db = &PV_FIELD(live, selinux_policy, policydb);
    size_t padding, length, written;
    void *data;
    int rc;

    if (check_mul_overflow((size_t)PV_SYMTAB(live_db, p_types, SYM_TYPES).nprim,
                          sizeof(u32) + sizeof(u64), &padding) ||
        check_add_overflow((size_t)PV_FIELD(live_db, policydb, len), padding, &length))
        return ERR_PTR(-EOVERFLOW);
    data = vmalloc(length);
    if (!data)
        return ERR_PTR(-ENOMEM);
    fp = kzalloc(PV_SIZE(policy_file), GFP_KERNEL);
    if (!fp) {
        rc = -ENOMEM;
        goto free_data;
    }
    PV_FIELD(fp, policy_file, data) = data;
    PV_FIELD(fp, policy_file, len) = length;
    rc = policydb_write(live_db, fp);
    if (rc)
        goto free_data;
    written = length - PV_FIELD(fp, policy_file, len);
    /* Older Android serializers omit these active config flags. */
#if defined(POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE) && defined(POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH)
    if (written >= 24) {
        __le32 *config = (__le32 *)((char *)data + 20);
        u32 flags = le32_to_cpu(*config);
        if (PV_BITS(live_db, policydb, android_netlink_route))
            flags |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        if (PV_BITS(live_db, policydb, android_netlink_getneigh))
            flags |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        *config = cpu_to_le32(flags);
    }
#endif
    copy = kzalloc(PV_SIZE(selinux_policy), GFP_KERNEL);
    if (!copy) {
        rc = -ENOMEM;
        goto free_data;
    }
    PV_FIELD(fp, policy_file, data) = data;
    PV_FIELD(fp, policy_file, len) = written;
    rc = policydb_read(&PV_FIELD(copy, selinux_policy, policydb), fp);
    /* policydb_read destroys its partially decoded database on error. */
    if (rc)
        goto free_copy;
    PV_FIELD(&PV_FIELD(copy, selinux_policy, policydb), policydb, len) = written;
    PV_FIELD(copy, selinux_policy, latest_granting) = PV_FIELD(live, selinux_policy, latest_granting);
    PV_FIELD(copy, selinux_policy, sidtab) = kzalloc(PV_SIZE(sidtab), GFP_KERNEL);
    if (!PV_FIELD(copy, selinux_policy, sidtab)) {
        rc = -ENOMEM;
        goto destroy_db;
    }
    rc = policydb_load_isids(&PV_FIELD(copy, selinux_policy, policydb), PV_FIELD(copy, selinux_policy, sidtab));
    /* load_isids destroys an initialized SID table itself on failure. */
    if (rc) {
        kfree(PV_FIELD(copy, selinux_policy, sidtab));
        goto destroy_db;
    }
    kfree(fp);
    vfree(data);
    return copy;

destroy_db:
    policydb_destroy(&PV_FIELD(copy, selinux_policy, policydb));
free_copy:
    kfree(copy);
free_data:
    kfree(fp);
    vfree(data);
    return ERR_PTR(rc);
}

static void destroy_policy_copy(struct selinux_policy *policy)
{
    sidtab_destroy(PV_FIELD(policy, selinux_policy, sidtab));
    kfree(PV_FIELD(policy, selinux_policy, sidtab));
    policydb_destroy(&PV_FIELD(policy, selinux_policy, policydb));
    kfree(policy);
}

/* Initial preparation and genuine reload refresh both own view_epoch_lock for
 * writing. Readers keep one snapshot throughout a context/access transaction. */
static int capture_view(bool replace)
{
    struct selinux_policy *live, *copy, *previous;
    struct page *status, *snapshot;
    struct selinux_kernel_status baseline;
    int rc = 0;

#if !defined(MAPLESU_POLICY_BOOT_HOST_TEST)
    if (READ_ONCE(maplesu_policy_layout.ready) != 1)
        return -EINVAL;
#endif
    if (pv_current_uid().val != 0)
        return -EPERM;
    /* The SDK transport is not a proof of a sleepable caller. Reject before
     * the first mutex/allocation, including preemptible RCU read sections. */
    if (!in_task() || irqs_disabled() || in_atomic() || rcu_preempt_depth())
        return -EWOULDBLOCK;
    mutex_lock(&view_prepare_lock);
    if (maplesu_view.policy && !replace) {
        rc = -EALREADY;
        goto out;
    }
    /* This mutex serializes real reloads, without sleeping under an RCU lock. */
    mutex_lock(&PV_FIELD(&selinux_state, selinux_state, policy_mutex));
    live = rcu_dereference_protected(PV_FIELD(&selinux_state, selinux_state, policy),
                                    lockdep_is_held(&PV_FIELD(&selinux_state, selinux_state, policy_mutex)));
    if (!live) {
        rc = -EAGAIN;
        goto out_policy;
    }
    copy = copy_policy(live);
    if (IS_ERR(copy)) {
        rc = PTR_ERR(copy);
        goto out_policy;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    status = selinux_kernel_status_page();
#else
    status = selinux_kernel_status_page(&selinux_state);
#endif
    if (!status) {
        rc = -ENOMEM;
        goto destroy_copy;
    }
    mutex_lock(&PV_FIELD(&selinux_state, selinux_state, status_lock));
    memcpy(&baseline, page_address(status), sizeof(baseline));
    mutex_unlock(&PV_FIELD(&selinux_state, selinux_state, status_lock));
    /* NATIVE_MODULE may suppress status notifications before a retry reaches us. The
     * copied policy is authoritative; the status notification counter is not. */
    if (baseline.version != SELINUX_KERNEL_STATUS_VERSION ||
        (baseline.sequence & 1)) {
        rc = -EAGAIN;
        goto destroy_copy;
    }
    snapshot = maplesu_view.status;
    if (!snapshot)
        snapshot = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!snapshot) {
        rc = -ENOMEM;
        goto destroy_copy;
    }
    if (!replace) {
        /* Both environment loaders run after platform policy initialization.
         * Match KSU late-load status semantics only in the independent app
         * page. These values describe that view, not a universal stock state. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
        baseline.sequence = 4;
        baseline.policyload = 1;
#else
        baseline.sequence = 0;
        baseline.policyload = 0;
#endif
        baseline.enforcing = 1;
    } else {
        /* Refresh policy contents without publishing the loader's later
         * enforcement/policyload history into an inherited app mapping. */
        memcpy(&baseline, page_address(snapshot), sizeof(baseline));
    }
    {
        struct selinux_kernel_status *target = (void *)page_address(snapshot);

        /* Keep inherited VMAs on the same page and publish with seqlock order. */
        WRITE_ONCE(target->sequence, baseline.sequence | 1);
        smp_wmb();
        WRITE_ONCE(target->version, baseline.version);
        WRITE_ONCE(target->enforcing, baseline.enforcing);
        WRITE_ONCE(target->policyload, baseline.policyload);
        WRITE_ONCE(target->deny_unknown, baseline.deny_unknown);
        smp_wmb();
        WRITE_ONCE(target->sequence, baseline.sequence);
    }
    maplesu_view.status = snapshot;
    /* The KSU fast path is valid only for this exact live table/generation.
     * Ultra's independent reloaders use the name-based fallback automatically. */
    maplesu_view.original_live_db = &PV_FIELD(live, selinux_policy, policydb);
    maplesu_view.original_live_generation = PV_FIELD(live, selinux_policy, latest_granting);
    maplesu_view.original_type_limit = PV_SYMTAB(&PV_FIELD(copy, selinux_policy, policydb), p_types, SYM_TYPES).nprim;
    /* Publication is last: query hooks never see a partially built view. */
    previous = maplesu_view.policy;
    smp_store_release(&maplesu_view.policy, copy);
    if (previous)
        destroy_policy_copy(previous);
    goto out_policy;
destroy_copy:
    destroy_policy_copy(copy);
out_policy:
    mutex_unlock(&PV_FIELD(&selinux_state, selinux_state, policy_mutex));
out:
    mutex_unlock(&view_prepare_lock);
    return rc;
}

int maplesu_policy_view_prepare(void)
{
    int rc;

    if (!in_task() || irqs_disabled() || in_atomic() || rcu_preempt_depth())
        return -EWOULDBLOCK;
    maplesu_policy_view_reload(0, 0);
    rc = capture_view(false);
    /* A failed/initial prepare must not refresh a second time on unlock. */
    maplesu_policy_view_reload(1, -1);
    return rc;
}

int maplesu_policy_refresh_snapshot(void)
{
    return capture_view(true);
}

int maplesu_policy_view_handles(unsigned int operation, const void *first,
                                const void *second)
{
    if (!smp_load_acquire(&maplesu_view.policy))
        return 0;
    /* Delivery runs in the sender's context, not the receiver's UID. */
    if (operation == MAPLESU_POLICY_NOTIFY_FILTER)
        return maplesu_policy_filter_selected(first, second);
    if (operation == MAPLESU_POLICY_CRED_COMMIT) {
        const struct cred *next = first;

        return next && PV_FIELD(current, task_struct, mm) &&
            (pv_current_uid().val >= 10000) != (PV_FIELD(next, cred, uid).val >= 10000);
    }
    if (pv_current_uid().val < 10000)
        return 0;
    if (operation == MAPLESU_POLICY_NOTIFY_RECEIVE) {
        const struct sock *sk = first;

        return sk && pv_sock_family(sk) == AF_NETLINK && PV_FIELD(sk, sock, sk_protocol) == NETLINK_SELINUX;
    }
    if (operation == MAPLESU_POLICY_SETPROCATTR)
        return first && !strcmp(first, "current");
    return operation <= MAPLESU_POLICY_STATUS_MMAP;
}

int maplesu_policy_view_status_open(struct inode *inode, struct file *file)
{
    struct page *status;
    (void)inode;
    /* Retain native FD ownership in both transfer directions. Only read/mmap
     * select the app view; a root reader of an app-opened FD stays live too. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    status = selinux_kernel_status_page();
#else
    status = selinux_kernel_status_page(&selinux_state);
#endif
    PV_FIELD(file, file, private_data) = status;
    return status ? 0 : -ENOMEM;
}

int maplesu_type_is_original(struct policydb *live, u32 generation, u32 type)
{
    if (live != maplesu_view.original_live_db ||
        generation != maplesu_view.original_live_generation || !generation ||
        !maplesu_view.original_type_limit || type > PV_SYMTAB(live, p_types, SYM_TYPES).nprim)
        return -1;
    return type && type <= maplesu_view.original_type_limit ? 1 : 0;
}
